//! SAMD21 Platform Adapter
//!
//! **Constraints:**
//! - 256 KB flash: **NO RSA support**, **NO HSM application**
//! - FIDO2 + OATH only
//! - No hardware TRNG (use SAMD21's limited entropy source — multiple
//!   ADC reads mixed for seed material)
//! - No OTP fuses: MKEK stored encrypted in flash
//! - USB FS on PA24 (D−) / PA25 (D+)
//! - Single-color LED on GPIO13 (digital output, on/off only)
//! - Configurable button GPIO; default: always-confirmed
//!   (no dedicated BOOTSEL on most SAMD21 boards)

use core::ops::Range;

use embedded_storage::nor_flash::{ErrorType, MultiwriteNorFlash, NorFlash, ReadNorFlash};
use rand_core::{CryptoRng, RngCore};

use crate::button::{AlwaysConfirm, ButtonReader};
use crate::led::{LedColor, LedDriver};
use crate::store::otp::{NoOtpStorage, SecureStorage};
use crate::store::StoreError;

use super::Platform;

// ---------------------------------------------------------------------------
// Flash layout: last 32 KB of the 256 KB internal flash
// ---------------------------------------------------------------------------

/// Total internal flash (256 KB).
pub const FLASH_TOTAL: u32 = 256 * 1024;
/// Storage region size (32 KB — small to leave room for firmware).
pub const FLASH_STORAGE_SIZE: u32 = 32 * 1024;
/// Start address of the storage partition.
pub const FLASH_STORAGE_START: u32 = FLASH_TOTAL - FLASH_STORAGE_SIZE;
/// End address (exclusive).
pub const FLASH_STORAGE_END: u32 = FLASH_TOTAL;

/// Erase-row size on SAMD21 is 256 bytes (4 pages × 64 bytes).
pub const ERASE_ROW_SIZE: u32 = 256;
/// NVM page size (64 bytes) — minimum write granularity.
pub const PAGE_SIZE: usize = 64;
/// Read granularity.
pub const READ_SIZE: usize = 1;

// ---------------------------------------------------------------------------
// GPIO assignments
// ---------------------------------------------------------------------------

/// USB D− pin (PA24).
pub const USB_DM_PIN: u8 = 24;
/// USB D+ pin (PA25).
pub const USB_DP_PIN: u8 = 25;
/// Single-color LED pin.
pub const LED_GPIO: u8 = 13;

// ---------------------------------------------------------------------------
// RNG entropy pool parameters
// ---------------------------------------------------------------------------

/// Number of raw 32-bit ADC noise samples to mix per request.
/// The SAMD21 has no dedicated TRNG; we harvest LSBs from the ADC.
const ENTROPY_ROUNDS: usize = 32;

// ---------------------------------------------------------------------------
// Samd21Rng — limited entropy via ADC noise mixing
// ---------------------------------------------------------------------------

/// Software RNG seeded from SAMD21 ADC thermal noise.
///
/// The SAMD21 lacks a dedicated TRNG. We read the internal temperature
/// sensor / bandgap reference ADC channel multiple times and mix the
/// least-significant bits through a simple xorshift accumulator to
/// produce randomness. This is **not** as strong as a hardware TRNG;
/// for production use, an external entropy source or SAMD51 is preferred.
pub struct Samd21Rng {
    state: u64,
}

impl Samd21Rng {
    /// Create a new RNG, seeded from ADC noise.
    pub fn new() -> Self {
        let mut rng = Self {
            state: 0xDEAD_BEEF_CAFE_BABE,
        };
        // Mix initial entropy from hardware.
        rng.reseed_from_adc();
        rng
    }

    /// Read a raw ADC sample from the internal temperature sensor and
    /// return the low bits as entropy.
    fn read_adc_noise() -> u32 {
        // SAMD21 ADC base registers.
        const ADC_BASE: u32 = 0x4200_4000;
        const ADC_CTRLA: u32 = ADC_BASE;
        const ADC_INPUTCTRL: u32 = ADC_BASE + 0x10;
        const ADC_SWTRIG: u32 = ADC_BASE + 0x0C;
        const ADC_INTFLAG: u32 = ADC_BASE + 0x18;
        const ADC_RESULT: u32 = ADC_BASE + 0x1A;

        unsafe {
            // Select internal temperature sensor (MUXPOS = 0x18).
            core::ptr::write_volatile(
                ADC_INPUTCTRL as *mut u32,
                0x18 << 0, // MUXPOS = temp sensor
            );

            // Enable ADC.
            let ctrla = core::ptr::read_volatile(ADC_CTRLA as *const u16);
            core::ptr::write_volatile(ADC_CTRLA as *mut u16, ctrla | 0x02);

            // Trigger a conversion.
            core::ptr::write_volatile(ADC_SWTRIG as *mut u8, 0x02);

            // Wait for RESRDY flag.
            loop {
                let flags = core::ptr::read_volatile(ADC_INTFLAG as *const u8);
                if flags & 0x01 != 0 {
                    break;
                }
            }

            // Read result.
            let result = core::ptr::read_volatile(ADC_RESULT as *const u16);
            result as u32
        }
    }

    /// Mix multiple ADC samples into the internal state using xorshift.
    fn reseed_from_adc(&mut self) {
        for _ in 0..ENTROPY_ROUNDS {
            let noise = Self::read_adc_noise() as u64;
            self.state ^= noise;
            self.state = self.xorshift64(self.state);
        }
    }

    /// xorshift64* PRNG step.
    fn xorshift64(&self, mut s: u64) -> u64 {
        s ^= s >> 12;
        s ^= s << 25;
        s ^= s >> 27;
        s.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
}

impl RngCore for Samd21Rng {
    fn next_u32(&mut self) -> u32 {
        self.state = self.xorshift64(self.state);
        // Periodically re-mix hardware entropy.
        if (self.state & 0xFF) == 0 {
            self.reseed_from_adc();
        }
        (self.state >> 16) as u32
    }

    fn next_u64(&mut self) -> u64 {
        let hi = self.next_u32() as u64;
        let lo = self.next_u32() as u64;
        (hi << 32) | lo
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        let mut offset = 0;
        while offset + 4 <= dest.len() {
            let word = self.next_u32();
            dest[offset..offset + 4].copy_from_slice(&word.to_le_bytes());
            offset += 4;
        }
        if offset < dest.len() {
            let word = self.next_u32();
            let bytes = word.to_le_bytes();
            for (i, b) in bytes.iter().enumerate() {
                if offset + i >= dest.len() {
                    break;
                }
                dest[offset + i] = *b;
            }
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

// SAMD21 entropy quality is limited but this is the best we can do
// without external hardware. Document accordingly.
impl CryptoRng for Samd21Rng {}

// ---------------------------------------------------------------------------
// Samd21Flash — internal NVM, last 32 KB
// ---------------------------------------------------------------------------

/// NOR flash driver for the SAMD21 internal NVM controller.
///
/// The SAMD21 NVM has:
/// - 256-byte erase rows (4 × 64-byte pages)
/// - 64-byte page writes (minimum granularity)
///
/// We use the last 32 KB for key-value storage.
pub struct Samd21Flash {
    range: Range<u32>,
}

#[derive(Debug)]
pub struct Samd21FlashError;

impl embedded_storage::nor_flash::NorFlashError for Samd21FlashError {
    fn kind(&self) -> embedded_storage::nor_flash::NorFlashErrorKind {
        embedded_storage::nor_flash::NorFlashErrorKind::Other
    }
}

impl Samd21Flash {
    pub fn new() -> Self {
        Self {
            range: FLASH_STORAGE_START..FLASH_STORAGE_END,
        }
    }

    pub fn with_range(range: Range<u32>) -> Self {
        Self { range }
    }

    /// Read bytes via direct memory-mapped access (NVM is XIP on SAMD21).
    fn raw_read(&self, address: u32, buf: &mut [u8]) -> Result<(), Samd21FlashError> {
        unsafe {
            let src = address as *const u8;
            core::ptr::copy_nonoverlapping(src, buf.as_mut_ptr(), buf.len());
        }
        Ok(())
    }

    /// Write a page (64 bytes) through the NVM controller.
    fn raw_write_page(&mut self, page_addr: u32, data: &[u8]) -> Result<(), Samd21FlashError> {
        const NVMCTRL_BASE: u32 = 0x4100_4000;
        const NVMCTRL_CTRLA: u32 = NVMCTRL_BASE;
        const NVMCTRL_INTFLAG: u32 = NVMCTRL_BASE + 0x14;
        const NVMCTRL_ADDR: u32 = NVMCTRL_BASE + 0x1C;
        const CMD_WP: u16 = 0xA504; // Write Page command with key

        unsafe {
            // Clear the page buffer by writing to the address.
            core::ptr::write_volatile(NVMCTRL_ADDR as *mut u32, page_addr >> 1);

            // Fill the page buffer by writing to the NVM address space.
            let dst = page_addr as *mut u8;
            let len = data.len().min(PAGE_SIZE);
            core::ptr::copy_nonoverlapping(data.as_ptr(), dst, len);
            // Pad remaining bytes with 0xFF.
            if len < PAGE_SIZE {
                core::ptr::write_bytes(dst.add(len), 0xFF, PAGE_SIZE - len);
            }

            // Issue Write Page command.
            core::ptr::write_volatile(NVMCTRL_CTRLA as *mut u16, CMD_WP);

            // Wait for NVM ready.
            loop {
                let flags = core::ptr::read_volatile(NVMCTRL_INTFLAG as *const u8);
                if flags & 0x01 != 0 {
                    // Clear READY flag.
                    core::ptr::write_volatile(NVMCTRL_INTFLAG as *mut u8, 0x01);
                    break;
                }
            }
        }
        Ok(())
    }

    /// Erase a 256-byte row.
    fn raw_erase_row(&mut self, row_addr: u32) -> Result<(), Samd21FlashError> {
        const NVMCTRL_BASE: u32 = 0x4100_4000;
        const NVMCTRL_CTRLA: u32 = NVMCTRL_BASE;
        const NVMCTRL_INTFLAG: u32 = NVMCTRL_BASE + 0x14;
        const NVMCTRL_ADDR: u32 = NVMCTRL_BASE + 0x1C;
        const CMD_ER: u16 = 0xA502; // Erase Row command with key

        unsafe {
            core::ptr::write_volatile(NVMCTRL_ADDR as *mut u32, row_addr >> 1);
            core::ptr::write_volatile(NVMCTRL_CTRLA as *mut u16, CMD_ER);

            loop {
                let flags = core::ptr::read_volatile(NVMCTRL_INTFLAG as *const u8);
                if flags & 0x01 != 0 {
                    core::ptr::write_volatile(NVMCTRL_INTFLAG as *mut u8, 0x01);
                    break;
                }
            }
        }
        Ok(())
    }
}

impl ErrorType for Samd21Flash {
    type Error = Samd21FlashError;
}

impl ReadNorFlash for Samd21Flash {
    const READ_SIZE: usize = READ_SIZE;

    fn read(&mut self, offset: u32, bytes: &mut [u8]) -> Result<(), Self::Error> {
        let abs = self.range.start + offset;
        self.raw_read(abs, bytes)
    }

    fn capacity(&self) -> usize {
        (self.range.end - self.range.start) as usize
    }
}

impl NorFlash for Samd21Flash {
    const WRITE_SIZE: usize = PAGE_SIZE;
    const ERASE_SIZE: usize = ERASE_ROW_SIZE as usize;

    fn erase(&mut self, from: u32, to: u32) -> Result<(), Self::Error> {
        let mut addr = self.range.start + from;
        let end = self.range.start + to;
        while addr < end {
            self.raw_erase_row(addr)?;
            addr += ERASE_ROW_SIZE;
        }
        Ok(())
    }

    fn write(&mut self, offset: u32, bytes: &[u8]) -> Result<(), Self::Error> {
        let base = self.range.start + offset;
        let mut written = 0;
        while written < bytes.len() {
            let page_addr = base + written as u32;
            let chunk_end = (written + PAGE_SIZE).min(bytes.len());
            self.raw_write_page(page_addr, &bytes[written..chunk_end])?;
            written = chunk_end;
        }
        Ok(())
    }
}

impl MultiwriteNorFlash for Samd21Flash {}

// ---------------------------------------------------------------------------
// Samd21Led — single-color GPIO13 toggle
// ---------------------------------------------------------------------------

/// Simple on/off LED on GPIO13 (port PA13 on most SAMD21 boards).
///
/// This is a single digital output — set_color is a no-op.
pub struct Samd21Led {
    gpio: u8,
    is_on: bool,
}

impl Samd21Led {
    pub fn new() -> Self {
        Self::on_pin(LED_GPIO)
    }

    pub fn on_pin(gpio: u8) -> Self {
        // Configure the pin as output via PORT registers.
        Self::configure_output(gpio);
        Self { gpio, is_on: false }
    }

    /// Set the GPIO pin direction to output.
    fn configure_output(gpio: u8) {
        // PORT group 0 (PA) base.
        const PORT_BASE: u32 = 0x4100_4400;
        const DIRSET_OFFSET: u32 = 0x08;

        unsafe {
            let dirset = (PORT_BASE + DIRSET_OFFSET) as *mut u32;
            core::ptr::write_volatile(dirset, 1 << gpio);
        }
    }

    /// Drive the GPIO high (LED on) or low (LED off).
    fn set_gpio(&self, high: bool) {
        const PORT_BASE: u32 = 0x4100_4400;
        const OUTSET_OFFSET: u32 = 0x18;
        const OUTCLR_OFFSET: u32 = 0x14;

        let offset = if high { OUTSET_OFFSET } else { OUTCLR_OFFSET };
        unsafe {
            let reg = (PORT_BASE + offset) as *mut u32;
            core::ptr::write_volatile(reg, 1 << self.gpio);
        }
    }
}

impl LedDriver for Samd21Led {
    fn set_on(&mut self) {
        self.is_on = true;
        self.set_gpio(true);
    }

    fn set_off(&mut self) {
        self.is_on = false;
        self.set_gpio(false);
    }

    fn set_color(&mut self, _color: LedColor) {
        // Single-color LED — colour is ignored.
    }
}

// ---------------------------------------------------------------------------
// Samd21Button — configurable GPIO or AlwaysConfirm fallback
// ---------------------------------------------------------------------------

/// Button reader that supports either a physical GPIO or the
/// [`AlwaysConfirm`] fallback when no button hardware is available.
///
/// Most SAMD21 boards lack a dedicated BOOTSEL button. The default
/// behaviour is always-confirmed to avoid blocking user-presence flows.
pub enum Samd21Button {
    /// Physical GPIO button (active-low with external pull-up expected).
    Gpio { gpio: u8 },
    /// No physical button — always reports pressed.
    AlwaysConfirm(AlwaysConfirm),
}

impl Samd21Button {
    /// Create with a specific GPIO pin configured as input with pull-up.
    pub fn on_pin(gpio: u8) -> Self {
        // Configure as input with pull-up.
        const PORT_BASE: u32 = 0x4100_4400;
        const DIRCLR_OFFSET: u32 = 0x04;
        const PINCFG_OFFSET: u32 = 0x40;

        unsafe {
            // Set direction to input.
            let dirclr = (PORT_BASE + DIRCLR_OFFSET) as *mut u32;
            core::ptr::write_volatile(dirclr, 1 << gpio);

            // Enable input + pull-up (INEN | PULLEN).
            let pincfg = (PORT_BASE + PINCFG_OFFSET + gpio as u32) as *mut u8;
            core::ptr::write_volatile(pincfg, 0x06);

            // Set pull direction to up via OUTSET.
            let outset = (PORT_BASE + 0x18) as *mut u32;
            core::ptr::write_volatile(outset, 1 << gpio);
        }

        Samd21Button::Gpio { gpio }
    }

    /// Create the default always-confirmed fallback.
    pub fn always_confirm() -> Self {
        Samd21Button::AlwaysConfirm(AlwaysConfirm)
    }

    /// Read a physical GPIO pin level (true = low = pressed).
    fn read_gpio(gpio: u8) -> bool {
        const PORT_BASE: u32 = 0x4100_4400;
        const IN_OFFSET: u32 = 0x20;

        let val = unsafe { core::ptr::read_volatile((PORT_BASE + IN_OFFSET) as *const u32) };
        (val & (1 << gpio)) == 0
    }
}

impl ButtonReader for Samd21Button {
    fn is_pressed(&mut self) -> bool {
        match self {
            Samd21Button::Gpio { gpio } => Self::read_gpio(*gpio),
            Samd21Button::AlwaysConfirm(inner) => inner.is_pressed(),
        }
    }
}

// ---------------------------------------------------------------------------
// Samd21Platform — top-level Platform impl
// ---------------------------------------------------------------------------

/// SAMD21 platform aggregating all peripheral drivers.
///
/// **Feature-gated exclusions:** When the `samd21` feature is active, RSA
/// and HSM modules must be excluded at the application level via
/// `#[cfg(not(feature = "samd21"))]` to fit within the 256 KB flash limit.
/// Only FIDO2 and OATH applications are supported.
pub struct Samd21Platform {
    pub flash: Samd21Flash,
    pub rng: Samd21Rng,
    pub led: Samd21Led,
    pub button: Samd21Button,
    /// No OTP hardware — MKEK must be stored encrypted in flash.
    pub secure_storage: NoOtpStorage,
}

impl Samd21Platform {
    /// Initialise the platform with defaults:
    /// - Flash: last 32 KB internal NVM
    /// - RNG: ADC noise mixing
    /// - LED: GPIO13 single-color
    /// - Button: always-confirmed (no physical button)
    /// - SecureStorage: NoOtpStorage (MKEK in flash)
    pub fn new() -> Self {
        Self {
            flash: Samd21Flash::new(),
            rng: Samd21Rng::new(),
            led: Samd21Led::new(),
            button: Samd21Button::always_confirm(),
            secure_storage: NoOtpStorage,
        }
    }

    /// Create with a specific button GPIO pin.
    pub fn with_button(gpio: u8) -> Self {
        Self {
            flash: Samd21Flash::new(),
            rng: Samd21Rng::new(),
            led: Samd21Led::new(),
            button: Samd21Button::on_pin(gpio),
            secure_storage: NoOtpStorage,
        }
    }
}

impl Platform for Samd21Platform {
    type Flash = Samd21Flash;
    type Rng = Samd21Rng;
    type Led = Samd21Led;
    type Button = Samd21Button;
}
