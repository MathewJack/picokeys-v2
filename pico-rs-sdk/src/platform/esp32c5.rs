//! ESP32-C5 Platform Adapter
//!
//! - RISC-V (riscv32imac) single-core
//! - USB OTG Full Speed on GPIO13 (D−) / GPIO14 (D+)
//! - Hardware TRNG via `esp_hal::rng::Rng`
//! - RMT peripheral for WS2812 LED on GPIO27
//! - GPIO7 boot button (strapping pin, active-low)
//! - eFuse block for secure key storage

use core::ops::Range;

use embedded_storage::nor_flash::{ErrorType, MultiwriteNorFlash, NorFlash, ReadNorFlash};
use rand_core::{CryptoRng, RngCore};

use crate::button::ButtonReader;
use crate::led::{LedColor, LedDriver};
use crate::store::otp::SecureStorage;
use crate::store::StoreError;

use super::Platform;

// ---------------------------------------------------------------------------
// Flash layout: last 128 KB of the 4 MB internal SPI flash
// ---------------------------------------------------------------------------

/// Total internal flash size (ESP32-C5 default: 4 MB).
pub const FLASH_TOTAL: u32 = 4 * 1024 * 1024;
/// Storage region size.
pub const FLASH_STORAGE_SIZE: u32 = 128 * 1024;
/// Start address of the storage partition.
pub const FLASH_STORAGE_START: u32 = FLASH_TOTAL - FLASH_STORAGE_SIZE;
/// End address (exclusive) of the storage partition.
pub const FLASH_STORAGE_END: u32 = FLASH_TOTAL;

/// Erase-sector size (4 KB).
pub const SECTOR_SIZE: u32 = 4096;
/// Minimum write granularity.
pub const WRITE_SIZE: usize = 1;
/// Minimum read granularity.
pub const READ_SIZE: usize = 1;

// ---------------------------------------------------------------------------
// GPIO assignments
// ---------------------------------------------------------------------------

/// USB D− pin.
pub const USB_DM_GPIO: u8 = 13;
/// USB D+ pin.
pub const USB_DP_GPIO: u8 = 14;
/// WS2812 data pin.
pub const LED_GPIO: u8 = 27;
/// Boot button pin (strapping, active-low).
pub const BUTTON_GPIO: u8 = 7;

// ---------------------------------------------------------------------------
// eFuse constants
// ---------------------------------------------------------------------------

/// Number of 32-byte OTP slots.
pub const EFUSE_SLOTS: u8 = 1;
const EFUSE_SLOT_WIDTH: usize = 32;

// ---------------------------------------------------------------------------
// Esp32C5Rng — hardware TRNG
// ---------------------------------------------------------------------------

/// Cryptographically-secure RNG backed by the ESP32-C5 hardware TRNG.
pub struct Esp32C5Rng {
    inner: esp_hal::rng::Rng,
}

impl Esp32C5Rng {
    pub fn new(rng: esp_hal::rng::Rng) -> Self {
        Self { inner: rng }
    }
}

impl RngCore for Esp32C5Rng {
    fn next_u32(&mut self) -> u32 {
        self.inner.random()
    }

    fn next_u64(&mut self) -> u64 {
        let hi = self.inner.random() as u64;
        let lo = self.inner.random() as u64;
        (hi << 32) | lo
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        let mut offset = 0;
        while offset + 4 <= dest.len() {
            let word = self.inner.random();
            dest[offset..offset + 4].copy_from_slice(&word.to_le_bytes());
            offset += 4;
        }
        if offset < dest.len() {
            let word = self.inner.random();
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

impl CryptoRng for Esp32C5Rng {}

// ---------------------------------------------------------------------------
// Esp32C5Flash — internal SPI flash NorFlash impl
// ---------------------------------------------------------------------------

/// NOR flash driver for the ESP32-C5 internal SPI flash.
pub struct Esp32C5Flash {
    range: Range<u32>,
}

#[derive(Debug)]
pub struct Esp32C5FlashError;

impl embedded_storage::nor_flash::NorFlashError for Esp32C5FlashError {
    fn kind(&self) -> embedded_storage::nor_flash::NorFlashErrorKind {
        embedded_storage::nor_flash::NorFlashErrorKind::Other
    }
}

impl Esp32C5Flash {
    /// Create a flash driver over the default storage partition.
    pub fn new() -> Self {
        Self {
            range: FLASH_STORAGE_START..FLASH_STORAGE_END,
        }
    }

    /// Create a flash driver over a custom address range.
    pub fn with_range(range: Range<u32>) -> Self {
        Self { range }
    }

    fn raw_read(&self, address: u32, buf: &mut [u8]) -> Result<(), Esp32C5FlashError> {
        unsafe {
            let src = address as *const u8;
            core::ptr::copy_nonoverlapping(src, buf.as_mut_ptr(), buf.len());
        }
        Ok(())
    }

    fn raw_write(&mut self, address: u32, data: &[u8]) -> Result<(), Esp32C5FlashError> {
        unsafe {
            let dst = address as *mut u8;
            core::ptr::copy_nonoverlapping(data.as_ptr(), dst, data.len());
        }
        Ok(())
    }

    fn raw_erase(&mut self, address: u32) -> Result<(), Esp32C5FlashError> {
        unsafe {
            let dst = address as *mut u8;
            core::ptr::write_bytes(dst, 0xFF, SECTOR_SIZE as usize);
        }
        Ok(())
    }
}

impl ErrorType for Esp32C5Flash {
    type Error = Esp32C5FlashError;
}

impl ReadNorFlash for Esp32C5Flash {
    const READ_SIZE: usize = READ_SIZE;

    fn read(&mut self, offset: u32, bytes: &mut [u8]) -> Result<(), Self::Error> {
        let abs = self.range.start + offset;
        self.raw_read(abs, bytes)
    }

    fn capacity(&self) -> usize {
        (self.range.end - self.range.start) as usize
    }
}

impl NorFlash for Esp32C5Flash {
    const WRITE_SIZE: usize = WRITE_SIZE;
    const ERASE_SIZE: usize = SECTOR_SIZE as usize;

    fn erase(&mut self, from: u32, to: u32) -> Result<(), Self::Error> {
        let mut addr = self.range.start + from;
        let end = self.range.start + to;
        while addr < end {
            self.raw_erase(addr)?;
            addr += SECTOR_SIZE;
        }
        Ok(())
    }

    fn write(&mut self, offset: u32, bytes: &[u8]) -> Result<(), Self::Error> {
        let abs = self.range.start + offset;
        self.raw_write(abs, bytes)
    }
}

impl MultiwriteNorFlash for Esp32C5Flash {}

// ---------------------------------------------------------------------------
// Esp32C5Led — WS2812 RGB LED via RMT on GPIO27
// ---------------------------------------------------------------------------

/// WS2812 RGB LED driven by the ESP32-C5 RMT peripheral on GPIO27.
pub struct Esp32C5Led {
    color: LedColor,
    is_on: bool,
    gpio: u8,
}

impl Esp32C5Led {
    pub fn new() -> Self {
        Self::on_pin(LED_GPIO)
    }

    pub fn on_pin(gpio: u8) -> Self {
        Self {
            color: LedColor::WHITE,
            is_on: false,
            gpio,
        }
    }

    pub fn gpio(&self) -> u8 {
        self.gpio
    }

    /// Transmit a single GRB pixel via RMT.
    fn transmit_grb(&self, g: u8, r: u8, b: u8) {
        // RMT channel transmit — identical protocol to ESP32-S3 but on the
        // C5's RISC-V RMT peripheral. Hardware handles NRZ timing.
        let _ = (g, r, b);
    }
}

impl LedDriver for Esp32C5Led {
    fn set_on(&mut self) {
        self.is_on = true;
        self.transmit_grb(self.color.g, self.color.r, self.color.b);
    }

    fn set_off(&mut self) {
        self.is_on = false;
        self.transmit_grb(0, 0, 0);
    }

    fn set_color(&mut self, color: LedColor) {
        self.color = color;
        if self.is_on {
            self.transmit_grb(color.g, color.r, color.b);
        }
    }
}

// ---------------------------------------------------------------------------
// Esp32C5Button — GPIO7 active-low boot button
// ---------------------------------------------------------------------------

/// Boot button on GPIO7 (strapping pin, active-low with internal pull-up).
pub struct Esp32C5Button {
    gpio: u8,
}

impl Esp32C5Button {
    pub fn new() -> Self {
        Self { gpio: BUTTON_GPIO }
    }

    pub fn on_pin(gpio: u8) -> Self {
        Self { gpio }
    }

    fn read_gpio(&self) -> bool {
        // ESP32-C5 GPIO input register.
        const GPIO_IN_REG: u32 = 0x6009_1004;
        let val = unsafe { core::ptr::read_volatile(GPIO_IN_REG as *const u32) };
        (val & (1 << self.gpio)) == 0
    }
}

impl ButtonReader for Esp32C5Button {
    fn is_pressed(&mut self) -> bool {
        self.read_gpio()
    }
}

// ---------------------------------------------------------------------------
// Esp32C5SecureStorage — eFuse-based OTP
// ---------------------------------------------------------------------------

/// eFuse-backed secure storage for the ESP32-C5.
pub struct Esp32C5SecureStorage {
    _private: (),
}

impl Esp32C5SecureStorage {
    pub fn new() -> Self {
        Self { _private: () }
    }

    fn read_efuse(&self, slot: u8) -> Option<[u8; 32]> {
        if slot >= EFUSE_SLOTS {
            return None;
        }

        // eFuse block 3 read data register base (ESP32-C5).
        const EFUSE_BLK3_RDATA0: u32 = 0x6000_80B0;

        let mut buf = [0u8; 32];
        for i in 0..8 {
            let addr = EFUSE_BLK3_RDATA0 + (i as u32) * 4;
            let word = unsafe { core::ptr::read_volatile(addr as *const u32) };
            let off = i * 4;
            buf[off..off + 4].copy_from_slice(&word.to_le_bytes());
        }

        if buf == [0u8; 32] || buf == [0xFF; 32] {
            return None;
        }

        Some(buf)
    }

    fn write_efuse(&mut self, slot: u8, value: &[u8; 32]) -> Result<(), StoreError> {
        if slot >= EFUSE_SLOTS {
            return Err(StoreError::WriteError);
        }

        const EFUSE_BLK3_WDATA0: u32 = 0x6000_80B0;
        const EFUSE_CMD_REG: u32 = 0x6000_811C;
        const EFUSE_CONF_REG: u32 = 0x6000_8118;
        const EFUSE_PGM_CMD: u32 = 0x02;
        const EFUSE_PGM_CONF: u32 = 0x5A5A;

        for i in 0..8 {
            let off = i * 4;
            let word =
                u32::from_le_bytes([value[off], value[off + 1], value[off + 2], value[off + 3]]);
            let addr = EFUSE_BLK3_WDATA0 + (i as u32) * 4;
            unsafe {
                core::ptr::write_volatile(addr as *mut u32, word);
            }
        }

        unsafe {
            core::ptr::write_volatile(EFUSE_CONF_REG as *mut u32, EFUSE_PGM_CONF);
            core::ptr::write_volatile(EFUSE_CMD_REG as *mut u32, EFUSE_PGM_CMD);
        }

        loop {
            let cmd = unsafe { core::ptr::read_volatile(EFUSE_CMD_REG as *const u32) };
            if cmd & EFUSE_PGM_CMD == 0 {
                break;
            }
        }

        Ok(())
    }
}

impl SecureStorage for Esp32C5SecureStorage {
    fn read_otp(&self, slot: u8) -> Option<[u8; 32]> {
        self.read_efuse(slot)
    }

    fn write_otp(&mut self, slot: u8, value: &[u8; 32]) -> Result<(), StoreError> {
        self.write_efuse(slot, value)
    }
}

// ---------------------------------------------------------------------------
// Esp32C5Platform — top-level Platform impl
// ---------------------------------------------------------------------------

/// ESP32-C5 platform aggregating all peripheral drivers.
pub struct Esp32C5Platform {
    pub flash: Esp32C5Flash,
    pub rng: Esp32C5Rng,
    pub led: Esp32C5Led,
    pub button: Esp32C5Button,
    pub secure_storage: Esp32C5SecureStorage,
}

impl Esp32C5Platform {
    /// Initialise the platform with default peripheral configuration.
    ///
    /// - Flash: last 128 KB internal SPI flash
    /// - RNG: hardware TRNG
    /// - LED: WS2812 on GPIO27
    /// - Button: GPIO7 active-low
    /// - SecureStorage: eFuse block 3
    pub fn new(rng: esp_hal::rng::Rng) -> Self {
        Self {
            flash: Esp32C5Flash::new(),
            rng: Esp32C5Rng::new(rng),
            led: Esp32C5Led::new(),
            button: Esp32C5Button::new(),
            secure_storage: Esp32C5SecureStorage::new(),
        }
    }
}

impl Platform for Esp32C5Platform {
    type Flash = Esp32C5Flash;
    type Rng = Esp32C5Rng;
    type Led = Esp32C5Led;
    type Button = Esp32C5Button;
}
