//! RP2350 platform adapter for the Raspberry Pi Pico 2.
//!
//! Provides concrete implementations of [`Platform`], [`LedDriver`],
//! [`ButtonReader`], [`SecureStorage`], and RNG for the RP2350 MCU:
//!
//! | Peripheral | Implementation |
//! |------------|----------------|
//! | **Flash** | QSPI via `embassy_rp::flash::Flash`, last 128 KB for KV storage |
//! | **RNG** | Dedicated hardware TRNG peripheral (ARM CryptoCell-based) |
//! | **LED** | GPIO25 digital output (single-color on-board LED) |
//! | **Button** | BOOTSEL via QSPI_SS_N (bit 17 in `GPIO_HI_IN`) |
//! | **OTP** | Hardware OTP fuses — [`Rp2350OtpStorage`] implements [`SecureStorage`] |
//! | **Secure boot** | ARM TrustZone state checked via [`check_secure_boot`] |

use cortex_m::interrupt;
use embassy_rp::flash::{Async, Flash};
use embassy_rp::gpio::Output;
use embassy_rp::peripherals::FLASH;
use rand_core::{CryptoRng, RngCore};

use crate::button::ButtonReader;
use crate::led::{LedColor, LedDriver};
use crate::platform::Platform;
use crate::store::otp::SecureStorage;
use crate::store::StoreError;

// ── Flash layout ──────────────────────────────────────────────────

/// Total flash size on the Raspberry Pi Pico 2 (4 MB).
pub const TOTAL_FLASH_SIZE: usize = 4 * 1024 * 1024;

/// Size of the storage region reserved for key-value data (128 KB).
pub const STORAGE_SIZE: u32 = 128 * 1024;

/// Start offset of the KV storage region within flash.
pub const STORAGE_START: u32 = TOTAL_FLASH_SIZE as u32 - STORAGE_SIZE;

/// Erase-sector size of the on-board flash (4 KB).
pub const STORAGE_PAGE_SIZE: u32 = 4096;

// ── RNG — Hardware TRNG ──────────────────────────────────────────

/// RP2350 TRNG peripheral base address (ARM CryptoCell-based).
const TRNG_BASE: u32 = 0x400D_0000;

/// TRNG register offsets (RP2350 datasheet §6.4 / ARM CryptoCell-312).
mod trng_regs {
    /// Interrupt mask — write 0 to unmask EHR_VALID.
    pub const RNG_IMR: u32 = 0x100;
    /// Interrupt clear register — write 1 to acknowledge.
    pub const RNG_ICR: u32 = 0x108;
    /// Configuration: 0 = full entropy (Von Neumann + CRNGT).
    pub const TRNG_CONFIG: u32 = 0x10C;
    /// Valid flag — bit 0 set when 192 bits of entropy are ready.
    pub const TRNG_VALID: u32 = 0x110;
    /// First of 6 entropy holding registers (EHR_DATA0..5, 192 bits total).
    pub const EHR_DATA0: u32 = 0x114;
    /// Random source enable — write 1 to start the ROSC entropy source.
    pub const RND_SOURCE_ENABLE: u32 = 0x12C;
    /// Number of ROSC samples per entropy bit.
    pub const SAMPLE_CNT1: u32 = 0x190;
    /// Reset / trigger a new entropy collection cycle.
    pub const RST_BITS_COUNTER: u32 = 0x1C0;
}

/// Cryptographic RNG backed by the RP2350 dedicated TRNG peripheral.
///
/// Unlike the RP2040 (which uses ROSC jitter alone), the RP2350 has a
/// purpose-built true random number generator that passes NIST SP 800-90B
/// health tests.  Each collection cycle yields 192 bits (6 × 32-bit words)
/// which are cached internally and dispensed on demand.
pub struct TrngRng {
    /// Cached entropy words from the last TRNG collection.
    cache: [u32; 6],
    /// Index of the next unused word in `cache` (0–5).  6 = cache empty.
    idx: usize,
}

impl TrngRng {
    /// Create and initialise a new TRNG-backed RNG.
    ///
    /// Programs the TRNG with 256 ROSC-sample cycles per entropy bit and
    /// enables the entropy source.  Must be called once during platform
    /// init before any random numbers are requested.
    pub fn new() -> Self {
        // SAFETY: One-time peripheral init.  Register writes are idempotent
        // and do not affect other peripherals.
        unsafe { Self::init_trng() };
        Self {
            cache: [0u32; 6],
            idx: 6, // empty — first `next_word` will trigger a collection
        }
    }

    unsafe fn init_trng() {
        let base = TRNG_BASE as *mut u8;
        let write = |off: u32, val: u32| {
            core::ptr::write_volatile(base.add(off as usize) as *mut u32, val);
        };

        // 256 ROSC samples per entropy bit — good balance of speed vs quality.
        write(trng_regs::SAMPLE_CNT1, 256);
        // Full entropy mode: Von Neumann de-biasing + CRNGT health test.
        write(trng_regs::TRNG_CONFIG, 0);
        // Enable the ROSC entropy source.
        write(trng_regs::RND_SOURCE_ENABLE, 1);
        // Unmask the EHR_VALID interrupt (we poll, not IRQ-driven).
        write(trng_regs::RNG_IMR, 0);
    }

    /// Collect 192 bits of fresh entropy from the TRNG into the cache.
    fn collect(&mut self) {
        unsafe {
            let base = TRNG_BASE as *mut u8;
            let read = |off: u32| -> u32 {
                core::ptr::read_volatile(base.add(off as usize) as *const u32)
            };
            let write = |off: u32, val: u32| {
                core::ptr::write_volatile(base.add(off as usize) as *mut u32, val);
            };

            // Acknowledge any previous completion.
            write(trng_regs::RNG_ICR, 0xFFFF_FFFF);

            // Trigger a new 192-bit entropy collection.
            write(trng_regs::RST_BITS_COUNTER, 1);

            // Busy-wait until the entropy holding registers are valid.
            while (read(trng_regs::TRNG_VALID) & 1) == 0 {
                cortex_m::asm::nop();
            }

            // Read all 6 entropy words (reading EHR_DATA resets TRNG_VALID).
            for i in 0..6u32 {
                self.cache[i as usize] = read(trng_regs::EHR_DATA0 + i * 4);
            }

            // Clear interrupt status for next cycle.
            write(trng_regs::RNG_ICR, 0xFFFF_FFFF);
        }
        self.idx = 0;
    }

    /// Return the next 32-bit entropy word, triggering a new collection
    /// cycle when the cache is exhausted.
    fn next_word(&mut self) -> u32 {
        if self.idx >= 6 {
            self.collect();
        }
        let w = self.cache[self.idx];
        self.idx += 1;
        w
    }
}

impl Default for TrngRng {
    fn default() -> Self {
        Self::new()
    }
}

impl RngCore for TrngRng {
    fn next_u32(&mut self) -> u32 {
        self.next_word()
    }

    fn next_u64(&mut self) -> u64 {
        let lo = self.next_word() as u64;
        let hi = self.next_word() as u64;
        (hi << 32) | lo
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        let mut pos = 0;
        while pos < dest.len() {
            let word = self.next_word().to_le_bytes();
            let remaining = dest.len() - pos;
            let n = remaining.min(4);
            dest[pos..pos + n].copy_from_slice(&word[..n]);
            pos += n;
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

// SAFETY: The RP2350 TRNG is a dedicated hardware entropy source (ARM
// CryptoCell-based) that passes NIST SP 800-90B health tests.
impl CryptoRng for TrngRng {}

// ── LED driver — GPIO25 single-color ──────────────────────────────

/// Single-colour LED driver on GPIO25 (Raspberry Pi Pico 2 on-board LED).
///
/// Identical to the RP2040 Pico — a plain green indicator.
/// [`LedDriver::set_color`] is accepted but ignored.
pub struct Rp2350Led<'d> {
    pin: Output<'d>,
}

impl<'d> Rp2350Led<'d> {
    /// Create a new LED driver.
    ///
    /// `pin` should be GPIO25 configured as output, initially LOW (off).
    pub fn new(pin: Output<'d>) -> Self {
        Self { pin }
    }
}

impl LedDriver for Rp2350Led<'_> {
    fn set_on(&mut self) {
        self.pin.set_high();
    }

    fn set_off(&mut self) {
        self.pin.set_low();
    }

    fn set_color(&mut self, _color: LedColor) {
        // Single-color LED — colour value is ignored.
    }
}

// ── BOOTSEL button reader ─────────────────────────────────────────

// RP2350 register addresses for BOOTSEL (QSPI_SS_N) reading.
// Same technique as RP2040 (see `super::rp2040::BootselButton`), but with
// updated register addresses and bit positions.
//
// Key differences from RP2040:
// - IO_QSPI base is 0x4003_0000 (was 0x4001_8000).
// - GPIO_HI_IN now carries GPIOs 32–47 in bits [15:0] and the 6 QSPI
//   GPIOs in bits [21:16], so QSPI_SS is at bit 17 (was bit 1).

/// IO_QSPI base address on RP2350.
const IO_QSPI_BASE: u32 = 0x4003_0000;

/// QSPI_SS CTRL register (QSPI GPIO index 1).
const QSPI_SS_CTRL: *mut u32 = (IO_QSPI_BASE + 0x0C) as *mut u32;

/// SIO base address (same as RP2040).
const SIO_BASE: u32 = 0xD000_0000;

/// SIO GPIO_HI_IN register.
const GPIO_HI_IN: *const u32 = (SIO_BASE + 0x08) as *const u32;

/// Bit mask for QSPI_SS in GPIO_HI_IN.
///
/// On RP2350, bits [15:0] = GPIOs 32–47, bits [21:16] = QSPI GPIOs.
/// QSPI ordering: SCLK=16, SS=17, SD0=18, SD1=19, SD2=20, SD3=21.
const QSPI_SS_BIT: u32 = 1 << 17;

/// OEOVER field in QSPI_SS_CTRL: bits [13:12].
const OEOVER_BITS: u32 = 0x3 << 12;

/// OEOVER value to disable output (drive-enable forced LOW).
const OEOVER_DISABLE: u32 = 0x2 << 12;

/// Reads the BOOTSEL button on the Raspberry Pi Pico 2 (RP2350).
///
/// # Safety concerns — QSPI bus sharing
///
/// Identical constraints to [`super::rp2040::BootselButton`]:
///
/// 1. All interrupts are disabled via `cortex_m::interrupt::free`.
/// 2. The QSPI_SS output-enable is temporarily overridden to *disabled*
///    so the XIP controller stops driving the pin.  No flash command is
///    issued — only the pad level is sampled.
/// 3. The original CTRL register value is restored immediately after
///    the read.
///
/// The critical section is < 20 CPU cycles.  DMA-driven flash
/// transfers must not be in progress (Embassy async flash is
/// cooperative, so this is safe in normal usage).
pub struct BootselButton;

impl BootselButton {
    pub fn new() -> Self {
        Self
    }

    fn read_raw() -> bool {
        interrupt::free(|_cs| unsafe {
            let saved = core::ptr::read_volatile(QSPI_SS_CTRL);
            core::ptr::write_volatile(
                QSPI_SS_CTRL,
                (saved & !OEOVER_BITS) | OEOVER_DISABLE,
            );

            // Brief delay for pad voltage to settle (~4 cycles).
            cortex_m::asm::nop();
            cortex_m::asm::nop();
            cortex_m::asm::nop();
            cortex_m::asm::nop();

            // Active-low: BOOTSEL pressed when bit is 0.
            let pressed = (core::ptr::read_volatile(GPIO_HI_IN) & QSPI_SS_BIT) == 0;

            core::ptr::write_volatile(QSPI_SS_CTRL, saved);

            pressed
        })
    }
}

impl Default for BootselButton {
    fn default() -> Self {
        Self::new()
    }
}

impl ButtonReader for BootselButton {
    fn is_pressed(&mut self) -> bool {
        Self::read_raw()
    }
}

// ── OTP secure storage ───────────────────────────────────────────

/// OTP data (ECC-protected) memory-mapped base address.
///
/// Each row is accessible as a 32-bit read at `OTP_DATA_BASE + 4 * row`,
/// but only the lower 16 bits contain valid data (upper bits are ECC /
/// zero-padded).
const OTP_DATA_BASE: *const u32 = 0x4012_0000 as *const u32;

/// OTP controller base address (for programming fuses).
const OTP_CTRL_BASE: u32 = 0x4010_4000;

mod otp_ctrl_regs {
    /// Command register: row address [12:0], ECC-write flag bit 13.
    pub const OTP_CMD: u32 = 0x00;
    /// Write data register (lower 16 bits).
    pub const OTP_WDATA: u32 = 0x04;
    /// Status register: bit 0 = busy.
    pub const OTP_STATUS: u32 = 0x0C;
}

/// Number of 16-bit OTP rows consumed per 32-byte slot.
///
/// 32 bytes / 2 bytes-per-row = 16 rows.
const ROWS_PER_SLOT: usize = 16;

/// First OTP row used for PicoKeys secret storage.
///
/// Rows 0x700–0x77F (last 128 rows of the user-programmable region) are
/// reserved, providing up to [`MAX_OTP_SLOTS`] × 32-byte slots.
const OTP_SLOT_BASE_ROW: usize = 0x700;

/// Maximum number of 32-byte OTP secret slots.
pub const MAX_OTP_SLOTS: u8 = 8;

/// OTP-backed secure storage for the RP2350.
///
/// Each "slot" stores 32 bytes across 16 consecutive OTP rows (each row
/// provides 16 bits of ECC-protected data).  Slots are allocated starting
/// at row [`OTP_SLOT_BASE_ROW`].
///
/// # Important
///
/// OTP fuses are **one-time-programmable**: once a slot is written, it
/// **cannot** be erased or overwritten.  [`SecureStorage::write_otp`] on
/// an already-programmed slot returns [`StoreError::WriteError`].
pub struct Rp2350OtpStorage;

impl Rp2350OtpStorage {
    pub fn new() -> Self {
        Self
    }

    fn slot_row(slot: u8) -> Option<usize> {
        if slot >= MAX_OTP_SLOTS {
            return None;
        }
        Some(OTP_SLOT_BASE_ROW + (slot as usize) * ROWS_PER_SLOT)
    }
}

impl Default for Rp2350OtpStorage {
    fn default() -> Self {
        Self::new()
    }
}

impl SecureStorage for Rp2350OtpStorage {
    fn read_otp(&self, slot: u8) -> Option<[u8; 32]> {
        let base_row = Self::slot_row(slot)?;
        let mut buf = [0u8; 32];

        for i in 0..ROWS_PER_SLOT {
            // Each row is memory-mapped at OTP_DATA_BASE + 4*row.
            // Lower 16 bits contain the ECC-protected data.
            let word = unsafe { core::ptr::read_volatile(OTP_DATA_BASE.add(base_row + i)) };
            buf[i * 2] = (word & 0xFF) as u8;
            buf[i * 2 + 1] = ((word >> 8) & 0xFF) as u8;
        }

        // Unprogrammed OTP rows read as all-zeros.
        if buf == [0u8; 32] {
            return None;
        }

        Some(buf)
    }

    fn write_otp(&mut self, slot: u8, value: &[u8; 32]) -> Result<(), StoreError> {
        let base_row = Self::slot_row(slot).ok_or(StoreError::WriteError)?;

        // Refuse to overwrite an already-programmed slot.
        if self.read_otp(slot).is_some() {
            return Err(StoreError::WriteError);
        }

        // SAFETY: We program each OTP row exactly once via the OTP
        // controller.  The caller must ensure single-threaded access
        // (typically called once during initial provisioning).
        unsafe {
            let ctrl_base = OTP_CTRL_BASE as *mut u8;
            let write_reg = |off: u32, val: u32| {
                core::ptr::write_volatile(ctrl_base.add(off as usize) as *mut u32, val);
            };
            let read_reg = |off: u32| -> u32 {
                core::ptr::read_volatile(ctrl_base.add(off as usize) as *const u32)
            };

            for i in 0..ROWS_PER_SLOT {
                let row = (base_row + i) as u32;
                let lo = value[i * 2] as u32;
                let hi = value[i * 2 + 1] as u32;
                let data_16 = lo | (hi << 8);

                // Load the 16-bit data word.
                write_reg(otp_ctrl_regs::OTP_WDATA, data_16);

                // Issue write command: row address + ECC-write flag (bit 13).
                write_reg(otp_ctrl_regs::OTP_CMD, row | (1 << 13));

                // Poll until the controller is no longer busy.
                while (read_reg(otp_ctrl_regs::OTP_STATUS) & 1) != 0 {
                    cortex_m::asm::nop();
                }
            }
        }

        // Read-back verification.
        match self.read_otp(slot) {
            Some(readback) if readback == *value => Ok(()),
            _ => Err(StoreError::WriteError),
        }
    }
}

// ── Secure boot ──────────────────────────────────────────────────

/// Secure boot verification status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, defmt::Format)]
pub enum SecureBootState {
    /// ARM TrustZone secure boot is active and verified.
    Enabled,
    /// Secure boot is not configured or not verified.
    Disabled,
}

/// ACCESSCTRL peripheral base address on RP2350.
///
/// The access-control block governs TrustZone partitioning and records
/// whether the boot ROM verified a signed image.
const ACCESSCTRL_BASE: u32 = 0x4015_C000;

/// Check whether the RP2350 booted via the ARM TrustZone secure boot chain.
///
/// Reads the access-control lock register to determine if the boot ROM
/// enforced secure-boot partitioning at startup.
///
/// # Limitations
///
/// This is a best-effort runtime check.  A comprehensive secure-boot
/// audit should also verify the OTP boot-key hash, image signature, and
/// SAU/IDAU configuration.
pub fn check_secure_boot() -> SecureBootState {
    // LOCK0 register at offset 0x00 — bit 0 indicates whether the boot
    // ROM activated TrustZone secure partitioning.
    let val =
        unsafe { core::ptr::read_volatile((ACCESSCTRL_BASE) as *const u32) };

    if (val & 1) != 0 {
        SecureBootState::Enabled
    } else {
        SecureBootState::Disabled
    }
}

// ── Platform struct ───────────────────────────────────────────────

/// RP2350 platform adapter.
///
/// Zero-sized marker type that wires up concrete peripheral
/// implementations via the [`Platform`] associated types.
///
/// Compared to [`super::rp2040::Rp2040Platform`]:
///
/// * **OTP**: [`Rp2350OtpStorage`] provides hardware fuse-backed MKEK
///   storage (no AES-wrapping needed).
/// * **TRNG**: [`TrngRng`] uses the dedicated TRNG peripheral instead
///   of ROSC-only jitter.
/// * **Secure boot**: call [`check_secure_boot()`] at init to verify
///   ARM TrustZone state.
pub struct Rp2350Platform;

impl Rp2350Platform {
    /// Returns the flash address range reserved for KV storage.
    pub const fn storage_range() -> core::ops::Range<u32> {
        STORAGE_START..(STORAGE_START + STORAGE_SIZE)
    }
}

impl Platform for Rp2350Platform {
    type Flash = Flash<'static, FLASH, Async, TOTAL_FLASH_SIZE>;
    type Rng = TrngRng;
    type Led = Rp2350Led<'static>;
    type Button = BootselButton;
}
