//! RP2040 platform adapter for the Raspberry Pi Pico.
//!
//! Provides concrete implementations of [`Platform`], [`LedDriver`],
//! [`ButtonReader`], and RNG for the RP2040 MCU:
//!
//! | Peripheral | Implementation |
//! |------------|----------------|
//! | **Flash** | QSPI via `embassy_rp::flash::Flash`, last 128 KB for KV storage |
//! | **RNG** | ROSC ring-oscillator jitter (`embassy_rp::clocks::RoscRng`) |
//! | **LED** | GPIO25 digital output (single-color on-board LED) |
//! | **Button** | BOOTSEL via QSPI_SS_N line, read atomically to avoid flash corruption |
//! | **OTP** | Not available — [`NoOtpStorage`]; MKEK stored AES-wrapped in flash |

use cortex_m::interrupt;
use embassy_rp::flash::{Async, Flash};
use embassy_rp::gpio::Output;
use embassy_rp::peripherals::FLASH;
use rand_core::{CryptoRng, RngCore};

use crate::button::ButtonReader;
use crate::led::{LedColor, LedDriver};
use crate::platform::Platform;

// ── Flash layout ──────────────────────────────────────────────────

/// Total flash size on the Raspberry Pi Pico (2 MB).
pub const TOTAL_FLASH_SIZE: usize = 2 * 1024 * 1024;

/// Size of the storage region reserved for key-value data (128 KB).
pub const STORAGE_SIZE: u32 = 128 * 1024;

/// Start offset of the KV storage region within flash.
pub const STORAGE_START: u32 = TOTAL_FLASH_SIZE as u32 - STORAGE_SIZE;

/// Erase-sector size of the on-board W25Q16JV flash (4 KB).
pub const STORAGE_PAGE_SIZE: u32 = 4096;

// ── RNG — ROSC ring-oscillator ────────────────────────────────────

/// Cryptographic RNG backed by the RP2040 ROSC ring-oscillator jitter.
///
/// The randomness bit is sampled from the ROSC `RANDOMBIT` register.
/// While not a dedicated TRNG, the jitter provides sufficient entropy
/// for cryptographic use on RP2040 (see RP2040 datasheet §2.17).
pub struct RoscHwRng(embassy_rp::clocks::RoscRng);

impl RoscHwRng {
    pub fn new() -> Self {
        Self(embassy_rp::clocks::RoscRng)
    }
}

impl Default for RoscHwRng {
    fn default() -> Self {
        Self::new()
    }
}

impl RngCore for RoscHwRng {
    fn next_u32(&mut self) -> u32 {
        self.0.next_u32()
    }

    fn next_u64(&mut self) -> u64 {
        self.0.next_u64()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.fill_bytes(dest);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.0.try_fill_bytes(dest)
    }
}

// SAFETY: `embassy_rp::clocks::RoscRng` samples jitter from the ring
// oscillator, which is documented as suitable for cryptographic seeding
// on RP2040 (datasheet §2.17).
impl CryptoRng for RoscHwRng {}

// ── LED driver — GPIO25 single-color ──────────────────────────────

/// Single-colour LED driver on GPIO25 (Raspberry Pi Pico on-board LED).
///
/// The Pico's LED is a plain green indicator — [`LedDriver::set_color`]
/// is accepted but ignored.
pub struct Rp2040Led<'d> {
    pin: Output<'d>,
}

impl<'d> Rp2040Led<'d> {
    /// Create a new LED driver.
    ///
    /// `pin` should be GPIO25 configured as output, initially LOW (off).
    pub fn new(pin: Output<'d>) -> Self {
        Self { pin }
    }
}

impl LedDriver for Rp2040Led<'_> {
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

// RP2040 register addresses for BOOTSEL (QSPI_SS_N) reading.
// See RP2040 datasheet §2.19.6.3 (IO_QSPI) and §2.3.1.7 (SIO).

/// IO_QSPI base address on RP2040.
const IO_QSPI_BASE: u32 = 0x4001_8000;

/// QSPI_SS CTRL register.
///
/// QSPI GPIO index 1 (SS): STATUS @ +0x08, CTRL @ +0x0C.
const QSPI_SS_CTRL: *mut u32 = (IO_QSPI_BASE + 0x0C) as *mut u32;

/// SIO base address.
const SIO_BASE: u32 = 0xD000_0000;

/// SIO GPIO_HI_IN register (QSPI bank input state).
///
/// On RP2040 this register contains only the 6 QSPI GPIOs (bits 0–5).
const GPIO_HI_IN: *const u32 = (SIO_BASE + 0x08) as *const u32;

/// Bit mask for QSPI_SS in GPIO_HI_IN.
///
/// QSPI GPIOs: bit 0 = SCLK, bit 1 = SS, bits 2–5 = SD0–SD3.
const QSPI_SS_BIT: u32 = 1 << 1;

/// OEOVER field in QSPI_SS_CTRL: bits [13:12].
const OEOVER_BITS: u32 = 0x3 << 12;

/// OEOVER value to disable output (drive-enable forced LOW).
const OEOVER_DISABLE: u32 = 0x2 << 12;

/// Reads the BOOTSEL button on the Raspberry Pi Pico (RP2040).
///
/// # How it works
///
/// The BOOTSEL button is wired to the flash chip-select line (QSPI_SS_N).
/// Pressing the button pulls QSPI_SS_N LOW, which the XIP controller
/// normally keeps HIGH to deselect the flash.
///
/// # Safety concerns — QSPI bus sharing
///
/// QSPI_SS_N is shared with the flash XIP bus.  Carelessly reading it
/// during an in-flight flash operation can deselect the flash and corrupt
/// data.  The safe procedure implemented here:
///
/// 1. **Disable all interrupts** (`cortex_m::interrupt::free`) so no
///    flash-accessing ISR can preempt us.
/// 2. **Override OEOVER** in `IO_QSPI_GPIO_QSPI_SS_CTRL` to *disable*
///    the output driver (value 2).  This disconnects the XIP controller's
///    drive on the pin **without** changing FUNCSEL, so no flash command
///    is issued.  The internal pull-up keeps the pin HIGH unless the
///    button pulls it LOW.
/// 3. **Sample** `SIO.GPIO_HI_IN` bit 1.
/// 4. **Restore** the original CTRL value (OEOVER back to normal = 0).
///
/// The critical section is < 20 CPU cycles and issues **no** flash
/// commands.  It is safe provided no DMA-driven flash transfer is in
/// progress.  In an Embassy async context, flash operations are
/// cooperative and will not preempt this read.
pub struct BootselButton;

impl BootselButton {
    pub fn new() -> Self {
        Self
    }

    fn read_raw() -> bool {
        interrupt::free(|_cs| unsafe {
            // Save original CTRL and override OEOVER to disable output.
            let saved = core::ptr::read_volatile(QSPI_SS_CTRL);
            core::ptr::write_volatile(QSPI_SS_CTRL, (saved & !OEOVER_BITS) | OEOVER_DISABLE);

            // Brief delay for the pad voltage to settle (~4 cycles).
            cortex_m::asm::nop();
            cortex_m::asm::nop();
            cortex_m::asm::nop();
            cortex_m::asm::nop();

            // Sample the pin.  Active-low: pressed when bit is 0.
            let pressed = (core::ptr::read_volatile(GPIO_HI_IN) & QSPI_SS_BIT) == 0;

            // Restore original CTRL value (re-enables XIP drive on SS).
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

// ── Platform struct ───────────────────────────────────────────────

/// RP2040 platform adapter.
///
/// Zero-sized marker type that wires up the concrete peripheral
/// implementations via the [`Platform`] associated types.
///
/// * **No OTP**: use [`crate::store::otp::NoOtpStorage`].  MKEK is stored
///   AES-wrapped in flash instead of burned into fuses.
/// * Call [`storage_range()`](Self::storage_range) to obtain the flash
///   address range for [`crate::store::FlashStore`].
pub struct Rp2040Platform;

impl Rp2040Platform {
    /// Returns the flash address range reserved for KV storage.
    pub const fn storage_range() -> core::ops::Range<u32> {
        STORAGE_START..(STORAGE_START + STORAGE_SIZE)
    }
}

impl Platform for Rp2040Platform {
    type Flash = Flash<'static, FLASH, Async, TOTAL_FLASH_SIZE>;
    type Rng = RoscHwRng;
    type Led = Rp2040Led<'static>;
    type Button = BootselButton;
}
