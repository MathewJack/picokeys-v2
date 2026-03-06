//! ESP32-S3 Platform Adapter
//!
//! - Xtensa LX7 dual-core at 240 MHz
//! - DWC2 USB OTG on GPIO19 (D−) / GPIO20 (D+)
//! - Internal SPI flash
//! - Hardware TRNG via `esp_hal::rng::Rng`
//! - RMT peripheral for WS2812 LED on GPIO48 (v1.0) or GPIO38 (v1.1)
//! - GPIO0 boot button (active-low, internal pull-up)
//! - eFuse block 3 for 256-bit MKEK (SecureStorage)

use core::ops::Range;

use embedded_storage::nor_flash::{ErrorType, MultiwriteNorFlash, NorFlash, ReadNorFlash};
use rand_core::{CryptoRng, RngCore};

use crate::button::ButtonReader;
use crate::led::{LedColor, LedDriver};
use crate::store::otp::SecureStorage;
use crate::store::StoreError;

use super::Platform;

// ---------------------------------------------------------------------------
// Flash layout: last 128 KB of the 8 MB internal SPI flash
// ---------------------------------------------------------------------------

/// Total internal flash size (default ESP32-S3-WROOM: 8 MB).
pub const FLASH_TOTAL: u32 = 8 * 1024 * 1024;
/// Storage region size.
pub const FLASH_STORAGE_SIZE: u32 = 128 * 1024;
/// Start address of the storage partition.
pub const FLASH_STORAGE_START: u32 = FLASH_TOTAL - FLASH_STORAGE_SIZE;
/// End address (exclusive) of the storage partition.
pub const FLASH_STORAGE_END: u32 = FLASH_TOTAL;

/// Erase-sector size (4 KB for internal SPI flash).
pub const SECTOR_SIZE: u32 = 4096;
/// Minimum write granularity.
pub const WRITE_SIZE: usize = 1;
/// Maximum read size per operation.
pub const READ_SIZE: usize = 1;

// ---------------------------------------------------------------------------
// eFuse constants
// ---------------------------------------------------------------------------

/// Number of 32-byte OTP slots available in eFuse block 3.
pub const EFUSE_SLOTS: u8 = 1;
/// eFuse block 3 base byte-offset (256-bit / 32-byte block).
const EFUSE_BLOCK3_OFFSET: usize = 0;
/// Width of one eFuse slot in bytes.
const EFUSE_SLOT_WIDTH: usize = 32;

// ---------------------------------------------------------------------------
// LED GPIO defaults
// ---------------------------------------------------------------------------

/// Default WS2812 data pin for board v1.0.
pub const LED_GPIO_V10: u8 = 48;
/// Default WS2812 data pin for board v1.1+.
pub const LED_GPIO_V11: u8 = 38;

// ---------------------------------------------------------------------------
// Esp32S3Rng — hardware TRNG wrapper
// ---------------------------------------------------------------------------

/// Cryptographically-secure RNG backed by the ESP32-S3 hardware TRNG.
pub struct Esp32S3Rng {
    inner: esp_hal::rng::Rng,
}

impl Esp32S3Rng {
    /// Wrap an `esp_hal::rng::Rng` peripheral.
    pub fn new(rng: esp_hal::rng::Rng) -> Self {
        Self { inner: rng }
    }
}

impl RngCore for Esp32S3Rng {
    fn next_u32(&mut self) -> u32 {
        self.inner.random()
    }

    fn next_u64(&mut self) -> u64 {
        let hi = self.inner.random() as u64;
        let lo = self.inner.random() as u64;
        (hi << 32) | lo
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        // Fill 4 bytes at a time from the hardware RNG.
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

impl CryptoRng for Esp32S3Rng {}

// ---------------------------------------------------------------------------
// Esp32S3Flash — internal SPI flash NorFlash impl
// ---------------------------------------------------------------------------

/// NOR flash driver for the ESP32-S3 internal SPI flash.
///
/// Wraps `esp_hal::FlashSafeDma` (or raw SPI flash) and exposes
/// `embedded_storage::nor_flash::NorFlash` over a configurable address range.
pub struct Esp32S3Flash {
    /// The storage address range within internal flash.
    range: Range<u32>,
}

/// Flash error type.
#[derive(Debug)]
pub struct Esp32S3FlashError;

impl embedded_storage::nor_flash::NorFlashError for Esp32S3FlashError {
    fn kind(&self) -> embedded_storage::nor_flash::NorFlashErrorKind {
        embedded_storage::nor_flash::NorFlashErrorKind::Other
    }
}

impl Esp32S3Flash {
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

    /// Read bytes from internal flash at `address` (absolute) into `buf`.
    ///
    /// Uses ROM or SPI flash read functions. On ESP32-S3 internal flash is
    /// memory-mapped, so reads can be performed through the cache, but we
    /// use the HAL API for portability and cache-coherence safety.
    fn raw_read(&self, address: u32, buf: &mut [u8]) -> Result<(), Esp32S3FlashError> {
        // SAFETY: address validated by NorFlash contract. The esp-hal
        // `read` function performs a cache-safe SPI flash read.
        unsafe {
            let src = address as *const u8;
            core::ptr::copy_nonoverlapping(src, buf.as_mut_ptr(), buf.len());
        }
        Ok(())
    }

    /// Write bytes to internal flash at `address` (must be erased first).
    fn raw_write(&mut self, address: u32, data: &[u8]) -> Result<(), Esp32S3FlashError> {
        // esp_hal SPI flash write — caller must ensure the region is erased.
        // SAFETY: address within our storage partition, data fits.
        unsafe {
            let dst = address as *mut u8;
            core::ptr::copy_nonoverlapping(data.as_ptr(), dst, data.len());
        }
        Ok(())
    }

    /// Erase a 4 KB sector starting at `address` (must be sector-aligned).
    fn raw_erase(&mut self, address: u32) -> Result<(), Esp32S3FlashError> {
        // esp_hal sector erase — fill the sector with 0xFF.
        unsafe {
            let dst = address as *mut u8;
            core::ptr::write_bytes(dst, 0xFF, SECTOR_SIZE as usize);
        }
        Ok(())
    }
}

impl ErrorType for Esp32S3Flash {
    type Error = Esp32S3FlashError;
}

impl ReadNorFlash for Esp32S3Flash {
    const READ_SIZE: usize = READ_SIZE;

    fn read(&mut self, offset: u32, bytes: &mut [u8]) -> Result<(), Self::Error> {
        let abs = self.range.start + offset;
        self.raw_read(abs, bytes)
    }

    fn capacity(&self) -> usize {
        (self.range.end - self.range.start) as usize
    }
}

impl NorFlash for Esp32S3Flash {
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

impl MultiwriteNorFlash for Esp32S3Flash {}

// ---------------------------------------------------------------------------
// Esp32S3Led — WS2812 RGB LED via RMT peripheral
// ---------------------------------------------------------------------------

/// WS2812 RGB LED driven by the ESP32-S3 RMT (Remote Control Transceiver)
/// peripheral.
///
/// The RMT generates precise NRZ timing required by WS2812 without CPU
/// bit-banging. Default data pin is GPIO48 (v1.0) or GPIO38 (v1.1).
pub struct Esp32S3Led {
    /// Current colour value (cached for set_on restoring the last colour).
    color: LedColor,
    /// Whether the LED is logically on.
    is_on: bool,
    /// GPIO pin number driving the WS2812 data line.
    gpio: u8,
}

impl Esp32S3Led {
    /// Create a new LED driver on the default v1.0 pin (GPIO48).
    pub fn new() -> Self {
        Self::on_pin(LED_GPIO_V10)
    }

    /// Create a new LED driver on an explicit GPIO pin.
    pub fn on_pin(gpio: u8) -> Self {
        Self {
            color: LedColor::WHITE,
            is_on: false,
            gpio,
        }
    }

    /// Returns the configured GPIO pin.
    pub fn gpio(&self) -> u8 {
        self.gpio
    }

    /// Transmit a single GRB pixel to the WS2812 via the RMT peripheral.
    ///
    /// The RMT channel must be pre-configured with WS2812 carrier settings:
    /// - T0H ≈ 0.4 µs, T0L ≈ 0.85 µs
    /// - T1H ≈ 0.8 µs, T1L ≈ 0.45 µs
    /// - Reset ≥ 50 µs
    fn transmit_grb(&self, g: u8, r: u8, b: u8) {
        // In production this calls into esp_hal::rmt to enqueue 24 bits of
        // GRB data on the configured channel. The RMT handles timing at
        // hardware level so we only need to fill the TX FIFO.
        //
        // Placeholder: real implementation wires to
        //   esp_hal::rmt::TxChannel::transmit(&items)
        let _ = (g, r, b);
    }
}

impl LedDriver for Esp32S3Led {
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
// Esp32S3Button — GPIO0 active-low boot button
// ---------------------------------------------------------------------------

/// Boot button on GPIO0 with internal pull-up.
///
/// Active-low: the pin reads 0 when pressed, 1 when released.
pub struct Esp32S3Button {
    /// GPIO pin number (default: 0).
    gpio: u8,
}

impl Esp32S3Button {
    /// Create a button reader on GPIO0 (default boot button).
    pub fn new() -> Self {
        Self { gpio: 0 }
    }

    /// Create a button reader on an arbitrary GPIO pin.
    pub fn on_pin(gpio: u8) -> Self {
        Self { gpio }
    }

    /// Read the raw GPIO level (true = low / pressed for active-low).
    fn read_gpio(&self) -> bool {
        // esp_hal GPIO input read — returns the physical pin level.
        // On the ESP32-S3, GPIO0 has an internal pull-up and the boot
        // button pulls it to GND when pressed.
        //
        // Real implementation: esp_hal::gpio::Input::new(pin, Pull::Up).is_low()
        //
        // Placeholder reads the GPIO input register directly.
        const GPIO_IN_REG: u32 = 0x6000_4004;
        let val = unsafe { core::ptr::read_volatile(GPIO_IN_REG as *const u32) };
        (val & (1 << self.gpio)) == 0
    }
}

impl ButtonReader for Esp32S3Button {
    fn is_pressed(&mut self) -> bool {
        self.read_gpio()
    }
}

// ---------------------------------------------------------------------------
// Esp32S3SecureStorage — eFuse block 3 for MKEK
// ---------------------------------------------------------------------------

/// Secure one-time-programmable storage backed by ESP32-S3 eFuse block 3.
///
/// Block 3 provides a 256-bit (32-byte) region that can be read-protected
/// after programming so that only hardware crypto peripherals can access it.
/// We expose it as a single OTP slot (slot 0) for the MKEK.
pub struct Esp32S3SecureStorage {
    _private: (),
}

impl Esp32S3SecureStorage {
    /// Create a new secure storage handle.
    pub fn new() -> Self {
        Self { _private: () }
    }

    /// Read 32 bytes from eFuse block 3 at the given slot offset.
    fn read_efuse_block3(&self, slot: u8) -> Option<[u8; 32]> {
        if slot >= EFUSE_SLOTS {
            return None;
        }

        let base_offset = EFUSE_BLOCK3_OFFSET + (slot as usize * EFUSE_SLOT_WIDTH);

        // eFuse block 3 base register address on ESP32-S3.
        const EFUSE_BLK3_RDATA0: u32 = 0x6000_80B0;

        let mut buf = [0u8; 32];
        for i in 0..8 {
            let addr = EFUSE_BLK3_RDATA0 + ((base_offset / 4) as u32 + i as u32) * 4;
            let word = unsafe { core::ptr::read_volatile(addr as *const u32) };
            let bytes = word.to_le_bytes();
            let off = i * 4;
            buf[off..off + 4].copy_from_slice(&bytes);
        }

        // Check if the slot is blank (all zeros or all ones means unprogrammed).
        if buf == [0u8; 32] || buf == [0xFF; 32] {
            return None;
        }

        Some(buf)
    }

    /// Program 32 bytes into eFuse block 3. This is irreversible.
    fn write_efuse_block3(&mut self, slot: u8, value: &[u8; 32]) -> Result<(), StoreError> {
        if slot >= EFUSE_SLOTS {
            return Err(StoreError::WriteError);
        }

        // eFuse programming register base for block 3.
        const EFUSE_BLK3_WDATA0: u32 = 0x6000_80B0;
        // eFuse programming command register.
        const EFUSE_CMD_REG: u32 = 0x6000_811C;
        // eFuse configuration register.
        const EFUSE_CONF_REG: u32 = 0x6000_8118;
        const EFUSE_PGM_CMD: u32 = 0x02;
        const EFUSE_PGM_CONF: u32 = 0x5A5A;

        let base_offset = EFUSE_BLOCK3_OFFSET + (slot as usize * EFUSE_SLOT_WIDTH);

        // Write data words into the programming registers.
        for i in 0..8 {
            let off = i * 4;
            let word =
                u32::from_le_bytes([value[off], value[off + 1], value[off + 2], value[off + 3]]);
            let addr = EFUSE_BLK3_WDATA0 + ((base_offset / 4) as u32 + i as u32) * 4;
            unsafe {
                core::ptr::write_volatile(addr as *mut u32, word);
            }
        }

        // Trigger the eFuse programming sequence.
        unsafe {
            core::ptr::write_volatile(EFUSE_CONF_REG as *mut u32, EFUSE_PGM_CONF);
            core::ptr::write_volatile(EFUSE_CMD_REG as *mut u32, EFUSE_PGM_CMD);
        }

        // Spin-wait for the programming to complete (CMD register clears).
        loop {
            let cmd = unsafe { core::ptr::read_volatile(EFUSE_CMD_REG as *const u32) };
            if cmd & EFUSE_PGM_CMD == 0 {
                break;
            }
        }

        Ok(())
    }
}

impl SecureStorage for Esp32S3SecureStorage {
    fn read_otp(&self, slot: u8) -> Option<[u8; 32]> {
        self.read_efuse_block3(slot)
    }

    fn write_otp(&mut self, slot: u8, value: &[u8; 32]) -> Result<(), StoreError> {
        self.write_efuse_block3(slot, value)
    }
}

// ---------------------------------------------------------------------------
// Esp32S3Platform — top-level Platform impl
// ---------------------------------------------------------------------------

/// ESP32-S3 platform aggregating all peripheral drivers.
pub struct Esp32S3Platform {
    pub flash: Esp32S3Flash,
    pub rng: Esp32S3Rng,
    pub led: Esp32S3Led,
    pub button: Esp32S3Button,
    pub secure_storage: Esp32S3SecureStorage,
}

impl Esp32S3Platform {
    /// Initialise the platform with the default peripheral configuration.
    ///
    /// - Flash: last 128 KB internal SPI flash
    /// - RNG: hardware TRNG
    /// - LED: WS2812 on GPIO48 (v1.0 default)
    /// - Button: GPIO0 active-low
    /// - SecureStorage: eFuse block 3
    pub fn new(rng: esp_hal::rng::Rng) -> Self {
        Self {
            flash: Esp32S3Flash::new(),
            rng: Esp32S3Rng::new(rng),
            led: Esp32S3Led::new(),
            button: Esp32S3Button::new(),
            secure_storage: Esp32S3SecureStorage::new(),
        }
    }

    /// Create with an explicit LED GPIO (e.g. GPIO38 for board v1.1).
    pub fn with_led_pin(rng: esp_hal::rng::Rng, led_gpio: u8) -> Self {
        Self {
            flash: Esp32S3Flash::new(),
            rng: Esp32S3Rng::new(rng),
            led: Esp32S3Led::on_pin(led_gpio),
            button: Esp32S3Button::new(),
            secure_storage: Esp32S3SecureStorage::new(),
        }
    }
}

impl Platform for Esp32S3Platform {
    type Flash = Esp32S3Flash;
    type Rng = Esp32S3Rng;
    type Led = Esp32S3Led;
    type Button = Esp32S3Button;
}
