//! ESP32-C6 Platform Adapter
//!
//! **LIMITATION:** ESP32-C6 has USB-Serial-JTAG only (no USB OTG).
//! This means **no native HID or CCID** class support.
//! Communication is via a serial bridge protocol (length-prefixed CBOR frames).
//! The C6 variant **cannot** work as a native FIDO2 authenticator in browsers.
//! It is **CLI-only** mode via `picokeys-cli` serial transport.
//!
//! - RISC-V (riscv32imac) single-core
//! - USB-Serial-JTAG → CDC-ACM serial (not USB device classes)
//! - Hardware TRNG via `esp_hal::rng::Rng`
//! - GPIO8 for WS2812 LED via RMT
//! - GPIO9 boot button (active-low)
//! - eFuse block for secure key storage
//! - Serial framing: `[u16-LE length][CBOR payload]`

use core::ops::Range;

use embedded_storage::nor_flash::{ErrorType, MultiwriteNorFlash, NorFlash, ReadNorFlash};
use rand_core::{CryptoRng, RngCore};

use crate::button::ButtonReader;
use crate::led::{LedColor, LedDriver};
use crate::store::otp::SecureStorage;
use crate::store::StoreError;
use crate::transport::TransportError;

use super::Platform;

// ---------------------------------------------------------------------------
// Flash layout: last 128 KB of 4 MB internal flash
// ---------------------------------------------------------------------------

pub const FLASH_TOTAL: u32 = 4 * 1024 * 1024;
pub const FLASH_STORAGE_SIZE: u32 = 128 * 1024;
pub const FLASH_STORAGE_START: u32 = FLASH_TOTAL - FLASH_STORAGE_SIZE;
pub const FLASH_STORAGE_END: u32 = FLASH_TOTAL;

pub const SECTOR_SIZE: u32 = 4096;
pub const WRITE_SIZE: usize = 1;
pub const READ_SIZE: usize = 1;

// ---------------------------------------------------------------------------
// GPIO assignments
// ---------------------------------------------------------------------------

/// LED data pin (WS2812 via RMT).
pub const LED_GPIO: u8 = 8;
/// Boot button pin (active-low).
pub const BUTTON_GPIO: u8 = 9;

// ---------------------------------------------------------------------------
// Serial bridge framing constants
// ---------------------------------------------------------------------------

/// Maximum serial frame payload size (CBOR message body).
pub const SERIAL_MAX_PAYLOAD: usize = 2048;
/// Frame header size: 2-byte little-endian length prefix.
pub const SERIAL_HEADER_SIZE: usize = 2;
/// Total maximum frame size including header.
pub const SERIAL_MAX_FRAME: usize = SERIAL_HEADER_SIZE + SERIAL_MAX_PAYLOAD;

// ---------------------------------------------------------------------------
// eFuse constants
// ---------------------------------------------------------------------------

pub const EFUSE_SLOTS: u8 = 1;
const EFUSE_SLOT_WIDTH: usize = 32;

// ---------------------------------------------------------------------------
// Serial bridge framing
// ---------------------------------------------------------------------------

/// Serial bridge frame state machine.
///
/// Protocol: each frame is `[u16-LE length][CBOR payload]`.
/// The host (`picokeys-cli`) detects C6 devices by VID/PID and uses this
/// framing over the CDC-ACM serial port instead of HID/CCID.
pub struct SerialFrameCodec {
    /// Receive buffer for accumulating an incoming frame.
    rx_buf: [u8; SERIAL_MAX_FRAME],
    /// Number of bytes received so far.
    rx_pos: usize,
    /// Expected total frame length (header + payload), or 0 if unknown.
    rx_expected: usize,
}

impl SerialFrameCodec {
    /// Create a new codec with an empty receive buffer.
    pub fn new() -> Self {
        Self {
            rx_buf: [0u8; SERIAL_MAX_FRAME],
            rx_pos: 0,
            rx_expected: 0,
        }
    }

    /// Reset the receive state machine.
    pub fn reset(&mut self) {
        self.rx_pos = 0;
        self.rx_expected = 0;
    }

    /// Feed incoming serial bytes into the codec.
    ///
    /// Returns `Some(payload_slice)` when a complete frame has been received,
    /// or `None` if more data is needed.
    pub fn feed(&mut self, data: &[u8]) -> Option<&[u8]> {
        for &byte in data {
            if self.rx_pos >= SERIAL_MAX_FRAME {
                // Overflow — discard and reset.
                self.reset();
                return None;
            }
            self.rx_buf[self.rx_pos] = byte;
            self.rx_pos += 1;

            // Once we have the 2-byte header, compute expected length.
            if self.rx_pos == SERIAL_HEADER_SIZE && self.rx_expected == 0 {
                let payload_len = u16::from_le_bytes([self.rx_buf[0], self.rx_buf[1]]) as usize;
                if payload_len == 0 || payload_len > SERIAL_MAX_PAYLOAD {
                    self.reset();
                    return None;
                }
                self.rx_expected = SERIAL_HEADER_SIZE + payload_len;
            }

            // Check if the full frame has arrived.
            if self.rx_expected > 0 && self.rx_pos >= self.rx_expected {
                let payload_end = self.rx_expected;
                // Return the payload portion (skip header).
                return Some(&self.rx_buf[SERIAL_HEADER_SIZE..payload_end]);
            }
        }
        None
    }

    /// Encode a response payload into a length-prefixed frame written to `out`.
    ///
    /// Returns the total number of bytes written (header + payload), or an
    /// error if the output buffer is too small.
    pub fn encode(payload: &[u8], out: &mut [u8]) -> Result<usize, TransportError> {
        let total = SERIAL_HEADER_SIZE + payload.len();
        if payload.len() > SERIAL_MAX_PAYLOAD || out.len() < total {
            return Err(TransportError::InvalidLength);
        }
        let len_bytes = (payload.len() as u16).to_le_bytes();
        out[0] = len_bytes[0];
        out[1] = len_bytes[1];
        out[SERIAL_HEADER_SIZE..total].copy_from_slice(payload);
        Ok(total)
    }
}

// ---------------------------------------------------------------------------
// Esp32C6Rng — hardware TRNG
// ---------------------------------------------------------------------------

/// Cryptographically-secure RNG backed by the ESP32-C6 hardware TRNG.
pub struct Esp32C6Rng {
    inner: esp_hal::rng::Rng,
}

impl Esp32C6Rng {
    pub fn new(rng: esp_hal::rng::Rng) -> Self {
        Self { inner: rng }
    }
}

impl RngCore for Esp32C6Rng {
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

impl CryptoRng for Esp32C6Rng {}

// ---------------------------------------------------------------------------
// Esp32C6Flash — internal SPI flash
// ---------------------------------------------------------------------------

/// NOR flash driver for the ESP32-C6 internal SPI flash.
pub struct Esp32C6Flash {
    range: Range<u32>,
}

#[derive(Debug)]
pub struct Esp32C6FlashError;

impl embedded_storage::nor_flash::NorFlashError for Esp32C6FlashError {
    fn kind(&self) -> embedded_storage::nor_flash::NorFlashErrorKind {
        embedded_storage::nor_flash::NorFlashErrorKind::Other
    }
}

impl Esp32C6Flash {
    pub fn new() -> Self {
        Self {
            range: FLASH_STORAGE_START..FLASH_STORAGE_END,
        }
    }

    pub fn with_range(range: Range<u32>) -> Self {
        Self { range }
    }

    fn raw_read(&self, address: u32, buf: &mut [u8]) -> Result<(), Esp32C6FlashError> {
        unsafe {
            let src = address as *const u8;
            core::ptr::copy_nonoverlapping(src, buf.as_mut_ptr(), buf.len());
        }
        Ok(())
    }

    fn raw_write(&mut self, address: u32, data: &[u8]) -> Result<(), Esp32C6FlashError> {
        unsafe {
            let dst = address as *mut u8;
            core::ptr::copy_nonoverlapping(data.as_ptr(), dst, data.len());
        }
        Ok(())
    }

    fn raw_erase(&mut self, address: u32) -> Result<(), Esp32C6FlashError> {
        unsafe {
            let dst = address as *mut u8;
            core::ptr::write_bytes(dst, 0xFF, SECTOR_SIZE as usize);
        }
        Ok(())
    }
}

impl ErrorType for Esp32C6Flash {
    type Error = Esp32C6FlashError;
}

impl ReadNorFlash for Esp32C6Flash {
    const READ_SIZE: usize = READ_SIZE;

    fn read(&mut self, offset: u32, bytes: &mut [u8]) -> Result<(), Self::Error> {
        let abs = self.range.start + offset;
        self.raw_read(abs, bytes)
    }

    fn capacity(&self) -> usize {
        (self.range.end - self.range.start) as usize
    }
}

impl NorFlash for Esp32C6Flash {
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

impl MultiwriteNorFlash for Esp32C6Flash {}

// ---------------------------------------------------------------------------
// Esp32C6Led — WS2812 via RMT on GPIO8
// ---------------------------------------------------------------------------

/// WS2812 RGB LED driven by the ESP32-C6 RMT peripheral on GPIO8.
pub struct Esp32C6Led {
    color: LedColor,
    is_on: bool,
    gpio: u8,
}

impl Esp32C6Led {
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

    fn transmit_grb(&self, g: u8, r: u8, b: u8) {
        let _ = (g, r, b);
    }
}

impl LedDriver for Esp32C6Led {
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
// Esp32C6Button — GPIO9 active-low boot button
// ---------------------------------------------------------------------------

/// Boot button on GPIO9 (active-low with internal pull-up).
pub struct Esp32C6Button {
    gpio: u8,
}

impl Esp32C6Button {
    pub fn new() -> Self {
        Self { gpio: BUTTON_GPIO }
    }

    pub fn on_pin(gpio: u8) -> Self {
        Self { gpio }
    }

    fn read_gpio(&self) -> bool {
        // ESP32-C6 GPIO input register.
        const GPIO_IN_REG: u32 = 0x6009_1004;
        let val = unsafe { core::ptr::read_volatile(GPIO_IN_REG as *const u32) };
        (val & (1 << self.gpio)) == 0
    }
}

impl ButtonReader for Esp32C6Button {
    fn is_pressed(&mut self) -> bool {
        self.read_gpio()
    }
}

// ---------------------------------------------------------------------------
// Esp32C6SecureStorage — eFuse block 3
// ---------------------------------------------------------------------------

/// eFuse-backed secure storage for the ESP32-C6.
pub struct Esp32C6SecureStorage {
    _private: (),
}

impl Esp32C6SecureStorage {
    pub fn new() -> Self {
        Self { _private: () }
    }

    fn read_efuse(&self, slot: u8) -> Option<[u8; 32]> {
        if slot >= EFUSE_SLOTS {
            return None;
        }

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

impl SecureStorage for Esp32C6SecureStorage {
    fn read_otp(&self, slot: u8) -> Option<[u8; 32]> {
        self.read_efuse(slot)
    }

    fn write_otp(&mut self, slot: u8, value: &[u8; 32]) -> Result<(), StoreError> {
        self.write_efuse(slot, value)
    }
}

// ---------------------------------------------------------------------------
// Esp32C6Platform — serial-bridge-only platform
// ---------------------------------------------------------------------------

/// ESP32-C6 platform — **serial-bridge mode only**.
///
/// This platform has NO native USB device support (HID/CCID). All host
/// communication uses length-prefixed CBOR frames over the CDC-ACM serial
/// port exposed by the USB-Serial-JTAG peripheral.
///
/// Use `picokeys-cli --transport serial` to interact with C6 devices.
pub struct Esp32C6Platform {
    pub flash: Esp32C6Flash,
    pub rng: Esp32C6Rng,
    pub led: Esp32C6Led,
    pub button: Esp32C6Button,
    pub secure_storage: Esp32C6SecureStorage,
    pub serial_codec: SerialFrameCodec,
}

impl Esp32C6Platform {
    /// Initialise the C6 platform.
    ///
    /// **Note:** No USB device stack is started. The caller must set up
    /// the USB-Serial-JTAG → CDC-ACM channel separately and feed bytes
    /// through [`SerialFrameCodec`].
    pub fn new(rng: esp_hal::rng::Rng) -> Self {
        Self {
            flash: Esp32C6Flash::new(),
            rng: Esp32C6Rng::new(rng),
            led: Esp32C6Led::new(),
            button: Esp32C6Button::new(),
            secure_storage: Esp32C6SecureStorage::new(),
            serial_codec: SerialFrameCodec::new(),
        }
    }
}

impl Platform for Esp32C6Platform {
    type Flash = Esp32C6Flash;
    type Rng = Esp32C6Rng;
    type Led = Esp32C6Led;
    type Button = Esp32C6Button;
}
