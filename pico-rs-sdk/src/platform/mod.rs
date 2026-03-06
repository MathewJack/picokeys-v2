//! Platform abstraction layer.
//!
//! Each supported MCU provides an implementation of the [`Platform`] trait
//! that wires up flash, RNG, LED, and button peripherals.

use crate::button::ButtonReader;
use crate::led::LedDriver;

// Conditionally compiled platform adapters
#[cfg(feature = "esp32c5")]
pub mod esp32c5;
#[cfg(feature = "esp32c6")]
pub mod esp32c6;
#[cfg(feature = "esp32s3")]
pub mod esp32s3;
#[cfg(feature = "rp2040")]
pub mod rp2040;
#[cfg(feature = "rp2350")]
pub mod rp2350;
#[cfg(feature = "samd21")]
pub mod samd21;

/// LED output type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, defmt::Format)]
pub enum LedType {
    /// Single digital output (on/off only).
    SingleColor,
    /// Addressable RGB LED (e.g. WS2812).
    Rgb,
}

/// Electrical polarity of the button GPIO.
#[derive(Debug, Clone, Copy, PartialEq, Eq, defmt::Format)]
pub enum ButtonPolarity {
    /// GPIO reads LOW when the button is pressed.
    ActiveLow,
    /// GPIO reads HIGH when the button is pressed.
    ActiveHigh,
}

/// Board-level configuration stored in flash.
#[derive(Debug, Clone, Copy)]
pub struct PlatformConfig {
    pub led_gpio: u8,
    pub button_gpio: u8,
    pub led_type: LedType,
    pub button_polarity: ButtonPolarity,
    pub button_timeout_ms: u32,
    pub usb_vid: u16,
    pub usb_pid: u16,
}

impl Default for PlatformConfig {
    fn default() -> Self {
        Self {
            led_gpio: 25,
            button_gpio: 0,
            led_type: LedType::Rgb,
            button_polarity: ButtonPolarity::ActiveLow,
            button_timeout_ms: 15_000,
            usb_vid: 0x20A0,
            usb_pid: 0x4287,
        }
    }
}

/// Top-level platform trait.
///
/// Each MCU adapter provides concrete associated types for the
/// peripherals required by the SDK.
pub trait Platform {
    /// NOR-flash storage backend.
    type Flash: embedded_storage::nor_flash::NorFlash;
    /// Cryptographically-secure random number generator.
    type Rng: rand_core::RngCore + rand_core::CryptoRng;
    /// LED hardware driver.
    type Led: LedDriver;
    /// Physical button reader.
    type Button: ButtonReader;
}
