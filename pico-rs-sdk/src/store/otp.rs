//! Secure OTP (one-time-programmable) storage abstraction.
//!
//! Some MCUs (e.g. RP2350) expose hardware OTP fuse banks that can store
//! secrets that are unreadable after lock-down.  [`SecureStorage`] provides a
//! uniform trait for reading/writing 32-byte OTP slots.
//!
//! Platforms without OTP (RP2040, SAMD21, …) should use [`NoOtpStorage`],
//! which always returns `None`.

use crate::store::StoreError;

/// Trait for hardware OTP / eFuse secret storage.
pub trait SecureStorage {
    /// Read a 32-byte secret from the given OTP `slot`.
    ///
    /// Returns `None` if the slot has not been programmed or is unreadable.
    fn read_otp(&self, slot: u8) -> Option<[u8; 32]>;

    /// Program a 32-byte secret into the given OTP `slot`.
    ///
    /// This is a **one-time** operation on real hardware — the slot cannot be
    /// overwritten once programmed.
    fn write_otp(&mut self, slot: u8, value: &[u8; 32]) -> Result<(), StoreError>;
}

/// Stub [`SecureStorage`] for platforms without OTP hardware (RP2040, SAMD21, …).
///
/// Reads always return `None`; writes always fail with [`StoreError::WriteError`].
pub struct NoOtpStorage;

impl SecureStorage for NoOtpStorage {
    fn read_otp(&self, _slot: u8) -> Option<[u8; 32]> {
        None
    }

    fn write_otp(&mut self, _slot: u8, _value: &[u8; 32]) -> Result<(), StoreError> {
        Err(StoreError::WriteError)
    }
}
