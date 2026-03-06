//! Storage module — wear-levelled, power-fail-safe flash key-value store.
//!
//! Provides a platform-agnostic [`FileStore`] trait backed by `sequential-storage`
//! for NOR flash, and a [`SecureStorage`] trait for OTP (one-time-programmable) slots.

pub mod file;
pub mod flash;
pub mod otp;

pub use file::FileId;
pub use flash::FlashStore;
pub use otp::{NoOtpStorage, SecureStorage};

/// Maximum file data size (bytes) for a single stored item.
pub const MAX_FILE_SIZE: usize = 1024;

/// Errors from file storage operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, defmt::Format)]
pub enum StoreError {
    /// Requested file does not exist.
    NotFound,
    /// Flash storage is full; no space for the write.
    NoSpace,
    /// Flash contents are corrupted (CRC mismatch or invalid state).
    Corrupted,
    /// Low-level flash write failed.
    WriteError,
    /// Low-level flash read failed.
    ReadError,
}

/// Platform-agnostic file storage trait.
///
/// Implementations map [`FileId`] keys to variable-length byte values on flash.
/// All methods are async to support non-blocking flash drivers (e.g. embassy).
pub trait FileStore {
    /// Read the file into `buf`, returning the number of bytes written.
    ///
    /// Returns [`StoreError::NotFound`] if the key has never been written or was deleted.
    async fn read_file(&mut self, fid: FileId, buf: &mut [u8]) -> Result<usize, StoreError>;

    /// Write (or overwrite) a file. `data` must not exceed [`MAX_FILE_SIZE`].
    async fn write_file(&mut self, fid: FileId, data: &[u8]) -> Result<(), StoreError>;

    /// Delete a file. Subsequent reads will return [`StoreError::NotFound`].
    async fn delete_file(&mut self, fid: FileId) -> Result<(), StoreError>;

    /// Check whether a file exists without reading its contents.
    async fn exists(&mut self, fid: FileId) -> bool;
}
