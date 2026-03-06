//! Flash-backed [`FileStore`] implementation using `sequential-storage` map API.
//!
//! [`FlashStore`] wraps a NOR flash peripheral and provides wear-levelled,
//! CRC-protected, power-fail-safe key-value storage for [`FileId`] → byte-blob
//! pairs.

use core::ops::Range;

use embedded_storage_async::nor_flash::NorFlash;
use sequential_storage::cache::NoCache;
use sequential_storage::map;
use zeroize::Zeroize;

use crate::store::file::FileId;
use crate::store::{FileStore, StoreError, MAX_FILE_SIZE};

/// Internal buffer size: key (2 B) + value (MAX_FILE_SIZE) + alignment headroom.
const BUF_SIZE: usize = MAX_FILE_SIZE + 32;

/// Flash-backed file store.
///
/// Generic over the async NOR flash driver `F` (e.g. embassy-rp internal flash).
/// The `flash_range` defines which region of flash is dedicated to storage and
/// **must** span at least two erase-sectors.
pub struct FlashStore<F: NorFlash> {
    flash: F,
    flash_range: Range<u32>,
    buf: [u8; BUF_SIZE],
}

impl<F: NorFlash> FlashStore<F> {
    /// Create a new store over the given flash peripheral and address range.
    ///
    /// # Safety contract
    /// The caller must ensure that `flash_range` covers at least two full
    /// erase-pages and does not overlap with firmware code or other data.
    pub fn new(flash: F, flash_range: Range<u32>) -> Self {
        Self {
            flash,
            flash_range,
            buf: [0u8; BUF_SIZE],
        }
    }

    /// Consume the store and return the underlying flash peripheral.
    ///
    /// The internal data buffer is zeroized before the flash is returned.
    pub fn into_inner(mut self) -> F {
        self.buf.zeroize();
        // SAFETY: We read `flash` out, then `forget` self so Drop doesn't
        // double-free. The buffer was already zeroized above.
        let flash = unsafe { core::ptr::read(&self.flash) };
        core::mem::forget(self);
        flash
    }
}

impl<F: NorFlash> Drop for FlashStore<F> {
    fn drop(&mut self) {
        self.buf.zeroize();
    }
}

// ---------------------------------------------------------------------------
// Map sequential-storage errors to our StoreError.
// ---------------------------------------------------------------------------
fn map_error<E>(e: sequential_storage::Error<E>) -> StoreError {
    match e {
        sequential_storage::Error::FullStorage => StoreError::NoSpace,
        sequential_storage::Error::Corrupted { .. } => StoreError::Corrupted,
        sequential_storage::Error::BufferTooSmall(_) => StoreError::ReadError,
        sequential_storage::Error::BufferTooBig => StoreError::ReadError,
        sequential_storage::Error::SerializationError(_) => StoreError::Corrupted,
        sequential_storage::Error::ItemTooBig => StoreError::NoSpace,
        sequential_storage::Error::Storage { .. } => StoreError::WriteError,
        _ => StoreError::WriteError,
    }
}

impl<F: NorFlash> FileStore for FlashStore<F> {
    async fn read_file(&mut self, fid: FileId, buf: &mut [u8]) -> Result<usize, StoreError> {
        let result = map::fetch_item::<FileId, &[u8], F>(
            &mut self.flash,
            self.flash_range.clone(),
            &mut NoCache::new(),
            &mut self.buf,
            &fid,
        )
        .await;

        let ret = match result {
            Ok(Some(data)) if !data.is_empty() => {
                let len = data.len().min(buf.len());
                buf[..len].copy_from_slice(&data[..len]);
                Ok(len)
            }
            // Empty value is our deletion sentinel.
            Ok(Some(_)) | Ok(None) => Err(StoreError::NotFound),
            Err(e) => Err(map_error(e)),
        };

        // Scrub the internal buffer so secrets don't linger in RAM.
        self.buf.zeroize();
        ret
    }

    async fn write_file(&mut self, fid: FileId, data: &[u8]) -> Result<(), StoreError> {
        map::store_item::<FileId, &[u8], F>(
            &mut self.flash,
            self.flash_range.clone(),
            &mut NoCache::new(),
            &mut self.buf,
            &fid,
            &data,
        )
        .await
        .map_err(map_error)?;

        self.buf.zeroize();
        Ok(())
    }

    async fn delete_file(&mut self, fid: FileId) -> Result<(), StoreError> {
        // Store an empty value as a deletion sentinel. This avoids the need
        // for `MultiwriteNorFlash` (which `remove_item` requires) and works
        // on all NOR flash parts.
        let empty: &[u8] = &[];
        map::store_item::<FileId, &[u8], F>(
            &mut self.flash,
            self.flash_range.clone(),
            &mut NoCache::new(),
            &mut self.buf,
            &fid,
            &empty,
        )
        .await
        .map_err(map_error)?;

        self.buf.zeroize();
        Ok(())
    }

    async fn exists(&mut self, fid: FileId) -> bool {
        let result = map::fetch_item::<FileId, &[u8], F>(
            &mut self.flash,
            self.flash_range.clone(),
            &mut NoCache::new(),
            &mut self.buf,
            &fid,
        )
        .await;

        let found = matches!(result, Ok(Some(data)) if !data.is_empty());
        self.buf.zeroize();
        found
    }
}
