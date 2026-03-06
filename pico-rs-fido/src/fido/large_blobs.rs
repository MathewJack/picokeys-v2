//! CTAP2.1 largeBlobs storage.
//!
//! Provides a fixed-size in-RAM blob buffer with offset-based read/write and
//! SHA-256 integrity verification.

use super::ctap::CtapError;
use sha2::{Sha256, Digest};

/// Maximum size of the large-blob array.
pub const LARGE_BLOB_MAX: usize = 2048;

/// Left-truncated SHA-256 length stored at the end of the blob array.
const HASH_LEN: usize = 16;

/// In-memory large-blob store.
#[derive(defmt::Format)]
pub struct LargeBlobStore {
    /// Raw blob data (includes trailing 16-byte hash when written).
    data: [u8; LARGE_BLOB_MAX],
    /// Number of valid bytes currently stored.
    len: usize,
}

impl LargeBlobStore {
    /// Create an empty store, pre-populated with the CTAP2.1 initial value
    /// (a zero-length CBOR byte string 0x80 followed by a 16-byte hash).
    pub fn new() -> Self {
        let mut s = Self {
            data: [0u8; LARGE_BLOB_MAX],
            len: 0,
        };
        // CTAP2.1 §6.10.3: initial serialized large-blob array is 0x80
        // followed by LEFT(SHA-256(h'80'), 16).
        s.data[0] = 0x80;
        let hash = Sha256::digest(&[0x80]);
        s.data[1..1 + HASH_LEN].copy_from_slice(&hash[..HASH_LEN]);
        s.len = 1 + HASH_LEN;
        s
    }

    /// Read `length` bytes starting at `offset`.
    pub fn read(
        &self,
        offset: usize,
        length: usize,
    ) -> Result<&[u8], CtapError> {
        let end = offset.checked_add(length).ok_or(CtapError::InvalidLength)?;
        if end > self.len {
            return Err(CtapError::InvalidLength);
        }
        Ok(&self.data[offset..end])
    }

    /// Write `data` starting at `offset`.
    ///
    /// When a write completes the full blob (i.e. the caller has finished
    /// streaming), the last 16 bytes are expected to be
    /// `LEFT(SHA-256(content), 16)`.  Verification is done by
    /// [`verify_hash`](Self::verify_hash).
    pub fn write(
        &mut self,
        offset: usize,
        src: &[u8],
    ) -> Result<(), CtapError> {
        let end = offset
            .checked_add(src.len())
            .ok_or(CtapError::InvalidLength)?;
        if end > LARGE_BLOB_MAX {
            return Err(CtapError::LimitExceeded);
        }
        self.data[offset..end].copy_from_slice(src);
        if end > self.len {
            self.len = end;
        }
        Ok(())
    }

    /// Verify the trailing SHA-256 hash of the stored blob content.
    pub fn verify_hash(&self) -> bool {
        if self.len <= HASH_LEN {
            return false;
        }
        let content_len = self.len - HASH_LEN;
        let hash = Sha256::digest(&self.data[..content_len]);
        // Constant-time comparison would be ideal but correctness is
        // sufficient here since large-blob data is not secret.
        hash[..HASH_LEN] == self.data[content_len..self.len]
    }

    /// Erase all stored data and re-initialise to the default empty state.
    pub fn clear(&mut self) {
        *self = Self::new();
    }

    /// Total number of valid bytes currently stored.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether the store is in its initial empty state.
    pub fn is_empty(&self) -> bool {
        self.len <= 1 + HASH_LEN
    }
}
