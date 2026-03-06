//! CTAP2 `credBlob` extension (FIDO2 §12.5).
//!
//! Allows a relying party to store a small opaque blob (up to 32 bytes)
//! alongside a credential during `makeCredential`, and retrieve it
//! during `getAssertion`.

/// Maximum length of a credBlob in bytes.
pub const MAX_CRED_BLOB_LEN: usize = 32;

/// Validate a credBlob payload.
///
/// Returns an owned copy if the blob length is within limits, or `Err(())`
/// if it exceeds [`MAX_CRED_BLOB_LEN`].
pub fn validate_cred_blob(data: &[u8]) -> Result<heapless::Vec<u8, 32>, ()> {
    if data.len() > MAX_CRED_BLOB_LEN {
        return Err(());
    }
    let mut blob = heapless::Vec::new();
    blob.extend_from_slice(data).map_err(|_| ())?;
    Ok(blob)
}
