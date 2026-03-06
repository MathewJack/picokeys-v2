//! CTAP2 `largeBlobKey` extension (FIDO2 §12.6).
//!
//! Generates and verifies a per-credential 32-byte key used to
//! encrypt/decrypt large blob data stored on the authenticator.

use subtle::ConstantTimeEq;

/// Generate a new 32-byte large blob key.
///
/// In production firmware this must use a platform CSPRNG.
/// The caller should fill the returned array with true random bytes
/// from the platform RNG before storing.
pub fn generate_large_blob_key() -> [u8; 32] {
    // Placeholder: production firmware must replace with platform RNG output.
    [0u8; 32]
}

/// Constant-time comparison of a stored large blob key against a provided value.
///
/// Returns `true` if and only if `provided` is exactly 32 bytes and matches
/// `stored` in constant time.
pub fn verify_large_blob_key(stored: &[u8; 32], provided: &[u8]) -> bool {
    if provided.len() != 32 {
        return false;
    }
    stored.ct_eq(provided).into()
}
