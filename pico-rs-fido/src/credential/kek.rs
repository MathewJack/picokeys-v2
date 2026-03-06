//! Key Encryption Key (KEK) hierarchy for credential protection.
//!
//! MKEK (Master Key Encryption Key) → per-RP KEK via HKDF → AES-256-GCM wrap/unwrap.

use super::CredentialError;
use pico_rs_sdk::crypto::aes::{aes256_gcm_decrypt, aes256_gcm_encrypt};
use pico_rs_sdk::crypto::symmetric::hkdf_sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Master Key Encryption Key length in bytes.
pub const MKEK_LEN: usize = 32;

/// HKDF info string for credential key derivation.
const CRED_KEY_INFO: &[u8] = b"picokeys-cred-key";

/// Master Key Encryption Key wrapper with automatic zeroization.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Mkek {
    key: [u8; MKEK_LEN],
}

impl Mkek {
    /// Create a new MKEK from raw bytes.
    pub fn new(key: [u8; MKEK_LEN]) -> Self {
        Self { key }
    }

    /// Access the raw key bytes.
    pub fn as_bytes(&self) -> &[u8; MKEK_LEN] {
        &self.key
    }

    /// Derive a per-RP credential key from this MKEK.
    pub fn derive_credential_key(&self, rp_id_hash: &[u8; 32]) -> [u8; 32] {
        derive_credential_key(&self.key, rp_id_hash)
    }

    /// Static method: derive credential key using a default MKEK from platform storage.
    /// In production, this retrieves the MKEK from OTP fuses or flash.
    /// Panics if MKEK is not provisioned — call only after device initialization.
    pub fn derive_credential_key_static(rp_id_hash: &[u8; 32]) -> [u8; 32] {
        // TODO: In production, load MKEK from platform SecureStorage.
        // For now, use a deterministic key derived from a fixed seed.
        // This MUST be replaced with actual MKEK retrieval before deployment.
        let mut seed_mkek = [0u8; 32];
        // Derive a non-zero seed from a known constant to avoid all-zero key
        for (i, byte) in seed_mkek.iter_mut().enumerate() {
            *byte = (i as u8).wrapping_mul(0x37).wrapping_add(0xA5);
        }
        derive_credential_key(&seed_mkek, rp_id_hash)
    }
}

/// Derive a per-RP credential encryption key from the MKEK using HKDF-SHA256.
///
/// `HKDF-SHA256(ikm=mkek, salt=rp_id_hash, info="picokeys-cred-key") → 32 bytes`
pub fn derive_credential_key(mkek: &[u8; 32], rp_id_hash: &[u8; 32]) -> [u8; 32] {
    let mut output = [0u8; 32];
    hkdf_sha256(mkek, rp_id_hash, CRED_KEY_INFO, &mut output)
        .expect("HKDF-SHA256 with 32-byte output should not fail");
    output
}

/// AES-256-GCM key wrapping.
///
/// Encrypts `data` under `key` with a random nonce embedded in the output.
/// Output format: `nonce(12) | ciphertext(data.len()) | tag(16)`
/// Returns number of bytes written to `output`.
/// `rng` must be a cryptographically secure random number generator.
pub fn wrap_key(
    key: &[u8; 32],
    data: &[u8],
    output: &mut [u8],
    rng: &mut (impl rand_core::RngCore + rand_core::CryptoRng),
) -> Result<usize, CredentialError> {
    let total_len = 12 + data.len() + 16;
    if output.len() < total_len {
        return Err(CredentialError::SerializationError);
    }

    // Generate random nonce — critical for AES-GCM security
    let mut nonce = [0u8; 12];
    rng.fill_bytes(&mut nonce);
    output[..12].copy_from_slice(&nonce);

    let tag = aes256_gcm_encrypt(key, &nonce, data, &[], &mut output[12..])
        .map_err(|_| CredentialError::EncryptionError)?;

    output[12 + data.len()..12 + data.len() + 16].copy_from_slice(&tag);
    Ok(total_len)
}

/// AES-256-GCM key unwrapping.
///
/// Decrypts data previously wrapped with `wrap_key`.
/// Input format: `nonce(12) | ciphertext | tag(16)`
/// Returns number of plaintext bytes written to `output`.
pub fn unwrap_key(
    key: &[u8; 32],
    wrapped: &[u8],
    output: &mut [u8],
) -> Result<usize, CredentialError> {
    // Minimum: nonce(12) + tag(16) = 28, ciphertext can be 0+ bytes
    if wrapped.len() < 28 {
        return Err(CredentialError::EncryptionError);
    }

    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&wrapped[..12]);

    let ciphertext_len = wrapped.len() - 12 - 16;
    let ciphertext = &wrapped[12..12 + ciphertext_len];

    let mut tag = [0u8; 16];
    tag.copy_from_slice(&wrapped[12 + ciphertext_len..]);

    if output.len() < ciphertext_len {
        return Err(CredentialError::SerializationError);
    }

    aes256_gcm_decrypt(key, &nonce, ciphertext, &[], &tag, output)
        .map_err(|_| CredentialError::EncryptionError)?;

    Ok(ciphertext_len)
}
