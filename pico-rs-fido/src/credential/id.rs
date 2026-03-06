//! Credential ID generation and decryption.
//!
//! Format: `nonce(16) | AES-GCM(key, nonce[..12], private_key || rp_id_hash) | tag(16)`
//!
//! The 16-byte nonce is truncated to 12 bytes for AES-GCM (standard nonce size).
//! The full 16 bytes are stored in the credential ID for future flexibility.

use super::CredentialError;
use heapless::Vec;
use pico_rs_sdk::crypto::aes::{aes256_gcm_decrypt, aes256_gcm_encrypt};

/// Generate an encrypted credential ID from a private key and RP ID hash.
///
/// Returns: `nonce(16) | ciphertext(private_key.len() + 32) | tag(16)`
pub fn generate_credential_id(
    private_key: &[u8],
    rp_id_hash: &[u8; 32],
    nonce: &[u8; 16],
    encryption_key: &[u8; 32],
) -> Vec<u8, 128> {
    // Build plaintext: private_key || rp_id_hash
    let plaintext_len = private_key.len() + 32;
    let mut plaintext = [0u8; 98]; // max 66 (key) + 32 (hash)
    plaintext[..private_key.len()].copy_from_slice(private_key);
    plaintext[private_key.len()..plaintext_len].copy_from_slice(rp_id_hash);

    // Use first 12 bytes of nonce for AES-GCM
    let mut gcm_nonce = [0u8; 12];
    gcm_nonce.copy_from_slice(&nonce[..12]);

    // Encrypt
    let mut ciphertext = [0u8; 98];
    let tag = aes256_gcm_encrypt(
        encryption_key,
        &gcm_nonce,
        &plaintext[..plaintext_len],
        &[], // no AAD
        &mut ciphertext,
    )
    .expect("AES-GCM encrypt should not fail with valid inputs");

    // Zeroize plaintext
    use zeroize::Zeroize;
    plaintext.zeroize();

    // Build credential ID: nonce(16) | ciphertext | tag(16)
    let total_len = 16 + plaintext_len + 16;
    let mut result: Vec<u8, 128> = Vec::new();
    let _ = result.extend_from_slice(nonce);
    let _ = result.extend_from_slice(&ciphertext[..plaintext_len]);
    let _ = result.extend_from_slice(&tag);
    debug_assert_eq!(result.len(), total_len);

    result
}

/// Decrypt a credential ID to recover the private key and RP ID hash.
///
/// Expected input format: `nonce(16) | ciphertext | tag(16)`
/// Returns: `(private_key, rp_id_hash)`
pub fn decrypt_credential_id(
    cred_id: &[u8],
    encryption_key: &[u8; 32],
) -> Result<(Vec<u8, 66>, [u8; 32]), CredentialError> {
    // Minimum: nonce(16) + at least 32 bytes (rp_id_hash) + tag(16) = 64
    if cred_id.len() < 64 {
        return Err(CredentialError::EncryptionError);
    }

    let nonce_bytes = &cred_id[..16];
    let tag_start = cred_id.len() - 16;
    let ciphertext = &cred_id[16..tag_start];
    let tag_bytes = &cred_id[tag_start..];

    let mut gcm_nonce = [0u8; 12];
    gcm_nonce.copy_from_slice(&nonce_bytes[..12]);

    let mut tag = [0u8; 16];
    tag.copy_from_slice(tag_bytes);

    let mut plaintext = [0u8; 98];
    aes256_gcm_decrypt(
        encryption_key,
        &gcm_nonce,
        ciphertext,
        &[],
        &tag,
        &mut plaintext,
    )
    .map_err(|_| CredentialError::EncryptionError)?;

    // Split plaintext: private_key (everything before last 32 bytes) | rp_id_hash (last 32)
    if ciphertext.len() < 32 {
        return Err(CredentialError::EncryptionError);
    }

    let key_len = ciphertext.len() - 32;
    let mut private_key: Vec<u8, 66> = Vec::new();
    private_key
        .extend_from_slice(&plaintext[..key_len])
        .map_err(|_| CredentialError::SerializationError)?;

    let mut rp_id_hash = [0u8; 32];
    rp_id_hash.copy_from_slice(&plaintext[key_len..key_len + 32]);

    // Zeroize plaintext buffer
    use zeroize::Zeroize;
    plaintext.zeroize();

    Ok((private_key, rp_id_hash))
}
