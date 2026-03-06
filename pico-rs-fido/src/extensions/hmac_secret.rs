//! CTAP2 `hmac-secret` extension (FIDO2 §12.1).
//!
//! Allows relying parties to store and retrieve symmetric secrets
//! bound to a credential, using platform-negotiated shared secrets
//! for transport encryption.

use pico_rs_sdk::crypto::symmetric::hmac_sha256;

/// Generate 64 random bytes for a new credential's `credRandom`.
///
/// In production firmware this must use a platform CSPRNG.
/// The caller should supply randomness via platform RNG and write
/// it into the returned buffer.
pub fn create_hmac_secret_credential_random() -> [u8; 64] {
    // Placeholder: production firmware must replace this with true
    // random bytes from the platform RNG before storing.
    [0u8; 64]
}

/// Process an hmac-secret `getAssertion` request.
///
/// - `cred_random`: 64-byte per-credential random stored at creation time.
/// - `salt1`: 32-byte salt from the platform (mandatory).
/// - `salt2`: optional second 32-byte salt.
/// - `shared_secret`: 32-byte ECDH shared secret negotiated with the platform.
///
/// Returns the AES-256-CBC encrypted HMAC output(s).
pub fn process_hmac_secret_get(
    cred_random: &[u8; 64],
    salt1: &[u8; 32],
    salt2: Option<&[u8; 32]>,
    shared_secret: &[u8; 32],
) -> Result<heapless::Vec<u8, 80>, ()> {
    let output1 = hmac_sha256(&cred_random[..32], salt1);

    let plaintext_len;
    let mut plaintext_buf = [0u8; 64];

    match salt2 {
        Some(s2) => {
            let output2 = hmac_sha256(&cred_random[32..64], s2);
            plaintext_buf[..32].copy_from_slice(&output1);
            plaintext_buf[32..64].copy_from_slice(&output2);
            plaintext_len = 64;
        }
        None => {
            plaintext_buf[..32].copy_from_slice(&output1);
            plaintext_len = 32;
        }
    }

    // AES-256-CBC encrypt with IV = 0 (CTAP2 hmac-secret spec)
    let iv = [0u8; 16];
    let mut enc_buf = [0u8; 80];

    let enc_len = pico_rs_sdk::crypto::aes::aes256_cbc_encrypt(
        shared_secret,
        &iv,
        &plaintext_buf[..plaintext_len],
        &mut enc_buf,
    )
    .map_err(|_| ())?;

    let mut result = heapless::Vec::new();
    result
        .extend_from_slice(&enc_buf[..enc_len])
        .map_err(|_| ())?;

    Ok(result)
}
