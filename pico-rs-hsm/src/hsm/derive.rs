//! Key derivation functions: HKDF, PBKDF2, X9.63 KDF.

use super::apdu_router::*;

/// HKDF-SHA256 key derivation (RFC 5869).
pub fn hkdf_derive(key: &[u8], salt: &[u8], info: &[u8], output: &mut [u8]) -> Result<(), u16> {
    pico_rs_sdk::crypto::symmetric::hkdf_sha256(key, salt, info, output)
        .map_err(|_| SW_INVALID_DATA)
}

/// PBKDF2-HMAC-SHA256 key derivation.
pub fn pbkdf2_derive(
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    output: &mut [u8],
) -> Result<(), u16> {
    if iterations == 0 {
        return Err(SW_INVALID_DATA);
    }
    pico_rs_sdk::crypto::symmetric::pbkdf2_sha256(password, salt, iterations, output);
    Ok(())
}

/// ANSI X9.63 KDF using SHA-256.
///
/// `KDM(Z, OtherInfo)` as per SEC 1 v2.0 §3.6.1:
/// `K = Hash(Z || counter || SharedInfo)` for counter = 1, 2, …
pub fn x963_kdf(shared_secret: &[u8], info: &[u8], output: &mut [u8]) -> Result<(), u16> {
    use sha2::{Digest, Sha256};

    let hash_len = 32usize;
    let out_len = output.len();
    if out_len == 0 {
        return Ok(());
    }

    let iterations = (out_len + hash_len - 1) / hash_len;
    // SEC 1 limits counter to u32
    if iterations > 0xFFFF_FFFF {
        return Err(SW_INVALID_DATA);
    }

    let mut offset = 0usize;
    for counter in 1..=(iterations as u32) {
        let mut hasher = Sha256::new();
        hasher.update(shared_secret);
        hasher.update(counter.to_be_bytes());
        hasher.update(info);
        let hash_result = hasher.finalize();

        let remaining = out_len - offset;
        let to_copy = if remaining < hash_len {
            remaining
        } else {
            hash_len
        };
        output[offset..offset + to_copy].copy_from_slice(&hash_result[..to_copy]);
        offset += to_copy;
    }

    Ok(())
}
