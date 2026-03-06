//! HOTP — HMAC-Based One-Time Password (RFC 4226).

use super::OathAlgorithm;

/// Generate an HOTP code.
///
/// - `secret`: shared secret key
/// - `counter`: 8-byte moving factor
/// - `digits`: number of OTP digits (typically 6 or 8)
/// - `algorithm`: HMAC hash algorithm
pub fn generate_hotp(secret: &[u8], counter: u64, digits: u8, algorithm: OathAlgorithm) -> u32 {
    let counter_bytes = counter.to_be_bytes();
    let hash = compute_hmac(secret, &counter_bytes, algorithm);
    let code = dynamic_truncation(&hash);
    let modulus = 10u32.pow(digits as u32);
    code % modulus
}

/// Compute HMAC with the specified algorithm, returning the raw digest bytes.
fn compute_hmac(key: &[u8], data: &[u8], algorithm: OathAlgorithm) -> heapless::Vec<u8, 64> {
    use hmac::{Hmac, Mac};
    let mut result = heapless::Vec::new();

    match algorithm {
        OathAlgorithm::Sha1 => {
            type HmacSha1 = Hmac<sha1::Sha1>;
            let mut mac = HmacSha1::new_from_slice(key).expect("HMAC key length");
            mac.update(data);
            let hash = mac.finalize().into_bytes();
            let _ = result.extend_from_slice(&hash);
        }
        OathAlgorithm::Sha256 => {
            type HmacSha256 = Hmac<sha2::Sha256>;
            let mut mac = HmacSha256::new_from_slice(key).expect("HMAC key length");
            mac.update(data);
            let hash = mac.finalize().into_bytes();
            let _ = result.extend_from_slice(&hash);
        }
        OathAlgorithm::Sha512 => {
            type HmacSha512 = Hmac<sha2::Sha512>;
            let mut mac = HmacSha512::new_from_slice(key).expect("HMAC key length");
            mac.update(data);
            let hash = mac.finalize().into_bytes();
            let _ = result.extend_from_slice(&hash);
        }
    }

    result
}

/// Dynamic truncation per RFC 4226 §5.3.
fn dynamic_truncation(hash: &[u8]) -> u32 {
    let offset = (hash[hash.len() - 1] & 0x0F) as usize;
    ((hash[offset] & 0x7F) as u32) << 24
        | (hash[offset + 1] as u32) << 16
        | (hash[offset + 2] as u32) << 8
        | (hash[offset + 3] as u32)
}
