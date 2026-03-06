//! Symmetric cryptography: HMAC, CMAC, HKDF, PBKDF2.

use super::CryptoError;
use subtle::ConstantTimeEq;

/// HMAC-SHA256.
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    type HmacSha256 = Hmac<Sha256>;

    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    let result = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// HMAC-SHA1 (for legacy OATH TOTP/HOTP).
pub fn hmac_sha1(key: &[u8], data: &[u8]) -> [u8; 20] {
    use hmac::{Hmac, Mac};
    use sha1::Sha1;

    type HmacSha1 = Hmac<Sha1>;

    let mut mac = HmacSha1::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    let result = mac.finalize().into_bytes();
    let mut out = [0u8; 20];
    out.copy_from_slice(&result);
    out
}

/// Constant-time HMAC-SHA256 verification. NEVER use `==` for MAC comparison.
pub fn hmac_sha256_verify(key: &[u8], data: &[u8], expected: &[u8]) -> bool {
    let computed = hmac_sha256(key, data);
    if expected.len() != 32 {
        return false;
    }
    computed.ct_eq(expected).into()
}

/// HKDF-SHA256 key derivation (RFC 5869).
pub fn hkdf_sha256(
    ikm: &[u8],
    salt: &[u8],
    info: &[u8],
    output: &mut [u8],
) -> Result<(), CryptoError> {
    use hkdf::Hkdf;
    use sha2::Sha256;

    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    hk.expand(info, output)
        .map_err(|_| CryptoError::InvalidLength)
}

/// PBKDF2-HMAC-SHA256 key derivation.
pub fn pbkdf2_sha256(password: &[u8], salt: &[u8], iterations: u32, output: &mut [u8]) {
    pbkdf2::pbkdf2_hmac::<sha2::Sha256>(password, salt, iterations, output);
}

/// AES-CMAC (128-bit key, 128-bit output).
pub fn aes_cmac(key: &[u8; 16], data: &[u8]) -> [u8; 16] {
    use aes::Aes128;
    use cmac::{Cmac, Mac};

    let mut mac = <Cmac<Aes128> as Mac>::new_from_slice(key).expect("valid key length");
    mac.update(data);
    let result = mac.finalize().into_bytes();
    let mut out = [0u8; 16];
    out.copy_from_slice(&result);
    out
}

/// Constant-time AES-CMAC verification.
pub fn aes_cmac_verify(key: &[u8; 16], data: &[u8], expected: &[u8; 16]) -> bool {
    let computed = aes_cmac(key, data);
    computed.ct_eq(expected).into()
}
