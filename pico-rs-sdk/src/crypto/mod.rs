//! Cryptography abstraction layer for PicoKeys v2.
//! Wraps RustCrypto primitives behind platform-agnostic interfaces.

pub mod aes;
pub mod asn1;
pub mod ecc;
pub mod rng;
pub mod rsa_ops;
pub mod symmetric;

/// Cryptographic operation error types.
#[derive(Debug, Clone, PartialEq, Eq, defmt::Format)]
pub enum CryptoError {
    InvalidKey,
    InvalidSignature,
    BufferTooSmall,
    UnsupportedAlgorithm,
    InternalError,
    RngError,
    DecryptionFailed,
    InvalidPadding,
    InvalidLength,
}

/// Elliptic curve identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, defmt::Format)]
pub enum EcCurve {
    P256,
    P384,
    P521,
    Secp256k1,
    Ed25519,
    X25519,
}

/// RSA key size variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, defmt::Format)]
pub enum RsaKeySize {
    Rsa1024 = 1024,
    Rsa2048 = 2048,
    Rsa3072 = 3072,
    Rsa4096 = 4096,
}

impl RsaKeySize {
    pub fn bits(&self) -> usize {
        *self as usize
    }
    pub fn byte_len(&self) -> usize {
        self.bits() / 8
    }
}

/// Hash algorithm identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, defmt::Format)]
pub enum HashAlgorithm {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

/// Compute SHA-256 hash.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// Compute SHA-1 hash (for legacy HMAC-SHA1 in OATH).
pub fn sha1(data: &[u8]) -> [u8; 20] {
    use sha1::Sha1;
    use sha1::Digest;
    let mut hasher = Sha1::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut out = [0u8; 20];
    out.copy_from_slice(&result);
    out
}
