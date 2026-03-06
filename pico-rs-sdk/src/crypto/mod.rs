//! Cryptography abstraction layer for PicoKeys v2.
//!
//! Provides platform-agnostic wrappers around RustCrypto primitives for ECDSA,
//! ECDH, RSA, AES, HMAC, and hashing. All operations are `no_std`-compatible.
//! RSA operations require the `alloc` feature.

pub mod aes;
pub mod asn1;
pub mod ecc;
pub mod rng;
#[cfg(feature = "alloc")]
pub mod rsa;
pub mod symmetric;

pub use aes::{aes256_cbc_decrypt, aes256_cbc_encrypt, aes256_gcm_decrypt, aes256_gcm_encrypt};
pub use ecc::EcKeyPair;
pub use rng::RngSource;
pub use symmetric::{hmac_sha256, hmac_sha256_verify};

/// Errors returned by cryptographic operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, defmt::Format)]
pub enum CryptoError {
    /// The supplied key material is invalid or malformed.
    InvalidKey,
    /// The signature failed verification or could not be parsed.
    InvalidSignature,
    /// An output buffer is too small for the result.
    BufferTooSmall,
    /// The requested algorithm or curve is not supported.
    UnsupportedAlgorithm,
    /// An internal/unexpected error occurred inside a crypto primitive.
    InternalError,
    /// The random number generator failed.
    RngError,
    /// Authenticated decryption or padding check failed.
    DecryptionFailed,
    /// PKCS#7 or similar padding is invalid.
    InvalidPadding,
    /// Input length does not meet requirements.
    InvalidLength,
}

/// Elliptic curves supported by the crypto layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, defmt::Format)]
pub enum EcCurve {
    P256,
    P384,
    P521,
    Secp256k1,
    Ed25519,
    X25519,
}

/// RSA key sizes.
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

/// AES block cipher modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, defmt::Format)]
pub enum AesMode {
    Ecb,
    Cbc,
    Gcm,
    Ccm,
}

/// Hash algorithms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, defmt::Format)]
pub enum HashAlgorithm {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

/// Compute SHA-256 hash.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::digest(data).into()
}

/// Compute SHA-384 hash.
pub fn sha384(data: &[u8]) -> [u8; 48] {
    use sha2::{Digest, Sha384};
    Sha384::digest(data).into()
}

/// Compute SHA-512 hash.
pub fn sha512(data: &[u8]) -> [u8; 64] {
    use sha2::{Digest, Sha512};
    Sha512::digest(data).into()
}

/// Compute SHA-1 hash (for legacy HMAC-SHA1 in OATH).
pub fn sha1(data: &[u8]) -> [u8; 20] {
    use sha2::Digest;
    sha1::Sha1::digest(data).into()
}

// ─── CryptoBackend trait ────────────────────────────────────────────────────

/// Platform-agnostic trait that unifies all crypto operations behind runtime dispatch.
///
/// Standalone functions in sub-modules (e.g. [`ecc::ecdsa_sign_p256`]) are preferred
/// when the algorithm is known at compile time. This trait is useful when the caller
/// selects the algorithm dynamically (e.g. from a COSE key type).
pub trait CryptoBackend {
    // ── RNG ──────────────────────────────────────────────────────────────
    fn rng_fill(&mut self, buf: &mut [u8]);

    // ── ECC key generation ──────────────────────────────────────────────
    fn ec_generate(&mut self, curve: EcCurve) -> Result<ecc::EcKeyPair, CryptoError>;

    // ── ECDSA ───────────────────────────────────────────────────────────
    /// Sign `message` and return the DER-encoded ECDSA signature (or raw Ed25519).
    fn ecdsa_sign(
        &self,
        curve: EcCurve,
        private_key: &[u8],
        message: &[u8],
    ) -> Result<heapless::Vec<u8, 104>, CryptoError>;

    fn ecdsa_verify(
        &self,
        curve: EcCurve,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<bool, CryptoError>;

    // ── ECDH ────────────────────────────────────────────────────────────
    fn ecdh(
        &self,
        curve: EcCurve,
        private_key: &[u8],
        peer_public_key: &[u8],
    ) -> Result<heapless::Vec<u8, 66>, CryptoError>;

    // ── AES-GCM ─────────────────────────────────────────────────────────
    fn aes256_gcm_encrypt(
        &self,
        key: &[u8; 32],
        nonce: &[u8; 12],
        plaintext: &[u8],
        aad: &[u8],
        output: &mut [u8],
    ) -> Result<[u8; 16], CryptoError>;

    fn aes256_gcm_decrypt(
        &self,
        key: &[u8; 32],
        nonce: &[u8; 12],
        ciphertext: &[u8],
        aad: &[u8],
        tag: &[u8; 16],
        output: &mut [u8],
    ) -> Result<(), CryptoError>;

    // ── Hashing ─────────────────────────────────────────────────────────
    fn sha256(&self, data: &[u8]) -> [u8; 32];
    fn sha384(&self, data: &[u8]) -> [u8; 48];
    fn sha512(&self, data: &[u8]) -> [u8; 64];
    fn sha1(&self, data: &[u8]) -> [u8; 20];

    // ── HMAC ────────────────────────────────────────────────────────────
    fn hmac_sha256(&self, key: &[u8], data: &[u8]) -> [u8; 32];
    /// Constant-time HMAC comparison — never use `==` for MAC tags.
    fn hmac_sha256_verify(&self, key: &[u8], data: &[u8], expected: &[u8]) -> bool;
}

// ─── Software CryptoBackend ─────────────────────────────────────────────────

/// Reference [`CryptoBackend`] backed by pure-software RustCrypto crates.
pub struct SoftwareCryptoBackend<R: RngSource> {
    pub rng: R,
}

impl<R: RngSource> SoftwareCryptoBackend<R> {
    pub fn new(rng: R) -> Self {
        Self { rng }
    }
}

impl<R: RngSource> CryptoBackend for SoftwareCryptoBackend<R> {
    fn rng_fill(&mut self, buf: &mut [u8]) {
        use rand_core::RngCore;
        self.rng.fill_bytes(buf);
    }

    fn ec_generate(&mut self, curve: EcCurve) -> Result<ecc::EcKeyPair, CryptoError> {
        match curve {
            EcCurve::P256 => ecc::generate_p256(&mut self.rng),
            EcCurve::P384 => ecc::generate_p384(&mut self.rng),
            EcCurve::P521 => ecc::generate_p521(&mut self.rng),
            EcCurve::Secp256k1 => ecc::generate_k256(&mut self.rng),
            EcCurve::Ed25519 => ecc::generate_ed25519(&mut self.rng),
            EcCurve::X25519 => ecc::generate_x25519(&mut self.rng),
            _ => Err(CryptoError::UnsupportedAlgorithm),
        }
    }

    fn ecdsa_sign(
        &self,
        curve: EcCurve,
        private_key: &[u8],
        message: &[u8],
    ) -> Result<heapless::Vec<u8, 104>, CryptoError> {
        let mut out = heapless::Vec::new();
        match curve {
            EcCurve::P256 => {
                let sig = ecc::ecdsa_sign_p256(private_key, message)?;
                out.extend_from_slice(&sig)
                    .map_err(|_| CryptoError::BufferTooSmall)?;
            }
            EcCurve::P384 => {
                let sig = ecc::ecdsa_sign_p384(private_key, message)?;
                out.extend_from_slice(&sig)
                    .map_err(|_| CryptoError::BufferTooSmall)?;
            }
            EcCurve::P521 => {
                let sig = ecc::ecdsa_sign_p521(private_key, message)?;
                out.extend_from_slice(&sig)
                    .map_err(|_| CryptoError::BufferTooSmall)?;
            }
            EcCurve::Secp256k1 => {
                let sig = ecc::ecdsa_sign_k256(private_key, message)?;
                out.extend_from_slice(&sig)
                    .map_err(|_| CryptoError::BufferTooSmall)?;
            }
            EcCurve::Ed25519 => {
                let sig = ecc::ed25519_sign(private_key, message)?;
                out.extend_from_slice(&sig)
                    .map_err(|_| CryptoError::BufferTooSmall)?;
            }
            _ => return Err(CryptoError::UnsupportedAlgorithm),
        }
        Ok(out)
    }

    fn ecdsa_verify(
        &self,
        curve: EcCurve,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<bool, CryptoError> {
        match curve {
            EcCurve::P256 => ecc::ecdsa_verify_p256(public_key, message, signature),
            EcCurve::P384 => ecc::ecdsa_verify_p384(public_key, message, signature),
            EcCurve::P521 => ecc::ecdsa_verify_p521(public_key, message, signature),
            EcCurve::Secp256k1 => ecc::ecdsa_verify_k256(public_key, message, signature),
            EcCurve::Ed25519 => ecc::ed25519_verify(public_key, message, signature),
            _ => Err(CryptoError::UnsupportedAlgorithm),
        }
    }

    fn ecdh(
        &self,
        curve: EcCurve,
        private_key: &[u8],
        peer_public_key: &[u8],
    ) -> Result<heapless::Vec<u8, 66>, CryptoError> {
        let mut out = heapless::Vec::new();
        match curve {
            EcCurve::P256 => {
                let s = ecc::ecdh_p256(private_key, peer_public_key)?;
                out.extend_from_slice(&s)
                    .map_err(|_| CryptoError::BufferTooSmall)?;
            }
            EcCurve::P384 => {
                let s = ecc::ecdh_p384(private_key, peer_public_key)?;
                out.extend_from_slice(&s)
                    .map_err(|_| CryptoError::BufferTooSmall)?;
            }
            EcCurve::P521 => {
                let s = ecc::ecdh_p521(private_key, peer_public_key)?;
                out.extend_from_slice(&s)
                    .map_err(|_| CryptoError::BufferTooSmall)?;
            }
            EcCurve::Secp256k1 => {
                let s = ecc::ecdh_k256(private_key, peer_public_key)?;
                out.extend_from_slice(&s)
                    .map_err(|_| CryptoError::BufferTooSmall)?;
            }
            EcCurve::X25519 => {
                let s = ecc::x25519_ecdh(private_key, peer_public_key)?;
                out.extend_from_slice(&s)
                    .map_err(|_| CryptoError::BufferTooSmall)?;
            }
            _ => return Err(CryptoError::UnsupportedAlgorithm),
        }
        Ok(out)
    }

    fn aes256_gcm_encrypt(
        &self,
        key: &[u8; 32],
        nonce: &[u8; 12],
        plaintext: &[u8],
        aad: &[u8],
        output: &mut [u8],
    ) -> Result<[u8; 16], CryptoError> {
        aes::aes256_gcm_encrypt(key, nonce, plaintext, aad, output)
    }

    fn aes256_gcm_decrypt(
        &self,
        key: &[u8; 32],
        nonce: &[u8; 12],
        ciphertext: &[u8],
        aad: &[u8],
        tag: &[u8; 16],
        output: &mut [u8],
    ) -> Result<(), CryptoError> {
        aes::aes256_gcm_decrypt(key, nonce, ciphertext, aad, tag, output)
    }

    fn sha256(&self, data: &[u8]) -> [u8; 32] {
        crate::crypto::sha256(data)
    }

    fn sha384(&self, data: &[u8]) -> [u8; 48] {
        crate::crypto::sha384(data)
    }

    fn sha512(&self, data: &[u8]) -> [u8; 64] {
        crate::crypto::sha512(data)
    }

    fn sha1(&self, data: &[u8]) -> [u8; 20] {
        crate::crypto::sha1(data)
    }

    fn hmac_sha256(&self, key: &[u8], data: &[u8]) -> [u8; 32] {
        symmetric::hmac_sha256(key, data)
    }

    fn hmac_sha256_verify(&self, key: &[u8], data: &[u8], expected: &[u8]) -> bool {
        symmetric::hmac_sha256_verify(key, data, expected)
    }
}
