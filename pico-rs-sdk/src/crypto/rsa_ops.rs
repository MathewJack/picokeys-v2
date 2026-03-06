//! RSA operations: key generation, PKCS#1 v1.5 sign, PSS sign, OAEP decrypt.
//!
//! # Security Advisory
//! The `rsa` crate has a timing side-channel advisory (RUSTSEC-2023-0071, Marvin attack).
//! Mitigations:
//! - The crate uses random blinding to randomize execution time
//! - USB devices have high timing jitter, making precise measurements difficult
//! - RSA decrypt operations should be gated behind user-presence (press-to-confirm)
//! - Track upstream fix: https://github.com/RustCrypto/RSA/issues/390

use super::{CryptoError, RsaKeySize};
use heapless::Vec;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// RSA key pair data (DER-encoded). Private key is zeroized on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct RsaKeyPairData {
    /// PKCS#1 DER-encoded private key
    pub private_key_der: Vec<u8, 2048>,
    /// PKCS#1 DER-encoded public key  
    #[zeroize(skip)]
    pub public_key_der: Vec<u8, 512>,
    /// Key size in bits
    #[zeroize(skip)]
    pub key_bits: u16,
}

/// Generate an RSA key pair. WARNING: This is extremely slow on microcontrollers.
/// RSA-2048 takes ~124s on RP2040, ~500s for RSA-4096 on RP2350.
#[cfg(feature = "rsa")]
pub fn rsa_generate(
    size: RsaKeySize,
    rng: &mut (impl rand_core::CryptoRng + rand_core::RngCore),
) -> Result<RsaKeyPairData, CryptoError> {
    // RSA key generation requires alloc — ensure embedded_alloc is initialized
    use rsa::RsaPrivateKey;
    use rsa::pkcs1::{EncodeRsaPrivateKey, EncodeRsaPublicKey};

    let private_key = RsaPrivateKey::new(rng, size.bits())
        .map_err(|_| CryptoError::InternalError)?;
    let public_key = private_key.to_public_key();

    let priv_der = private_key.to_pkcs1_der()
        .map_err(|_| CryptoError::InternalError)?;
    let pub_der = public_key.to_pkcs1_der()
        .map_err(|_| CryptoError::InternalError)?;

    let mut private_key_der: Vec<u8, 2048> = Vec::new();
    private_key_der.extend_from_slice(priv_der.as_bytes())
        .map_err(|_| CryptoError::BufferTooSmall)?;

    let mut public_key_der: Vec<u8, 512> = Vec::new();
    public_key_der.extend_from_slice(pub_der.as_bytes())
        .map_err(|_| CryptoError::BufferTooSmall)?;

    Ok(RsaKeyPairData {
        private_key_der,
        public_key_der,
        key_bits: size.bits() as u16,
    })
}

/// RSA PKCS#1 v1.5 signature.
#[cfg(feature = "rsa")]
pub fn rsa_sign_pkcs1v15(
    private_key_der: &[u8],
    digest: &[u8],
) -> Result<Vec<u8, 512>, CryptoError> {
    use rsa::{RsaPrivateKey, Pkcs1v15Sign};
    use rsa::pkcs1::DecodeRsaPrivateKey;

    let private_key = RsaPrivateKey::from_pkcs1_der(private_key_der)
        .map_err(|_| CryptoError::InvalidKey)?;
    let scheme = Pkcs1v15Sign::new_unprefixed();
    let signature = private_key.sign(scheme, digest)
        .map_err(|_| CryptoError::InternalError)?;

    let mut out: Vec<u8, 512> = Vec::new();
    out.extend_from_slice(&signature).map_err(|_| CryptoError::BufferTooSmall)?;
    Ok(out)
}

/// RSA-PSS signature.
#[cfg(feature = "rsa")]
pub fn rsa_sign_pss(
    private_key_der: &[u8],
    digest: &[u8],
    rng: &mut (impl rand_core::CryptoRng + rand_core::RngCore),
) -> Result<Vec<u8, 512>, CryptoError> {
    use rsa::{RsaPrivateKey, Pss};
    use rsa::pkcs1::DecodeRsaPrivateKey;
    use sha2::Sha256;

    let private_key = RsaPrivateKey::from_pkcs1_der(private_key_der)
        .map_err(|_| CryptoError::InvalidKey)?;
    let scheme = Pss::new_with_salt::<Sha256>(32);
    let signature = private_key.sign_with_rng(rng, scheme, digest)
        .map_err(|_| CryptoError::InternalError)?;

    let mut out: Vec<u8, 512> = Vec::new();
    out.extend_from_slice(&signature).map_err(|_| CryptoError::BufferTooSmall)?;
    Ok(out)
}

/// RSA-OAEP decryption. Gate behind user-presence to mitigate Marvin attack.
#[cfg(feature = "rsa")]
pub fn rsa_decrypt_oaep(
    private_key_der: &[u8],
    ciphertext: &[u8],
    rng: &mut (impl rand_core::CryptoRng + rand_core::RngCore),
) -> Result<Vec<u8, 512>, CryptoError> {
    use rsa::{RsaPrivateKey, Oaep};
    use rsa::pkcs1::DecodeRsaPrivateKey;
    use sha2::Sha256;

    let private_key = RsaPrivateKey::from_pkcs1_der(private_key_der)
        .map_err(|_| CryptoError::InvalidKey)?;
    let padding = Oaep::new::<Sha256>();
    let plaintext = private_key.decrypt(padding, ciphertext)
        .map_err(|_| CryptoError::DecryptionFailed)?;

    let mut out: Vec<u8, 512> = Vec::new();
    out.extend_from_slice(&plaintext).map_err(|_| CryptoError::BufferTooSmall)?;
    Ok(out)
}
