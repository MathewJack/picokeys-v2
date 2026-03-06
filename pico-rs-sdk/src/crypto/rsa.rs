//! RSA operations: key generation, PKCS#1 v1.5 sign, PSS sign, OAEP decrypt.
//!
//! # Security Advisory — RUSTSEC-2023-0071 (Marvin Attack)
//!
//! The `rsa` crate is subject to a timing side-channel during RSA decryption
//! (Marvin attack). Mitigations in this firmware:
//!
//! - The crate applies random blinding to each RSA operation, which randomises
//!   the execution time.
//! - USB transport adds high jitter, making precise timing measurements from a
//!   remote attacker impractical.
//! - RSA decrypt operations should always be gated behind user-presence
//!   (press-to-confirm) to limit the number of oracle queries.
//! - Track the upstream fix at <https://github.com/RustCrypto/RSA/issues/390>.

use alloc::vec::Vec;

use super::{CryptoError, HashAlgorithm, RsaKeySize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// RSA key pair data (DER-encoded). Private key material is zeroized on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct RsaKeyPairData {
    /// PKCS#1 DER-encoded RSA private key.
    pub private_key_der: Vec<u8>,
    /// PKCS#1 DER-encoded RSA public key.
    #[zeroize(skip)]
    pub public_key_der: Vec<u8>,
    /// Key size in bits.
    #[zeroize(skip)]
    pub key_bits: u16,
}

/// Generate an RSA key pair.
///
/// **WARNING:** This is extremely slow on microcontrollers — RSA-2048 can take
/// >120 s on RP2040.
pub fn rsa_generate(
    size: RsaKeySize,
    rng: &mut (impl rand_core::CryptoRng + rand_core::RngCore),
) -> Result<RsaKeyPairData, CryptoError> {
    use rsa::pkcs1::{EncodeRsaPrivateKey, EncodeRsaPublicKey};
    use rsa::RsaPrivateKey;

    let private_key =
        RsaPrivateKey::new(rng, size.bits()).map_err(|_| CryptoError::InternalError)?;
    let public_key = private_key.to_public_key();

    let priv_der = private_key
        .to_pkcs1_der()
        .map_err(|_| CryptoError::InternalError)?;
    let pub_der = public_key
        .to_pkcs1_der()
        .map_err(|_| CryptoError::InternalError)?;

    Ok(RsaKeyPairData {
        private_key_der: priv_der.as_bytes().to_vec(),
        public_key_der: pub_der.as_bytes().to_vec(),
        key_bits: size.bits() as u16,
    })
}

/// RSA PKCS#1 v1.5 signature over a pre-hashed digest.
///
/// `hash` selects the DigestInfo ASN.1 prefix embedded in the signature.
pub fn rsa_sign_pkcs1v15(
    private_key_der: &[u8],
    hash: HashAlgorithm,
    digest: &[u8],
) -> Result<heapless::Vec<u8, 512>, CryptoError> {
    use rsa::pkcs1::DecodeRsaPrivateKey;
    use rsa::{Pkcs1v15Sign, RsaPrivateKey};

    let private_key =
        RsaPrivateKey::from_pkcs1_der(private_key_der).map_err(|_| CryptoError::InvalidKey)?;

    let scheme = match hash {
        HashAlgorithm::Sha256 => Pkcs1v15Sign::new::<sha2::Sha256>(),
        HashAlgorithm::Sha384 => Pkcs1v15Sign::new::<sha2::Sha384>(),
        HashAlgorithm::Sha512 => Pkcs1v15Sign::new::<sha2::Sha512>(),
        HashAlgorithm::Sha1 => Pkcs1v15Sign::new::<sha1::Sha1>(),
    };

    let signature = private_key
        .sign(scheme, digest)
        .map_err(|_| CryptoError::InternalError)?;

    let mut out = heapless::Vec::new();
    out.extend_from_slice(&signature)
        .map_err(|_| CryptoError::BufferTooSmall)?;
    Ok(out)
}

/// RSA-PSS signature over a pre-hashed digest (requires RNG for salt).
pub fn rsa_sign_pss(
    private_key_der: &[u8],
    hash: HashAlgorithm,
    digest: &[u8],
    rng: &mut (impl rand_core::CryptoRng + rand_core::RngCore),
) -> Result<heapless::Vec<u8, 512>, CryptoError> {
    use rsa::pkcs1::DecodeRsaPrivateKey;
    use rsa::{Pss, RsaPrivateKey};

    let private_key =
        RsaPrivateKey::from_pkcs1_der(private_key_der).map_err(|_| CryptoError::InvalidKey)?;

    let scheme = match hash {
        HashAlgorithm::Sha256 => Pss::new_with_salt::<sha2::Sha256>(32),
        HashAlgorithm::Sha384 => Pss::new_with_salt::<sha2::Sha384>(48),
        HashAlgorithm::Sha512 => Pss::new_with_salt::<sha2::Sha512>(64),
        HashAlgorithm::Sha1 => Pss::new_with_salt::<sha1::Sha1>(20),
    };

    let signature = private_key
        .sign_with_rng(rng, scheme, digest)
        .map_err(|_| CryptoError::InternalError)?;

    let mut out = heapless::Vec::new();
    out.extend_from_slice(&signature)
        .map_err(|_| CryptoError::BufferTooSmall)?;
    Ok(out)
}

/// RSA-OAEP decryption (SHA-256 MGF).
///
/// Gate behind user-presence (press-to-confirm) to limit Marvin attack queries.
pub fn rsa_decrypt_oaep(
    private_key_der: &[u8],
    ciphertext: &[u8],
) -> Result<heapless::Vec<u8, 512>, CryptoError> {
    use rsa::pkcs1::DecodeRsaPrivateKey;
    use rsa::{Oaep, RsaPrivateKey};

    let private_key =
        RsaPrivateKey::from_pkcs1_der(private_key_der).map_err(|_| CryptoError::InvalidKey)?;
    let padding = Oaep::new::<sha2::Sha256>();
    let plaintext = private_key
        .decrypt(padding, ciphertext)
        .map_err(|_| CryptoError::DecryptionFailed)?;

    let mut out = heapless::Vec::new();
    out.extend_from_slice(&plaintext)
        .map_err(|_| CryptoError::BufferTooSmall)?;
    Ok(out)
}
