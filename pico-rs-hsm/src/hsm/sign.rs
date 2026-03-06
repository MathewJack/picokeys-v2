//! Signing operations: RSA PKCS#1 v1.5, RSA-PSS, ECDSA, EdDSA.

use heapless::Vec;
use zeroize::Zeroize;

use super::apdu_router::*;
use super::dkek::DkekState;
use super::key_management::{KeyObject, KeyType};
use pico_rs_sdk::crypto::HashAlgorithm;

/// Dispatch signing based on key type and algorithm selector.
pub fn sign(
    key: &KeyObject,
    dkek: &DkekState,
    digest: &[u8],
    algo: u8,
    rng: &mut (impl rand_core::CryptoRng + rand_core::RngCore),
) -> Result<Vec<u8, 512>, u16> {
    // Unwrap private key from DKEK
    let mut priv_raw = dkek.unwrap_key(&key.private_key_wrapped)?;

    let result = match key.key_type {
        KeyType::EcP256 => sign_ecdsa_p256(&priv_raw, digest),
        KeyType::EcP384 => sign_ecdsa_p384(&priv_raw, digest),
        KeyType::EcP521 => sign_ecdsa_p521(&priv_raw, digest),
        KeyType::EcK256 => sign_ecdsa_k256(&priv_raw, digest),
        KeyType::Ed25519 => sign_eddsa(&priv_raw, digest),
        KeyType::Rsa1024 | KeyType::Rsa2048 | KeyType::Rsa3072 | KeyType::Rsa4096 => match algo {
            ALGO_RSA_PSS => sign_rsa_pss(&priv_raw, digest, HashAlgorithm::Sha256, rng),
            _ => sign_rsa_pkcs1(&priv_raw, digest, HashAlgorithm::Sha256),
        },
        _ => Err(SW_INCORRECT_P1P2),
    };

    // Zeroize unwrapped key material
    for b in priv_raw.iter_mut() {
        *b = 0;
    }
    priv_raw.clear();

    result
}

// ---------------------------------------------------------------------------
// RSA signatures
// ---------------------------------------------------------------------------

pub fn sign_rsa_pkcs1(
    private_key_der: &[u8],
    digest: &[u8],
    _hash_algorithm: HashAlgorithm,
) -> Result<Vec<u8, 512>, u16> {
    use rsa::pkcs1::DecodeRsaPrivateKey;
    use rsa::{Pkcs1v15Sign, RsaPrivateKey};

    let private_key =
        RsaPrivateKey::from_pkcs1_der(private_key_der).map_err(|_| SW_INVALID_DATA)?;
    let scheme = Pkcs1v15Sign::new_unprefixed();
    let signature = private_key
        .sign(scheme, digest)
        .map_err(|_| SW_INVALID_DATA)?;

    let mut out: Vec<u8, 512> = Vec::new();
    out.extend_from_slice(&signature)
        .map_err(|_| SW_WRONG_LENGTH)?;
    Ok(out)
}

pub fn sign_rsa_pss(
    private_key_der: &[u8],
    digest: &[u8],
    _hash_algorithm: HashAlgorithm,
    rng: &mut (impl rand_core::CryptoRng + rand_core::RngCore),
) -> Result<Vec<u8, 512>, u16> {
    use rsa::pkcs1::DecodeRsaPrivateKey;
    use rsa::{Pss, RsaPrivateKey};
    use sha2::Sha256;

    let private_key =
        RsaPrivateKey::from_pkcs1_der(private_key_der).map_err(|_| SW_INVALID_DATA)?;
    let scheme = Pss::new_with_salt::<Sha256>(32);
    let signature = private_key
        .sign_with_rng(rng, scheme, digest)
        .map_err(|_| SW_INVALID_DATA)?;

    let mut out: Vec<u8, 512> = Vec::new();
    out.extend_from_slice(&signature)
        .map_err(|_| SW_WRONG_LENGTH)?;
    Ok(out)
}

// ---------------------------------------------------------------------------
// ECDSA signatures
// ---------------------------------------------------------------------------

pub fn sign_ecdsa_p256(private_key: &[u8], digest: &[u8]) -> Result<Vec<u8, 512>, u16> {
    let sig = pico_rs_sdk::crypto::ecc::ecdsa_sign_p256(private_key, digest)
        .map_err(|_| SW_INVALID_DATA)?;
    let mut out: Vec<u8, 512> = Vec::new();
    out.extend_from_slice(&sig).map_err(|_| SW_WRONG_LENGTH)?;
    Ok(out)
}

pub fn sign_ecdsa_p384(private_key: &[u8], digest: &[u8]) -> Result<Vec<u8, 512>, u16> {
    use p384::ecdsa::{signature::Signer, Signature, SigningKey};

    let signing_key = SigningKey::from_bytes(private_key.into()).map_err(|_| SW_INVALID_DATA)?;
    let signature: Signature = signing_key.sign(digest);
    let der = signature.to_der();

    let mut out: Vec<u8, 512> = Vec::new();
    out.extend_from_slice(der.as_bytes())
        .map_err(|_| SW_WRONG_LENGTH)?;
    Ok(out)
}

pub fn sign_ecdsa_p521(private_key: &[u8], digest: &[u8]) -> Result<Vec<u8, 512>, u16> {
    use p521::ecdsa::{signature::Signer, Signature, SigningKey};

    let signing_key = SigningKey::from_bytes(private_key.into()).map_err(|_| SW_INVALID_DATA)?;
    let signature: Signature = signing_key.sign(digest);
    let der = signature.to_der();

    let mut out: Vec<u8, 512> = Vec::new();
    out.extend_from_slice(der.as_bytes())
        .map_err(|_| SW_WRONG_LENGTH)?;
    Ok(out)
}

pub fn sign_ecdsa_k256(private_key: &[u8], digest: &[u8]) -> Result<Vec<u8, 512>, u16> {
    let sig = pico_rs_sdk::crypto::ecc::ecdsa_sign_k256(private_key, digest)
        .map_err(|_| SW_INVALID_DATA)?;
    let mut out: Vec<u8, 512> = Vec::new();
    out.extend_from_slice(&sig).map_err(|_| SW_WRONG_LENGTH)?;
    Ok(out)
}

// ---------------------------------------------------------------------------
// EdDSA (Ed25519)
// ---------------------------------------------------------------------------

pub fn sign_eddsa(private_key: &[u8], message: &[u8]) -> Result<Vec<u8, 512>, u16> {
    let sig = pico_rs_sdk::crypto::ecc::ed25519_sign(private_key, message)
        .map_err(|_| SW_INVALID_DATA)?;
    let mut out: Vec<u8, 512> = Vec::new();
    out.extend_from_slice(&sig).map_err(|_| SW_WRONG_LENGTH)?;
    Ok(out)
}
