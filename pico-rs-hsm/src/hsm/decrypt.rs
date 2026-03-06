//! Decryption operations: RSA-OAEP, RSA PKCS#1 v1.5.

use heapless::Vec;
use zeroize::Zeroize;

use super::apdu_router::*;
use super::dkek::DkekState;
use super::key_management::{KeyObject, KeyType};
use pico_rs_sdk::crypto::HashAlgorithm;

/// Dispatch decryption based on key type and algorithm selector.
pub fn decrypt(
    key: &KeyObject,
    dkek: &DkekState,
    ciphertext: &[u8],
    algo: u8,
    rng: &mut (impl rand_core::CryptoRng + rand_core::RngCore),
) -> Result<Vec<u8, 512>, u16> {
    let mut priv_raw = dkek.unwrap_key(&key.private_key_wrapped)?;

    let result = match key.key_type {
        KeyType::Rsa1024 | KeyType::Rsa2048 | KeyType::Rsa3072 | KeyType::Rsa4096 => match algo {
            ALGO_RSA_OAEP => decrypt_rsa_oaep(&priv_raw, ciphertext, HashAlgorithm::Sha256, rng),
            _ => decrypt_rsa_pkcs1(&priv_raw, ciphertext),
        },
        _ => Err(SW_INCORRECT_P1P2),
    };

    for b in priv_raw.iter_mut() {
        *b = 0;
    }
    priv_raw.clear();

    result
}

pub fn decrypt_rsa_oaep(
    private_key_der: &[u8],
    ciphertext: &[u8],
    _hash: HashAlgorithm,
    rng: &mut (impl rand_core::CryptoRng + rand_core::RngCore),
) -> Result<Vec<u8, 512>, u16> {
    use rsa::pkcs1::DecodeRsaPrivateKey;
    use rsa::{Oaep, RsaPrivateKey};
    use sha2::Sha256;

    let private_key =
        RsaPrivateKey::from_pkcs1_der(private_key_der).map_err(|_| SW_INVALID_DATA)?;
    let padding = Oaep::new::<Sha256>();
    let plaintext = private_key
        .decrypt(padding, ciphertext)
        .map_err(|_| SW_SECURITY_NOT_SATISFIED)?;

    let mut out: Vec<u8, 512> = Vec::new();
    out.extend_from_slice(&plaintext)
        .map_err(|_| SW_WRONG_LENGTH)?;
    Ok(out)
}

pub fn decrypt_rsa_pkcs1(private_key_der: &[u8], ciphertext: &[u8]) -> Result<Vec<u8, 512>, u16> {
    use rsa::pkcs1::DecodeRsaPrivateKey;
    use rsa::{Pkcs1v15Encrypt, RsaPrivateKey};

    let private_key =
        RsaPrivateKey::from_pkcs1_der(private_key_der).map_err(|_| SW_INVALID_DATA)?;
    let plaintext = private_key
        .decrypt(Pkcs1v15Encrypt, ciphertext)
        .map_err(|_| SW_SECURITY_NOT_SATISFIED)?;

    let mut out: Vec<u8, 512> = Vec::new();
    out.extend_from_slice(&plaintext)
        .map_err(|_| SW_WRONG_LENGTH)?;
    Ok(out)
}
