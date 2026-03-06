//! ECDH key agreement: P-256, P-384, P-521, X25519.

use heapless::Vec;
use zeroize::Zeroize;

use super::apdu_router::*;
use super::dkek::DkekState;
use super::key_management::{KeyObject, KeyType};

/// Perform ECDH key agreement, returning the raw shared secret.
pub fn ecdh_derive(
    key: &KeyObject,
    dkek: &DkekState,
    peer_public_key: &[u8],
) -> Result<Vec<u8, 66>, u16> {
    let mut priv_raw = dkek.unwrap_key(&key.private_key_wrapped)?;

    let result = match key.key_type {
        KeyType::EcP256 => ecdh_p256(&priv_raw, peer_public_key),
        KeyType::EcP384 => ecdh_p384(&priv_raw, peer_public_key),
        KeyType::EcP521 => ecdh_p521(&priv_raw, peer_public_key),
        KeyType::X25519 => ecdh_x25519(&priv_raw, peer_public_key),
        _ => Err(SW_INCORRECT_P1P2),
    };

    for b in priv_raw.iter_mut() {
        *b = 0;
    }
    priv_raw.clear();

    result
}

fn ecdh_p256(private_key: &[u8], peer_public_key: &[u8]) -> Result<Vec<u8, 66>, u16> {
    let shared = pico_rs_sdk::crypto::ecc::ecdh_p256(private_key, peer_public_key)
        .map_err(|_| SW_INVALID_DATA)?;
    let mut out: Vec<u8, 66> = Vec::new();
    out.extend_from_slice(&shared)
        .map_err(|_| SW_WRONG_LENGTH)?;
    Ok(out)
}

fn ecdh_p384(private_key: &[u8], peer_public_key: &[u8]) -> Result<Vec<u8, 66>, u16> {
    use p384::elliptic_curve::sec1::FromEncodedPoint;
    use p384::{EncodedPoint, PublicKey, SecretKey};

    let sk = SecretKey::from_bytes(private_key.into()).map_err(|_| SW_INVALID_DATA)?;
    let point = EncodedPoint::from_bytes(peer_public_key).map_err(|_| SW_INVALID_DATA)?;
    let pk = PublicKey::from_encoded_point(&point);

    let pk = Option::from(pk).ok_or(SW_INVALID_DATA)?;
    let shared = p384::ecdh::diffie_hellman(sk.to_nonzero_scalar(), pk.as_affine());

    let mut out: Vec<u8, 66> = Vec::new();
    out.extend_from_slice(shared.raw_secret_bytes())
        .map_err(|_| SW_WRONG_LENGTH)?;
    Ok(out)
}

fn ecdh_p521(private_key: &[u8], peer_public_key: &[u8]) -> Result<Vec<u8, 66>, u16> {
    use p521::elliptic_curve::sec1::FromEncodedPoint;
    use p521::{EncodedPoint, PublicKey, SecretKey};

    let sk = SecretKey::from_bytes(private_key.into()).map_err(|_| SW_INVALID_DATA)?;
    let point = EncodedPoint::from_bytes(peer_public_key).map_err(|_| SW_INVALID_DATA)?;
    let pk = PublicKey::from_encoded_point(&point);

    let pk = Option::from(pk).ok_or(SW_INVALID_DATA)?;
    let shared = p521::ecdh::diffie_hellman(sk.to_nonzero_scalar(), pk.as_affine());

    // P-521 shared secret is 66 bytes — use full size buffer
    let mut out: Vec<u8, 66> = Vec::new();
    out.extend_from_slice(shared.raw_secret_bytes())
        .map_err(|_| SW_WRONG_LENGTH)?;
    Ok(out)
}

fn ecdh_x25519(private_key: &[u8], peer_public_key: &[u8]) -> Result<Vec<u8, 66>, u16> {
    if private_key.len() < 32 || peer_public_key.len() < 32 {
        return Err(SW_WRONG_LENGTH);
    }

    let mut priv_arr = [0u8; 32];
    priv_arr.copy_from_slice(&private_key[..32]);
    let mut pub_arr = [0u8; 32];
    pub_arr.copy_from_slice(&peer_public_key[..32]);

    let shared =
        pico_rs_sdk::crypto::ecc::x25519_ecdh(&priv_arr, &pub_arr).map_err(|_| SW_INVALID_DATA)?;
    priv_arr.zeroize();

    let mut out: Vec<u8, 66> = Vec::new();
    out.extend_from_slice(&shared)
        .map_err(|_| SW_WRONG_LENGTH)?;
    Ok(out)
}
