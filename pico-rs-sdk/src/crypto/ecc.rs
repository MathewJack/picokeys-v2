//! Elliptic curve cryptography: ECDSA sign/verify, ECDH, Ed25519, X25519.

use super::CryptoError;
use heapless::Vec;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// EC key pair with zeroize-on-drop for the private key.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct EcPrivateKey {
    pub bytes: Vec<u8, 66>,
}

pub struct EcPublicKey {
    pub bytes: Vec<u8, 133>,
}

// ---- P-256 ----

pub fn generate_p256(rng: &mut impl rand_core::CryptoRng + rand_core::RngCore) -> Result<(EcPrivateKey, EcPublicKey), CryptoError> {
    use p256::SecretKey;
    use p256::elliptic_curve::sec1::ToEncodedPoint;

    let secret = SecretKey::random(rng);
    let public = secret.public_key();
    let pub_point = public.to_encoded_point(false);

    let mut priv_bytes: Vec<u8, 66> = Vec::new();
    priv_bytes.extend_from_slice(&secret.to_bytes()).map_err(|_| CryptoError::BufferTooSmall)?;

    let mut pub_bytes: Vec<u8, 133> = Vec::new();
    pub_bytes.extend_from_slice(pub_point.as_bytes()).map_err(|_| CryptoError::BufferTooSmall)?;

    Ok((EcPrivateKey { bytes: priv_bytes }, EcPublicKey { bytes: pub_bytes }))
}

pub fn ecdsa_sign_p256(private_key: &[u8], message_hash: &[u8]) -> Result<Vec<u8, 72>, CryptoError> {
    use p256::ecdsa::{SigningKey, signature::Signer, Signature};

    let signing_key = SigningKey::from_bytes(private_key.into())
        .map_err(|_| CryptoError::InvalidKey)?;
    let signature: Signature = signing_key.sign(message_hash);
    let der = signature.to_der();

    let mut out: Vec<u8, 72> = Vec::new();
    out.extend_from_slice(der.as_bytes()).map_err(|_| CryptoError::BufferTooSmall)?;
    Ok(out)
}

pub fn ecdsa_verify_p256(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<bool, CryptoError> {
    use p256::ecdsa::{VerifyingKey, Signature, signature::Verifier};
    use p256::EncodedPoint;

    let point = EncodedPoint::from_bytes(public_key).map_err(|_| CryptoError::InvalidKey)?;
    let vk = VerifyingKey::from_encoded_point(&point).map_err(|_| CryptoError::InvalidKey)?;
    let sig = Signature::from_der(signature).map_err(|_| CryptoError::InvalidSignature)?;

    match vk.verify(message, &sig) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

pub fn ecdh_p256(private_key: &[u8], peer_public_key: &[u8]) -> Result<[u8; 32], CryptoError> {
    use p256::{SecretKey, PublicKey, EncodedPoint};
    use p256::ecdh::diffie_hellman;

    let sk = SecretKey::from_bytes(private_key.into()).map_err(|_| CryptoError::InvalidKey)?;
    let point = EncodedPoint::from_bytes(peer_public_key).map_err(|_| CryptoError::InvalidKey)?;
    let pk = PublicKey::from_encoded_point(&point).map_err(|_| CryptoError::InvalidKey)?;

    let shared = diffie_hellman(sk.to_nonzero_scalar(), pk.as_affine());
    let mut out = [0u8; 32];
    out.copy_from_slice(shared.raw_secret_bytes());
    Ok(out)
}

// ---- secp256k1 ----

pub fn generate_k256(rng: &mut impl rand_core::CryptoRng + rand_core::RngCore) -> Result<(EcPrivateKey, EcPublicKey), CryptoError> {
    use k256::SecretKey;
    use k256::elliptic_curve::sec1::ToEncodedPoint;

    let secret = SecretKey::random(rng);
    let public = secret.public_key();
    let pub_point = public.to_encoded_point(false);

    let mut priv_bytes: Vec<u8, 66> = Vec::new();
    priv_bytes.extend_from_slice(&secret.to_bytes()).map_err(|_| CryptoError::BufferTooSmall)?;

    let mut pub_bytes: Vec<u8, 133> = Vec::new();
    pub_bytes.extend_from_slice(pub_point.as_bytes()).map_err(|_| CryptoError::BufferTooSmall)?;

    Ok((EcPrivateKey { bytes: priv_bytes }, EcPublicKey { bytes: pub_bytes }))
}

pub fn ecdsa_sign_k256(private_key: &[u8], message_hash: &[u8]) -> Result<Vec<u8, 72>, CryptoError> {
    use k256::ecdsa::{SigningKey, signature::Signer, Signature};

    let signing_key = SigningKey::from_bytes(private_key.into())
        .map_err(|_| CryptoError::InvalidKey)?;
    let signature: Signature = signing_key.sign(message_hash);
    let der = signature.to_der();

    let mut out: Vec<u8, 72> = Vec::new();
    out.extend_from_slice(der.as_bytes()).map_err(|_| CryptoError::BufferTooSmall)?;
    Ok(out)
}

// ---- Ed25519 ----

pub fn generate_ed25519(rng: &mut impl rand_core::CryptoRng + rand_core::RngCore) -> Result<(EcPrivateKey, EcPublicKey), CryptoError> {
    use ed25519_dalek::SigningKey;

    let signing_key = SigningKey::generate(rng);
    let verifying_key = signing_key.verifying_key();

    let mut priv_bytes: Vec<u8, 66> = Vec::new();
    priv_bytes.extend_from_slice(signing_key.as_bytes()).map_err(|_| CryptoError::BufferTooSmall)?;

    let mut pub_bytes: Vec<u8, 133> = Vec::new();
    pub_bytes.extend_from_slice(verifying_key.as_bytes()).map_err(|_| CryptoError::BufferTooSmall)?;

    Ok((EcPrivateKey { bytes: priv_bytes }, EcPublicKey { bytes: pub_bytes }))
}

pub fn ed25519_sign(private_key: &[u8], message: &[u8]) -> Result<[u8; 64], CryptoError> {
    use ed25519_dalek::{SigningKey, Signer};

    if private_key.len() != 32 {
        return Err(CryptoError::InvalidKey);
    }
    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(private_key);
    let signing_key = SigningKey::from_bytes(&key_bytes);
    key_bytes.zeroize();

    let sig = signing_key.sign(message);
    Ok(sig.to_bytes())
}

pub fn ed25519_verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<bool, CryptoError> {
    use ed25519_dalek::{VerifyingKey, Signature, Verifier};

    if public_key.len() != 32 || signature.len() != 64 {
        return Err(CryptoError::InvalidKey);
    }
    let mut pk_bytes = [0u8; 32];
    pk_bytes.copy_from_slice(public_key);
    let vk = VerifyingKey::from_bytes(&pk_bytes).map_err(|_| CryptoError::InvalidKey)?;

    let mut sig_bytes = [0u8; 64];
    sig_bytes.copy_from_slice(signature);
    let sig = Signature::from_bytes(&sig_bytes);

    match vk.verify(message, &sig) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

// ---- X25519 ECDH ----

pub fn x25519_diffie_hellman(private_key: &[u8; 32], peer_public_key: &[u8; 32]) -> [u8; 32] {
    use x25519_dalek::{StaticSecret, PublicKey};

    let secret = StaticSecret::from(*private_key);
    let public = PublicKey::from(*peer_public_key);
    let shared = secret.diffie_hellman(&public);
    *shared.as_bytes()
}
