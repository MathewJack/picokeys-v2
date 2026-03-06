//! Elliptic curve cryptography: ECDSA sign/verify, ECDH, Ed25519, X25519.

use super::{CryptoError, EcCurve};
use crate::crypto::rng::RngSource;
use heapless::Vec;
use zeroize::Zeroize;

/// EC key pair. Private key bytes are zeroized on drop.
pub struct EcKeyPair {
    pub curve: EcCurve,
    pub private_key: Vec<u8, 66>,
    pub public_key: Vec<u8, 133>,
}

impl Zeroize for EcKeyPair {
    fn zeroize(&mut self) {
        self.private_key.as_mut_slice().zeroize();
        self.private_key.clear();
    }
}

impl Drop for EcKeyPair {
    fn drop(&mut self) {
        self.zeroize();
    }
}

// ──────────────────────────────────────────────────────────────────────────
// P-256
// ──────────────────────────────────────────────────────────────────────────

pub fn generate_p256(rng: &mut impl RngSource) -> Result<EcKeyPair, CryptoError> {
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    use p256::SecretKey;

    let secret = SecretKey::random(rng);
    let public = secret.public_key();
    let pub_point = public.to_encoded_point(false);

    let mut private_key = Vec::new();
    private_key
        .extend_from_slice(&secret.to_bytes())
        .map_err(|_| CryptoError::BufferTooSmall)?;

    let mut public_key = Vec::new();
    public_key
        .extend_from_slice(pub_point.as_bytes())
        .map_err(|_| CryptoError::BufferTooSmall)?;

    Ok(EcKeyPair {
        curve: EcCurve::P256,
        private_key,
        public_key,
    })
}

pub fn ecdsa_sign_p256(
    private_key: &[u8],
    message: &[u8],
) -> Result<Vec<u8, 72>, CryptoError> {
    use p256::ecdsa::{signature::Signer, Signature, SigningKey};

    let signing_key =
        SigningKey::from_bytes(private_key.into()).map_err(|_| CryptoError::InvalidKey)?;
    let signature: Signature = signing_key.sign(message);
    let der = signature.to_der();

    let mut out = Vec::new();
    out.extend_from_slice(der.as_bytes())
        .map_err(|_| CryptoError::BufferTooSmall)?;
    Ok(out)
}

pub fn ecdsa_verify_p256(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<bool, CryptoError> {
    use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
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
    use p256::ecdh::diffie_hellman;
    use p256::{EncodedPoint, PublicKey, SecretKey};

    let sk = SecretKey::from_bytes(private_key.into()).map_err(|_| CryptoError::InvalidKey)?;
    let point =
        EncodedPoint::from_bytes(peer_public_key).map_err(|_| CryptoError::InvalidKey)?;
    let pk = PublicKey::from_encoded_point(&point).map_err(|_| CryptoError::InvalidKey)?;

    let shared = diffie_hellman(sk.to_nonzero_scalar(), pk.as_affine());
    let mut out = [0u8; 32];
    out.copy_from_slice(shared.raw_secret_bytes());
    Ok(out)
}

// ──────────────────────────────────────────────────────────────────────────
// P-384
// ──────────────────────────────────────────────────────────────────────────

pub fn generate_p384(rng: &mut impl RngSource) -> Result<EcKeyPair, CryptoError> {
    use p384::elliptic_curve::sec1::ToEncodedPoint;
    use p384::SecretKey;

    let secret = SecretKey::random(rng);
    let public = secret.public_key();
    let pub_point = public.to_encoded_point(false);

    let mut private_key = Vec::new();
    private_key
        .extend_from_slice(&secret.to_bytes())
        .map_err(|_| CryptoError::BufferTooSmall)?;

    let mut public_key = Vec::new();
    public_key
        .extend_from_slice(pub_point.as_bytes())
        .map_err(|_| CryptoError::BufferTooSmall)?;

    Ok(EcKeyPair {
        curve: EcCurve::P384,
        private_key,
        public_key,
    })
}

pub fn ecdsa_sign_p384(
    private_key: &[u8],
    message: &[u8],
) -> Result<Vec<u8, 104>, CryptoError> {
    use p384::ecdsa::{signature::Signer, Signature, SigningKey};

    let signing_key =
        SigningKey::from_bytes(private_key.into()).map_err(|_| CryptoError::InvalidKey)?;
    let signature: Signature = signing_key.sign(message);
    let der = signature.to_der();

    let mut out = Vec::new();
    out.extend_from_slice(der.as_bytes())
        .map_err(|_| CryptoError::BufferTooSmall)?;
    Ok(out)
}

pub fn ecdsa_verify_p384(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<bool, CryptoError> {
    use p384::ecdsa::{signature::Verifier, Signature, VerifyingKey};
    use p384::EncodedPoint;

    let point = EncodedPoint::from_bytes(public_key).map_err(|_| CryptoError::InvalidKey)?;
    let vk = VerifyingKey::from_encoded_point(&point).map_err(|_| CryptoError::InvalidKey)?;
    let sig = Signature::from_der(signature).map_err(|_| CryptoError::InvalidSignature)?;

    match vk.verify(message, &sig) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

pub fn ecdh_p384(private_key: &[u8], peer_public_key: &[u8]) -> Result<[u8; 48], CryptoError> {
    use p384::ecdh::diffie_hellman;
    use p384::{EncodedPoint, PublicKey, SecretKey};

    let sk = SecretKey::from_bytes(private_key.into()).map_err(|_| CryptoError::InvalidKey)?;
    let point =
        EncodedPoint::from_bytes(peer_public_key).map_err(|_| CryptoError::InvalidKey)?;
    let pk = PublicKey::from_encoded_point(&point).map_err(|_| CryptoError::InvalidKey)?;

    let shared = diffie_hellman(sk.to_nonzero_scalar(), pk.as_affine());
    let mut out = [0u8; 48];
    out.copy_from_slice(shared.raw_secret_bytes());
    Ok(out)
}

// ──────────────────────────────────────────────────────────────────────────
// secp256k1 (k256)
// ──────────────────────────────────────────────────────────────────────────

pub fn generate_k256(rng: &mut impl RngSource) -> Result<EcKeyPair, CryptoError> {
    use k256::elliptic_curve::sec1::ToEncodedPoint;
    use k256::SecretKey;

    let secret = SecretKey::random(rng);
    let public = secret.public_key();
    let pub_point = public.to_encoded_point(false);

    let mut private_key = Vec::new();
    private_key
        .extend_from_slice(&secret.to_bytes())
        .map_err(|_| CryptoError::BufferTooSmall)?;

    let mut public_key = Vec::new();
    public_key
        .extend_from_slice(pub_point.as_bytes())
        .map_err(|_| CryptoError::BufferTooSmall)?;

    Ok(EcKeyPair {
        curve: EcCurve::Secp256k1,
        private_key,
        public_key,
    })
}

pub fn ecdsa_sign_k256(
    private_key: &[u8],
    message: &[u8],
) -> Result<Vec<u8, 72>, CryptoError> {
    use k256::ecdsa::{signature::Signer, Signature, SigningKey};

    let signing_key =
        SigningKey::from_bytes(private_key.into()).map_err(|_| CryptoError::InvalidKey)?;
    let signature: Signature = signing_key.sign(message);
    let der = signature.to_der();

    let mut out = Vec::new();
    out.extend_from_slice(der.as_bytes())
        .map_err(|_| CryptoError::BufferTooSmall)?;
    Ok(out)
}

pub fn ecdsa_verify_k256(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<bool, CryptoError> {
    use k256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
    use k256::EncodedPoint;

    let point = EncodedPoint::from_bytes(public_key).map_err(|_| CryptoError::InvalidKey)?;
    let vk = VerifyingKey::from_encoded_point(&point).map_err(|_| CryptoError::InvalidKey)?;
    let sig = Signature::from_der(signature).map_err(|_| CryptoError::InvalidSignature)?;

    match vk.verify(message, &sig) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

pub fn ecdh_k256(private_key: &[u8], peer_public_key: &[u8]) -> Result<[u8; 32], CryptoError> {
    use k256::ecdh::diffie_hellman;
    use k256::{EncodedPoint, PublicKey, SecretKey};

    let sk = SecretKey::from_bytes(private_key.into()).map_err(|_| CryptoError::InvalidKey)?;
    let point =
        EncodedPoint::from_bytes(peer_public_key).map_err(|_| CryptoError::InvalidKey)?;
    let pk = PublicKey::from_encoded_point(&point).map_err(|_| CryptoError::InvalidKey)?;

    let shared = diffie_hellman(sk.to_nonzero_scalar(), pk.as_affine());
    let mut out = [0u8; 32];
    out.copy_from_slice(shared.raw_secret_bytes());
    Ok(out)
}

// ──────────────────────────────────────────────────────────────────────────
// Ed25519
// ──────────────────────────────────────────────────────────────────────────

pub fn generate_ed25519(rng: &mut impl RngSource) -> Result<EcKeyPair, CryptoError> {
    use ed25519_dalek::SigningKey;

    let signing_key = SigningKey::generate(rng);
    let verifying_key = signing_key.verifying_key();

    let mut private_key = Vec::new();
    private_key
        .extend_from_slice(signing_key.as_bytes())
        .map_err(|_| CryptoError::BufferTooSmall)?;

    let mut public_key = Vec::new();
    public_key
        .extend_from_slice(verifying_key.as_bytes())
        .map_err(|_| CryptoError::BufferTooSmall)?;

    Ok(EcKeyPair {
        curve: EcCurve::Ed25519,
        private_key,
        public_key,
    })
}

pub fn ed25519_sign(private_key: &[u8], message: &[u8]) -> Result<[u8; 64], CryptoError> {
    use ed25519_dalek::{Signer, SigningKey};

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

pub fn ed25519_verify(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<bool, CryptoError> {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    if public_key.len() != 32 {
        return Err(CryptoError::InvalidKey);
    }
    if signature.len() != 64 {
        return Err(CryptoError::InvalidSignature);
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

// ──────────────────────────────────────────────────────────────────────────
// X25519 ECDH
// ──────────────────────────────────────────────────────────────────────────

pub fn generate_x25519(rng: &mut impl RngSource) -> Result<EcKeyPair, CryptoError> {
    use x25519_dalek::{PublicKey, StaticSecret};

    let secret = StaticSecret::random_from_rng(rng);
    let public = PublicKey::from(&secret);

    let mut private_key = Vec::new();
    private_key
        .extend_from_slice(&secret.to_bytes())
        .map_err(|_| CryptoError::BufferTooSmall)?;

    let mut public_key = Vec::new();
    public_key
        .extend_from_slice(public.as_bytes())
        .map_err(|_| CryptoError::BufferTooSmall)?;

    Ok(EcKeyPair {
        curve: EcCurve::X25519,
        private_key,
        public_key,
    })
}

pub fn x25519_ecdh(
    private_key: &[u8],
    peer_public_key: &[u8],
) -> Result<[u8; 32], CryptoError> {
    use x25519_dalek::{PublicKey, StaticSecret};

    if private_key.len() != 32 {
        return Err(CryptoError::InvalidKey);
    }
    if peer_public_key.len() != 32 {
        return Err(CryptoError::InvalidKey);
    }

    let mut sk_bytes = [0u8; 32];
    sk_bytes.copy_from_slice(private_key);
    let secret = StaticSecret::from(sk_bytes);
    sk_bytes.zeroize();

    let mut pk_bytes = [0u8; 32];
    pk_bytes.copy_from_slice(peer_public_key);
    let public = PublicKey::from(pk_bytes);

    let shared = secret.diffie_hellman(&public);
    Ok(*shared.as_bytes())
}
