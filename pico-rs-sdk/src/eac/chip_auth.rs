//! Chip Authentication (CA) protocol using ECDH on P-256.

use p256::ecdh::diffie_hellman;
use p256::{EncodedPoint, PublicKey, SecretKey};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

/// Chip Authentication using ECDH on NIST P-256.
///
/// The device holds a static CA key pair; the terminal sends an ephemeral
/// public key. ECDH is performed and the SHA-256 hash of the shared secret
/// is returned for session key derivation.
pub struct ChipAuthentication {
    /// Device's static private key (32 bytes, P-256 scalar).
    device_private: Option<[u8; 32]>,
    /// Device's public key (uncompressed, 65 bytes: 0x04 || X || Y).
    device_public: Option<[u8; 65]>,
}

impl ChipAuthentication {
    pub const fn new() -> Self {
        Self {
            device_private: None,
            device_public: None,
        }
    }

    /// Load a pre-existing CA key pair (e.g. from flash storage).
    pub fn load_key_pair(&mut self, private_key: &[u8; 32], public_key: &[u8; 65]) {
        self.device_private = Some(*private_key);
        self.device_public = Some(*public_key);
    }

    /// Return the device's CA public key (for the terminal to retrieve via
    /// EF.CardSecurity).
    pub fn public_key(&self) -> Option<&[u8; 65]> {
        self.device_public.as_ref()
    }

    /// Perform Chip Authentication.
    ///
    /// The terminal sends its ephemeral public key (uncompressed, 65 bytes).
    /// The device performs ECDH and returns SHA-256 of the shared secret for
    /// session key derivation.
    ///
    /// Returns `Ok(shared_secret_hash)` (32 bytes) on success.
    pub fn perform_ca(&self, terminal_public_key: &[u8]) -> Result<[u8; 32], u16> {
        // Must be 65 bytes uncompressed point (0x04 || X || Y)
        if terminal_public_key.len() != 65 || terminal_public_key[0] != 0x04 {
            return Err(0x6A80); // Wrong data
        }

        let device_private = self.device_private.as_ref().ok_or(0x6985u16)?;

        // Parse terminal's public key
        let terminal_point =
            EncodedPoint::from_bytes(terminal_public_key).map_err(|_| 0x6A80u16)?;
        let terminal_pk = PublicKey::from_encoded_point(&terminal_point).map_err(|_| 0x6A80u16)?;

        // Parse device's private key
        let sk = SecretKey::from_bytes(device_private.into()).map_err(|_| 0x6985u16)?;

        // ECDH: shared_point = device_private * terminal_public
        let shared_secret = diffie_hellman(sk.to_nonzero_scalar(), terminal_pk.as_affine());

        // Hash the shared secret for key derivation
        let mut hasher = Sha256::new();
        hasher.update(shared_secret.raw_secret_bytes());
        let hash = hasher.finalize();

        let mut result = [0u8; 32];
        result.copy_from_slice(&hash);
        Ok(result)
    }

    /// Clear key material.
    pub fn clear(&mut self) {
        if let Some(ref mut key) = self.device_private {
            key.zeroize();
        }
        self.device_private = None;
        self.device_public = None;
    }
}

impl Drop for ChipAuthentication {
    fn drop(&mut self) {
        self.clear();
    }
}
