//! Key object storage, generation, import/export.

use heapless::Vec;
use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroize;

use super::apdu_router::*;
use super::dkek::DkekState;

// ---------------------------------------------------------------------------
// Key types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum KeyType {
    Rsa1024 = 0,
    Rsa2048 = 1,
    Rsa3072 = 2,
    Rsa4096 = 3,
    EcP256 = 4,
    EcP384 = 5,
    EcP521 = 6,
    EcK256 = 7,
    Ed25519 = 8,
    X25519 = 9,
    Aes128 = 10,
    Aes192 = 11,
    Aes256 = 12,
}

impl Zeroize for KeyType {
    fn zeroize(&mut self) {
        *self = KeyType::Aes128;
    }
}

impl KeyType {
    pub fn from_u8(v: u8) -> Result<Self, u16> {
        match v {
            0 => Ok(KeyType::Rsa1024),
            1 => Ok(KeyType::Rsa2048),
            2 => Ok(KeyType::Rsa3072),
            3 => Ok(KeyType::Rsa4096),
            4 => Ok(KeyType::EcP256),
            5 => Ok(KeyType::EcP384),
            6 => Ok(KeyType::EcP521),
            7 => Ok(KeyType::EcK256),
            8 => Ok(KeyType::Ed25519),
            9 => Ok(KeyType::X25519),
            10 => Ok(KeyType::Aes128),
            11 => Ok(KeyType::Aes192),
            12 => Ok(KeyType::Aes256),
            _ => Err(SW_INVALID_DATA),
        }
    }

    pub fn is_rsa(self) -> bool {
        matches!(
            self,
            KeyType::Rsa1024 | KeyType::Rsa2048 | KeyType::Rsa3072 | KeyType::Rsa4096
        )
    }

    pub fn is_ec(self) -> bool {
        matches!(
            self,
            KeyType::EcP256 | KeyType::EcP384 | KeyType::EcP521 | KeyType::EcK256
        )
    }

    pub fn rsa_bits(self) -> Option<usize> {
        match self {
            KeyType::Rsa1024 => Some(1024),
            KeyType::Rsa2048 => Some(2048),
            KeyType::Rsa3072 => Some(3072),
            KeyType::Rsa4096 => Some(4096),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Key object
// ---------------------------------------------------------------------------

pub struct KeyObject {
    pub id: u8,
    pub key_type: KeyType,
    pub label: Vec<u8, 64>,
    /// DKEK-wrapped private key: [nonce(12) | ciphertext | tag(16)]
    pub private_key_wrapped: Vec<u8, 2048>,
    pub public_key: Vec<u8, 512>,
    pub usage_counter: u32,
    pub usage_limit: Option<u32>,
    pub domain: u8,
}

impl Zeroize for KeyObject {
    fn zeroize(&mut self) {
        self.id = 0;
        self.key_type.zeroize();
        for b in self.label.iter_mut() {
            *b = 0;
        }
        self.label.clear();
        for b in self.private_key_wrapped.iter_mut() {
            *b = 0;
        }
        self.private_key_wrapped.clear();
        for b in self.public_key.iter_mut() {
            *b = 0;
        }
        self.public_key.clear();
        self.usage_counter = 0;
        self.usage_limit = None;
        self.domain = 0;
    }
}

impl Drop for KeyObject {
    fn drop(&mut self) {
        self.zeroize();
    }
}

// ---------------------------------------------------------------------------
// Key store
// ---------------------------------------------------------------------------

pub struct KeyStore {
    keys: Vec<KeyObject, 64>,
    next_id: u8,
}

impl KeyStore {
    pub fn new() -> Self {
        Self {
            keys: Vec::new(),
            next_id: 1,
        }
    }

    fn allocate_id(&mut self) -> Result<u8, u16> {
        let start = self.next_id;
        loop {
            if !self.keys.iter().any(|k| k.id == self.next_id) {
                let id = self.next_id;
                self.next_id = self.next_id.wrapping_add(1);
                if self.next_id == 0 {
                    self.next_id = 1;
                }
                return Ok(id);
            }
            self.next_id = self.next_id.wrapping_add(1);
            if self.next_id == 0 {
                self.next_id = 1;
            }
            if self.next_id == start {
                return Err(SW_FILE_FULL);
            }
        }
    }

    pub fn generate_key<R: CryptoRng + RngCore>(
        &mut self,
        key_type: KeyType,
        label: &[u8],
        domain: u8,
        dkek: &DkekState,
        rng: &mut R,
    ) -> Result<u8, u16> {
        if self.keys.is_full() {
            return Err(SW_FILE_FULL);
        }
        if !dkek.is_ready() {
            return Err(SW_CONDITIONS_NOT_SATISFIED);
        }

        let id = self.allocate_id()?;
        let (mut priv_raw, pub_key) = generate_raw_keypair(key_type, rng)?;

        let wrapped = dkek.wrap_key(&priv_raw, rng)?;
        // Zeroize the raw private material
        for b in priv_raw.iter_mut() {
            *b = 0;
        }
        priv_raw.clear();

        let mut label_vec: Vec<u8, 64> = Vec::new();
        let copy_len = label.len().min(64);
        let _ = label_vec.extend_from_slice(&label[..copy_len]);

        let key = KeyObject {
            id,
            key_type,
            label: label_vec,
            private_key_wrapped: wrapped,
            public_key: pub_key,
            usage_counter: 0,
            usage_limit: None,
            domain,
        };

        self.keys.push(key).map_err(|_| SW_FILE_FULL)?;
        Ok(id)
    }

    pub fn delete_key(&mut self, key_id: u8) -> Result<(), u16> {
        let pos = self
            .keys
            .iter()
            .position(|k| k.id == key_id)
            .ok_or(SW_KEY_NOT_FOUND)?;
        self.keys.swap_remove(pos);
        Ok(())
    }

    pub fn get_key(&self, key_id: u8) -> Option<&KeyObject> {
        self.keys.iter().find(|k| k.id == key_id)
    }

    pub fn get_key_mut(&mut self, key_id: u8) -> Option<&mut KeyObject> {
        self.keys.iter_mut().find(|k| k.id == key_id)
    }

    pub fn list_keys(&self) -> &[KeyObject] {
        &self.keys
    }

    /// Export a key wrapped under DKEK.
    ///
    /// Format: `[key_type(1) | id(1) | domain(1) | label_len(1) | label(N)
    ///           | pub_len(2 BE) | pub(N) | wrapped_priv(N)]`
    pub fn wrap_key_for_export(&self, key_id: u8, dkek: &DkekState) -> Result<Vec<u8, 4096>, u16> {
        let key = self.get_key(key_id).ok_or(SW_KEY_NOT_FOUND)?;
        if !dkek.is_ready() {
            return Err(SW_CONDITIONS_NOT_SATISFIED);
        }

        let mut out: Vec<u8, 4096> = Vec::new();
        out.push(key.key_type as u8).map_err(|_| SW_WRONG_LENGTH)?;
        out.push(key.id).map_err(|_| SW_WRONG_LENGTH)?;
        out.push(key.domain).map_err(|_| SW_WRONG_LENGTH)?;
        out.push(key.label.len() as u8)
            .map_err(|_| SW_WRONG_LENGTH)?;
        out.extend_from_slice(&key.label)
            .map_err(|_| SW_WRONG_LENGTH)?;
        let pub_len = key.public_key.len() as u16;
        out.extend_from_slice(&pub_len.to_be_bytes())
            .map_err(|_| SW_WRONG_LENGTH)?;
        out.extend_from_slice(&key.public_key)
            .map_err(|_| SW_WRONG_LENGTH)?;
        out.extend_from_slice(&key.private_key_wrapped)
            .map_err(|_| SW_WRONG_LENGTH)?;
        Ok(out)
    }

    /// Import a key from a wrapped blob (see `wrap_key_for_export` for format).
    pub fn import_wrapped_key(&mut self, wrapped: &[u8], dkek: &DkekState) -> Result<u8, u16> {
        if !dkek.is_ready() {
            return Err(SW_CONDITIONS_NOT_SATISFIED);
        }
        if self.keys.is_full() {
            return Err(SW_FILE_FULL);
        }
        if wrapped.len() < 6 {
            return Err(SW_WRONG_LENGTH);
        }

        let key_type = KeyType::from_u8(wrapped[0])?;
        let original_id = wrapped[1];
        let domain = wrapped[2];
        let label_len = wrapped[3] as usize;

        if wrapped.len() < 4 + label_len + 2 {
            return Err(SW_WRONG_LENGTH);
        }

        let label_data = &wrapped[4..4 + label_len];
        let pub_len_off = 4 + label_len;
        let pub_len = u16::from_be_bytes([wrapped[pub_len_off], wrapped[pub_len_off + 1]]) as usize;
        let pub_off = pub_len_off + 2;

        if wrapped.len() < pub_off + pub_len {
            return Err(SW_WRONG_LENGTH);
        }

        let pub_data = &wrapped[pub_off..pub_off + pub_len];
        let priv_data = &wrapped[pub_off + pub_len..];

        // Validate: try unwrapping to verify integrity
        let mut unwrapped = dkek.unwrap_key(priv_data)?;
        for b in unwrapped.iter_mut() {
            *b = 0;
        }

        let id = if self.keys.iter().any(|k| k.id == original_id) {
            self.allocate_id()?
        } else {
            original_id
        };

        let mut label_vec: Vec<u8, 64> = Vec::new();
        let _ = label_vec.extend_from_slice(label_data);

        let mut pub_key: Vec<u8, 512> = Vec::new();
        pub_key
            .extend_from_slice(pub_data)
            .map_err(|_| SW_WRONG_LENGTH)?;

        let mut priv_wrapped: Vec<u8, 2048> = Vec::new();
        priv_wrapped
            .extend_from_slice(priv_data)
            .map_err(|_| SW_WRONG_LENGTH)?;

        let key = KeyObject {
            id,
            key_type,
            label: label_vec,
            private_key_wrapped: priv_wrapped,
            public_key: pub_key,
            usage_counter: 0,
            usage_limit: None,
            domain,
        };

        self.keys.push(key).map_err(|_| SW_FILE_FULL)?;
        Ok(id)
    }

    /// Increment the usage counter for a key. Returns error if the key's
    /// usage limit has been reached.
    pub fn check_and_increment_usage(&mut self, key_id: u8) -> Result<(), u16> {
        let key = self
            .keys
            .iter_mut()
            .find(|k| k.id == key_id)
            .ok_or(SW_KEY_NOT_FOUND)?;
        if let Some(limit) = key.usage_limit {
            if key.usage_counter >= limit {
                return Err(SW_CONDITIONS_NOT_SATISFIED);
            }
        }
        key.usage_counter += 1;
        Ok(())
    }

    pub fn clear(&mut self) {
        // Zeroize happens on drop for each KeyObject
        self.keys.clear();
        self.next_id = 1;
    }
}

// ---------------------------------------------------------------------------
// Raw key generation helpers
// ---------------------------------------------------------------------------

fn generate_raw_keypair<R: CryptoRng + RngCore>(
    key_type: KeyType,
    rng: &mut R,
) -> Result<(Vec<u8, 2048>, Vec<u8, 512>), u16> {
    match key_type {
        KeyType::EcP256 => generate_ec_p256(rng),
        KeyType::EcP384 => generate_ec_p384(rng),
        KeyType::EcP521 => generate_ec_p521(rng),
        KeyType::EcK256 => generate_ec_k256(rng),
        KeyType::Ed25519 => generate_ed25519(rng),
        KeyType::X25519 => generate_x25519(rng),
        KeyType::Aes128 => generate_symmetric(16, rng),
        KeyType::Aes192 => generate_symmetric(24, rng),
        KeyType::Aes256 => generate_symmetric(32, rng),
        KeyType::Rsa1024 | KeyType::Rsa2048 | KeyType::Rsa3072 | KeyType::Rsa4096 => {
            generate_rsa(key_type, rng)
        }
    }
}

fn generate_ec_p256<R: CryptoRng + RngCore>(
    rng: &mut R,
) -> Result<(Vec<u8, 2048>, Vec<u8, 512>), u16> {
    let keypair = pico_rs_sdk::crypto::ecc::generate_p256(rng).map_err(|_| SW_INVALID_DATA)?;
    let mut priv_raw: Vec<u8, 2048> = Vec::new();
    priv_raw
        .extend_from_slice(&keypair.private_key)
        .map_err(|_| SW_WRONG_LENGTH)?;
    let mut pub_raw: Vec<u8, 512> = Vec::new();
    pub_raw
        .extend_from_slice(&keypair.public_key)
        .map_err(|_| SW_WRONG_LENGTH)?;
    Ok((priv_raw, pub_raw))
}

fn generate_ec_p384<R: CryptoRng + RngCore>(
    rng: &mut R,
) -> Result<(Vec<u8, 2048>, Vec<u8, 512>), u16> {
    use p384::elliptic_curve::sec1::ToEncodedPoint;
    use p384::SecretKey;

    let secret = SecretKey::random(rng);
    let public = secret.public_key();
    let pub_point = public.to_encoded_point(false);

    let mut priv_raw: Vec<u8, 2048> = Vec::new();
    priv_raw
        .extend_from_slice(&secret.to_bytes())
        .map_err(|_| SW_WRONG_LENGTH)?;
    let mut pub_raw: Vec<u8, 512> = Vec::new();
    pub_raw
        .extend_from_slice(pub_point.as_bytes())
        .map_err(|_| SW_WRONG_LENGTH)?;
    Ok((priv_raw, pub_raw))
}

fn generate_ec_p521<R: CryptoRng + RngCore>(
    rng: &mut R,
) -> Result<(Vec<u8, 2048>, Vec<u8, 512>), u16> {
    use p521::elliptic_curve::sec1::ToEncodedPoint;
    use p521::SecretKey;

    let secret = SecretKey::random(rng);
    let public = secret.public_key();
    let pub_point = public.to_encoded_point(false);

    let mut priv_raw: Vec<u8, 2048> = Vec::new();
    priv_raw
        .extend_from_slice(&secret.to_bytes())
        .map_err(|_| SW_WRONG_LENGTH)?;
    let mut pub_raw: Vec<u8, 512> = Vec::new();
    // P-521 uncompressed point = 1 + 66 + 66 = 133 bytes
    pub_raw
        .extend_from_slice(pub_point.as_bytes())
        .map_err(|_| SW_WRONG_LENGTH)?;
    Ok((priv_raw, pub_raw))
}

fn generate_ec_k256<R: CryptoRng + RngCore>(
    rng: &mut R,
) -> Result<(Vec<u8, 2048>, Vec<u8, 512>), u16> {
    let keypair = pico_rs_sdk::crypto::ecc::generate_k256(rng).map_err(|_| SW_INVALID_DATA)?;
    let mut priv_raw: Vec<u8, 2048> = Vec::new();
    priv_raw
        .extend_from_slice(&keypair.private_key)
        .map_err(|_| SW_WRONG_LENGTH)?;
    let mut pub_raw: Vec<u8, 512> = Vec::new();
    pub_raw
        .extend_from_slice(&keypair.public_key)
        .map_err(|_| SW_WRONG_LENGTH)?;
    Ok((priv_raw, pub_raw))
}

fn generate_ed25519<R: CryptoRng + RngCore>(
    rng: &mut R,
) -> Result<(Vec<u8, 2048>, Vec<u8, 512>), u16> {
    let keypair = pico_rs_sdk::crypto::ecc::generate_ed25519(rng).map_err(|_| SW_INVALID_DATA)?;
    let mut priv_raw: Vec<u8, 2048> = Vec::new();
    priv_raw
        .extend_from_slice(&keypair.private_key)
        .map_err(|_| SW_WRONG_LENGTH)?;
    let mut pub_raw: Vec<u8, 512> = Vec::new();
    pub_raw
        .extend_from_slice(&keypair.public_key)
        .map_err(|_| SW_WRONG_LENGTH)?;
    Ok((priv_raw, pub_raw))
}

fn generate_x25519<R: CryptoRng + RngCore>(
    rng: &mut R,
) -> Result<(Vec<u8, 2048>, Vec<u8, 512>), u16> {
    let mut priv_bytes = [0u8; 32];
    rng.fill_bytes(&mut priv_bytes);

    let secret = x25519_dalek::StaticSecret::from(priv_bytes);
    let public = x25519_dalek::PublicKey::from(&secret);

    let mut priv_raw: Vec<u8, 2048> = Vec::new();
    priv_raw
        .extend_from_slice(&priv_bytes)
        .map_err(|_| SW_WRONG_LENGTH)?;
    priv_bytes.zeroize();

    let mut pub_raw: Vec<u8, 512> = Vec::new();
    pub_raw
        .extend_from_slice(public.as_bytes())
        .map_err(|_| SW_WRONG_LENGTH)?;
    Ok((priv_raw, pub_raw))
}

fn generate_symmetric<R: CryptoRng + RngCore>(
    len: usize,
    rng: &mut R,
) -> Result<(Vec<u8, 2048>, Vec<u8, 512>), u16> {
    let mut buf = [0u8; 32];
    rng.fill_bytes(&mut buf[..len]);

    let mut priv_raw: Vec<u8, 2048> = Vec::new();
    priv_raw
        .extend_from_slice(&buf[..len])
        .map_err(|_| SW_WRONG_LENGTH)?;
    buf.zeroize();

    // Symmetric keys have no public component
    let pub_raw: Vec<u8, 512> = Vec::new();
    Ok((priv_raw, pub_raw))
}

fn generate_rsa<R: CryptoRng + RngCore>(
    key_type: KeyType,
    rng: &mut R,
) -> Result<(Vec<u8, 2048>, Vec<u8, 512>), u16> {
    use alloc::vec::Vec as AllocVec;
    use rsa::pkcs1::{EncodeRsaPrivateKey, EncodeRsaPublicKey};
    use rsa::RsaPrivateKey;

    let bits = key_type.rsa_bits().ok_or(SW_INVALID_DATA)?;

    let private_key = RsaPrivateKey::new(rng, bits).map_err(|_| SW_INVALID_DATA)?;
    let public_key = private_key.to_public_key();

    let priv_der = private_key.to_pkcs1_der().map_err(|_| SW_INVALID_DATA)?;
    let pub_der = public_key.to_pkcs1_der().map_err(|_| SW_INVALID_DATA)?;

    let mut priv_raw: Vec<u8, 2048> = Vec::new();
    priv_raw
        .extend_from_slice(priv_der.as_bytes())
        .map_err(|_| SW_WRONG_LENGTH)?;

    let mut pub_raw: Vec<u8, 512> = Vec::new();
    pub_raw
        .extend_from_slice(pub_der.as_bytes())
        .map_err(|_| SW_WRONG_LENGTH)?;

    Ok((priv_raw, pub_raw))
}
