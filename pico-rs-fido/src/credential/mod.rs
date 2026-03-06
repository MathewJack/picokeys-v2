//! Credential storage for FIDO2 resident keys.
//!
//! Provides encrypted credential storage with AES-256-GCM protection,
//! TLV serialization, and a fixed-capacity credential store.

pub mod id;
pub mod kek;
pub mod backup;

use heapless::{String, Vec};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Maximum number of resident credentials.
pub const MAX_CREDENTIALS: usize = 128;

// TLV tag constants for serialization
const TLV_RP_ID_HASH: u8 = 0x01;
const TLV_CREDENTIAL_ID: u8 = 0x02;
const TLV_USER_ID: u8 = 0x03;
const TLV_USER_NAME: u8 = 0x04;
const TLV_DISPLAY_NAME: u8 = 0x05;
const TLV_PRIVATE_KEY: u8 = 0x06;
const TLV_PUBLIC_KEY_COSE: u8 = 0x07;
const TLV_SIGN_COUNT: u8 = 0x08;
const TLV_CRED_PROTECT: u8 = 0x09;
const TLV_DISCOVERABLE: u8 = 0x0A;
const TLV_HMAC_SECRET: u8 = 0x0B;
const TLV_CRED_BLOB: u8 = 0x0C;
const TLV_LARGE_BLOB_KEY: u8 = 0x0D;

/// Credential error types.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CredentialError {
    StoreFull,
    NotFound,
    EncryptionError,
    SerializationError,
}

/// Wrapper for private key material that zeroizes on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct PrivateKeyMaterial {
    pub bytes: Vec<u8, 66>,
}

impl PrivateKeyMaterial {
    pub fn new() -> Self {
        Self { bytes: Vec::new() }
    }

    pub fn from_slice(data: &[u8]) -> Result<Self, CredentialError> {
        let mut bytes = Vec::new();
        bytes
            .extend_from_slice(data)
            .map_err(|_| CredentialError::SerializationError)?;
        Ok(Self { bytes })
    }
}

impl Default for PrivateKeyMaterial {
    fn default() -> Self {
        Self::new()
    }
}

/// A resident (discoverable) FIDO2 credential.
pub struct ResidentCredential {
    pub rp_id_hash: [u8; 32],
    pub credential_id: Vec<u8, 128>,
    pub user_id: Vec<u8, 64>,
    pub user_name: String<64>,
    pub display_name: String<64>,
    pub private_key: PrivateKeyMaterial,
    pub public_key_cose: Vec<u8, 133>,
    pub sign_count: u32,
    pub cred_protect_level: u8,
    pub discoverable: bool,
    pub hmac_secret: Option<[u8; 64]>,
    pub cred_blob: Option<Vec<u8, 32>>,
    pub large_blob_key: Option<[u8; 32]>,
}

impl Drop for ResidentCredential {
    fn drop(&mut self) {
        // hmac_secret contains key material
        if let Some(ref mut secret) = self.hmac_secret {
            secret.zeroize();
        }
        if let Some(ref mut key) = self.large_blob_key {
            key.zeroize();
        }
    }
}

impl ResidentCredential {
    pub fn new() -> Self {
        Self {
            rp_id_hash: [0u8; 32],
            credential_id: Vec::new(),
            user_id: Vec::new(),
            user_name: String::new(),
            display_name: String::new(),
            private_key: PrivateKeyMaterial::new(),
            public_key_cose: Vec::new(),
            sign_count: 0,
            cred_protect_level: 0,
            discoverable: false,
            hmac_secret: None,
            cred_blob: None,
            large_blob_key: None,
        }
    }

    /// Serialize credential to TLV-encoded byte buffer.
    /// Format: repeated `[tag(1) | length(2 BE) | value(length)]` fields.
    pub fn serialize(&self, buf: &mut [u8]) -> Result<usize, CredentialError> {
        let mut pos = 0;

        pos = tlv_write(buf, pos, TLV_RP_ID_HASH, &self.rp_id_hash)?;
        pos = tlv_write(buf, pos, TLV_CREDENTIAL_ID, &self.credential_id)?;
        pos = tlv_write(buf, pos, TLV_USER_ID, &self.user_id)?;
        pos = tlv_write(buf, pos, TLV_USER_NAME, self.user_name.as_bytes())?;
        pos = tlv_write(buf, pos, TLV_DISPLAY_NAME, self.display_name.as_bytes())?;
        pos = tlv_write(buf, pos, TLV_PRIVATE_KEY, &self.private_key.bytes)?;
        pos = tlv_write(buf, pos, TLV_PUBLIC_KEY_COSE, &self.public_key_cose)?;
        pos = tlv_write(buf, pos, TLV_SIGN_COUNT, &self.sign_count.to_be_bytes())?;
        pos = tlv_write(buf, pos, TLV_CRED_PROTECT, &[self.cred_protect_level])?;
        pos = tlv_write(buf, pos, TLV_DISCOVERABLE, &[self.discoverable as u8])?;

        if let Some(ref secret) = self.hmac_secret {
            pos = tlv_write(buf, pos, TLV_HMAC_SECRET, secret)?;
        }
        if let Some(ref blob) = self.cred_blob {
            pos = tlv_write(buf, pos, TLV_CRED_BLOB, blob)?;
        }
        if let Some(ref key) = self.large_blob_key {
            pos = tlv_write(buf, pos, TLV_LARGE_BLOB_KEY, key)?;
        }

        Ok(pos)
    }

    /// Deserialize credential from TLV-encoded bytes.
    pub fn deserialize(data: &[u8]) -> Result<Self, CredentialError> {
        let mut cred = Self::new();
        let mut pos = 0;

        while pos < data.len() {
            let (tag, value, next) = tlv_read(data, pos)?;
            match tag {
                TLV_RP_ID_HASH => {
                    if value.len() != 32 {
                        return Err(CredentialError::SerializationError);
                    }
                    cred.rp_id_hash.copy_from_slice(value);
                }
                TLV_CREDENTIAL_ID => {
                    cred.credential_id = Vec::new();
                    cred.credential_id
                        .extend_from_slice(value)
                        .map_err(|_| CredentialError::SerializationError)?;
                }
                TLV_USER_ID => {
                    cred.user_id = Vec::new();
                    cred.user_id
                        .extend_from_slice(value)
                        .map_err(|_| CredentialError::SerializationError)?;
                }
                TLV_USER_NAME => {
                    let s = core::str::from_utf8(value)
                        .map_err(|_| CredentialError::SerializationError)?;
                    cred.user_name = String::new();
                    cred.user_name
                        .push_str(s)
                        .map_err(|_| CredentialError::SerializationError)?;
                }
                TLV_DISPLAY_NAME => {
                    let s = core::str::from_utf8(value)
                        .map_err(|_| CredentialError::SerializationError)?;
                    cred.display_name = String::new();
                    cred.display_name
                        .push_str(s)
                        .map_err(|_| CredentialError::SerializationError)?;
                }
                TLV_PRIVATE_KEY => {
                    cred.private_key = PrivateKeyMaterial::from_slice(value)?;
                }
                TLV_PUBLIC_KEY_COSE => {
                    cred.public_key_cose = Vec::new();
                    cred.public_key_cose
                        .extend_from_slice(value)
                        .map_err(|_| CredentialError::SerializationError)?;
                }
                TLV_SIGN_COUNT => {
                    if value.len() != 4 {
                        return Err(CredentialError::SerializationError);
                    }
                    cred.sign_count = u32::from_be_bytes([value[0], value[1], value[2], value[3]]);
                }
                TLV_CRED_PROTECT => {
                    if value.is_empty() {
                        return Err(CredentialError::SerializationError);
                    }
                    cred.cred_protect_level = value[0];
                }
                TLV_DISCOVERABLE => {
                    if value.is_empty() {
                        return Err(CredentialError::SerializationError);
                    }
                    cred.discoverable = value[0] != 0;
                }
                TLV_HMAC_SECRET => {
                    if value.len() != 64 {
                        return Err(CredentialError::SerializationError);
                    }
                    let mut secret = [0u8; 64];
                    secret.copy_from_slice(value);
                    cred.hmac_secret = Some(secret);
                }
                TLV_CRED_BLOB => {
                    let mut blob = Vec::new();
                    blob.extend_from_slice(value)
                        .map_err(|_| CredentialError::SerializationError)?;
                    cred.cred_blob = Some(blob);
                }
                TLV_LARGE_BLOB_KEY => {
                    if value.len() != 32 {
                        return Err(CredentialError::SerializationError);
                    }
                    let mut key = [0u8; 32];
                    key.copy_from_slice(value);
                    cred.large_blob_key = Some(key);
                }
                _ => {
                    // Skip unknown tags for forward compatibility
                }
            }
            pos = next;
        }

        Ok(cred)
    }
}

impl Default for ResidentCredential {
    fn default() -> Self {
        Self::new()
    }
}

/// Write a single TLV field: tag(1) | length(2 BE) | value.
fn tlv_write(buf: &mut [u8], pos: usize, tag: u8, value: &[u8]) -> Result<usize, CredentialError> {
    let needed = 1 + 2 + value.len();
    if pos + needed > buf.len() {
        return Err(CredentialError::SerializationError);
    }
    buf[pos] = tag;
    let len = value.len() as u16;
    buf[pos + 1] = (len >> 8) as u8;
    buf[pos + 2] = (len & 0xFF) as u8;
    buf[pos + 3..pos + 3 + value.len()].copy_from_slice(value);
    Ok(pos + needed)
}

/// Read a single TLV field. Returns (tag, value_slice, next_position).
fn tlv_read(data: &[u8], pos: usize) -> Result<(u8, &[u8], usize), CredentialError> {
    if pos + 3 > data.len() {
        return Err(CredentialError::SerializationError);
    }
    let tag = data[pos];
    let len = ((data[pos + 1] as usize) << 8) | (data[pos + 2] as usize);
    let value_start = pos + 3;
    let value_end = value_start + len;
    if value_end > data.len() {
        return Err(CredentialError::SerializationError);
    }
    Ok((tag, &data[value_start..value_end], value_end))
}

/// Fixed-capacity store for resident credentials.
pub struct CredentialStore {
    slots: [Option<ResidentCredential>; MAX_CREDENTIALS],
}

impl CredentialStore {
    pub fn new() -> Self {
        // Initialize all slots to None using array::from_fn
        Self {
            slots: core::array::from_fn(|_| None),
        }
    }

    /// Store a credential in the next available slot. Returns slot index.
    pub fn store_credential(&mut self, cred: &ResidentCredential) -> Result<u8, CredentialError> {
        // Check if a credential with same rp_id_hash + user_id exists (update in place)
        for i in 0..MAX_CREDENTIALS {
            if let Some(ref existing) = self.slots[i] {
                if existing.rp_id_hash == cred.rp_id_hash
                    && existing.user_id.as_slice() == cred.user_id.as_slice()
                {
                    self.slots[i] = Some(clone_credential(cred)?);
                    return Ok(i as u8);
                }
            }
        }

        // Find first empty slot
        for i in 0..MAX_CREDENTIALS {
            if self.slots[i].is_none() {
                self.slots[i] = Some(clone_credential(cred)?);
                return Ok(i as u8);
            }
        }

        Err(CredentialError::StoreFull)
    }

    /// Find all slot indices matching a given RP ID hash.
    pub fn find_by_rp_id(&self, rp_id_hash: &[u8; 32]) -> Vec<u8, 128> {
        let mut result = Vec::new();
        for i in 0..MAX_CREDENTIALS {
            if let Some(ref cred) = self.slots[i] {
                if cred.rp_id_hash == *rp_id_hash {
                    let _ = result.push(i as u8);
                }
            }
        }
        result
    }

    /// Find a slot index by credential ID.
    pub fn find_by_credential_id(&self, cred_id: &[u8]) -> Option<u8> {
        for i in 0..MAX_CREDENTIALS {
            if let Some(ref cred) = self.slots[i] {
                if cred.credential_id.as_slice() == cred_id {
                    return Some(i as u8);
                }
            }
        }
        None
    }

    /// Get a reference to a credential by slot index.
    pub fn get_credential(&self, slot: u8) -> Option<&ResidentCredential> {
        let idx = slot as usize;
        if idx >= MAX_CREDENTIALS {
            return None;
        }
        self.slots[idx].as_ref()
    }

    /// Get a mutable reference to a credential by slot index.
    pub fn get_credential_mut(&mut self, slot: u8) -> Option<&mut ResidentCredential> {
        let idx = slot as usize;
        if idx >= MAX_CREDENTIALS {
            return None;
        }
        self.slots[idx].as_mut()
    }

    /// Delete a credential by slot index.
    pub fn delete_credential(&mut self, slot: u8) -> Result<(), CredentialError> {
        let idx = slot as usize;
        if idx >= MAX_CREDENTIALS {
            return Err(CredentialError::NotFound);
        }
        if self.slots[idx].is_none() {
            return Err(CredentialError::NotFound);
        }
        self.slots[idx] = None;
        Ok(())
    }

    /// Number of occupied credential slots.
    pub fn count(&self) -> usize {
        self.slots.iter().filter(|s| s.is_some()).count()
    }

    /// Maximum capacity.
    pub fn max_capacity(&self) -> usize {
        MAX_CREDENTIALS
    }

    /// Enumerate unique RP ID hashes across all stored credentials.
    pub fn enumerate_rp_ids(&self) -> Vec<[u8; 32], 64> {
        let mut rp_ids: Vec<[u8; 32], 64> = Vec::new();
        for slot in &self.slots {
            if let Some(ref cred) = slot {
                let already_present = rp_ids.iter().any(|id| *id == cred.rp_id_hash);
                if !already_present {
                    let _ = rp_ids.push(cred.rp_id_hash);
                }
            }
        }
        rp_ids
    }
}

impl Default for CredentialStore {
    fn default() -> Self {
        Self::new()
    }
}

/// Clone a credential (deep copy). Private key material is copied carefully.
fn clone_credential(src: &ResidentCredential) -> Result<ResidentCredential, CredentialError> {
    let mut cred = ResidentCredential::new();
    cred.rp_id_hash = src.rp_id_hash;

    cred.credential_id
        .extend_from_slice(&src.credential_id)
        .map_err(|_| CredentialError::SerializationError)?;
    cred.user_id
        .extend_from_slice(&src.user_id)
        .map_err(|_| CredentialError::SerializationError)?;
    cred.user_name
        .push_str(src.user_name.as_str())
        .map_err(|_| CredentialError::SerializationError)?;
    cred.display_name
        .push_str(src.display_name.as_str())
        .map_err(|_| CredentialError::SerializationError)?;
    cred.private_key = PrivateKeyMaterial::from_slice(&src.private_key.bytes)?;
    cred.public_key_cose
        .extend_from_slice(&src.public_key_cose)
        .map_err(|_| CredentialError::SerializationError)?;
    cred.sign_count = src.sign_count;
    cred.cred_protect_level = src.cred_protect_level;
    cred.discoverable = src.discoverable;
    cred.hmac_secret = src.hmac_secret;

    if let Some(ref blob) = src.cred_blob {
        let mut new_blob = Vec::new();
        new_blob
            .extend_from_slice(blob)
            .map_err(|_| CredentialError::SerializationError)?;
        cred.cred_blob = Some(new_blob);
    }
    cred.large_blob_key = src.large_blob_key;

    Ok(cred)
}
