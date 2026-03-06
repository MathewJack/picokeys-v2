//! File identifier type for the key-value store.
//!
//! Each [`FileId`] variant maps to a unique 2-byte key used internally by
//! `sequential-storage`. Parameterised variants (e.g. [`FileId::ResidentKey`])
//! encode the slot index in the second byte.

use sequential_storage::map::{Key, SerializationError};

/// Identifies a stored file / data blob.
///
/// Numeric tag values are chosen to be compatible with the pico-keys-sdk
/// file ID space while leaving room for future additions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, defmt::Format)]
pub enum FileId {
    /// FIDO2 Authenticator Attestation GUID (16 bytes).
    Aaguid,
    /// Master Key Encryption Key — wraps all credential secrets.
    Mkek,
    /// General device configuration blob.
    Config,
    /// PIN retry counter (persisted across resets).
    PinRetryCount,
    /// X.509 attestation certificate (DER).
    AttestationCert,
    /// FIDO2 discoverable (resident) credential, indexed 0–255.
    ResidentKey(u8),
    /// OATH TOTP / HOTP credential, indexed 0–255.
    OathCredential(u8),
    /// OTP secret slot, indexed 0–255.
    OtpSlot(u8),
}

// ---------------------------------------------------------------------------
// Tag constants used for on-flash serialisation (1 byte tag + 1 byte param).
// ---------------------------------------------------------------------------
const TAG_AAGUID: u8 = 0x01;
const TAG_MKEK: u8 = 0x02;
const TAG_CONFIG: u8 = 0x03;
const TAG_PIN_RETRY: u8 = 0x04;
const TAG_ATTEST_CERT: u8 = 0x05;
const TAG_RESIDENT_KEY: u8 = 0x10;
const TAG_OATH_CRED: u8 = 0x20;
const TAG_OTP_SLOT: u8 = 0x30;

/// Serialised key length (tag + parameter).
const KEY_LEN: usize = 2;

impl Key for FileId {
    fn serialize_into(&self, buffer: &mut [u8]) -> Result<usize, SerializationError> {
        if buffer.len() < KEY_LEN {
            return Err(SerializationError::BufferTooSmall);
        }
        let (tag, param) = match *self {
            Self::Aaguid => (TAG_AAGUID, 0),
            Self::Mkek => (TAG_MKEK, 0),
            Self::Config => (TAG_CONFIG, 0),
            Self::PinRetryCount => (TAG_PIN_RETRY, 0),
            Self::AttestationCert => (TAG_ATTEST_CERT, 0),
            Self::ResidentKey(n) => (TAG_RESIDENT_KEY, n),
            Self::OathCredential(n) => (TAG_OATH_CRED, n),
            Self::OtpSlot(n) => (TAG_OTP_SLOT, n),
        };
        buffer[0] = tag;
        buffer[1] = param;
        Ok(KEY_LEN)
    }

    fn deserialize_from(buffer: &[u8]) -> Result<(Self, usize), SerializationError> {
        if buffer.len() < KEY_LEN {
            return Err(SerializationError::BufferTooSmall);
        }
        let tag = buffer[0];
        let param = buffer[1];
        let fid = match tag {
            TAG_AAGUID => Self::Aaguid,
            TAG_MKEK => Self::Mkek,
            TAG_CONFIG => Self::Config,
            TAG_PIN_RETRY => Self::PinRetryCount,
            TAG_ATTEST_CERT => Self::AttestationCert,
            TAG_RESIDENT_KEY => Self::ResidentKey(param),
            TAG_OATH_CRED => Self::OathCredential(param),
            TAG_OTP_SLOT => Self::OtpSlot(param),
            _ => return Err(SerializationError::InvalidData),
        };
        Ok((fid, KEY_LEN))
    }

    fn get_len(buffer: &[u8]) -> Result<usize, SerializationError> {
        if buffer.len() < KEY_LEN {
            return Err(SerializationError::BufferTooSmall);
        }
        Ok(KEY_LEN)
    }
}
