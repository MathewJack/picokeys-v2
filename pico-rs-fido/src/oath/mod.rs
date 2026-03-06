//! YKOATH (OATH TOTP/HOTP) application for PicoKeys v2.
//!
//! Implements the YKOATH protocol for managing TOTP and HOTP credentials,
//! compatible with the Yubico Authenticator app.

pub mod hotp;
pub mod totp;
pub mod yubikey_otp;

use heapless::{String, Vec};

/// OATH application AID (Yubico OATH applet).
pub const OATH_AID: [u8; 7] = [0xA0, 0x00, 0x00, 0x05, 0x27, 0x21, 0x01];

/// Maximum number of OATH credentials.
pub const MAX_CREDENTIALS: usize = 32;

// YKOATH INS codes
pub const INS_PUT: u8 = 0x01;
pub const INS_DELETE: u8 = 0x02;
pub const INS_SET_CODE: u8 = 0x03;
pub const INS_RESET: u8 = 0x04;
pub const INS_RENAME: u8 = 0x05;
pub const INS_LIST: u8 = 0xA1;
pub const INS_CALCULATE: u8 = 0xA2;
pub const INS_CALCULATE_ALL: u8 = 0xA4;

// TLV tags for YKOATH protocol
const TAG_NAME: u8 = 0x71;
const TAG_NAME_LIST: u8 = 0x72;
const TAG_KEY: u8 = 0x73;
const TAG_CHALLENGE: u8 = 0x74;
#[allow(dead_code)]
const TAG_RESPONSE: u8 = 0x75;
const TAG_TRUNCATED: u8 = 0x76;
const TAG_PROPERTY: u8 = 0x78;
const TAG_IMF: u8 = 0x7A;
const TAG_TOUCH_RESPONSE: u8 = 0x7C;

// Property bits
const PROP_REQUIRE_TOUCH: u8 = 0x02;

/// OTP type identifier (encoded in upper nibble of type/algorithm byte).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum OathType {
    Hotp = 0x10,
    Totp = 0x20,
}

impl OathType {
    pub fn from_byte(b: u8) -> Option<Self> {
        match b & 0xF0 {
            0x10 => Some(OathType::Hotp),
            0x20 => Some(OathType::Totp),
            _ => None,
        }
    }
}

/// Hash algorithm for OATH (encoded in lower nibble of type/algorithm byte).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum OathAlgorithm {
    Sha1 = 0x01,
    Sha256 = 0x02,
    Sha512 = 0x03,
}

impl OathAlgorithm {
    pub fn from_byte(b: u8) -> Option<Self> {
        match b & 0x0F {
            0x01 => Some(OathAlgorithm::Sha1),
            0x02 => Some(OathAlgorithm::Sha256),
            0x03 => Some(OathAlgorithm::Sha512),
            _ => None,
        }
    }
}

/// A single OATH credential.
pub struct OathCredential {
    pub name: String<64>,
    pub secret: Vec<u8, 64>,
    pub oath_type: OathType,
    pub digits: u8,
    pub period: u32,
    pub algorithm: OathAlgorithm,
    /// Moving counter (HOTP only; TOTP derives counter from time).
    pub counter: u64,
    pub touch_required: bool,
}

impl OathCredential {
    pub fn new() -> Self {
        Self {
            name: String::new(),
            secret: Vec::new(),
            oath_type: OathType::Totp,
            digits: 6,
            period: 30,
            algorithm: OathAlgorithm::Sha1,
            counter: 0,
            touch_required: false,
        }
    }
}

impl Default for OathCredential {
    fn default() -> Self {
        Self::new()
    }
}

/// OATH application managing up to [`MAX_CREDENTIALS`] credentials.
pub struct OathApp {
    credentials: [Option<OathCredential>; MAX_CREDENTIALS],
    /// Optional access code (16-byte key derived from password via PBKDF2).
    access_key: Option<[u8; 16]>,
}

impl OathApp {
    pub fn new() -> Self {
        Self {
            credentials: core::array::from_fn(|_| None),
            access_key: None,
        }
    }

    /// Process an incoming OATH APDU. Returns bytes written to `response` or a SW error code.
    pub fn process_oath_apdu(
        &mut self,
        ins: u8,
        _p1: u8,
        _p2: u8,
        data: &[u8],
        response: &mut [u8],
    ) -> Result<usize, u16> {
        match ins {
            INS_PUT => self.cmd_put(data),
            INS_DELETE => self.cmd_delete(data),
            INS_LIST => self.cmd_list(response),
            INS_CALCULATE => self.cmd_calculate(data, response),
            INS_CALCULATE_ALL => self.cmd_calculate_all(data, response),
            INS_SET_CODE => self.cmd_set_code(data),
            INS_RESET => self.cmd_reset(),
            INS_RENAME => self.cmd_rename(data),
            _ => Err(0x6D00), // INS not supported
        }
    }

    /// PUT — register or update a credential.
    fn cmd_put(&mut self, data: &[u8]) -> Result<usize, u16> {
        let mut pos = 0;

        // Parse NAME tag
        if data.get(pos) != Some(&TAG_NAME) {
            return Err(SW_WRONG_DATA);
        }
        pos += 1;
        let name_len = *data.get(pos).ok_or(SW_WRONG_DATA)? as usize;
        pos += 1;
        if pos + name_len > data.len() {
            return Err(SW_WRONG_DATA);
        }
        let name_str =
            core::str::from_utf8(&data[pos..pos + name_len]).map_err(|_| SW_WRONG_DATA)?;
        pos += name_len;

        // Parse KEY tag
        if data.get(pos) != Some(&TAG_KEY) {
            return Err(SW_WRONG_DATA);
        }
        pos += 1;
        let key_len = *data.get(pos).ok_or(SW_WRONG_DATA)? as usize;
        pos += 1;
        if key_len < 2 || pos + key_len > data.len() {
            return Err(SW_WRONG_DATA);
        }
        let type_alg_byte = data[pos];
        let digits = data[pos + 1];
        let secret = &data[pos + 2..pos + key_len];
        pos += key_len;

        let oath_type = OathType::from_byte(type_alg_byte).ok_or(SW_WRONG_DATA)?;
        let algorithm = OathAlgorithm::from_byte(type_alg_byte).ok_or(SW_WRONG_DATA)?;

        // Parse optional PROPERTY tag
        let mut touch_required = false;
        if pos < data.len() && data[pos] == TAG_PROPERTY {
            pos += 1;
            let prop_val = *data.get(pos).ok_or(SW_WRONG_DATA)?;
            touch_required = (prop_val & PROP_REQUIRE_TOUCH) != 0;
            pos += 1;
        }

        // Parse optional IMF (Initial Moving Factor) for HOTP
        let mut counter: u64 = 0;
        if pos + 1 < data.len() && data[pos] == TAG_IMF {
            pos += 1;
            let imf_len = *data.get(pos).ok_or(SW_WRONG_DATA)? as usize;
            pos += 1;
            if imf_len == 4 && pos + 4 <= data.len() {
                counter =
                    u32::from_be_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]])
                        as u64;
            }
        }

        let mut cred = OathCredential::new();
        cred.name.push_str(name_str).map_err(|_| SW_WRONG_DATA)?;
        cred.secret
            .extend_from_slice(secret)
            .map_err(|_| SW_WRONG_DATA)?;
        cred.oath_type = oath_type;
        cred.digits = digits;
        cred.algorithm = algorithm;
        cred.touch_required = touch_required;
        cred.counter = counter;
        cred.period = 30;

        // Replace existing credential with same name
        for slot in self.credentials.iter_mut() {
            if let Some(ref existing) = slot {
                if existing.name == cred.name {
                    *slot = Some(cred);
                    return Ok(0);
                }
            }
        }

        // Find first empty slot
        for slot in self.credentials.iter_mut() {
            if slot.is_none() {
                *slot = Some(cred);
                return Ok(0);
            }
        }

        Err(SW_MEMORY_FULL)
    }

    /// DELETE — remove a credential by name.
    fn cmd_delete(&mut self, data: &[u8]) -> Result<usize, u16> {
        let name = parse_name_tag(data)?;

        for slot in self.credentials.iter_mut() {
            if let Some(ref existing) = slot {
                if existing.name.as_str() == name {
                    *slot = None;
                    return Ok(0);
                }
            }
        }

        Err(SW_DATA_NOT_FOUND)
    }

    /// LIST — enumerate all stored credential names and types.
    fn cmd_list(&self, response: &mut [u8]) -> Result<usize, u16> {
        let mut pos = 0;

        for slot in &self.credentials {
            if let Some(ref cred) = slot {
                let name_bytes = cred.name.as_bytes();
                // TAG_NAME_LIST(1) + length(1) + type_alg(1) + name_bytes
                let entry_len = 3 + name_bytes.len();
                if pos + entry_len > response.len() {
                    break;
                }
                response[pos] = TAG_NAME_LIST;
                response[pos + 1] = (1 + name_bytes.len()) as u8;
                response[pos + 2] = (cred.oath_type as u8) | (cred.algorithm as u8);
                response[pos + 3..pos + 3 + name_bytes.len()].copy_from_slice(name_bytes);
                pos += 3 + name_bytes.len();
            }
        }

        Ok(pos)
    }

    /// CALCULATE — compute OTP for a single credential.
    fn cmd_calculate(&mut self, data: &[u8], response: &mut [u8]) -> Result<usize, u16> {
        let mut dpos = 0;
        let name = parse_name_tag_at(data, &mut dpos)?;
        let challenge = parse_challenge_tag_at(data, &mut dpos)?;

        // Find credential index
        let cred_idx = self
            .credentials
            .iter()
            .position(|slot| slot.as_ref().map_or(false, |c| c.name.as_str() == name))
            .ok_or(SW_DATA_NOT_FOUND)?;

        let cred = self.credentials[cred_idx].as_mut().unwrap();

        let code = match cred.oath_type {
            OathType::Totp => {
                let time = bytes_to_u64(challenge);
                totp::generate_totp(&cred.secret, time, cred.period, cred.digits, cred.algorithm)
            }
            OathType::Hotp => {
                let c =
                    hotp::generate_hotp(&cred.secret, cred.counter, cred.digits, cred.algorithm);
                cred.counter += 1;
                c
            }
        };

        // TAG_TRUNCATED(1) + len(1) + digits(1) + code(4)
        if response.len() < 7 {
            return Err(SW_CONDITIONS_NOT_SATISFIED);
        }
        response[0] = TAG_TRUNCATED;
        response[1] = 5;
        response[2] = cred.digits;
        response[3..7].copy_from_slice(&code.to_be_bytes());

        Ok(7)
    }

    /// CALCULATE ALL — compute OTPs for every credential.
    fn cmd_calculate_all(&mut self, data: &[u8], response: &mut [u8]) -> Result<usize, u16> {
        let mut dpos = 0;
        let challenge = parse_challenge_tag_at(data, &mut dpos)?;
        let time = bytes_to_u64(challenge);

        let mut rpos = 0;

        for slot in self.credentials.iter_mut() {
            if let Some(ref mut cred) = slot {
                let name_bytes = cred.name.as_bytes();
                // Name TLV: tag(1) + len(1) + name
                let name_tlv_len = 2 + name_bytes.len();

                if cred.touch_required {
                    // Touch-required: TAG_TOUCH_RESPONSE(1) + len(1) + digits(1)
                    if rpos + name_tlv_len + 3 > response.len() {
                        break;
                    }
                    response[rpos] = TAG_NAME;
                    response[rpos + 1] = name_bytes.len() as u8;
                    response[rpos + 2..rpos + 2 + name_bytes.len()].copy_from_slice(name_bytes);
                    rpos += 2 + name_bytes.len();

                    response[rpos] = TAG_TOUCH_RESPONSE;
                    response[rpos + 1] = 1;
                    response[rpos + 2] = cred.digits;
                    rpos += 3;
                } else {
                    // Code TLV: TAG_TRUNCATED(1) + len(1) + digits(1) + code(4)
                    if rpos + name_tlv_len + 7 > response.len() {
                        break;
                    }
                    response[rpos] = TAG_NAME;
                    response[rpos + 1] = name_bytes.len() as u8;
                    response[rpos + 2..rpos + 2 + name_bytes.len()].copy_from_slice(name_bytes);
                    rpos += 2 + name_bytes.len();

                    let code = match cred.oath_type {
                        OathType::Totp => totp::generate_totp(
                            &cred.secret,
                            time,
                            cred.period,
                            cred.digits,
                            cred.algorithm,
                        ),
                        OathType::Hotp => {
                            let c = hotp::generate_hotp(
                                &cred.secret,
                                cred.counter,
                                cred.digits,
                                cred.algorithm,
                            );
                            cred.counter += 1;
                            c
                        }
                    };

                    response[rpos] = TAG_TRUNCATED;
                    response[rpos + 1] = 5;
                    response[rpos + 2] = cred.digits;
                    response[rpos + 3..rpos + 7].copy_from_slice(&code.to_be_bytes());
                    rpos += 7;
                }
            }
        }

        Ok(rpos)
    }

    /// SET CODE — set or clear the OATH access code.
    fn cmd_set_code(&mut self, data: &[u8]) -> Result<usize, u16> {
        if data.is_empty() {
            self.access_key = None;
            return Ok(0);
        }

        let mut pos = 0;
        if data.get(pos) != Some(&TAG_KEY) {
            return Err(SW_WRONG_DATA);
        }
        pos += 1;
        let key_len = *data.get(pos).ok_or(SW_WRONG_DATA)? as usize;
        pos += 1;
        if key_len < 1 || pos + key_len > data.len() {
            return Err(SW_WRONG_DATA);
        }
        // First byte is type_alg, rest is key material
        let key_data = &data[pos + 1..pos + key_len];
        pos += key_len;

        // Skip optional CHALLENGE + RESPONSE validation
        if pos < data.len() && data[pos] == TAG_CHALLENGE {
            pos += 1;
            let chal_len = *data.get(pos).ok_or(SW_WRONG_DATA)? as usize;
            pos += 1 + chal_len;
        }
        let _ = pos;

        if key_data.len() >= 16 {
            let mut key = [0u8; 16];
            key.copy_from_slice(&key_data[..16]);
            self.access_key = Some(key);
        } else {
            self.access_key = None;
        }

        Ok(0)
    }

    /// RESET — factory reset: delete all credentials and access code.
    fn cmd_reset(&mut self) -> Result<usize, u16> {
        for slot in self.credentials.iter_mut() {
            *slot = None;
        }
        self.access_key = None;
        Ok(0)
    }

    /// RENAME — change the name of an existing credential.
    fn cmd_rename(&mut self, data: &[u8]) -> Result<usize, u16> {
        let mut pos = 0;
        let old_name = parse_name_tag_at(data, &mut pos)?;
        let new_name = parse_name_tag_at(data, &mut pos)?;

        // Reject if new name already exists
        for slot in self.credentials.iter() {
            if let Some(ref cred) = slot {
                if cred.name.as_str() == new_name {
                    return Err(SW_CONDITIONS_NOT_SATISFIED);
                }
            }
        }

        // Find and rename
        for slot in self.credentials.iter_mut() {
            if let Some(ref mut cred) = slot {
                if cred.name.as_str() == old_name {
                    cred.name.clear();
                    cred.name.push_str(new_name).map_err(|_| SW_WRONG_DATA)?;
                    return Ok(0);
                }
            }
        }

        Err(SW_DATA_NOT_FOUND)
    }

    /// Number of occupied credential slots.
    pub fn credential_count(&self) -> usize {
        self.credentials.iter().filter(|s| s.is_some()).count()
    }
}

impl Default for OathApp {
    fn default() -> Self {
        Self::new()
    }
}

// --- SW status words ---

const SW_WRONG_DATA: u16 = 0x6A80;
const SW_DATA_NOT_FOUND: u16 = 0x6A82;
const SW_MEMORY_FULL: u16 = 0x6A84;
const SW_CONDITIONS_NOT_SATISFIED: u16 = 0x6985;

// --- TLV parsing helpers ---

/// Parse a NAME TLV from the start of `data`.
fn parse_name_tag(data: &[u8]) -> Result<&str, u16> {
    if data.len() < 2 || data[0] != TAG_NAME {
        return Err(SW_WRONG_DATA);
    }
    let len = data[1] as usize;
    if 2 + len > data.len() {
        return Err(SW_WRONG_DATA);
    }
    core::str::from_utf8(&data[2..2 + len]).map_err(|_| SW_WRONG_DATA)
}

/// Parse a NAME TLV at `*pos`, advancing `*pos` past it.
fn parse_name_tag_at<'a>(data: &'a [u8], pos: &mut usize) -> Result<&'a str, u16> {
    if data.get(*pos) != Some(&TAG_NAME) {
        return Err(SW_WRONG_DATA);
    }
    *pos += 1;
    let len = *data.get(*pos).ok_or(SW_WRONG_DATA)? as usize;
    *pos += 1;
    if *pos + len > data.len() {
        return Err(SW_WRONG_DATA);
    }
    let name = core::str::from_utf8(&data[*pos..*pos + len]).map_err(|_| SW_WRONG_DATA)?;
    *pos += len;
    Ok(name)
}

/// Parse a CHALLENGE TLV at `*pos`, advancing `*pos` past it.
fn parse_challenge_tag_at<'a>(data: &'a [u8], pos: &mut usize) -> Result<&'a [u8], u16> {
    if data.get(*pos) != Some(&TAG_CHALLENGE) {
        return Err(SW_WRONG_DATA);
    }
    *pos += 1;
    let len = *data.get(*pos).ok_or(SW_WRONG_DATA)? as usize;
    *pos += 1;
    if *pos + len > data.len() {
        return Err(SW_WRONG_DATA);
    }
    let challenge = &data[*pos..*pos + len];
    *pos += len;
    Ok(challenge)
}

/// Convert a big-endian byte slice (up to 8 bytes) to `u64`.
fn bytes_to_u64(data: &[u8]) -> u64 {
    let mut buf = [0u8; 8];
    let start = 8usize.saturating_sub(data.len());
    let copy_len = data.len().min(8);
    buf[start..start + copy_len].copy_from_slice(&data[..copy_len]);
    u64::from_be_bytes(buf)
}
