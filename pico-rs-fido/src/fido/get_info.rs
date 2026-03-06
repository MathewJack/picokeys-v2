//! CTAP2.1 authenticatorGetInfo response builder.
//!
//! Encodes the GetInfo response as a hand-built CBOR map so the crate stays
//! independent of any CBOR serialisation library's API.

use super::ctap::CtapError;
use super::FidoConfig;

/// COSE algorithm identifiers for supported public-key types.
const COSE_ALG_ES256: i32 = -7;
const COSE_ALG_EDDSA: i32 = -8;
const COSE_ALG_ES384: i32 = -35;
const COSE_ALG_ES512: i32 = -36;
const COSE_ALG_ES256K: i32 = -47;

/// Complete GetInfo response, ready to be CBOR-encoded.
#[derive(Debug, Clone, defmt::Format)]
pub struct GetInfoResponse {
    pub aaguid: [u8; 16],
    pub client_pin_set: bool,
    pub always_uv: bool,
    pub firmware_version: u32,
}

impl GetInfoResponse {
    /// Build a response from the current authenticator configuration.
    pub fn from_config(cfg: &FidoConfig) -> Self {
        Self {
            aaguid: cfg.aaguid,
            client_pin_set: cfg.client_pin_set,
            always_uv: cfg.always_uv,
            firmware_version: cfg.firmware_version,
        }
    }

    /// Encode the full GetInfo response as a CBOR map into `buf`.
    ///
    /// Returns the number of bytes written, or `CtapError::InvalidLength`
    /// when `buf` is too small (≈300 bytes should always suffice).
    pub fn encode(&self, buf: &mut [u8]) -> Result<usize, CtapError> {
        let mut w = CborWriter::new(buf);

        // Top-level map with 12 entries
        w.write_map_header(12)?;

        // 0x01 — versions
        w.write_uint(0x01)?;
        w.write_array_header(3)?;
        w.write_text("FIDO_2_1")?;
        w.write_text("FIDO_2_0")?;
        w.write_text("U2F_V2")?;

        // 0x02 — extensions
        w.write_uint(0x02)?;
        w.write_array_header(5)?;
        w.write_text("hmac-secret")?;
        w.write_text("credProtect")?;
        w.write_text("credBlob")?;
        w.write_text("largeBlobKey")?;
        w.write_text("minPinLength")?;

        // 0x03 — aaguid (16-byte bstr)
        w.write_uint(0x03)?;
        w.write_bytes(&self.aaguid)?;

        // 0x04 — options map
        w.write_uint(0x04)?;
        w.write_map_header(7)?;
        w.write_text("rk")?;
        w.write_bool(true)?;
        w.write_text("up")?;
        w.write_bool(true)?;
        w.write_text("clientPin")?;
        w.write_bool(self.client_pin_set)?;
        w.write_text("uv")?;
        w.write_bool(false)?;
        w.write_text("credMgmt")?;
        w.write_bool(true)?;
        w.write_text("authnrCfg")?;
        w.write_bool(true)?;
        w.write_text("largeBlobs")?;
        w.write_bool(true)?;

        // 0x05 — maxMsgSize
        w.write_uint(0x05)?;
        w.write_uint(1200)?;

        // 0x06 — pinUvAuthProtocols
        w.write_uint(0x06)?;
        w.write_array_header(2)?;
        w.write_uint(2)?;
        w.write_uint(1)?;

        // 0x07 — maxCredentialCountInList
        w.write_uint(0x07)?;
        w.write_uint(8)?;

        // 0x08 — maxCredentialIdLength
        w.write_uint(0x08)?;
        w.write_uint(128)?;

        // 0x09 — transports
        w.write_uint(0x09)?;
        w.write_array_header(1)?;
        w.write_text("usb")?;

        // 0x0A — algorithms
        w.write_uint(0x0A)?;
        w.write_array_header(5)?;
        Self::write_algorithm_entry(&mut w, COSE_ALG_ES256)?;
        Self::write_algorithm_entry(&mut w, COSE_ALG_ES384)?;
        Self::write_algorithm_entry(&mut w, COSE_ALG_ES512)?;
        Self::write_algorithm_entry(&mut w, COSE_ALG_EDDSA)?;
        Self::write_algorithm_entry(&mut w, COSE_ALG_ES256K)?;

        // 0x0E — firmwareVersion
        w.write_uint(0x0E)?;
        w.write_uint(self.firmware_version as u64)?;

        Ok(w.pos)
    }

    fn write_algorithm_entry(w: &mut CborWriter<'_>, alg: i32) -> Result<(), CtapError> {
        w.write_map_header(2)?;
        w.write_text("type")?;
        w.write_text("public-key")?;
        w.write_text("alg")?;
        w.write_neg_int(alg)?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Minimal CBOR encoder (RFC 8949 subset)
// ---------------------------------------------------------------------------

struct CborWriter<'a> {
    buf: &'a mut [u8],
    pos: usize,
}

impl<'a> CborWriter<'a> {
    fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    fn push(&mut self, byte: u8) -> Result<(), CtapError> {
        if self.remaining() == 0 {
            return Err(CtapError::InvalidLength);
        }
        self.buf[self.pos] = byte;
        self.pos += 1;
        Ok(())
    }

    fn push_slice(&mut self, data: &[u8]) -> Result<(), CtapError> {
        if self.remaining() < data.len() {
            return Err(CtapError::InvalidLength);
        }
        self.buf[self.pos..self.pos + data.len()].copy_from_slice(data);
        self.pos += data.len();
        Ok(())
    }

    /// Encode a CBOR unsigned integer (major type 0).
    fn write_uint(&mut self, value: u64) -> Result<(), CtapError> {
        self.write_type_and_value(0, value)
    }

    /// Encode a CBOR negative integer (major type 1) from a *signed* value.
    /// Only used for negative COSE algorithm IDs (e.g. -7 → CBOR "neg 6").
    fn write_neg_int(&mut self, value: i32) -> Result<(), CtapError> {
        if value >= 0 {
            self.write_uint(value as u64)
        } else {
            let n = (-(value as i64) - 1) as u64;
            self.write_type_and_value(1, n)
        }
    }

    /// Encode a CBOR byte string (major type 2).
    fn write_bytes(&mut self, data: &[u8]) -> Result<(), CtapError> {
        self.write_type_and_value(2, data.len() as u64)?;
        self.push_slice(data)
    }

    /// Encode a CBOR text string (major type 3).
    fn write_text(&mut self, s: &str) -> Result<(), CtapError> {
        self.write_type_and_value(3, s.len() as u64)?;
        self.push_slice(s.as_bytes())
    }

    /// Encode a CBOR array header (major type 4).
    fn write_array_header(&mut self, count: u64) -> Result<(), CtapError> {
        self.write_type_and_value(4, count)
    }

    /// Encode a CBOR map header (major type 5).
    fn write_map_header(&mut self, count: u64) -> Result<(), CtapError> {
        self.write_type_and_value(5, count)
    }

    /// Encode a CBOR boolean (major type 7, simple values).
    fn write_bool(&mut self, value: bool) -> Result<(), CtapError> {
        self.push(if value { 0xf5 } else { 0xf4 })
    }

    /// Write major-type header with argument encoding.
    fn write_type_and_value(&mut self, major: u8, value: u64) -> Result<(), CtapError> {
        let mt = major << 5;
        if value < 24 {
            self.push(mt | value as u8)
        } else if value <= 0xFF {
            self.push(mt | 24)?;
            self.push(value as u8)
        } else if value <= 0xFFFF {
            self.push(mt | 25)?;
            self.push((value >> 8) as u8)?;
            self.push(value as u8)
        } else if value <= 0xFFFF_FFFF {
            self.push(mt | 26)?;
            let bytes = (value as u32).to_be_bytes();
            self.push_slice(&bytes)
        } else {
            self.push(mt | 27)?;
            let bytes = value.to_be_bytes();
            self.push_slice(&bytes)
        }
    }
}
