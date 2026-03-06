//! Minimal CBOR encoder and decoder for CTAP2 protocol messages.
//!
//! Implements the subset of RFC 8949 required by FIDO2/CTAP2:
//! major types 0–5 (unsigned, negative, bytes, text, array, map)
//! plus simple values (bool) from major type 7.

use super::ctap::CtapError;

// ---------------------------------------------------------------------------
// Encoder
// ---------------------------------------------------------------------------

/// Streaming CBOR encoder that writes directly into a byte buffer.
pub struct CborEncoder<'a> {
    buf: &'a mut [u8],
    pos: usize,
}

impl<'a> CborEncoder<'a> {
    pub fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    pub fn position(&self) -> usize {
        self.pos
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
            self.push_slice(&(value as u32).to_be_bytes())
        } else {
            self.push(mt | 27)?;
            self.push_slice(&value.to_be_bytes())
        }
    }

    /// Encode unsigned integer (major type 0).
    pub fn write_unsigned(&mut self, value: usize) -> Result<(), CtapError> {
        self.write_type_and_value(0, value as u64)
    }

    /// Encode a CBOR integer that may be negative.
    /// For COSE algorithm IDs: negative values use major type 1.
    pub fn write_negative(&mut self, value: i32) -> Result<(), CtapError> {
        if value >= 0 {
            self.write_type_and_value(0, value as u64)
        } else {
            let n = (-(value as i64) - 1) as u64;
            self.write_type_and_value(1, n)
        }
    }

    /// Encode byte string (major type 2).
    pub fn write_bytes(&mut self, data: &[u8]) -> Result<(), CtapError> {
        self.write_type_and_value(2, data.len() as u64)?;
        self.push_slice(data)
    }

    /// Encode text string (major type 3).
    pub fn write_text(&mut self, s: &str) -> Result<(), CtapError> {
        self.write_type_and_value(3, s.len() as u64)?;
        self.push_slice(s.as_bytes())
    }

    /// Encode array header (major type 4).
    pub fn write_array_header(&mut self, count: usize) -> Result<(), CtapError> {
        self.write_type_and_value(4, count as u64)
    }

    /// Encode map header (major type 5).
    pub fn write_map_header(&mut self, count: usize) -> Result<(), CtapError> {
        self.write_type_and_value(5, count as u64)
    }

    /// Encode boolean (major type 7 simple values).
    pub fn write_bool(&mut self, value: bool) -> Result<(), CtapError> {
        self.push(if value { 0xF5 } else { 0xF4 })
    }

    /// Write raw bytes directly (for pre-encoded CBOR data).
    pub fn write_raw(&mut self, data: &[u8]) -> Result<(), CtapError> {
        self.push_slice(data)
    }
}

// ---------------------------------------------------------------------------
// Decoder
// ---------------------------------------------------------------------------

/// Position-tracking CBOR decoder over an immutable byte slice.
pub struct CborDecoder<'a> {
    data: &'a [u8],
    pos: usize,
}

/// A decoded CBOR value reference (zero-copy for bytes/text).
#[derive(Debug, Clone, Copy)]
pub enum CborValue<'a> {
    Unsigned(u64),
    Negative(i64),
    Bytes(&'a [u8]),
    Text(&'a str),
    Array(usize),
    Map(usize),
    Bool(bool),
    Null,
    Undefined,
}

impl<'a> CborDecoder<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    pub fn position(&self) -> usize {
        self.pos
    }

    pub fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    pub fn is_empty(&self) -> bool {
        self.pos >= self.data.len()
    }

    fn peek(&self) -> Result<u8, CtapError> {
        if self.pos >= self.data.len() {
            return Err(CtapError::InvalidLength);
        }
        Ok(self.data[self.pos])
    }

    fn read_byte(&mut self) -> Result<u8, CtapError> {
        if self.pos >= self.data.len() {
            return Err(CtapError::InvalidLength);
        }
        let b = self.data[self.pos];
        self.pos += 1;
        Ok(b)
    }

    fn read_argument(&mut self, additional: u8) -> Result<u64, CtapError> {
        match additional {
            0..=23 => Ok(additional as u64),
            24 => {
                let b = self.read_byte()?;
                Ok(b as u64)
            }
            25 => {
                if self.pos + 2 > self.data.len() {
                    return Err(CtapError::InvalidLength);
                }
                let val = u16::from_be_bytes([self.data[self.pos], self.data[self.pos + 1]]);
                self.pos += 2;
                Ok(val as u64)
            }
            26 => {
                if self.pos + 4 > self.data.len() {
                    return Err(CtapError::InvalidLength);
                }
                let val = u32::from_be_bytes([
                    self.data[self.pos],
                    self.data[self.pos + 1],
                    self.data[self.pos + 2],
                    self.data[self.pos + 3],
                ]);
                self.pos += 4;
                Ok(val as u64)
            }
            27 => {
                if self.pos + 8 > self.data.len() {
                    return Err(CtapError::InvalidLength);
                }
                let val = u64::from_be_bytes([
                    self.data[self.pos],
                    self.data[self.pos + 1],
                    self.data[self.pos + 2],
                    self.data[self.pos + 3],
                    self.data[self.pos + 4],
                    self.data[self.pos + 5],
                    self.data[self.pos + 6],
                    self.data[self.pos + 7],
                ]);
                self.pos += 8;
                Ok(val)
            }
            _ => Err(CtapError::InvalidParameter),
        }
    }

    /// Decode the next CBOR value. For Array/Map, returns the count;
    /// the caller must then decode that many items/pairs.
    pub fn decode_value(&mut self) -> Result<CborValue<'a>, CtapError> {
        let initial = self.read_byte()?;
        let major = initial >> 5;
        let additional = initial & 0x1F;

        match major {
            0 => {
                // Unsigned
                let val = self.read_argument(additional)?;
                Ok(CborValue::Unsigned(val))
            }
            1 => {
                // Negative
                let val = self.read_argument(additional)?;
                Ok(CborValue::Negative(-1 - val as i64))
            }
            2 => {
                // Byte string
                let len = self.read_argument(additional)? as usize;
                if self.pos + len > self.data.len() {
                    return Err(CtapError::InvalidLength);
                }
                let slice = &self.data[self.pos..self.pos + len];
                self.pos += len;
                Ok(CborValue::Bytes(slice))
            }
            3 => {
                // Text string
                let len = self.read_argument(additional)? as usize;
                if self.pos + len > self.data.len() {
                    return Err(CtapError::InvalidLength);
                }
                let slice = &self.data[self.pos..self.pos + len];
                self.pos += len;
                let s = core::str::from_utf8(slice).map_err(|_| CtapError::InvalidParameter)?;
                Ok(CborValue::Text(s))
            }
            4 => {
                // Array
                let count = self.read_argument(additional)? as usize;
                Ok(CborValue::Array(count))
            }
            5 => {
                // Map
                let count = self.read_argument(additional)? as usize;
                Ok(CborValue::Map(count))
            }
            7 => {
                // Simple values and floats
                match additional {
                    20 => Ok(CborValue::Bool(false)),
                    21 => Ok(CborValue::Bool(true)),
                    22 => Ok(CborValue::Null),
                    23 => Ok(CborValue::Undefined),
                    _ => Err(CtapError::InvalidParameter),
                }
            }
            _ => Err(CtapError::InvalidParameter),
        }
    }

    /// Skip the next CBOR value entirely (including nested structures).
    pub fn skip_value(&mut self) -> Result<(), CtapError> {
        let val = self.decode_value()?;
        match val {
            CborValue::Array(count) => {
                for _ in 0..count {
                    self.skip_value()?;
                }
            }
            CborValue::Map(count) => {
                for _ in 0..count {
                    self.skip_value()?;
                    self.skip_value()?;
                }
            }
            _ => {} // Scalar values already consumed
        }
        Ok(())
    }

    /// Read the next value as an unsigned integer.
    pub fn expect_unsigned(&mut self) -> Result<u64, CtapError> {
        match self.decode_value()? {
            CborValue::Unsigned(v) => Ok(v),
            _ => Err(CtapError::InvalidParameter),
        }
    }

    /// Read the next value as a signed integer (handles both unsigned and negative).
    pub fn expect_int(&mut self) -> Result<i64, CtapError> {
        match self.decode_value()? {
            CborValue::Unsigned(v) => Ok(v as i64),
            CborValue::Negative(v) => Ok(v),
            _ => Err(CtapError::InvalidParameter),
        }
    }

    /// Read the next value as a byte string.
    pub fn expect_bytes(&mut self) -> Result<&'a [u8], CtapError> {
        match self.decode_value()? {
            CborValue::Bytes(b) => Ok(b),
            _ => Err(CtapError::InvalidParameter),
        }
    }

    /// Read the next value as a text string.
    pub fn expect_text(&mut self) -> Result<&'a str, CtapError> {
        match self.decode_value()? {
            CborValue::Text(s) => Ok(s),
            _ => Err(CtapError::InvalidParameter),
        }
    }

    /// Read the next value as a boolean.
    pub fn expect_bool(&mut self) -> Result<bool, CtapError> {
        match self.decode_value()? {
            CborValue::Bool(b) => Ok(b),
            _ => Err(CtapError::InvalidParameter),
        }
    }

    /// Read a map header and return the number of key-value pairs.
    pub fn expect_map(&mut self) -> Result<usize, CtapError> {
        match self.decode_value()? {
            CborValue::Map(n) => Ok(n),
            _ => Err(CtapError::InvalidParameter),
        }
    }

    /// Read an array header and return the element count.
    pub fn expect_array(&mut self) -> Result<usize, CtapError> {
        match self.decode_value()? {
            CborValue::Array(n) => Ok(n),
            _ => Err(CtapError::InvalidParameter),
        }
    }
}
