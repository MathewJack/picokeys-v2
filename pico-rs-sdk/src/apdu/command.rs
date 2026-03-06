use heapless::Vec;

/// Maximum APDU command data capacity.
pub const MAX_COMMAND_DATA_LEN: usize = 1024;

/// Errors that can occur when parsing a raw APDU command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandError {
    /// Fewer than the mandatory 4 header bytes.
    TooShort,
    /// Lc/Le length fields don't match the actual data length.
    InvalidLength,
    /// Command data exceeds the buffer capacity.
    DataTooLong,
}

/// Parsed ISO 7816-4 command APDU.
pub struct Command {
    pub cla: u8,
    pub ins: u8,
    pub p1: u8,
    pub p2: u8,
    pub data: Vec<u8, MAX_COMMAND_DATA_LEN>,
    /// Expected response length (Ne). 0x0000 in extended APDU means 65536.
    pub expected_len: Option<u32>,
}

impl Command {
    pub fn cla(&self) -> u8 {
        self.cla
    }
    pub fn ins(&self) -> u8 {
        self.ins
    }
    pub fn p1(&self) -> u8 {
        self.p1
    }
    pub fn p2(&self) -> u8 {
        self.p2
    }
    pub fn data(&self) -> &[u8] {
        &self.data
    }
    pub fn expected_len(&self) -> Option<u32> {
        self.expected_len
    }

    /// Parse an APDU command from raw bytes (ISO 7816-4 short and extended formats).
    pub fn from_bytes(raw: &[u8]) -> Result<Self, CommandError> {
        if raw.len() < 4 {
            return Err(CommandError::TooShort);
        }

        let cla = raw[0];
        let ins = raw[1];
        let p1 = raw[2];
        let p2 = raw[3];
        let body = &raw[4..];

        let (data_bytes, expected_len) = parse_body(body)?;

        let mut data = Vec::new();
        data.extend_from_slice(data_bytes)
            .map_err(|_| CommandError::DataTooLong)?;

        Ok(Command {
            cla,
            ins,
            p1,
            p2,
            data,
            expected_len,
        })
    }
}

/// Parse the body after the 4-byte header, returning (data_slice, optional Le).
fn parse_body(body: &[u8]) -> Result<(&[u8], Option<u32>), CommandError> {
    match body.len() {
        // Case 1: no body at all
        0 => Ok((&[], None)),

        // 1 byte: short Le only (Case 2S)
        1 => {
            let le = if body[0] == 0 { 256 } else { body[0] as u32 };
            Ok((&[], Some(le)))
        }

        _ => {
            // Check for extended APDU: first body byte == 0 and len >= 3
            if body[0] == 0x00 && body.len() >= 3 {
                return parse_extended(body);
            }

            // Short APDU
            parse_short(body)
        }
    }
}

/// Parse short APDU body (Lc is a single byte, Le is a single byte).
fn parse_short(body: &[u8]) -> Result<(&[u8], Option<u32>), CommandError> {
    let lc = body[0] as usize;

    if lc == 0 {
        // body[0] == 0 with len < 3 was already handled; shouldn't reach here normally.
        // Treat as Le=256.
        if body.len() == 1 {
            return Ok((&[], Some(256)));
        }
        return Err(CommandError::InvalidLength);
    }

    let data_start = 1;
    let data_end = data_start + lc;

    if data_end > body.len() {
        return Err(CommandError::InvalidLength);
    }

    let data = &body[data_start..data_end];

    if data_end == body.len() {
        // Case 3S: Lc + Data, no Le
        Ok((data, None))
    } else if data_end + 1 == body.len() {
        // Case 4S: Lc + Data + Le
        let le_byte = body[data_end];
        let le = if le_byte == 0 { 256 } else { le_byte as u32 };
        Ok((data, Some(le)))
    } else {
        Err(CommandError::InvalidLength)
    }
}

/// Parse extended APDU body (body starts with 0x00).
fn parse_extended(body: &[u8]) -> Result<(&[u8], Option<u32>), CommandError> {
    debug_assert!(body[0] == 0x00);

    let b1 = body[1] as usize;
    let b2 = body[2] as usize;
    let lc = (b1 << 8) | b2;

    if lc == 0 {
        // Extended Le only (Case 2E): [0x00, Le_hi, Le_lo]
        if body.len() == 3 {
            // Le_hi=0, Le_lo=0 → Ne=65536
            return Ok((&[], Some(65536)));
        }
        return Err(CommandError::InvalidLength);
    }

    let data_start = 3;
    let data_end = data_start + lc;

    if data_end > body.len() {
        return Err(CommandError::InvalidLength);
    }

    if lc > MAX_COMMAND_DATA_LEN {
        return Err(CommandError::DataTooLong);
    }

    let data = &body[data_start..data_end];

    if data_end == body.len() {
        // Case 3E: extended Lc + Data, no Le
        Ok((data, None))
    } else if data_end + 2 == body.len() {
        // Case 4E: extended Lc + Data + Le (2 bytes)
        let le_hi = body[data_end] as u32;
        let le_lo = body[data_end + 1] as u32;
        let le_val = (le_hi << 8) | le_lo;
        let le = if le_val == 0 { 65536 } else { le_val };
        Ok((data, Some(le)))
    } else {
        Err(CommandError::InvalidLength)
    }
}
