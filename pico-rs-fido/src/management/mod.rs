//! YubiKey Management application stub.
//!
//! Provides basic compatibility with the YubiKey management protocol
//! over CCID (ISO 7816 APDUs). This enables `ykman` and similar tools
//! to detect the device and query basic configuration.

/// YubiKey Management application AID.
pub const MANAGEMENT_AID: [u8; 8] = [0xA0, 0x00, 0x00, 0x05, 0x27, 0x47, 0x11, 0x17];

// Management INS codes
const INS_READ_CONFIG: u8 = 0x1D;
const INS_WRITE_CONFIG: u8 = 0x1C;
const INS_DEVICE_RESET: u8 = 0x1F;

// Status words
const SW_NO_ERROR: u16 = 0x9000;
const SW_INS_NOT_SUPPORTED: u16 = 0x6D00;
const SW_SECURITY_NOT_SATISFIED: u16 = 0x6982;

/// Firmware version reported to management tools.
const FIRMWARE_VERSION: [u8; 3] = [5, 7, 0];

/// Management application state.
pub struct ManagementApp {
    /// Whether device reset is locked (requires authentication).
    reset_locked: bool,
}

impl ManagementApp {
    pub fn new() -> Self {
        Self { reset_locked: true }
    }

    /// Check if the provided AID matches the management application.
    pub fn matches_aid(aid: &[u8]) -> bool {
        aid == MANAGEMENT_AID
    }
}

impl Default for ManagementApp {
    fn default() -> Self {
        Self::new()
    }
}

/// Process a management APDU command.
///
/// # Arguments
/// - `ins`: INS byte of the APDU command.
/// - `data`: Command data field.
/// - `response`: Buffer for response data.
///
/// # Returns
/// Number of response bytes on success, or SW error code.
pub fn process_management_apdu(ins: u8, data: &[u8], response: &mut [u8]) -> Result<usize, u16> {
    match ins {
        INS_READ_CONFIG => read_config(response),
        INS_WRITE_CONFIG => write_config(data),
        INS_DEVICE_RESET => device_reset(),
        _ => Err(SW_INS_NOT_SUPPORTED),
    }
}

/// Read device configuration.
///
/// Returns a TLV-encoded configuration block with firmware version,
/// form factor, and enabled application flags.
fn read_config(response: &mut [u8]) -> Result<usize, u16> {
    // Build minimal config TLV response
    // Tag 0x04 = USB enabled applications (2 bytes)
    // Tag 0x05 = firmware version (3 bytes)
    // Tag 0x06 = form factor (1 byte)

    let config: &[u8] = &[
        // Firmware version: tag 0x05, length 3
        0x05,
        0x03,
        FIRMWARE_VERSION[0],
        FIRMWARE_VERSION[1],
        FIRMWARE_VERSION[2],
        // Form factor: tag 0x06, length 1, value 0x01 (USB-A keychain)
        0x06,
        0x01,
        0x01,
        // USB enabled: tag 0x03, length 2, value = OTP | FIDO2 | CCID
        0x03,
        0x02,
        0x27,
        0x00,
    ];

    if response.len() < config.len() {
        return Err(0x6700); // SW_WRONG_LENGTH
    }

    response[..config.len()].copy_from_slice(config);
    Ok(config.len())
}

/// Write device configuration (stub — not yet implemented).
fn write_config(_data: &[u8]) -> Result<usize, u16> {
    // Configuration writes are not supported yet.
    // Return success to avoid breaking management tools.
    Ok(0)
}

/// Device reset (stub — requires authentication in production).
fn device_reset() -> Result<usize, u16> {
    // Full reset requires authenticated session; reject for now.
    Err(SW_SECURITY_NOT_SATISFIED)
}
