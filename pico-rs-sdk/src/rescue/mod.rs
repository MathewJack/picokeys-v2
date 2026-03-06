//! Rescue-mode module — minimal CCID stack for factory-reset of bricked devices.
//!
//! Rescue mode is entered when the BOOTSEL button is held during power-up.
//! In this mode the device enumerates as a bare CCID reader and only accepts
//! three APDUs: SELECT (rescue AID), GET_VERSION, and ERASE_ALL.

use crate::button::ButtonReader;

/// Whether the device booted into normal or rescue mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, defmt::Format)]
pub enum RescueMode {
    Normal,
    Rescue,
}

/// Detect rescue mode by sampling the button at boot time.
pub fn detect_rescue_mode(button: &mut impl ButtonReader) -> RescueMode {
    if button.is_pressed() {
        RescueMode::Rescue
    } else {
        RescueMode::Normal
    }
}

// ---------------------------------------------------------------------------
// Rescue APDU handler
// ---------------------------------------------------------------------------

/// Rescue AID: `A0 00 00 06 47 2F 00 01`
pub const RESCUE_AID: [u8; 8] = [0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01];

/// Firmware version returned by `GET_VERSION` in rescue mode.
const RESCUE_VERSION: [u8; 3] = [0x00, 0x01, 0x00]; // 0.1.0

// ISO 7816 class / instruction bytes
const CLA_ISO: u8 = 0x00;
const INS_SELECT: u8 = 0xA4;
const INS_GET_VERSION: u8 = 0xCA;

// Vendor command
const CLA_VENDOR: u8 = 0x80;
const INS_ERASE_ALL: u8 = 0xEE;

// Status words
const SW_OK: [u8; 2] = [0x90, 0x00];
const SW_FILE_NOT_FOUND: [u8; 2] = [0x6A, 0x82];
const SW_INS_NOT_SUPPORTED: [u8; 2] = [0x6D, 0x00];
const SW_CLA_NOT_SUPPORTED: [u8; 2] = [0x6E, 0x00];
const SW_WRONG_DATA: [u8; 2] = [0x6A, 0x80];

/// Minimal rescue-mode APDU handler.
///
/// The caller supplies the raw C-APDU in `command` and a mutable buffer for
/// the response. Returns the number of bytes written to `response`.
pub struct RescueHandler {
    selected: bool,
    erase_requested: bool,
}

impl RescueHandler {
    pub const fn new() -> Self {
        Self {
            selected: false,
            erase_requested: false,
        }
    }

    /// Returns `true` after a successful `ERASE_ALL` command so the caller
    /// can perform the actual flash wipe + reboot.
    pub fn erase_requested(&self) -> bool {
        self.erase_requested
    }

    /// Handle one rescue APDU. Returns the number of response bytes written.
    pub fn handle_rescue_apdu(&mut self, command: &[u8], response: &mut [u8]) -> usize {
        if command.len() < 4 {
            return Self::write_sw(response, SW_WRONG_DATA);
        }

        let cla = command[0];
        let ins = command[1];
        let _p1 = command[2];
        let _p2 = command[3];

        match (cla, ins) {
            (CLA_ISO, INS_SELECT) => self.handle_select(command, response),
            (CLA_ISO, INS_GET_VERSION) => self.handle_get_version(response),
            (CLA_VENDOR, INS_ERASE_ALL) => self.handle_erase_all(response),
            (CLA_ISO, _) | (CLA_VENDOR, _) => Self::write_sw(response, SW_INS_NOT_SUPPORTED),
            _ => Self::write_sw(response, SW_CLA_NOT_SUPPORTED),
        }
    }

    fn handle_select(&mut self, command: &[u8], response: &mut [u8]) -> usize {
        // Extract Lc and data
        let lc = if command.len() > 4 {
            command[4] as usize
        } else {
            0
        };
        let data_start = 5;
        let data_end = data_start + lc;

        if command.len() < data_end {
            return Self::write_sw(response, SW_WRONG_DATA);
        }

        let aid = &command[data_start..data_end];
        if aid == RESCUE_AID {
            self.selected = true;
            Self::write_sw(response, SW_OK)
        } else {
            self.selected = false;
            Self::write_sw(response, SW_FILE_NOT_FOUND)
        }
    }

    fn handle_get_version(&self, response: &mut [u8]) -> usize {
        if !self.selected {
            return Self::write_sw(response, SW_INS_NOT_SUPPORTED);
        }
        let ver_len = RESCUE_VERSION.len();
        if response.len() < ver_len + 2 {
            return Self::write_sw(response, SW_WRONG_DATA);
        }
        response[..ver_len].copy_from_slice(&RESCUE_VERSION);
        response[ver_len..ver_len + 2].copy_from_slice(&SW_OK);
        ver_len + 2
    }

    fn handle_erase_all(&mut self, response: &mut [u8]) -> usize {
        if !self.selected {
            return Self::write_sw(response, SW_INS_NOT_SUPPORTED);
        }
        self.erase_requested = true;
        Self::write_sw(response, SW_OK)
    }

    fn write_sw(response: &mut [u8], sw: [u8; 2]) -> usize {
        if response.len() >= 2 {
            response[0] = sw[0];
            response[1] = sw[1];
            2
        } else {
            0
        }
    }
}
