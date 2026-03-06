//! Rescue-mode module — minimal CCID stack for factory-reset of bricked devices.
//!
//! Rescue mode is entered when the BOOTSEL button is held during power-up.
//! In this mode the device enumerates as a bare CCID reader and only accepts
//! a small set of APDUs: SELECT (rescue AID), GET\_VERSION, ERASE\_ALL,
//! GET\_DEVICE\_ID, and REBOOT.
//!
//! **No crypto and no credential access** — this is a minimal recovery path.

use crate::button::ButtonReader;

// ── Boot detection ──────────────────────────────────────────────────────────

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

/// Convenience wrapper: returns `true` when rescue mode should be entered.
pub fn check_rescue_on_boot(button_pressed: bool) -> bool {
    button_pressed
}

/// Placeholder for platform-specific minimal USB descriptor configuration.
///
/// In rescue mode the device should enumerate as a bare CCID reader with no
/// HID interface.  Platform-level USB init code calls this to determine
/// whether to use the minimal descriptor set.
///
/// The actual USB descriptor swap is handled by the platform-specific binary
/// entrypoint.  Callers should check [`detect_rescue_mode`] during USB init
/// and use a CCID-only descriptor when in rescue mode.
pub fn enter_rescue_mode() {
    // Marker function — platforms implement the actual descriptor swap.
}

// ── APDU constants ──────────────────────────────────────────────────────────

/// Rescue AID: `A0 00 00 06 47 2F 00 01`
pub const RESCUE_AID: [u8; 8] = [0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01];

/// Firmware version returned by `GET_VERSION` in rescue mode.
const RESCUE_VERSION: [u8; 3] = [0x00, 0x01, 0x00]; // 0.1.0

// ISO 7816 class / instruction bytes
const CLA_ISO: u8 = 0x00;
const INS_SELECT: u8 = 0xA4;
const INS_GET_VERSION: u8 = 0xCA;
const INS_GET_DEVICE_ID: u8 = 0xB1;

// Vendor class + instructions
const CLA_VENDOR: u8 = 0x80;
const INS_ERASE_ALL: u8 = 0xEE;
const INS_REBOOT: u8 = 0xBB;

// Status words
const SW_OK: [u8; 2] = [0x90, 0x00];
const SW_FILE_NOT_FOUND: [u8; 2] = [0x6A, 0x82];
const SW_INS_NOT_SUPPORTED: [u8; 2] = [0x6D, 0x00];
const SW_CLA_NOT_SUPPORTED: [u8; 2] = [0x6E, 0x00];
const SW_WRONG_DATA: [u8; 2] = [0x6A, 0x80];
const SW_CONDITIONS_NOT_SATISFIED: [u8; 2] = [0x69, 0x85];

/// Default device ID returned when no platform-specific ID is available.
const DEFAULT_DEVICE_ID: [u8; 8] = [0xFF; 8];

// ── Rescue handler ──────────────────────────────────────────────────────────

/// Minimal rescue-mode APDU handler.
///
/// After processing a command, the caller should inspect
/// [`erase_requested`](Self::erase_requested) and
/// [`reboot_requested`](Self::reboot_requested) to perform the corresponding
/// platform actions (flash wipe / system reset).
pub struct RescueHandler {
    selected: bool,
    erase_requested: bool,
    reboot_requested: bool,
    /// Platform-provided unique device ID (e.g. from OTP or silicon ID).
    device_id: [u8; 8],
}

impl RescueHandler {
    /// Create a new handler with a default (all-0xFF) device ID.
    pub const fn new() -> Self {
        Self {
            selected: false,
            erase_requested: false,
            reboot_requested: false,
            device_id: DEFAULT_DEVICE_ID,
        }
    }

    /// Create a new handler with a platform-specific device ID.
    pub const fn with_device_id(device_id: [u8; 8]) -> Self {
        Self {
            selected: false,
            erase_requested: false,
            reboot_requested: false,
            device_id,
        }
    }

    /// Returns `true` after a successful `ERASE_ALL` command so the caller
    /// can perform the actual flash wipe + reboot.
    pub fn erase_requested(&self) -> bool {
        self.erase_requested
    }

    /// Returns `true` after a `REBOOT` command so the caller can initiate
    /// a system reset.
    pub fn reboot_requested(&self) -> bool {
        self.reboot_requested
    }

    /// Handle one rescue APDU.  Returns the number of response bytes written.
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
            (CLA_ISO, INS_GET_DEVICE_ID) => self.handle_get_device_id(response),
            (CLA_VENDOR, INS_ERASE_ALL) => self.handle_erase_all(response),
            (CLA_VENDOR, INS_REBOOT) => self.handle_reboot(response),
            (CLA_ISO, _) | (CLA_VENDOR, _) => Self::write_sw(response, SW_INS_NOT_SUPPORTED),
            _ => Self::write_sw(response, SW_CLA_NOT_SUPPORTED),
        }
    }

    // ── Individual APDU handlers ────────────────────────────────────────

    fn handle_select(&mut self, command: &[u8], response: &mut [u8]) -> usize {
        // Extract Lc and data.
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
            // Return a version TLV: tag 0x01, length 3, version bytes.
            let tlv = [
                0x01,
                0x03,
                RESCUE_VERSION[0],
                RESCUE_VERSION[1],
                RESCUE_VERSION[2],
            ];
            if response.len() >= tlv.len() + 2 {
                response[..tlv.len()].copy_from_slice(&tlv);
                response[tlv.len()..tlv.len() + 2].copy_from_slice(&SW_OK);
                tlv.len() + 2
            } else {
                Self::write_sw(response, SW_OK)
            }
        } else {
            self.selected = false;
            Self::write_sw(response, SW_FILE_NOT_FOUND)
        }
    }

    fn handle_get_version(&self, response: &mut [u8]) -> usize {
        if !self.selected {
            return Self::write_sw(response, SW_CONDITIONS_NOT_SATISFIED);
        }
        let ver_len = RESCUE_VERSION.len();
        if response.len() < ver_len + 2 {
            return Self::write_sw(response, SW_WRONG_DATA);
        }
        response[..ver_len].copy_from_slice(&RESCUE_VERSION);
        response[ver_len..ver_len + 2].copy_from_slice(&SW_OK);
        ver_len + 2
    }

    fn handle_get_device_id(&self, response: &mut [u8]) -> usize {
        if !self.selected {
            return Self::write_sw(response, SW_CONDITIONS_NOT_SATISFIED);
        }
        let id_len = self.device_id.len();
        if response.len() < id_len + 2 {
            return Self::write_sw(response, SW_WRONG_DATA);
        }
        response[..id_len].copy_from_slice(&self.device_id);
        response[id_len..id_len + 2].copy_from_slice(&SW_OK);
        id_len + 2
    }

    fn handle_erase_all(&mut self, response: &mut [u8]) -> usize {
        if !self.selected {
            return Self::write_sw(response, SW_CONDITIONS_NOT_SATISFIED);
        }
        self.erase_requested = true;
        Self::write_sw(response, SW_OK)
    }

    fn handle_reboot(&mut self, response: &mut [u8]) -> usize {
        if !self.selected {
            return Self::write_sw(response, SW_CONDITIONS_NOT_SATISFIED);
        }
        self.reboot_requested = true;
        Self::write_sw(response, SW_OK)
    }

    // ── Utility ─────────────────────────────────────────────────────────

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
