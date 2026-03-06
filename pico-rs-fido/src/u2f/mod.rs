//! U2F / CTAP1 backward compatibility layer.
//!
//! Implements FIDO U2F Register (0x01), Authenticate (0x02), and Version (0x03) commands.

pub mod authenticate;
pub mod register;

pub use authenticate::u2f_authenticate;
pub use register::u2f_register;

/// U2F command identifiers (INS byte).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum U2fCommand {
    Register = 0x01,
    Authenticate = 0x02,
    Version = 0x03,
}

impl U2fCommand {
    pub fn from_ins(ins: u8) -> Option<Self> {
        match ins {
            0x01 => Some(Self::Register),
            0x02 => Some(Self::Authenticate),
            0x03 => Some(Self::Version),
            _ => None,
        }
    }
}

/// U2F authenticate control byte flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum U2fAuthenticateFlags {
    /// Check if key handle is valid, don't sign.
    CheckOnly = 0x07,
    /// Enforce user presence (button press) and sign.
    EnforcePresence = 0x03,
    /// Don't enforce user presence.
    DontEnforce = 0x08,
}

impl U2fAuthenticateFlags {
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x07 => Some(Self::CheckOnly),
            0x03 => Some(Self::EnforcePresence),
            0x08 => Some(Self::DontEnforce),
            _ => None,
        }
    }
}

// U2F status words
pub const SW_NO_ERROR: u16 = 0x9000;
pub const SW_CONDITIONS_NOT_SATISFIED: u16 = 0x6985;
pub const SW_WRONG_DATA: u16 = 0x6A80;
pub const SW_WRONG_LENGTH: u16 = 0x6700;
pub const SW_CLA_NOT_SUPPORTED: u16 = 0x6E00;
pub const SW_INS_NOT_SUPPORTED: u16 = 0x6D00;

/// U2F version string.
const U2F_VERSION: &[u8] = b"U2F_V2";

/// Dispatch a U2F command.
///
/// `data` contains the raw APDU data field.
/// `response` is the output buffer for the response data (excluding SW).
/// Returns the number of bytes written to `response`, or an SW error code.
pub fn dispatch_u2f(
    command: U2fCommand,
    control: u8,
    data: &[u8],
    response: &mut [u8],
    rng: &mut (impl rand_core::CryptoRng + rand_core::RngCore),
    encryption_key: &[u8; 32],
    sign_counter: &mut u32,
) -> Result<usize, u16> {
    match command {
        U2fCommand::Register => {
            if data.len() != 64 {
                return Err(SW_WRONG_LENGTH);
            }
            let mut challenge = [0u8; 32];
            let mut app_id = [0u8; 32];
            challenge.copy_from_slice(&data[..32]);
            app_id.copy_from_slice(&data[32..64]);
            u2f_register(&challenge, &app_id, response, rng, encryption_key)
        }
        U2fCommand::Authenticate => {
            if data.len() < 65 {
                return Err(SW_WRONG_LENGTH);
            }
            let mut challenge = [0u8; 32];
            let mut app_id = [0u8; 32];
            challenge.copy_from_slice(&data[..32]);
            app_id.copy_from_slice(&data[32..64]);
            let key_handle_len = data[64] as usize;
            if data.len() < 65 + key_handle_len {
                return Err(SW_WRONG_LENGTH);
            }
            let key_handle = &data[65..65 + key_handle_len];
            u2f_authenticate(
                control,
                &challenge,
                &app_id,
                key_handle,
                response,
                encryption_key,
                sign_counter,
            )
        }
        U2fCommand::Version => {
            if response.len() < U2F_VERSION.len() {
                return Err(SW_WRONG_LENGTH);
            }
            response[..U2F_VERSION.len()].copy_from_slice(U2F_VERSION);
            Ok(U2F_VERSION.len())
        }
    }
}
