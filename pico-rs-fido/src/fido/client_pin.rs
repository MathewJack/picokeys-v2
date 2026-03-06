//! CTAP2 authenticatorClientPIN — Phase 2 stub.
//!
//! Will implement PIN protocol v1 and v2 key agreement, PIN set/change,
//! PIN token retrieval, and permission management.

use super::ctap::CtapError;

/// Supported PIN/UV auth protocol versions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, defmt::Format)]
#[repr(u8)]
pub enum PinProtocol {
    V1 = 1,
    V2 = 2,
}

impl TryFrom<u8> for PinProtocol {
    type Error = CtapError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::V1),
            2 => Ok(Self::V2),
            _ => Err(CtapError::InvalidParameter),
        }
    }
}

/// ClientPIN sub-command identifiers (CTAP2 §6.5.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, defmt::Format)]
#[repr(u8)]
pub enum PinCommand {
    GetRetries = 0x01,
    GetKeyAgreement = 0x02,
    SetPin = 0x03,
    ChangePin = 0x04,
    GetPinToken = 0x05,
    GetPinUvAuthTokenUsingUvWithPermissions = 0x06,
    GetUvRetries = 0x07,
    GetPinUvAuthTokenUsingPinWithPermissions = 0x09,
}

impl TryFrom<u8> for PinCommand {
    type Error = CtapError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(Self::GetRetries),
            0x02 => Ok(Self::GetKeyAgreement),
            0x03 => Ok(Self::SetPin),
            0x04 => Ok(Self::ChangePin),
            0x05 => Ok(Self::GetPinToken),
            0x06 => Ok(Self::GetPinUvAuthTokenUsingUvWithPermissions),
            0x07 => Ok(Self::GetUvRetries),
            0x09 => Ok(Self::GetPinUvAuthTokenUsingPinWithPermissions),
            _ => Err(CtapError::InvalidParameter),
        }
    }
}

/// PIN token permission flags (CTAP2.1 §6.5.5.7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, defmt::Format)]
pub struct PinPermissions(u8);

impl PinPermissions {
    pub const MC: Self = Self(0x01);
    pub const GA: Self = Self(0x02);
    pub const CM: Self = Self(0x04);
    pub const BE: Self = Self(0x08);
    pub const LBW: Self = Self(0x10);
    pub const ACFG: Self = Self(0x20);

    pub fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }
}

/// Process a ClientPIN request.
///
/// # Stub
/// Returns `InvalidCommand` until the full handler is implemented.
pub fn handle_client_pin(
    _data: &[u8],
    _response: &mut [u8],
) -> Result<usize, CtapError> {
    Err(CtapError::InvalidCommand)
}
