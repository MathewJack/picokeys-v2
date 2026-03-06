//! CTAP2.1 authenticatorConfig (0x0D) sub-commands.

use super::ctap::CtapError;

/// Sub-command identifiers for authenticatorConfig.
#[derive(Debug, Clone, Copy, PartialEq, Eq, defmt::Format)]
#[repr(u8)]
pub enum ConfigSubCommand {
    /// Allow enterprise attestation for designated RPs.
    EnableEnterpriseAttestation = 0x01,
    /// Toggle the "always require UV" policy.
    ToggleAlwaysUv = 0x02,
    /// Set the minimum acceptable PIN length (4–63 digits).
    SetMinPinLength = 0x03,
}

impl TryFrom<u8> for ConfigSubCommand {
    type Error = CtapError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(Self::EnableEnterpriseAttestation),
            0x02 => Ok(Self::ToggleAlwaysUv),
            0x03 => Ok(Self::SetMinPinLength),
            _ => Err(CtapError::InvalidParameter),
        }
    }
}
