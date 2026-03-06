//! CTAP2.1 authenticatorConfig (0x0D) sub-commands.
//!
//! Manages authenticator-level policy: minimum PIN length, always-UV, and
//! enterprise attestation.  All sub-commands require a valid PIN token — the
//! caller verifies authentication before invoking [`handle_authenticator_config`].

use super::ctap::CtapError;

// ── Sub-command identifiers ─────────────────────────────────────────────────

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

// ── Extended config state ───────────────────────────────────────────────────

/// Maximum number of RP IDs in the `minPinLength` whitelist.
const MAX_RPID_ENTRIES: usize = 8;

/// Maximum byte length of a single RP ID.
const MAX_RPID_LEN: usize = 128;

/// Extra authenticator config state not covered by [`super::FidoConfig`].
///
/// [`super::FidoConfig`] carries the core policy flags (`min_pin_length`,
/// `always_uv`, `enterprise_attestation`).  This struct holds the additional
/// `setMinPinLength` parameters that need to persist but are not part of
/// `getInfo`.
pub struct ConfigExtras {
    /// RP IDs that receive the `minPinLength` extension in makeCredential.
    rpid_buf: [[u8; MAX_RPID_LEN]; MAX_RPID_ENTRIES],
    rpid_len: [u8; MAX_RPID_ENTRIES],
    rpid_count: u8,
    /// Force the user to change their PIN on the next getPinToken.
    pub force_change_pin: bool,
}

impl ConfigExtras {
    /// Create a new, empty extras state.
    pub const fn new() -> Self {
        Self {
            rpid_buf: [[0u8; MAX_RPID_LEN]; MAX_RPID_ENTRIES],
            rpid_len: [0u8; MAX_RPID_ENTRIES],
            rpid_count: 0,
            force_change_pin: false,
        }
    }

    /// Clear the RP ID whitelist.
    pub fn clear_rpids(&mut self) {
        self.rpid_count = 0;
    }

    /// Add an RP ID to the whitelist.
    ///
    /// Returns `false` if the list is full or the ID exceeds
    /// [`MAX_RPID_LEN`] bytes.
    pub fn add_rpid(&mut self, rpid: &[u8]) -> bool {
        if self.rpid_count as usize >= MAX_RPID_ENTRIES || rpid.len() > MAX_RPID_LEN {
            return false;
        }
        let idx = self.rpid_count as usize;
        self.rpid_buf[idx][..rpid.len()].copy_from_slice(rpid);
        self.rpid_len[idx] = rpid.len() as u8;
        self.rpid_count += 1;
        true
    }

    /// Check whether an RP ID is in the whitelist.
    pub fn contains_rpid(&self, rpid: &[u8]) -> bool {
        for i in 0..self.rpid_count as usize {
            let entry = &self.rpid_buf[i][..self.rpid_len[i] as usize];
            if entry == rpid {
                return true;
            }
        }
        false
    }

    /// Number of whitelisted RP IDs.
    pub fn rpid_count(&self) -> usize {
        self.rpid_count as usize
    }
}

// ── Sub-command handler ─────────────────────────────────────────────────────

/// Process an authenticatorConfig sub-command.
///
/// Modifies `fido_config` (core policy flags) and `extras` (RP ID whitelist
/// and force-change-PIN flag) as appropriate.
///
/// `params` is the sub-command-specific parameter bytes (if any).
/// PIN auth **must** have been verified by the caller before calling this.
pub fn handle_authenticator_config(
    sub_command: ConfigSubCommand,
    params: &[u8],
    fido_config: &mut super::FidoConfig,
    extras: &mut ConfigExtras,
) -> Result<(), CtapError> {
    match sub_command {
        ConfigSubCommand::EnableEnterpriseAttestation => {
            fido_config.enterprise_attestation = true;
            Ok(())
        }

        ConfigSubCommand::ToggleAlwaysUv => {
            fido_config.always_uv = !fido_config.always_uv;
            Ok(())
        }

        ConfigSubCommand::SetMinPinLength => handle_set_min_pin_length(params, fido_config, extras),
    }
}

/// `SetMinPinLength` parameter format (simple binary):
///
/// ```text
/// [new_min_pin_length: u8]            — 0 means "don't change"
/// [force_change_pin: u8]              — 0/1 (optional, default 0)
/// [rpid_count: u8]                    — number of RP IDs (optional)
/// [rpid_len: u8][rpid: rpid_len B]    — repeated rpid_count times
/// ```
fn handle_set_min_pin_length(
    params: &[u8],
    fido_config: &mut super::FidoConfig,
    extras: &mut ConfigExtras,
) -> Result<(), CtapError> {
    if params.is_empty() {
        return Err(CtapError::MissingParameter);
    }

    // ── new minimum length ──────────────────────────────────────────────
    let new_min = params[0];
    if new_min != 0 {
        if new_min < 4 || new_min > 63 {
            return Err(CtapError::InvalidParameter);
        }
        // The minimum PIN length can only be increased, never decreased.
        if new_min < fido_config.min_pin_length {
            return Err(CtapError::InvalidParameter);
        }
        fido_config.min_pin_length = new_min;
    }

    // ── optional: forceChangePin ────────────────────────────────────────
    if params.len() > 1 {
        extras.force_change_pin = params[1] != 0;
    }

    // ── optional: RP ID whitelist ───────────────────────────────────────
    if params.len() > 2 {
        let count = params[2] as usize;
        if count > MAX_RPID_ENTRIES {
            return Err(CtapError::LimitExceeded);
        }
        extras.clear_rpids();
        let mut offset = 3;
        for _ in 0..count {
            if offset >= params.len() {
                return Err(CtapError::InvalidLength);
            }
            let rpid_len = params[offset] as usize;
            offset += 1;
            if offset + rpid_len > params.len() {
                return Err(CtapError::InvalidLength);
            }
            let rpid = &params[offset..offset + rpid_len];
            // Validate UTF-8 (RP IDs are domain strings).
            if core::str::from_utf8(rpid).is_err() {
                return Err(CtapError::InvalidParameter);
            }
            if !extras.add_rpid(rpid) {
                return Err(CtapError::LimitExceeded);
            }
            offset += rpid_len;
        }
    }

    Ok(())
}
