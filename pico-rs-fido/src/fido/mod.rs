//! FIDO2/CTAP2 application — command routing, handlers, and protocol logic.

pub mod cbor;
pub mod client_pin;
pub mod config;
pub mod credential_mgmt;
pub mod ctap;
pub mod get_assertion;
pub mod get_info;
pub mod large_blobs;
pub mod make_credential;
pub mod reset;
pub mod selection;
pub mod vendor;

pub use ctap::{CtapCommand, CtapError};
pub use get_info::GetInfoResponse;

/// Runtime configuration for the FIDO authenticator.
#[derive(Debug, Clone, defmt::Format)]
pub struct FidoConfig {
    /// 16-byte AAGUID identifying this authenticator model.
    pub aaguid: [u8; 16],
    /// Whether a PIN has been set by the user.
    pub client_pin_set: bool,
    /// Minimum PIN length (default 4).
    pub min_pin_length: u8,
    /// Force user verification on every operation.
    pub always_uv: bool,
    /// Enterprise attestation enabled.
    pub enterprise_attestation: bool,
    /// Firmware version number.
    pub firmware_version: u32,
}

impl Default for FidoConfig {
    fn default() -> Self {
        Self {
            aaguid: [0u8; 16],
            client_pin_set: false,
            min_pin_length: 4,
            always_uv: false,
            enterprise_attestation: false,
            firmware_version: 1,
        }
    }
}

/// Main FIDO2 application state.
pub struct FidoApp {
    /// Authenticator configuration (persisted).
    pub config: FidoConfig,
    /// RAM-only PIN token (cleared on reset / power cycle).
    pin_token: Option<[u8; 32]>,
    /// Tick (ms since boot) when the device was powered on.
    boot_time_ms: u64,
    /// Large-blob store.
    pub large_blobs: large_blobs::LargeBlobStore,
}

impl FidoApp {
    /// Create a new `FidoApp` with the given config and boot timestamp.
    pub fn new(config: FidoConfig, boot_time_ms: u64) -> Self {
        Self {
            config,
            pin_token: None,
            boot_time_ms,
            large_blobs: large_blobs::LargeBlobStore::new(),
        }
    }

    /// Process a CTAPHID CBOR message.
    ///
    /// `data` is the raw CBOR payload (first byte = command).
    /// On success the encoded response (status byte + CBOR) is written to
    /// `response` and the number of bytes written is returned.
    pub fn process_ctaphid_cbor(
        &mut self,
        data: &[u8],
        response: &mut [u8],
        now_ms: u64,
        button_pressed: bool,
    ) -> Result<usize, CtapError> {
        if data.is_empty() {
            return Err(CtapError::InvalidLength);
        }

        let cmd_byte = data[0];
        let payload = &data[1..];

        let cmd = CtapCommand::try_from(cmd_byte)?;

        match cmd {
            CtapCommand::GetInfo => {
                let info = GetInfoResponse::from_config(&self.config);
                if response.is_empty() {
                    return Err(CtapError::InvalidLength);
                }
                response[0] = CtapError::Ok as u8;
                let n = info.encode(&mut response[1..])?;
                Ok(1 + n)
            }

            CtapCommand::MakeCredential => {
                // Phase-2 stub — will be filled in next dispatch
                let _ = payload;
                Err(CtapError::InvalidCommand)
            }

            CtapCommand::GetAssertion | CtapCommand::GetNextAssertion => {
                let _ = payload;
                Err(CtapError::InvalidCommand)
            }

            CtapCommand::ClientPin => {
                let _ = payload;
                Err(CtapError::InvalidCommand)
            }

            CtapCommand::Reset => {
                let elapsed_ms = now_ms.saturating_sub(self.boot_time_ms);
                reset::handle_reset(button_pressed, elapsed_ms)?;
                self.pin_token = None;
                self.config.client_pin_set = false;
                self.large_blobs.clear();
                if response.is_empty() {
                    return Err(CtapError::InvalidLength);
                }
                response[0] = CtapError::Ok as u8;
                Ok(1)
            }

            CtapCommand::Selection => {
                selection::handle_selection()?;
                if response.is_empty() {
                    return Err(CtapError::InvalidLength);
                }
                response[0] = CtapError::Ok as u8;
                Ok(1)
            }

            CtapCommand::CredentialManagement => {
                let _ = payload;
                Err(CtapError::InvalidCommand)
            }

            CtapCommand::LargeBlobs => {
                self.handle_large_blobs(payload, response)
            }

            CtapCommand::Config => {
                self.handle_config(payload, response)
            }

            CtapCommand::BioEnrollment => {
                Err(CtapError::InvalidCommand)
            }

            CtapCommand::VendorFirst => {
                self.handle_vendor_dispatch(payload, response)
            }
        }
    }

    // ---- internal dispatch helpers ----

    fn handle_large_blobs(
        &mut self,
        payload: &[u8],
        response: &mut [u8],
    ) -> Result<usize, CtapError> {
        // Minimal: first byte of payload selects get(0x01) vs set(0x02).
        if payload.is_empty() {
            return Err(CtapError::MissingParameter);
        }
        match payload[0] {
            0x01 => {
                // get — offset(2 bytes LE) + length(2 bytes LE) in payload[1..5]
                if payload.len() < 5 {
                    return Err(CtapError::InvalidLength);
                }
                let offset =
                    u16::from_le_bytes([payload[1], payload[2]]) as usize;
                let length =
                    u16::from_le_bytes([payload[3], payload[4]]) as usize;
                let data = self.large_blobs.read(offset, length)?;
                if response.len() < 1 + data.len() {
                    return Err(CtapError::InvalidLength);
                }
                response[0] = CtapError::Ok as u8;
                response[1..1 + data.len()].copy_from_slice(data);
                Ok(1 + data.len())
            }
            0x02 => {
                // set — offset(2 LE) then data
                if payload.len() < 3 {
                    return Err(CtapError::InvalidLength);
                }
                let offset =
                    u16::from_le_bytes([payload[1], payload[2]]) as usize;
                let data = &payload[3..];
                self.large_blobs.write(offset, data)?;
                if response.is_empty() {
                    return Err(CtapError::InvalidLength);
                }
                response[0] = CtapError::Ok as u8;
                Ok(1)
            }
            _ => Err(CtapError::InvalidParameter),
        }
    }

    fn handle_config(
        &mut self,
        payload: &[u8],
        response: &mut [u8],
    ) -> Result<usize, CtapError> {
        if payload.is_empty() {
            return Err(CtapError::MissingParameter);
        }
        let sub = config::ConfigSubCommand::try_from(payload[0])?;
        let params = &payload[1..];
        match sub {
            config::ConfigSubCommand::EnableEnterpriseAttestation => {
                self.config.enterprise_attestation = true;
            }
            config::ConfigSubCommand::ToggleAlwaysUv => {
                self.config.always_uv = !self.config.always_uv;
            }
            config::ConfigSubCommand::SetMinPinLength => {
                if params.is_empty() {
                    return Err(CtapError::MissingParameter);
                }
                let len = params[0];
                if len < 4 || len > 63 {
                    return Err(CtapError::InvalidParameter);
                }
                self.config.min_pin_length = len;
            }
        }
        if response.is_empty() {
            return Err(CtapError::InvalidLength);
        }
        response[0] = CtapError::Ok as u8;
        Ok(1)
    }

    fn handle_vendor_dispatch(
        &mut self,
        payload: &[u8],
        response: &mut [u8],
    ) -> Result<usize, CtapError> {
        if payload.is_empty() {
            return Err(CtapError::MissingParameter);
        }
        let vcmd = vendor::VendorCommand::try_from(payload[0])?;
        let vdata = &payload[1..];
        if response.is_empty() {
            return Err(CtapError::InvalidLength);
        }
        response[0] = CtapError::Ok as u8;
        let n = vendor::handle_vendor(vcmd, vdata, &mut response[1..])?;
        Ok(1 + n)
    }
}
