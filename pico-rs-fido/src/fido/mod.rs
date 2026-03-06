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
    /// Hardware / vendor-level device configuration (persisted).
    pub device_config: vendor::DeviceConfig,
    /// Extra authenticator-config state (RP ID whitelist, force PIN change).
    pub config_extras: config::ConfigExtras,
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
            device_config: vendor::DeviceConfig::default(),
            config_extras: config::ConfigExtras::new(),
            pin_token: None,
            boot_time_ms,
            large_blobs: large_blobs::LargeBlobStore::new(),
        }
    }

    /// Create a new `FidoApp` with both FIDO and device configs.
    pub fn with_device_config(
        config: FidoConfig,
        device_config: vendor::DeviceConfig,
        boot_time_ms: u64,
    ) -> Self {
        Self {
            config,
            device_config,
            config_extras: config::ConfigExtras::new(),
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
        // Payload format:
        //   [sub_command: u8]
        //   [pin_protocol: u8][pin_auth: 16 bytes]   ← present when PIN is set
        //   [params...]
        if payload.is_empty() {
            return Err(CtapError::MissingParameter);
        }
        let sub = config::ConfigSubCommand::try_from(payload[0])?;

        let params = if let Some(ref token) = self.pin_token {
            // PIN is set → require auth header.
            if payload.len() < 18 {
                return Err(CtapError::PinAuthInvalid);
            }
            let pin_protocol = client_pin::PinProtocol::try_from(payload[1])?;
            let pin_auth = &payload[2..18];
            let params = &payload[18..];

            // HMAC message = sub_command || params
            let mut msg = [0u8; 256];
            msg[0] = payload[0];
            let plen = params.len().min(255);
            msg[1..1 + plen].copy_from_slice(&params[..plen]);

            if !client_pin::verify_pin_auth(
                pin_protocol,
                token,
                &msg[..1 + plen],
                pin_auth,
            ) {
                return Err(CtapError::PinAuthInvalid);
            }
            params
        } else {
            // No PIN set — allow without auth.
            &payload[1..]
        };

        config::handle_authenticator_config(
            sub,
            params,
            &mut self.config,
            &mut self.config_extras,
        )?;

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
        let rest = &payload[1..];

        // Authenticated commands carry: [pin_protocol: u8][pin_auth: 16 B][data…]
        let cmd_data = if vcmd.requires_auth() {
            if let Some(ref token) = self.pin_token {
                if rest.len() < 17 {
                    return Err(CtapError::PinAuthInvalid);
                }
                let pin_protocol = client_pin::PinProtocol::try_from(rest[0])?;
                let pin_auth = &rest[1..17];
                let data = &rest[17..];

                // HMAC message = vendor_subcmd || data
                let mut msg = [0u8; 256];
                msg[0] = payload[0];
                let dlen = data.len().min(255);
                msg[1..1 + dlen].copy_from_slice(&data[..dlen]);

                if !client_pin::verify_pin_auth(
                    pin_protocol,
                    token,
                    &msg[..1 + dlen],
                    pin_auth,
                ) {
                    return Err(CtapError::PinAuthInvalid);
                }
                data
            } else {
                // No PIN set — allow without auth.
                rest
            }
        } else {
            rest
        };

        if response.is_empty() {
            return Err(CtapError::InvalidLength);
        }
        response[0] = CtapError::Ok as u8;
        let (n, effects) = vendor::handle_vendor(
            vcmd,
            cmd_data,
            &mut self.device_config,
            &mut response[1..],
        )?;

        // Apply side effects.
        if effects.aaguid_updated {
            self.config.aaguid = self.device_config.aaguid;
        }
        if effects.factory_reset {
            self.pin_token = None;
            self.config.client_pin_set = false;
            self.large_blobs.clear();
        }

        Ok(1 + n)
    }
}
