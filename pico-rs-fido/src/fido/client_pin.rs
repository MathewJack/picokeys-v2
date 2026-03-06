//! CTAP2.1 authenticatorClientPIN (0x06) handler.
//!
//! Implements PIN protocol v1 and v2: ECDH key agreement, PIN set/change,
//! PIN token retrieval with permissions, and retry counter management.

use super::cbor::{CborDecoder, CborEncoder};
use super::ctap::CtapError;
use pico_rs_sdk::crypto;
use pico_rs_sdk::crypto::aes::{aes256_cbc_decrypt, aes256_cbc_encrypt};
use pico_rs_sdk::crypto::ecc;
use pico_rs_sdk::crypto::symmetric::{hkdf_sha256, hmac_sha256};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

// ---- Constants ----

/// Maximum PIN retry attempts before lockout.
const MAX_PIN_RETRIES: u8 = 8;

/// Maximum UV retry attempts.
const MAX_UV_RETRIES: u8 = 3;

/// PIN token length in bytes.
const PIN_TOKEN_LEN: usize = 32;

/// Left-truncated HMAC length for PIN auth (v1: 16 bytes, v2: 32 bytes).
const PIN_AUTH_LEN_V1: usize = 16;
const PIN_AUTH_LEN_V2: usize = 32;

// ---- PIN protocol version ----

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

// ---- PIN command identifiers ----

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

// ---- PIN token permission flags ----

/// PIN token permission flags (CTAP2.1 §6.5.5.7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, defmt::Format)]
pub struct PinPermissions(pub u8);

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

    pub fn from_bits(bits: u8) -> Self {
        Self(bits)
    }
}

// ---- PIN persistent state ----

/// Persistent PIN state (stored in flash).
pub struct PinState {
    /// Whether a PIN has been set.
    pub is_set: bool,
    /// Remaining retry attempts (decremented on failure, reset on success).
    pub retries: u8,
    /// SHA-256 left-16 hash of the PIN (CTAP2 spec: left(SHA-256(pin), 16)).
    pub pin_hash: [u8; 16],
    /// Random salt for PIN hashing.
    pub pin_salt: [u8; 32],
}

impl PinState {
    pub fn new() -> Self {
        Self {
            is_set: false,
            retries: MAX_PIN_RETRIES,
            pin_hash: [0u8; 16],
            pin_salt: [0u8; 32],
        }
    }

    /// Check if PIN attempts are exhausted.
    pub fn is_locked(&self) -> bool {
        self.retries == 0
    }

    /// Decrement retry counter. Returns remaining retries.
    pub fn decrement_retries(&mut self) -> u8 {
        self.retries = self.retries.saturating_sub(1);
        self.retries
    }

    /// Reset retry counter to maximum (on successful PIN entry).
    pub fn reset_retries(&mut self) {
        self.retries = MAX_PIN_RETRIES;
    }

    /// Set a new PIN. Computes left-16 of SHA-256(pin).
    pub fn set_pin(&mut self, pin: &[u8]) {
        let full_hash = crypto::sha256(pin);
        self.pin_hash.copy_from_slice(&full_hash[..16]);
        self.is_set = true;
        self.retries = MAX_PIN_RETRIES;
    }

    /// Verify a PIN hash (left-16 of SHA-256(pin)) using constant-time comparison.
    pub fn verify_pin_hash(&self, candidate_hash: &[u8]) -> bool {
        if candidate_hash.len() < 16 {
            return false;
        }
        self.pin_hash.ct_eq(&candidate_hash[..16]).into()
    }
}

impl Default for PinState {
    fn default() -> Self {
        Self::new()
    }
}

// ---- PIN protocol runtime state ----

/// Per-session PIN protocol state (RAM only, cleared on reset).
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct PinProtocolState {
    /// Device's ephemeral ECDH private key.
    ecdh_private_key: [u8; 32],
    /// Device's ephemeral ECDH public key (SEC1 uncompressed, 65 bytes).
    #[zeroize(skip)]
    ecdh_public_key: [u8; 65],
    /// Derived shared secret (from ECDH + HKDF for v2, raw SHA-256 for v1).
    shared_secret: [u8; 32],
    /// Whether a shared secret has been established.
    #[zeroize(skip)]
    shared_secret_valid: bool,
    /// Current PIN token (random, regenerated per session).
    pin_token: [u8; PIN_TOKEN_LEN],
    /// Permissions associated with the current PIN token.
    #[zeroize(skip)]
    pin_token_permissions: u8,
    /// RP ID bound to the current PIN token (if any).
    #[zeroize(skip)]
    pin_token_rp_id_hash: Option<[u8; 32]>,
}

impl PinProtocolState {
    /// Create a new state with a fresh ECDH key pair and PIN token.
    pub fn new(rng: &mut (impl rand_core::CryptoRng + rand_core::RngCore)) -> Self {
        let mut state = Self {
            ecdh_private_key: [0u8; 32],
            ecdh_public_key: [0u8; 65],
            shared_secret: [0u8; 32],
            shared_secret_valid: false,
            pin_token: [0u8; PIN_TOKEN_LEN],
            pin_token_permissions: 0,
            pin_token_rp_id_hash: None,
        };
        state.regenerate_key_agreement(rng);
        rng.fill_bytes(&mut state.pin_token);
        state
    }

    /// Generate a new ECDH key pair.
    pub fn regenerate_key_agreement(
        &mut self,
        rng: &mut (impl rand_core::CryptoRng + rand_core::RngCore),
    ) {
        let keypair = ecc::generate_p256(rng).expect("P-256 key generation should not fail");
        self.ecdh_private_key.fill(0);
        self.ecdh_private_key[..keypair.private_key.len()].copy_from_slice(&keypair.private_key);
        self.ecdh_public_key.fill(0);
        self.ecdh_public_key[..keypair.public_key.len()].copy_from_slice(&keypair.public_key);
        self.shared_secret_valid = false;
    }

    /// Regenerate the PIN token.
    pub fn regenerate_pin_token(
        &mut self,
        rng: &mut (impl rand_core::CryptoRng + rand_core::RngCore),
    ) {
        rng.fill_bytes(&mut self.pin_token);
        self.pin_token_permissions = 0;
        self.pin_token_rp_id_hash = None;
    }

    /// Compute shared secret from peer's public key.
    ///
    /// PIN protocol v1: `SHA-256(ECDH(device_priv, peer_pub).x)`
    /// PIN protocol v2: `HKDF-SHA256(salt=32_zeros, IKM=ECDH.x, info="CTAP2 HMAC key")`
    pub fn compute_shared_secret(
        &mut self,
        protocol: PinProtocol,
        peer_public_key: &[u8],
    ) -> Result<(), CtapError> {
        let raw_shared = ecc::ecdh_p256(&self.ecdh_private_key, peer_public_key)
            .map_err(|_| CtapError::InvalidParameter)?;

        match protocol {
            PinProtocol::V1 => {
                self.shared_secret = crypto::sha256(&raw_shared);
            }
            PinProtocol::V2 => {
                let salt = [0u8; 32];
                hkdf_sha256(
                    &raw_shared,
                    &salt,
                    b"CTAP2 HMAC key",
                    &mut self.shared_secret,
                )
                .map_err(|_| CtapError::Other)?;
            }
        }
        self.shared_secret_valid = true;
        Ok(())
    }

    /// Decrypt a PIN using the shared secret.
    ///
    /// v1: AES-256-CBC decrypt with IV=0
    /// v2: AES-256-CBC decrypt with IV from first 16 bytes
    pub fn decrypt_pin(
        &self,
        protocol: PinProtocol,
        encrypted_pin: &[u8],
    ) -> Result<heapless::Vec<u8, 64>, CtapError> {
        if !self.shared_secret_valid {
            return Err(CtapError::PinAuthInvalid);
        }

        let mut output = [0u8; 64];
        let plaintext_len = match protocol {
            PinProtocol::V1 => {
                let iv = [0u8; 16];
                aes256_cbc_decrypt(&self.shared_secret, &iv, encrypted_pin, &mut output)
                    .map_err(|_| CtapError::PinInvalid)?
            }
            PinProtocol::V2 => {
                if encrypted_pin.len() < 16 {
                    return Err(CtapError::InvalidLength);
                }
                let mut iv = [0u8; 16];
                iv.copy_from_slice(&encrypted_pin[..16]);
                aes256_cbc_decrypt(&self.shared_secret, &iv, &encrypted_pin[16..], &mut output)
                    .map_err(|_| CtapError::PinInvalid)?
            }
        };

        let mut result = heapless::Vec::new();
        result
            .extend_from_slice(&output[..plaintext_len])
            .map_err(|_| CtapError::InvalidLength)?;

        output.zeroize();
        Ok(result)
    }

    /// Encrypt the PIN token for return to the client.
    ///
    /// v1: AES-256-CBC encrypt with IV=0
    /// v2: AES-256-CBC encrypt with random IV prepended
    pub fn encrypt_pin_token(
        &self,
        protocol: PinProtocol,
        rng: &mut (impl rand_core::CryptoRng + rand_core::RngCore),
    ) -> Result<heapless::Vec<u8, 80>, CtapError> {
        if !self.shared_secret_valid {
            return Err(CtapError::PinAuthInvalid);
        }

        let mut result = heapless::Vec::new();
        let mut output = [0u8; 64];

        match protocol {
            PinProtocol::V1 => {
                let iv = [0u8; 16];
                let ct_len =
                    aes256_cbc_encrypt(&self.shared_secret, &iv, &self.pin_token, &mut output)
                        .map_err(|_| CtapError::Other)?;
                result
                    .extend_from_slice(&output[..ct_len])
                    .map_err(|_| CtapError::InvalidLength)?;
            }
            PinProtocol::V2 => {
                let mut iv = [0u8; 16];
                rng.fill_bytes(&mut iv);
                result
                    .extend_from_slice(&iv)
                    .map_err(|_| CtapError::InvalidLength)?;
                let ct_len =
                    aes256_cbc_encrypt(&self.shared_secret, &iv, &self.pin_token, &mut output)
                        .map_err(|_| CtapError::Other)?;
                result
                    .extend_from_slice(&output[..ct_len])
                    .map_err(|_| CtapError::InvalidLength)?;
            }
        }
        output.zeroize();
        Ok(result)
    }

    /// Get a reference to the current PIN token.
    pub fn pin_token(&self) -> &[u8; PIN_TOKEN_LEN] {
        &self.pin_token
    }

    /// Get the ECDH public key (SEC1 uncompressed).
    pub fn ecdh_public_key(&self) -> &[u8; 65] {
        &self.ecdh_public_key
    }

    /// Set PIN token permissions and optional RP ID binding.
    pub fn set_permissions(&mut self, permissions: u8, rp_id: Option<&str>) {
        self.pin_token_permissions = permissions;
        self.pin_token_rp_id_hash = rp_id.map(|id| crypto::sha256(id.as_bytes()));
    }

    /// Check if the PIN token has the required permission.
    pub fn has_permission(&self, perm: PinPermissions) -> bool {
        PinPermissions(self.pin_token_permissions).contains(perm)
    }
}

// ---- PIN auth verification ----

/// Verify a pinUvAuthParam against the PIN token.
///
/// Computes `HMAC-SHA256(pinToken, data)` and performs constant-time
/// comparison with the expected `pin_auth`.
///
/// For v1: compare left-16 bytes.
/// For v2: compare full 32 bytes.
pub fn verify_pin_auth(
    protocol: PinProtocol,
    pin_token: &[u8; PIN_TOKEN_LEN],
    data: &[u8],
    pin_auth: &[u8],
) -> bool {
    let computed = hmac_sha256(pin_token, data);
    match protocol {
        PinProtocol::V1 => {
            if pin_auth.len() < PIN_AUTH_LEN_V1 {
                return false;
            }
            computed[..PIN_AUTH_LEN_V1]
                .ct_eq(&pin_auth[..PIN_AUTH_LEN_V1])
                .into()
        }
        PinProtocol::V2 => {
            if pin_auth.len() < PIN_AUTH_LEN_V2 {
                return false;
            }
            computed.ct_eq(&pin_auth[..PIN_AUTH_LEN_V2]).into()
        }
    }
}

// ---- Main handler ----

/// Process a ClientPIN CBOR request.
///
/// Returns the number of bytes written to `response`.
pub fn handle_client_pin(
    data: &[u8],
    response: &mut [u8],
    pin_state: &mut PinState,
    pin_protocol_state: &mut PinProtocolState,
    rng: &mut (impl rand_core::CryptoRng + rand_core::RngCore),
) -> Result<usize, CtapError> {
    // We parse a simplified version — full COSE key parsing is complex
    // and handled at a higher level. Here we parse the integer-keyed map.
    let mut dec = CborDecoder::new(data);
    let map_len = dec.expect_map()?;

    let mut protocol: Option<PinProtocol> = None;
    let mut sub_command: Option<PinCommand> = None;
    let mut pin_uv_auth_param: Option<&[u8]> = None;
    let mut new_pin_enc: Option<&[u8]> = None;
    let mut pin_hash_enc: Option<&[u8]> = None;
    let mut permissions: Option<u8> = None;
    let mut permissions_rp_id: Option<&str> = None;

    // For COSE key: extract x, y coordinates
    let mut cose_x: Option<&[u8]> = None;
    let mut cose_y: Option<&[u8]> = None;

    for _ in 0..map_len {
        let key = dec.expect_unsigned()? as u8;
        match key {
            0x01 => protocol = Some(PinProtocol::try_from(dec.expect_unsigned()? as u8)?),
            0x02 => sub_command = Some(PinCommand::try_from(dec.expect_unsigned()? as u8)?),
            0x03 => {
                // Parse COSE_Key map to extract x,y coordinates
                let cose_map_len = dec.expect_map()?;
                for _ in 0..cose_map_len {
                    let cose_key = dec.expect_int()?;
                    match cose_key {
                        -2 => cose_x = Some(dec.expect_bytes()?),
                        -3 => cose_y = Some(dec.expect_bytes()?),
                        _ => {
                            dec.skip_value()?;
                        }
                    }
                }
            }
            0x04 => pin_uv_auth_param = Some(dec.expect_bytes()?),
            0x05 => new_pin_enc = Some(dec.expect_bytes()?),
            0x06 => pin_hash_enc = Some(dec.expect_bytes()?),
            0x09 => permissions = Some(dec.expect_unsigned()? as u8),
            0x0A => permissions_rp_id = Some(dec.expect_text()?),
            _ => {
                dec.skip_value()?;
            }
        }
    }

    let sub_command = sub_command.ok_or(CtapError::MissingParameter)?;

    match sub_command {
        PinCommand::GetRetries => handle_get_retries(response, pin_state),

        PinCommand::GetKeyAgreement => {
            let proto = protocol.ok_or(CtapError::MissingParameter)?;
            handle_get_key_agreement(response, pin_protocol_state, proto)
        }

        PinCommand::SetPin => {
            let proto = protocol.ok_or(CtapError::MissingParameter)?;
            let new_pin_enc = new_pin_enc.ok_or(CtapError::MissingParameter)?;
            let pin_auth = pin_uv_auth_param.ok_or(CtapError::MissingParameter)?;

            // Reconstruct peer public key from COSE coordinates
            let peer_pub_key = reconstruct_sec1_point(cose_x, cose_y)?;
            pin_protocol_state.compute_shared_secret(proto, &peer_pub_key)?;

            // Verify pinUvAuthParam = HMAC(sharedSecret, newPinEnc)
            let computed_auth = hmac_sha256(&pin_protocol_state.shared_secret, new_pin_enc);
            let auth_valid: bool = match proto {
                PinProtocol::V1 => {
                    pin_auth.len() >= 16 && computed_auth[..16].ct_eq(&pin_auth[..16]).into()
                }
                PinProtocol::V2 => {
                    pin_auth.len() >= 32 && computed_auth.ct_eq(&pin_auth[..32]).into()
                }
            };
            if !auth_valid {
                return Err(CtapError::PinAuthInvalid);
            }

            if pin_state.is_set {
                return Err(CtapError::NotAllowed);
            }

            // Decrypt the new PIN
            let mut pin = pin_protocol_state.decrypt_pin(proto, new_pin_enc)?;

            // Remove padding (trailing zeros)
            let pin_len = pin.iter().rposition(|&b| b != 0).map_or(0, |p| p + 1);
            if pin_len < 4 || pin_len > 63 {
                pin.zeroize();
                return Err(CtapError::PinPolicyViolation);
            }

            pin_state.set_pin(&pin[..pin_len]);
            pin.zeroize();

            pin_protocol_state.regenerate_key_agreement(rng);

            if response.is_empty() {
                return Err(CtapError::InvalidLength);
            }
            // Empty success response
            Ok(0)
        }

        PinCommand::ChangePin => {
            let proto = protocol.ok_or(CtapError::MissingParameter)?;
            let new_pin_enc = new_pin_enc.ok_or(CtapError::MissingParameter)?;
            let pin_hash_enc = pin_hash_enc.ok_or(CtapError::MissingParameter)?;
            let pin_auth = pin_uv_auth_param.ok_or(CtapError::MissingParameter)?;

            if !pin_state.is_set {
                return Err(CtapError::PinNotSet);
            }
            if pin_state.is_locked() {
                return Err(CtapError::PinBlocked);
            }

            let peer_pub_key = reconstruct_sec1_point(cose_x, cose_y)?;
            pin_protocol_state.compute_shared_secret(proto, &peer_pub_key)?;

            // Verify pinUvAuthParam = HMAC(sharedSecret, newPinEnc || pinHashEnc)
            let mut auth_input = [0u8; 256];
            let auth_input_len = new_pin_enc.len() + pin_hash_enc.len();
            if auth_input_len > auth_input.len() {
                return Err(CtapError::InvalidLength);
            }
            auth_input[..new_pin_enc.len()].copy_from_slice(new_pin_enc);
            auth_input[new_pin_enc.len()..auth_input_len].copy_from_slice(pin_hash_enc);
            let computed_auth = hmac_sha256(
                &pin_protocol_state.shared_secret,
                &auth_input[..auth_input_len],
            );

            let auth_valid: bool = match proto {
                PinProtocol::V1 => {
                    pin_auth.len() >= 16 && computed_auth[..16].ct_eq(&pin_auth[..16]).into()
                }
                PinProtocol::V2 => {
                    pin_auth.len() >= 32 && computed_auth.ct_eq(&pin_auth[..32]).into()
                }
            };
            if !auth_valid {
                return Err(CtapError::PinAuthInvalid);
            }

            // Decrypt and verify old PIN hash
            let old_pin_hash = pin_protocol_state.decrypt_pin(proto, pin_hash_enc)?;
            if !pin_state.verify_pin_hash(&old_pin_hash) {
                pin_state.decrement_retries();
                pin_protocol_state.regenerate_key_agreement(rng);
                if pin_state.is_locked() {
                    return Err(CtapError::PinBlocked);
                }
                return Err(CtapError::PinInvalid);
            }

            // Decrypt new PIN
            let mut new_pin = pin_protocol_state.decrypt_pin(proto, new_pin_enc)?;
            let pin_len = new_pin.iter().rposition(|&b| b != 0).map_or(0, |p| p + 1);
            if pin_len < 4 || pin_len > 63 {
                new_pin.zeroize();
                return Err(CtapError::PinPolicyViolation);
            }

            pin_state.set_pin(&new_pin[..pin_len]);
            pin_state.reset_retries();
            new_pin.zeroize();

            pin_protocol_state.regenerate_key_agreement(rng);

            Ok(0)
        }

        PinCommand::GetPinToken => {
            let proto = protocol.ok_or(CtapError::MissingParameter)?;
            let pin_hash_enc = pin_hash_enc.ok_or(CtapError::MissingParameter)?;

            if !pin_state.is_set {
                return Err(CtapError::PinNotSet);
            }
            if pin_state.is_locked() {
                return Err(CtapError::PinBlocked);
            }

            let peer_pub_key = reconstruct_sec1_point(cose_x, cose_y)?;
            pin_protocol_state.compute_shared_secret(proto, &peer_pub_key)?;

            // Decrypt and verify PIN hash
            let pin_hash = pin_protocol_state.decrypt_pin(proto, pin_hash_enc)?;
            if !pin_state.verify_pin_hash(&pin_hash) {
                pin_state.decrement_retries();
                pin_protocol_state.regenerate_key_agreement(rng);
                if pin_state.is_locked() {
                    return Err(CtapError::PinBlocked);
                }
                return Err(CtapError::PinInvalid);
            }

            pin_state.reset_retries();
            pin_protocol_state.regenerate_pin_token(rng);

            // All permissions for legacy getPinToken
            pin_protocol_state.set_permissions(0xFF, None);

            // Return encrypted PIN token
            let encrypted_token = pin_protocol_state.encrypt_pin_token(proto, rng)?;
            encode_pin_token_response(response, &encrypted_token, proto)
        }

        PinCommand::GetPinUvAuthTokenUsingPinWithPermissions => {
            let proto = protocol.ok_or(CtapError::MissingParameter)?;
            let pin_hash_enc = pin_hash_enc.ok_or(CtapError::MissingParameter)?;
            let perms = permissions.ok_or(CtapError::MissingParameter)?;

            if !pin_state.is_set {
                return Err(CtapError::PinNotSet);
            }
            if pin_state.is_locked() {
                return Err(CtapError::PinBlocked);
            }
            if perms == 0 {
                return Err(CtapError::InvalidParameter);
            }

            let peer_pub_key = reconstruct_sec1_point(cose_x, cose_y)?;
            pin_protocol_state.compute_shared_secret(proto, &peer_pub_key)?;

            let pin_hash = pin_protocol_state.decrypt_pin(proto, pin_hash_enc)?;
            if !pin_state.verify_pin_hash(&pin_hash) {
                pin_state.decrement_retries();
                pin_protocol_state.regenerate_key_agreement(rng);
                if pin_state.is_locked() {
                    return Err(CtapError::PinBlocked);
                }
                return Err(CtapError::PinInvalid);
            }

            pin_state.reset_retries();
            pin_protocol_state.regenerate_pin_token(rng);
            pin_protocol_state.set_permissions(perms, permissions_rp_id);

            let encrypted_token = pin_protocol_state.encrypt_pin_token(proto, rng)?;
            encode_pin_token_response(response, &encrypted_token, proto)
        }

        PinCommand::GetPinUvAuthTokenUsingUvWithPermissions => {
            // UV not supported on this device
            Err(CtapError::InvalidParameter)
        }

        PinCommand::GetUvRetries => {
            // UV not supported; return max retries
            let mut enc = CborEncoder::new(response);
            enc.write_map_header(1)?;
            enc.write_unsigned(0x03)?; // uvRetries
            enc.write_unsigned(MAX_UV_RETRIES as usize)?;
            Ok(enc.position())
        }
    }
}

// ---- Sub-command handlers ----

fn handle_get_retries(response: &mut [u8], pin_state: &PinState) -> Result<usize, CtapError> {
    let mut enc = CborEncoder::new(response);
    enc.write_map_header(1)?;
    // 0x03: retries
    enc.write_unsigned(0x03)?;
    enc.write_unsigned(pin_state.retries as usize)?;
    Ok(enc.position())
}

fn handle_get_key_agreement(
    response: &mut [u8],
    state: &PinProtocolState,
    _protocol: PinProtocol,
) -> Result<usize, CtapError> {
    let pub_key = state.ecdh_public_key();
    if pub_key.len() != 65 || pub_key[0] != 0x04 {
        return Err(CtapError::Other);
    }

    let x = &pub_key[1..33];
    let y = &pub_key[33..65];

    let mut enc = CborEncoder::new(response);
    enc.write_map_header(1)?;

    // 0x01: keyAgreement (COSE_Key)
    enc.write_unsigned(0x01)?;
    enc.write_map_header(5)?;
    // 1: kty = 2 (EC2)
    enc.write_unsigned(1)?;
    enc.write_unsigned(2)?;
    // 3: alg = -25 (ECDH-ES+HKDF-256)
    enc.write_unsigned(3)?;
    enc.write_negative(-25)?;
    // -1: crv = 1 (P-256)
    enc.write_negative(-1)?;
    enc.write_unsigned(1)?;
    // -2: x coordinate
    enc.write_negative(-2)?;
    enc.write_bytes(x)?;
    // -3: y coordinate
    enc.write_negative(-3)?;
    enc.write_bytes(y)?;

    Ok(enc.position())
}

/// Reconstruct SEC1 uncompressed point (0x04 || x || y) from COSE coordinates.
fn reconstruct_sec1_point(x: Option<&[u8]>, y: Option<&[u8]>) -> Result<[u8; 65], CtapError> {
    let x = x.ok_or(CtapError::MissingParameter)?;
    let y = y.ok_or(CtapError::MissingParameter)?;
    if x.len() != 32 || y.len() != 32 {
        return Err(CtapError::InvalidParameter);
    }
    let mut point = [0u8; 65];
    point[0] = 0x04;
    point[1..33].copy_from_slice(x);
    point[33..65].copy_from_slice(y);
    Ok(point)
}

/// Encode a PIN token response: `{0x02: encrypted_pin_token}`
fn encode_pin_token_response(
    response: &mut [u8],
    encrypted_token: &[u8],
    _protocol: PinProtocol,
) -> Result<usize, CtapError> {
    let mut enc = CborEncoder::new(response);
    enc.write_map_header(1)?;
    enc.write_unsigned(0x02)?; // pinUvAuthToken
    enc.write_bytes(encrypted_token)?;
    Ok(enc.position())
}
