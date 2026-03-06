//! CTAP2.1 authenticatorCredentialManagement (0x0A) handler.
//!
//! Provides enumeration, deletion, and update of stored resident credentials.
//! All operations require the `cm` (credential management) permission in the
//! PIN token.

use super::cbor::{CborDecoder, CborEncoder};
use super::ctap::CtapError;
use crate::credential::CredentialStore;
use heapless::Vec;

// ---- Sub-command identifiers ----

/// Credential management sub-commands (CTAP2.1 §6.8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CredMgmtCommand {
    GetCredsMetadata = 0x01,
    EnumerateRpsBegin = 0x02,
    EnumerateRpsGetNextRp = 0x03,
    EnumerateCredentialsBegin = 0x04,
    EnumerateCredentialsGetNextCredential = 0x05,
    DeleteCredential = 0x06,
    UpdateUserInformation = 0x07,
}

impl TryFrom<u8> for CredMgmtCommand {
    type Error = CtapError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(Self::GetCredsMetadata),
            0x02 => Ok(Self::EnumerateRpsBegin),
            0x03 => Ok(Self::EnumerateRpsGetNextRp),
            0x04 => Ok(Self::EnumerateCredentialsBegin),
            0x05 => Ok(Self::EnumerateCredentialsGetNextCredential),
            0x06 => Ok(Self::DeleteCredential),
            0x07 => Ok(Self::UpdateUserInformation),
            _ => Err(CtapError::InvalidSubcommand),
        }
    }
}

// ---- Enumeration state ----

/// Iteration state for RP enumeration.
pub struct RpEnumerationState {
    /// Unique RP ID hashes found in the store.
    rp_id_hashes: Vec<[u8; 32], 64>,
    /// Current index in the enumeration.
    next_index: usize,
}

/// Iteration state for credential enumeration within an RP.
pub struct CredEnumerationState {
    /// RP ID hash being enumerated.
    rp_id_hash: [u8; 32],
    /// Slot indices for credentials matching the RP.
    slots: Vec<u8, 128>,
    /// Current index.
    next_index: usize,
}

// ---- CBOR parsing ----

/// Parsed credential management request.
struct CredMgmtRequest<'a> {
    sub_command: CredMgmtCommand,
    rp_id_hash: Option<&'a [u8]>,
    credential_id: Option<&'a [u8]>,
    user_name: Option<&'a str>,
    user_display_name: Option<&'a str>,
}

fn parse_cred_mgmt_request<'a>(data: &'a [u8]) -> Result<CredMgmtRequest<'a>, CtapError> {
    let mut dec = CborDecoder::new(data);
    let map_len = dec.expect_map()?;

    let mut sub_command: Option<CredMgmtCommand> = None;
    let mut rp_id_hash: Option<&[u8]> = None;
    let mut credential_id: Option<&[u8]> = None;
    let mut user_name: Option<&str> = None;
    let mut user_display_name: Option<&str> = None;

    for _ in 0..map_len {
        let key = dec.expect_unsigned()? as u8;
        match key {
            // 0x01: subCommand
            0x01 => {
                sub_command = Some(CredMgmtCommand::try_from(dec.expect_unsigned()? as u8)?);
            }
            // 0x02: subCommandParams (map)
            0x02 => {
                let params_map_len = dec.expect_map()?;
                for _ in 0..params_map_len {
                    let param_key = dec.expect_unsigned()? as u8;
                    match param_key {
                        // 0x01: rpIDHash
                        0x01 => rp_id_hash = Some(dec.expect_bytes()?),
                        // 0x02: credentialID (map with "id" and "type")
                        0x02 => {
                            let cred_map_len = dec.expect_map()?;
                            for _ in 0..cred_map_len {
                                let cred_key = dec.expect_text()?;
                                match cred_key {
                                    "id" => credential_id = Some(dec.expect_bytes()?),
                                    _ => {
                                        dec.skip_value()?;
                                    }
                                }
                            }
                        }
                        // 0x03: user (map with "name", "displayName")
                        0x03 => {
                            let user_map_len = dec.expect_map()?;
                            for _ in 0..user_map_len {
                                let user_key = dec.expect_text()?;
                                match user_key {
                                    "name" => user_name = Some(dec.expect_text()?),
                                    "displayName" => {
                                        user_display_name = Some(dec.expect_text()?);
                                    }
                                    _ => {
                                        dec.skip_value()?;
                                    }
                                }
                            }
                        }
                        _ => {
                            dec.skip_value()?;
                        }
                    }
                }
            }
            // 0x03: pinUvAuthProtocol (validated by caller)
            // 0x04: pinUvAuthParam (validated by caller)
            _ => {
                dec.skip_value()?;
            }
        }
    }

    let sub_command = sub_command.ok_or(CtapError::MissingParameter)?;

    Ok(CredMgmtRequest {
        sub_command,
        rp_id_hash,
        credential_id,
        user_name,
        user_display_name,
    })
}

// ---- Main handler ----

/// Process a credentialManagement CBOR request.
///
/// The caller must have verified that the PIN token has the `cm` permission
/// before calling this function.
///
/// Returns the number of bytes written to `response`.
pub fn handle_credential_management(
    data: &[u8],
    response: &mut [u8],
    credential_store: &mut CredentialStore,
    rp_enum_state: &mut Option<RpEnumerationState>,
    cred_enum_state: &mut Option<CredEnumerationState>,
) -> Result<usize, CtapError> {
    let request = parse_cred_mgmt_request(data)?;

    match request.sub_command {
        CredMgmtCommand::GetCredsMetadata => handle_get_creds_metadata(response, credential_store),
        CredMgmtCommand::EnumerateRpsBegin => {
            handle_enumerate_rps_begin(response, credential_store, rp_enum_state)
        }
        CredMgmtCommand::EnumerateRpsGetNextRp => {
            handle_enumerate_rps_next(response, credential_store, rp_enum_state)
        }
        CredMgmtCommand::EnumerateCredentialsBegin => {
            let rp_id_hash = request.rp_id_hash.ok_or(CtapError::MissingParameter)?;
            if rp_id_hash.len() != 32 {
                return Err(CtapError::InvalidParameter);
            }
            let mut hash = [0u8; 32];
            hash.copy_from_slice(rp_id_hash);
            handle_enumerate_credentials_begin(response, credential_store, &hash, cred_enum_state)
        }
        CredMgmtCommand::EnumerateCredentialsGetNextCredential => {
            handle_enumerate_credentials_next(response, credential_store, cred_enum_state)
        }
        CredMgmtCommand::DeleteCredential => {
            let cred_id = request.credential_id.ok_or(CtapError::MissingParameter)?;
            handle_delete_credential(credential_store, cred_id)
        }
        CredMgmtCommand::UpdateUserInformation => {
            let cred_id = request.credential_id.ok_or(CtapError::MissingParameter)?;
            handle_update_user_info(
                credential_store,
                cred_id,
                request.user_name,
                request.user_display_name,
            )
        }
    }
}

// ---- Sub-command implementations ----

/// GetCredsMetadata: returns existing count and remaining capacity.
///
/// Response: `{0x01: existingCount, 0x02: maxPossibleRemaining}`
fn handle_get_creds_metadata(
    response: &mut [u8],
    store: &CredentialStore,
) -> Result<usize, CtapError> {
    let existing = store.count();
    let remaining = store.max_capacity().saturating_sub(existing);

    let mut enc = CborEncoder::new(response);
    enc.write_map_header(2)?;
    // 0x01: existingResidentCredentialsCount
    enc.write_unsigned(0x01)?;
    enc.write_unsigned(existing)?;
    // 0x02: maxPossibleRemainingResidentCredentialsCount
    enc.write_unsigned(0x02)?;
    enc.write_unsigned(remaining)?;

    Ok(enc.position())
}

/// EnumerateRPsBegin: start RP enumeration and return the first RP.
///
/// Response: `{0x03: {id: rpId}, 0x04: rpIdHash, 0x05: totalRPs}`
fn handle_enumerate_rps_begin(
    response: &mut [u8],
    store: &CredentialStore,
    rp_state: &mut Option<RpEnumerationState>,
) -> Result<usize, CtapError> {
    let rp_ids = store.enumerate_rp_ids();
    if rp_ids.is_empty() {
        return Err(CtapError::NoCredentials);
    }

    let total_rps = rp_ids.len();
    let first_hash = rp_ids[0];

    *rp_state = Some(RpEnumerationState {
        rp_id_hashes: rp_ids,
        next_index: 1,
    });

    encode_rp_response(response, &first_hash, total_rps)
}

/// EnumerateRPsGetNextRP: return the next RP in the enumeration.
fn handle_enumerate_rps_next(
    response: &mut [u8],
    _store: &CredentialStore,
    rp_state: &mut Option<RpEnumerationState>,
) -> Result<usize, CtapError> {
    let state = rp_state.as_mut().ok_or(CtapError::NotAllowed)?;

    if state.next_index >= state.rp_id_hashes.len() {
        *rp_state = None;
        return Err(CtapError::NotAllowed);
    }

    let hash = state.rp_id_hashes[state.next_index];
    let total = state.rp_id_hashes.len();
    state.next_index += 1;

    // Clear state if we've exhausted all RPs
    if state.next_index >= state.rp_id_hashes.len() {
        *rp_state = None;
    }

    encode_rp_response(response, &hash, total)
}

/// Encode an RP enumeration response entry.
fn encode_rp_response(
    response: &mut [u8],
    rp_id_hash: &[u8; 32],
    total_rps: usize,
) -> Result<usize, CtapError> {
    let mut enc = CborEncoder::new(response);
    enc.write_map_header(3)?;

    // 0x03: rp (map with just the hash since we don't store the RP ID string
    // for non-discoverable flow; for discoverable we'd need rp.id)
    enc.write_unsigned(0x03)?;
    enc.write_map_header(1)?;
    enc.write_text("id")?;
    // We don't have the original rp.id string, so we return the hash
    // In a full implementation, rp.id would be stored with the credential
    enc.write_text("")?;

    // 0x04: rpIDHash
    enc.write_unsigned(0x04)?;
    enc.write_bytes(rp_id_hash)?;

    // 0x05: totalRPs
    enc.write_unsigned(0x05)?;
    enc.write_unsigned(total_rps)?;

    Ok(enc.position())
}

/// EnumerateCredentialsBegin: start credential enumeration for an RP.
///
/// Response: `{0x06: user, 0x07: credentialID, 0x08: publicKey, 0x09: totalCredentials, 0x0A: credProtect}`
fn handle_enumerate_credentials_begin(
    response: &mut [u8],
    store: &CredentialStore,
    rp_id_hash: &[u8; 32],
    cred_state: &mut Option<CredEnumerationState>,
) -> Result<usize, CtapError> {
    let slots = store.find_by_rp_id(rp_id_hash);
    if slots.is_empty() {
        return Err(CtapError::NoCredentials);
    }

    let total = slots.len();
    let first_slot = slots[0];

    *cred_state = Some(CredEnumerationState {
        rp_id_hash: *rp_id_hash,
        slots,
        next_index: 1,
    });

    encode_credential_response(response, store, first_slot, total)
}

/// EnumerateCredentialsGetNextCredential: return the next credential.
fn handle_enumerate_credentials_next(
    response: &mut [u8],
    store: &CredentialStore,
    cred_state: &mut Option<CredEnumerationState>,
) -> Result<usize, CtapError> {
    let state = cred_state.as_mut().ok_or(CtapError::NotAllowed)?;

    if state.next_index >= state.slots.len() {
        *cred_state = None;
        return Err(CtapError::NotAllowed);
    }

    let slot = state.slots[state.next_index];
    let total = state.slots.len();
    state.next_index += 1;

    if state.next_index >= state.slots.len() {
        *cred_state = None;
    }

    encode_credential_response(response, store, slot, total)
}

/// Encode a credential enumeration response entry.
fn encode_credential_response(
    response: &mut [u8],
    store: &CredentialStore,
    slot: u8,
    total_credentials: usize,
) -> Result<usize, CtapError> {
    let cred = store.get_credential(slot).ok_or(CtapError::NoCredentials)?;

    // Count map entries: user, credentialID, publicKey, totalCredentials, credProtect
    let mut map_entries = 4usize;
    if cred.cred_protect_level > 0 {
        map_entries += 1;
    }
    if cred.large_blob_key.is_some() {
        map_entries += 1;
    }

    let mut enc = CborEncoder::new(response);
    enc.write_map_header(map_entries)?;

    // 0x06: user
    enc.write_unsigned(0x06)?;
    let mut user_map_entries = 1usize;
    if !cred.user_name.is_empty() {
        user_map_entries += 1;
    }
    if !cred.display_name.is_empty() {
        user_map_entries += 1;
    }
    enc.write_map_header(user_map_entries)?;
    enc.write_text("id")?;
    enc.write_bytes(&cred.user_id)?;
    if !cred.user_name.is_empty() {
        enc.write_text("name")?;
        enc.write_text(cred.user_name.as_str())?;
    }
    if !cred.display_name.is_empty() {
        enc.write_text("displayName")?;
        enc.write_text(cred.display_name.as_str())?;
    }

    // 0x07: credentialID
    enc.write_unsigned(0x07)?;
    enc.write_map_header(2)?;
    enc.write_text("id")?;
    enc.write_bytes(&cred.credential_id)?;
    enc.write_text("type")?;
    enc.write_text("public-key")?;

    // 0x08: publicKey (COSE_Key, already CBOR-encoded)
    enc.write_unsigned(0x08)?;
    enc.write_raw(&cred.public_key_cose)?;

    // 0x09: totalCredentials
    enc.write_unsigned(0x09)?;
    enc.write_unsigned(total_credentials)?;

    // 0x0A: credProtect (if non-zero)
    if cred.cred_protect_level > 0 {
        enc.write_unsigned(0x0A)?;
        enc.write_unsigned(cred.cred_protect_level as usize)?;
    }

    // 0x0B: largeBlobKey (if present)
    if let Some(ref lbk) = cred.large_blob_key {
        enc.write_unsigned(0x0B)?;
        enc.write_bytes(lbk)?;
    }

    Ok(enc.position())
}

/// DeleteCredential: remove a credential by its ID.
fn handle_delete_credential(
    store: &mut CredentialStore,
    credential_id: &[u8],
) -> Result<usize, CtapError> {
    let slot = store
        .find_by_credential_id(credential_id)
        .ok_or(CtapError::NoCredentials)?;
    store
        .delete_credential(slot)
        .map_err(|_| CtapError::NoCredentials)?;
    // Success: empty response (0 bytes)
    Ok(0)
}

/// UpdateUserInformation: update userName/displayName for a stored credential.
fn handle_update_user_info(
    store: &mut CredentialStore,
    credential_id: &[u8],
    new_user_name: Option<&str>,
    new_display_name: Option<&str>,
) -> Result<usize, CtapError> {
    let slot = store
        .find_by_credential_id(credential_id)
        .ok_or(CtapError::NoCredentials)?;
    let cred = store
        .get_credential_mut(slot)
        .ok_or(CtapError::NoCredentials)?;

    if let Some(name) = new_user_name {
        cred.user_name = heapless::String::new();
        cred.user_name
            .push_str(name)
            .map_err(|_| CtapError::InvalidLength)?;
    }
    if let Some(display_name) = new_display_name {
        cred.display_name = heapless::String::new();
        cred.display_name
            .push_str(display_name)
            .map_err(|_| CtapError::InvalidLength)?;
    }

    // Success: empty response
    Ok(0)
}
