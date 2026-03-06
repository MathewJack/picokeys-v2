//! CTAP2.1 authenticatorGetAssertion (0x02) handler.
//!
//! Looks up matching credentials by allow-list or discoverable credentials,
//! signs the assertion, and returns the CBOR-encoded response.

use super::cbor::{CborDecoder, CborEncoder};
use super::ctap::CtapError;
use crate::credential::CredentialStore;
use heapless::Vec;
use pico_rs_sdk::crypto;
use pico_rs_sdk::crypto::ecc;
use zeroize::Zeroize;

// ---- Request types ----

/// Parsed GetAssertion request (CTAP2 §6.2).
pub struct GetAssertionRequest<'a> {
    pub rp_id: &'a str,
    pub client_data_hash: &'a [u8],
    pub allow_list: Vec<&'a [u8], 8>,
    pub extensions: GetAssertionExtensions<'a>,
    pub options: GetAssertionOptions,
    pub pin_uv_auth_param: Option<&'a [u8]>,
    pub pin_uv_auth_protocol: Option<u8>,
}

#[derive(Default)]
pub struct GetAssertionOptions {
    pub up: bool,
    pub uv: bool,
}

#[derive(Default)]
pub struct GetAssertionExtensions<'a> {
    pub hmac_secret: Option<HmacSecretInput<'a>>,
}

pub struct HmacSecretInput<'a> {
    pub key_agreement: &'a [u8],
    pub salt_enc: &'a [u8],
    pub salt_auth: &'a [u8],
}

/// State for GetNextAssertion iteration.
pub struct AssertionState {
    /// Indices of matched credential slots.
    pub matched_slots: Vec<u8, 128>,
    /// Index into matched_slots for the next assertion to return.
    pub next_index: usize,
    /// RP ID hash for this assertion session.
    pub rp_id_hash: [u8; 32],
    /// Client data hash for signing.
    pub client_data_hash: [u8; 32],
    /// Whether UV was verified for this session.
    pub uv_verified: bool,
}

// ---- Flags ----

const FLAG_UP: u8 = 0x01;
const FLAG_UV: u8 = 0x04;
const FLAG_ED: u8 = 0x80;

// ---- CBOR parsing ----

fn parse_get_assertion_request<'a>(data: &'a [u8]) -> Result<GetAssertionRequest<'a>, CtapError> {
    let mut dec = CborDecoder::new(data);
    let map_len = dec.expect_map()?;

    let mut rp_id: Option<&str> = None;
    let mut client_data_hash: Option<&[u8]> = None;
    let mut allow_list: Vec<&[u8], 8> = Vec::new();
    let mut extensions = GetAssertionExtensions::default();
    let mut options = GetAssertionOptions {
        up: true,
        uv: false,
    };
    let mut pin_uv_auth_param: Option<&[u8]> = None;
    let mut pin_uv_auth_protocol: Option<u8> = None;

    for _ in 0..map_len {
        let key = dec.expect_unsigned()? as u8;
        match key {
            // 0x01: rpId
            0x01 => {
                rp_id = Some(dec.expect_text()?);
            }
            // 0x02: clientDataHash
            0x02 => {
                client_data_hash = Some(dec.expect_bytes()?);
            }
            // 0x03: allowList
            0x03 => {
                let arr_len = dec.expect_array()?;
                for _ in 0..arr_len {
                    let entry_map_len = dec.expect_map()?;
                    let mut cred_id: Option<&[u8]> = None;
                    for _ in 0..entry_map_len {
                        let entry_key = dec.expect_text()?;
                        match entry_key {
                            "id" => cred_id = Some(dec.expect_bytes()?),
                            _ => {
                                dec.skip_value()?;
                            }
                        }
                    }
                    if let Some(id) = cred_id {
                        let _ = allow_list.push(id);
                    }
                }
            }
            // 0x04: extensions
            0x04 => {
                let ext_map_len = dec.expect_map()?;
                for _ in 0..ext_map_len {
                    let ext_key = dec.expect_text()?;
                    match ext_key {
                        "hmac-secret" => {
                            // hmac-secret extension input is a map:
                            // {1: keyAgreement, 2: saltEnc, 3: saltAuth}
                            let hmac_map_len = dec.expect_map()?;
                            let mut key_agreement: Option<&[u8]> = None;
                            let mut salt_enc: Option<&[u8]> = None;
                            let mut salt_auth: Option<&[u8]> = None;
                            for _ in 0..hmac_map_len {
                                let hk = dec.expect_unsigned()? as u8;
                                match hk {
                                    0x01 => {
                                        // keyAgreement is a COSE_Key — skip the map,
                                        // store raw bytes for processing later.
                                        // For simplicity, read as bytes.
                                        key_agreement = Some(dec.expect_bytes()?);
                                    }
                                    0x02 => salt_enc = Some(dec.expect_bytes()?),
                                    0x03 => salt_auth = Some(dec.expect_bytes()?),
                                    _ => {
                                        dec.skip_value()?;
                                    }
                                }
                            }
                            if let (Some(ka), Some(se), Some(sa)) =
                                (key_agreement, salt_enc, salt_auth)
                            {
                                extensions.hmac_secret = Some(HmacSecretInput {
                                    key_agreement: ka,
                                    salt_enc: se,
                                    salt_auth: sa,
                                });
                            }
                        }
                        _ => {
                            dec.skip_value()?;
                        }
                    }
                }
            }
            // 0x05: options
            0x05 => {
                let opt_map_len = dec.expect_map()?;
                for _ in 0..opt_map_len {
                    let opt_key = dec.expect_text()?;
                    match opt_key {
                        "up" => options.up = dec.expect_bool()?,
                        "uv" => options.uv = dec.expect_bool()?,
                        _ => {
                            dec.skip_value()?;
                        }
                    }
                }
            }
            // 0x08: pinUvAuthParam
            0x08 => {
                pin_uv_auth_param = Some(dec.expect_bytes()?);
            }
            // 0x09: pinUvAuthProtocol
            0x09 => {
                pin_uv_auth_protocol = Some(dec.expect_unsigned()? as u8);
            }
            _ => {
                dec.skip_value()?;
            }
        }
    }

    let rp_id = rp_id.ok_or(CtapError::MissingParameter)?;
    let client_data_hash = client_data_hash.ok_or(CtapError::MissingParameter)?;
    if client_data_hash.len() != 32 {
        return Err(CtapError::InvalidLength);
    }

    Ok(GetAssertionRequest {
        rp_id,
        client_data_hash,
        allow_list,
        extensions,
        options,
        pin_uv_auth_param,
        pin_uv_auth_protocol,
    })
}

// ---- Auth data for assertion ----

/// Build assertion authenticator data (no attested credential data).
///
/// Layout: `rp_id_hash(32) | flags(1) | sign_count(4) [| extensions_cbor]`
fn build_assertion_auth_data(
    rp_id_hash: &[u8; 32],
    sign_count: u32,
    uv: bool,
    up: bool,
    extensions_cbor: Option<&[u8]>,
    buf: &mut [u8],
) -> Result<usize, CtapError> {
    let has_ext = extensions_cbor.is_some();
    let min_len = 32 + 1 + 4 + extensions_cbor.map_or(0, |e| e.len());
    if buf.len() < min_len {
        return Err(CtapError::InvalidLength);
    }

    let mut pos = 0usize;

    // rp_id_hash
    buf[pos..pos + 32].copy_from_slice(rp_id_hash);
    pos += 32;

    // flags
    let mut flags = 0u8;
    if up {
        flags |= FLAG_UP;
    }
    if uv {
        flags |= FLAG_UV;
    }
    if has_ext {
        flags |= FLAG_ED;
    }
    buf[pos] = flags;
    pos += 1;

    // sign_count (big-endian)
    buf[pos..pos + 4].copy_from_slice(&sign_count.to_be_bytes());
    pos += 4;

    // extensions CBOR
    if let Some(ext) = extensions_cbor {
        buf[pos..pos + ext.len()].copy_from_slice(ext);
        pos += ext.len();
    }

    Ok(pos)
}

// ---- Detect algorithm from COSE public key ----

/// Detect the algorithm from the stored COSE public key CBOR.
/// Looks for the "alg" field (key 3) in the COSE key map.
fn detect_algorithm_from_cose_key(cose_key: &[u8]) -> Result<i32, CtapError> {
    let mut dec = CborDecoder::new(cose_key);
    let map_len = dec.expect_map()?;
    for _ in 0..map_len {
        let key = dec.expect_int()?;
        if key == 3 {
            return Ok(dec.expect_int()? as i32);
        }
        dec.skip_value()?;
    }
    Err(CtapError::InvalidCredential)
}

// ---- Signing ----

/// Sign `auth_data || client_data_hash` with the credential's private key.
fn sign_assertion(
    alg: i32,
    private_key: &[u8],
    auth_data: &[u8],
    client_data_hash: &[u8],
) -> Result<Vec<u8, 144>, CtapError> {
    // Concatenate auth_data || client_data_hash
    let total_len = auth_data.len() + client_data_hash.len();
    let mut sig_input = [0u8; 600];
    if total_len > sig_input.len() {
        return Err(CtapError::InvalidLength);
    }
    sig_input[..auth_data.len()].copy_from_slice(auth_data);
    sig_input[auth_data.len()..total_len].copy_from_slice(client_data_hash);

    let mut sig: Vec<u8, 144> = Vec::new();
    match alg {
        -7 => {
            let s = ecc::ecdsa_sign_p256(private_key, &sig_input[..total_len])
                .map_err(|_| CtapError::Other)?;
            sig.extend_from_slice(&s)
                .map_err(|_| CtapError::InvalidLength)?;
        }
        -35 => {
            let s = ecc::ecdsa_sign_p384(private_key, &sig_input[..total_len])
                .map_err(|_| CtapError::Other)?;
            sig.extend_from_slice(&s)
                .map_err(|_| CtapError::InvalidLength)?;
        }
        -36 => {
            let s = ecc::ecdsa_sign_p521(private_key, &sig_input[..total_len])
                .map_err(|_| CtapError::Other)?;
            sig.extend_from_slice(&s)
                .map_err(|_| CtapError::InvalidLength)?;
        }
        -47 => {
            let s = ecc::ecdsa_sign_k256(private_key, &sig_input[..total_len])
                .map_err(|_| CtapError::Other)?;
            sig.extend_from_slice(&s)
                .map_err(|_| CtapError::InvalidLength)?;
        }
        -8 => {
            let s = ecc::ed25519_sign(private_key, &sig_input[..total_len])
                .map_err(|_| CtapError::Other)?;
            sig.extend_from_slice(&s)
                .map_err(|_| CtapError::InvalidLength)?;
        }
        _ => return Err(CtapError::InvalidCredential),
    }

    // Zeroize sig_input
    sig_input.zeroize();

    Ok(sig)
}

// ---- hmac-secret extension processing ----

/// Process the hmac-secret extension for GetAssertion.
///
/// Computes `HMAC-SHA256(credRandom[0..32], salt1)` and optionally
/// `HMAC-SHA256(credRandom[32..64], salt2)`.
///
/// Returns the extension output CBOR.
#[allow(dead_code)]
fn process_hmac_secret(
    _cred_random: &[u8; 64],
    _input: &HmacSecretInput,
    _buf: &mut [u8],
) -> Result<usize, CtapError> {
    // Full implementation requires shared secret from PIN protocol to decrypt
    // salts and encrypt output. For now, compute using credential random directly.
    // In production this goes through the PIN protocol's shared secret.

    // The HMAC-SHA256 computation itself:
    // output1 = HMAC-SHA256(credRandom[0..32], salt1)
    // output2 = HMAC-SHA256(credRandom[32..64], salt2) if salt2 present
    // Then encrypt with shared secret and return.

    // Stub: return empty until full PIN protocol integration
    Ok(0)
}

// ---- Main handler ----

/// Process a GetAssertion CBOR request.
///
/// Returns the number of bytes written to `response`.
/// If multiple credentials match, the caller should store `assertion_state`
/// for subsequent GetNextAssertion calls.
pub fn handle_get_assertion(
    data: &[u8],
    response: &mut [u8],
    credential_store: &mut CredentialStore,
    assertion_state: &mut Option<AssertionState>,
    pin_uv_auth_verified: bool,
) -> Result<usize, CtapError> {
    let request = parse_get_assertion_request(data)?;

    // 1. Compute rp_id_hash
    let rp_id_hash = crypto::sha256(request.rp_id.as_bytes());

    // 2. Find matching credentials
    let matched_slots = if !request.allow_list.is_empty() {
        // Match by credential ID from allow list
        let mut slots: Vec<u8, 128> = Vec::new();
        for cred_id in &request.allow_list {
            if let Some(slot) = credential_store.find_by_credential_id(cred_id) {
                // Verify the credential belongs to this RP
                if let Some(cred) = credential_store.get_credential(slot) {
                    if cred.rp_id_hash == rp_id_hash {
                        let _ = slots.push(slot);
                    }
                }
            }
        }
        slots
    } else {
        // Discoverable credentials by rp_id_hash
        credential_store.find_by_rp_id(&rp_id_hash)
    };

    // 3. No credentials found
    if matched_slots.is_empty() {
        return Err(CtapError::NoCredentials);
    }

    // 4. Check UV / credProtect requirements
    let uv = if request.options.uv {
        if !pin_uv_auth_verified {
            return Err(CtapError::PinAuthInvalid);
        }
        true
    } else {
        pin_uv_auth_verified
    };

    // Check credProtect level 3: never return without UV
    let first_slot = matched_slots[0];
    if let Some(cred) = credential_store.get_credential(first_slot) {
        if cred.cred_protect_level >= 3 && !uv {
            return Err(CtapError::NotAllowed);
        }
        // Level 2: don't return in discoverable flow without UV
        if cred.cred_protect_level >= 2 && request.allow_list.is_empty() && !uv {
            return Err(CtapError::NotAllowed);
        }
    }

    let total_credentials = matched_slots.len();

    // 5. Process first credential
    let cred = credential_store
        .get_credential_mut(first_slot)
        .ok_or(CtapError::NoCredentials)?;

    // Increment sign count
    cred.sign_count = cred.sign_count.wrapping_add(1);
    let sign_count = cred.sign_count;

    // Build auth_data
    let mut auth_data_buf = [0u8; 256];
    let auth_data_len = build_assertion_auth_data(
        &rp_id_hash,
        sign_count,
        uv,
        request.options.up,
        None, // Extensions processed separately
        &mut auth_data_buf,
    )?;
    let auth_data = &auth_data_buf[..auth_data_len];

    // Detect algorithm from stored COSE public key
    let alg = detect_algorithm_from_cose_key(&cred.public_key_cose)?;

    // Sign auth_data || client_data_hash
    let signature = sign_assertion(
        alg,
        &cred.private_key.bytes,
        auth_data,
        request.client_data_hash,
    )?;

    // Gather credential info for response
    let credential_id: Vec<u8, 128> = {
        let mut v = Vec::new();
        v.extend_from_slice(&cred.credential_id)
            .map_err(|_| CtapError::InvalidLength)?;
        v
    };
    let is_discoverable = cred.discoverable;
    let user_id: Vec<u8, 64> = {
        let mut v = Vec::new();
        v.extend_from_slice(&cred.user_id)
            .map_err(|_| CtapError::InvalidLength)?;
        v
    };
    let user_name_str: Option<Vec<u8, 64>> = if !cred.user_name.is_empty() {
        let mut v = Vec::new();
        v.extend_from_slice(cred.user_name.as_bytes())
            .map_err(|_| CtapError::InvalidLength)?;
        Some(v)
    } else {
        None
    };
    let display_name_str: Option<Vec<u8, 64>> = if !cred.display_name.is_empty() {
        let mut v = Vec::new();
        v.extend_from_slice(cred.display_name.as_bytes())
            .map_err(|_| CtapError::InvalidLength)?;
        Some(v)
    } else {
        None
    };

    // 6. Store iteration state for GetNextAssertion
    if total_credentials > 1 {
        let mut cdh = [0u8; 32];
        cdh.copy_from_slice(request.client_data_hash);
        *assertion_state = Some(AssertionState {
            matched_slots: matched_slots.clone(),
            next_index: 1,
            rp_id_hash,
            client_data_hash: cdh,
            uv_verified: uv,
        });
    } else {
        *assertion_state = None;
    }

    // 7. Build CBOR response
    encode_assertion_response(
        response,
        &credential_id,
        auth_data,
        &signature,
        is_discoverable,
        &user_id,
        user_name_str.as_deref(),
        display_name_str.as_deref(),
        total_credentials,
    )
}

/// Process a GetNextAssertion request.
///
/// Returns the next assertion from the stored iterator state.
pub fn handle_get_next_assertion(
    response: &mut [u8],
    credential_store: &mut CredentialStore,
    assertion_state: &mut Option<AssertionState>,
) -> Result<usize, CtapError> {
    let state = assertion_state.as_mut().ok_or(CtapError::NotAllowed)?;

    if state.next_index >= state.matched_slots.len() {
        *assertion_state = None;
        return Err(CtapError::NotAllowed);
    }

    let slot = state.matched_slots[state.next_index];
    state.next_index += 1;

    let total_credentials = state.matched_slots.len();
    let rp_id_hash = state.rp_id_hash;
    let uv = state.uv_verified;

    let cred = credential_store
        .get_credential_mut(slot)
        .ok_or(CtapError::NoCredentials)?;

    cred.sign_count = cred.sign_count.wrapping_add(1);
    let sign_count = cred.sign_count;

    let mut auth_data_buf = [0u8; 256];
    let auth_data_len =
        build_assertion_auth_data(&rp_id_hash, sign_count, uv, true, None, &mut auth_data_buf)?;
    let auth_data = &auth_data_buf[..auth_data_len];

    let alg = detect_algorithm_from_cose_key(&cred.public_key_cose)?;
    let signature = sign_assertion(
        alg,
        &cred.private_key.bytes,
        auth_data,
        &state.client_data_hash,
    )?;

    let credential_id: Vec<u8, 128> = {
        let mut v = Vec::new();
        v.extend_from_slice(&cred.credential_id)
            .map_err(|_| CtapError::InvalidLength)?;
        v
    };
    let is_discoverable = cred.discoverable;
    let user_id: Vec<u8, 64> = {
        let mut v = Vec::new();
        v.extend_from_slice(&cred.user_id)
            .map_err(|_| CtapError::InvalidLength)?;
        v
    };
    let user_name_str: Option<Vec<u8, 64>> = if !cred.user_name.is_empty() {
        let mut v = Vec::new();
        v.extend_from_slice(cred.user_name.as_bytes())
            .map_err(|_| CtapError::InvalidLength)?;
        Some(v)
    } else {
        None
    };
    let display_name_str: Option<Vec<u8, 64>> = if !cred.display_name.is_empty() {
        let mut v = Vec::new();
        v.extend_from_slice(cred.display_name.as_bytes())
            .map_err(|_| CtapError::InvalidLength)?;
        Some(v)
    } else {
        None
    };

    // Clear state if this was the last
    if state.next_index >= state.matched_slots.len() {
        *assertion_state = None;
    }

    encode_assertion_response(
        response,
        &credential_id,
        auth_data,
        &signature,
        is_discoverable,
        &user_id,
        user_name_str.as_deref(),
        display_name_str.as_deref(),
        total_credentials,
    )
}

/// Encode a GetAssertion / GetNextAssertion CBOR response.
///
/// Response map:
///   1 (credential): {id: bstr, type: "public-key"}
///   2 (authData): bstr
///   3 (signature): bstr
///   4 (user): {id: bstr [, name: tstr, displayName: tstr]}  — if discoverable
///   5 (numberOfCredentials): uint — only on first assertion
fn encode_assertion_response(
    response: &mut [u8],
    credential_id: &[u8],
    auth_data: &[u8],
    signature: &[u8],
    is_discoverable: bool,
    user_id: &[u8],
    user_name: Option<&[u8]>,
    display_name: Option<&[u8]>,
    total_credentials: usize,
) -> Result<usize, CtapError> {
    // Count response map entries: credential, authData, signature + optional user, numberOfCredentials
    let mut map_entries = 3usize;
    if is_discoverable {
        map_entries += 1;
    }
    if total_credentials > 1 {
        map_entries += 1;
    }

    let mut enc = CborEncoder::new(response);
    enc.write_map_header(map_entries)?;

    // 1: credential descriptor
    enc.write_unsigned(1)?;
    enc.write_map_header(2)?;
    enc.write_text("id")?;
    enc.write_bytes(credential_id)?;
    enc.write_text("type")?;
    enc.write_text("public-key")?;

    // 2: authData
    enc.write_unsigned(2)?;
    enc.write_bytes(auth_data)?;

    // 3: signature
    enc.write_unsigned(3)?;
    enc.write_bytes(signature)?;

    // 4: user (only for discoverable credentials)
    if is_discoverable {
        enc.write_unsigned(4)?;
        let mut user_map_entries = 1usize;
        if user_name.is_some() {
            user_map_entries += 1;
        }
        if display_name.is_some() {
            user_map_entries += 1;
        }
        enc.write_map_header(user_map_entries)?;
        enc.write_text("id")?;
        enc.write_bytes(user_id)?;
        if let Some(name) = user_name {
            let s = core::str::from_utf8(name).unwrap_or("");
            enc.write_text("name")?;
            enc.write_text(s)?;
        }
        if let Some(dn) = display_name {
            let s = core::str::from_utf8(dn).unwrap_or("");
            enc.write_text("displayName")?;
            enc.write_text(s)?;
        }
    }

    // 5: numberOfCredentials
    if total_credentials > 1 {
        enc.write_unsigned(5)?;
        enc.write_unsigned(total_credentials)?;
    }

    Ok(enc.position())
}
