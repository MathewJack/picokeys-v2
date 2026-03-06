//! CTAP2.1 authenticatorMakeCredential (0x01) handler.
//!
//! Parses the CBOR request, validates parameters, generates a key pair,
//! constructs authData + attestation object, optionally stores a resident
//! credential, and returns the CBOR-encoded response.

use super::cbor::{CborDecoder, CborEncoder, CborValue};
use super::ctap::CtapError;
use crate::credential::{CredentialStore, PrivateKeyMaterial, ResidentCredential};
use heapless::{String, Vec};
use pico_rs_sdk::crypto;
use pico_rs_sdk::crypto::ecc;
use zeroize::Zeroize;

// ---- COSE algorithm identifiers ----

/// Supported COSE algorithm identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum CoseAlgorithm {
    Es256 = -7,
    EdDsa = -8,
    Es384 = -35,
    Es512 = -36,
    Es256K = -47,
}

impl CoseAlgorithm {
    pub fn from_i32(v: i32) -> Option<Self> {
        match v {
            -7 => Some(Self::Es256),
            -8 => Some(Self::EdDsa),
            -35 => Some(Self::Es384),
            -36 => Some(Self::Es512),
            -47 => Some(Self::Es256K),
            _ => None,
        }
    }
}

// ---- Request types ----

/// Parsed MakeCredential request (CTAP2 §6.1).
pub struct MakeCredentialRequest<'a> {
    pub client_data_hash: &'a [u8],
    pub rp_id: &'a str,
    pub rp_name: Option<&'a str>,
    pub user_id: &'a [u8],
    pub user_name: Option<&'a str>,
    pub user_display_name: Option<&'a str>,
    pub pub_key_cred_params: Vec<i32, 8>,
    pub exclude_list: Vec<&'a [u8], 8>,
    pub extensions: MakeCredentialExtensions,
    pub options: MakeCredentialOptions,
    pub pin_uv_auth_param: Option<&'a [u8]>,
    pub pin_uv_auth_protocol: Option<u8>,
    pub enterprise_attestation: Option<u8>,
}

#[derive(Default)]
pub struct MakeCredentialOptions {
    pub rk: bool,
    pub uv: bool,
}

#[derive(Default)]
pub struct MakeCredentialExtensions {
    pub hmac_secret: bool,
    pub cred_protect: Option<u8>,
    pub cred_blob: Option<Vec<u8, 32>>,
    pub large_blob_key: bool,
    pub min_pin_length: bool,
}

// ---- CBOR parsing ----

fn parse_make_credential_request<'a>(
    data: &'a [u8],
) -> Result<MakeCredentialRequest<'a>, CtapError> {
    let mut dec = CborDecoder::new(data);
    let map_len = dec.expect_map()?;

    let mut client_data_hash: Option<&[u8]> = None;
    let mut rp_id: Option<&str> = None;
    let mut rp_name: Option<&str> = None;
    let mut user_id: Option<&[u8]> = None;
    let mut user_name: Option<&str> = None;
    let mut user_display_name: Option<&str> = None;
    let mut pub_key_cred_params: Vec<i32, 8> = Vec::new();
    let mut exclude_list: Vec<&[u8], 8> = Vec::new();
    let mut extensions = MakeCredentialExtensions::default();
    let mut options = MakeCredentialOptions::default();
    let mut pin_uv_auth_param: Option<&[u8]> = None;
    let mut pin_uv_auth_protocol: Option<u8> = None;
    let mut enterprise_attestation: Option<u8> = None;

    for _ in 0..map_len {
        let key = dec.expect_unsigned()? as u8;
        match key {
            // 0x01: clientDataHash
            0x01 => {
                client_data_hash = Some(dec.expect_bytes()?);
            }
            // 0x02: rp (map with "id", "name")
            0x02 => {
                let rp_map_len = dec.expect_map()?;
                for _ in 0..rp_map_len {
                    let rp_key = dec.expect_text()?;
                    match rp_key {
                        "id" => rp_id = Some(dec.expect_text()?),
                        "name" => rp_name = Some(dec.expect_text()?),
                        _ => { dec.skip_value()?; }
                    }
                }
            }
            // 0x03: user (map with "id", "name", "displayName")
            0x03 => {
                let user_map_len = dec.expect_map()?;
                for _ in 0..user_map_len {
                    let user_key = dec.expect_text()?;
                    match user_key {
                        "id" => user_id = Some(dec.expect_bytes()?),
                        "name" => user_name = Some(dec.expect_text()?),
                        "displayName" => user_display_name = Some(dec.expect_text()?),
                        _ => { dec.skip_value()?; }
                    }
                }
            }
            // 0x04: pubKeyCredParams (array of {type, alg})
            0x04 => {
                let arr_len = dec.expect_array()?;
                for _ in 0..arr_len {
                    let entry_map_len = dec.expect_map()?;
                    let mut alg: Option<i32> = None;
                    for _ in 0..entry_map_len {
                        let entry_key = dec.expect_text()?;
                        match entry_key {
                            "alg" => alg = Some(dec.expect_int()? as i32),
                            _ => { dec.skip_value()?; }
                        }
                    }
                    if let Some(a) = alg {
                        let _ = pub_key_cred_params.push(a);
                    }
                }
            }
            // 0x05: excludeList (array of {type, id})
            0x05 => {
                let arr_len = dec.expect_array()?;
                for _ in 0..arr_len {
                    let entry_map_len = dec.expect_map()?;
                    let mut cred_id: Option<&[u8]> = None;
                    for _ in 0..entry_map_len {
                        let entry_key = dec.expect_text()?;
                        match entry_key {
                            "id" => cred_id = Some(dec.expect_bytes()?),
                            _ => { dec.skip_value()?; }
                        }
                    }
                    if let Some(id) = cred_id {
                        let _ = exclude_list.push(id);
                    }
                }
            }
            // 0x06: extensions
            0x06 => {
                let ext_map_len = dec.expect_map()?;
                for _ in 0..ext_map_len {
                    let ext_key = dec.expect_text()?;
                    match ext_key {
                        "hmac-secret" => extensions.hmac_secret = dec.expect_bool()?,
                        "credProtect" => {
                            extensions.cred_protect = Some(dec.expect_unsigned()? as u8);
                        }
                        "credBlob" => {
                            let blob_bytes = dec.expect_bytes()?;
                            if blob_bytes.len() <= 32 {
                                let mut v = Vec::new();
                                let _ = v.extend_from_slice(blob_bytes);
                                extensions.cred_blob = Some(v);
                            } else {
                                return Err(CtapError::LimitExceeded);
                            }
                        }
                        "largeBlobKey" => extensions.large_blob_key = dec.expect_bool()?,
                        "minPinLength" => extensions.min_pin_length = dec.expect_bool()?,
                        _ => { dec.skip_value()?; }
                    }
                }
            }
            // 0x07: options
            0x07 => {
                let opt_map_len = dec.expect_map()?;
                for _ in 0..opt_map_len {
                    let opt_key = dec.expect_text()?;
                    match opt_key {
                        "rk" => options.rk = dec.expect_bool()?,
                        "uv" => options.uv = dec.expect_bool()?,
                        _ => { dec.skip_value()?; }
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
            // 0x0A: enterpriseAttestation
            0x0A => {
                enterprise_attestation = Some(dec.expect_unsigned()? as u8);
            }
            _ => {
                dec.skip_value()?;
            }
        }
    }

    let client_data_hash = client_data_hash.ok_or(CtapError::MissingParameter)?;
    if client_data_hash.len() != 32 {
        return Err(CtapError::InvalidLength);
    }
    let rp_id = rp_id.ok_or(CtapError::MissingParameter)?;
    let user_id = user_id.ok_or(CtapError::MissingParameter)?;
    if pub_key_cred_params.is_empty() {
        return Err(CtapError::MissingParameter);
    }

    Ok(MakeCredentialRequest {
        client_data_hash,
        rp_id,
        rp_name,
        user_id,
        user_name,
        user_display_name,
        pub_key_cred_params,
        exclude_list,
        extensions,
        options,
        pin_uv_auth_param,
        pin_uv_auth_protocol,
        enterprise_attestation,
    })
}

// ---- Algorithm selection ----

/// Select the first supported algorithm from the client's priority list.
fn select_algorithm(params: &[i32]) -> Result<CoseAlgorithm, CtapError> {
    for &alg_id in params {
        if let Some(alg) = CoseAlgorithm::from_i32(alg_id) {
            match alg {
                CoseAlgorithm::Es256 | CoseAlgorithm::EdDsa | CoseAlgorithm::Es256K => {
                    return Ok(alg);
                }
                // ES384/ES512 not yet fully supported in SDK
                _ => continue,
            }
        }
    }
    Err(CtapError::InvalidParameter)
}

// ---- COSE public key encoding ----

/// Encode an EC2 COSE public key: {1: kty, 3: alg, -1: crv, -2: x, -3: y}
fn encode_cose_ec2_key(
    enc: &mut CborEncoder,
    alg: i32,
    crv: i32,
    x: &[u8],
    y: &[u8],
) -> Result<(), CtapError> {
    enc.write_map_header(5)?;
    // 1: kty = 2 (EC2)
    enc.write_unsigned(1)?;
    enc.write_unsigned(2)?;
    // 3: alg
    enc.write_unsigned(3)?;
    enc.write_negative(alg)?;
    // -1: crv
    enc.write_negative(-1)?;
    enc.write_unsigned(crv as usize)?;
    // -2: x
    enc.write_negative(-2)?;
    enc.write_bytes(x)?;
    // -3: y
    enc.write_negative(-3)?;
    enc.write_bytes(y)?;
    Ok(())
}

/// Encode an OKP COSE public key: {1: kty, 3: alg, -1: crv, -2: x}
fn encode_cose_okp_key(
    enc: &mut CborEncoder,
    x: &[u8],
) -> Result<(), CtapError> {
    enc.write_map_header(4)?;
    // 1: kty = 1 (OKP)
    enc.write_unsigned(1)?;
    enc.write_unsigned(1)?;
    // 3: alg = -8 (EdDSA)
    enc.write_unsigned(3)?;
    enc.write_negative(-8)?;
    // -1: crv = 6 (Ed25519)
    enc.write_negative(-1)?;
    enc.write_unsigned(6)?;
    // -2: x
    enc.write_negative(-2)?;
    enc.write_bytes(x)?;
    Ok(())
}

/// Encode the COSE public key into a buffer. Returns bytes written.
fn encode_cose_public_key(
    alg: CoseAlgorithm,
    pub_key: &ecc::EcPublicKey,
    buf: &mut [u8],
) -> Result<usize, CtapError> {
    let mut enc = CborEncoder::new(buf);
    match alg {
        CoseAlgorithm::Es256 => {
            // Uncompressed SEC1: 0x04 || x(32) || y(32)
            if pub_key.bytes.len() != 65 {
                return Err(CtapError::InvalidParameter);
            }
            let x = &pub_key.bytes[1..33];
            let y = &pub_key.bytes[33..65];
            // crv = 1 (P-256)
            encode_cose_ec2_key(&mut enc, -7, 1, x, y)?;
        }
        CoseAlgorithm::Es256K => {
            if pub_key.bytes.len() != 65 {
                return Err(CtapError::InvalidParameter);
            }
            let x = &pub_key.bytes[1..33];
            let y = &pub_key.bytes[33..65];
            // crv = 8 (secp256k1)
            encode_cose_ec2_key(&mut enc, -47, 8, x, y)?;
        }
        CoseAlgorithm::EdDsa => {
            // Ed25519 public key: 32 bytes
            if pub_key.bytes.len() != 32 {
                return Err(CtapError::InvalidParameter);
            }
            encode_cose_okp_key(&mut enc, &pub_key.bytes)?;
        }
        _ => return Err(CtapError::InvalidParameter),
    }
    Ok(enc.position())
}

// ---- Auth data construction ----

/// Flags byte values.
const FLAG_UP: u8 = 0x01;
const FLAG_UV: u8 = 0x04;
const FLAG_AT: u8 = 0x40;
const FLAG_ED: u8 = 0x80;

/// AAGUID placeholder (overridden by config at runtime).
const DEFAULT_AAGUID: [u8; 16] = [0u8; 16];

/// Build the authenticator data for MakeCredential.
///
/// Layout: `rp_id_hash(32) | flags(1) | sign_count(4) |
///          aaguid(16) | cred_id_len(2 BE) | cred_id | cose_pub_key`
///
/// If extensions are present, the extensions CBOR map is appended after
/// the attested credential data.
fn build_auth_data(
    rp_id_hash: &[u8; 32],
    aaguid: &[u8; 16],
    credential_id: &[u8],
    cose_pub_key: &[u8],
    uv: bool,
    has_extensions: bool,
    extensions_cbor: Option<&[u8]>,
    buf: &mut [u8],
) -> Result<usize, CtapError> {
    let mut pos = 0usize;

    // rp_id_hash (32 bytes)
    if buf.len() < 32 {
        return Err(CtapError::InvalidLength);
    }
    buf[pos..pos + 32].copy_from_slice(rp_id_hash);
    pos += 32;

    // flags (1 byte)
    let mut flags = FLAG_UP | FLAG_AT;
    if uv {
        flags |= FLAG_UV;
    }
    if has_extensions {
        flags |= FLAG_ED;
    }
    if pos >= buf.len() {
        return Err(CtapError::InvalidLength);
    }
    buf[pos] = flags;
    pos += 1;

    // sign_count (4 bytes, big-endian, starts at 0)
    if pos + 4 > buf.len() {
        return Err(CtapError::InvalidLength);
    }
    buf[pos..pos + 4].copy_from_slice(&0u32.to_be_bytes());
    pos += 4;

    // aaguid (16 bytes)
    if pos + 16 > buf.len() {
        return Err(CtapError::InvalidLength);
    }
    buf[pos..pos + 16].copy_from_slice(aaguid);
    pos += 16;

    // cred_id_len (2 bytes, big-endian)
    let cred_id_len = credential_id.len() as u16;
    if pos + 2 > buf.len() {
        return Err(CtapError::InvalidLength);
    }
    buf[pos..pos + 2].copy_from_slice(&cred_id_len.to_be_bytes());
    pos += 2;

    // cred_id
    if pos + credential_id.len() > buf.len() {
        return Err(CtapError::InvalidLength);
    }
    buf[pos..pos + credential_id.len()].copy_from_slice(credential_id);
    pos += credential_id.len();

    // COSE public key (already CBOR-encoded)
    if pos + cose_pub_key.len() > buf.len() {
        return Err(CtapError::InvalidLength);
    }
    buf[pos..pos + cose_pub_key.len()].copy_from_slice(cose_pub_key);
    pos += cose_pub_key.len();

    // Extensions CBOR map (if present)
    if let Some(ext_data) = extensions_cbor {
        if pos + ext_data.len() > buf.len() {
            return Err(CtapError::InvalidLength);
        }
        buf[pos..pos + ext_data.len()].copy_from_slice(ext_data);
        pos += ext_data.len();
    }

    Ok(pos)
}

// ---- Extensions processing ----

/// Encode MakeCredential extensions output as CBOR map.
/// Returns bytes written.
fn encode_extensions(
    ext: &MakeCredentialExtensions,
    hmac_secret_cred_random: Option<&[u8; 64]>,
    large_blob_key_value: Option<&[u8; 32]>,
    buf: &mut [u8],
) -> Result<usize, CtapError> {
    // Count how many extension outputs we have
    let mut count = 0usize;
    if ext.hmac_secret && hmac_secret_cred_random.is_some() {
        count += 1;
    }
    if ext.cred_protect.is_some() {
        count += 1;
    }
    if ext.cred_blob.is_some() {
        count += 1;
    }
    if ext.large_blob_key && large_blob_key_value.is_some() {
        count += 1;
    }
    if ext.min_pin_length {
        count += 1;
    }

    if count == 0 {
        return Ok(0);
    }

    let mut enc = CborEncoder::new(buf);
    enc.write_map_header(count)?;

    if ext.hmac_secret && hmac_secret_cred_random.is_some() {
        enc.write_text("hmac-secret")?;
        enc.write_bool(true)?;
    }
    if let Some(level) = ext.cred_protect {
        enc.write_text("credProtect")?;
        enc.write_unsigned(level as usize)?;
    }
    if ext.cred_blob.is_some() {
        enc.write_text("credBlob")?;
        enc.write_bool(true)?;
    }
    if ext.large_blob_key && large_blob_key_value.is_some() {
        enc.write_text("largeBlobKey")?;
        enc.write_bool(true)?;
    }
    if ext.min_pin_length {
        enc.write_text("minPinLength")?;
        enc.write_bool(true)?;
    }

    Ok(enc.position())
}

// ---- Signing ----

/// Sign data with the given algorithm and private key.
fn sign_with_algorithm(
    alg: CoseAlgorithm,
    private_key: &[u8],
    data: &[u8],
) -> Result<Vec<u8, 128>, CtapError> {
    let mut sig_buf: Vec<u8, 128> = Vec::new();
    match alg {
        CoseAlgorithm::Es256 => {
            let sig = ecc::ecdsa_sign_p256(private_key, data)
                .map_err(|_| CtapError::Other)?;
            sig_buf
                .extend_from_slice(&sig)
                .map_err(|_| CtapError::InvalidLength)?;
        }
        CoseAlgorithm::Es256K => {
            let sig = ecc::ecdsa_sign_k256(private_key, data)
                .map_err(|_| CtapError::Other)?;
            sig_buf
                .extend_from_slice(&sig)
                .map_err(|_| CtapError::InvalidLength)?;
        }
        CoseAlgorithm::EdDsa => {
            let sig = ecc::ed25519_sign(private_key, data)
                .map_err(|_| CtapError::Other)?;
            sig_buf
                .extend_from_slice(&sig)
                .map_err(|_| CtapError::InvalidLength)?;
        }
        _ => return Err(CtapError::InvalidParameter),
    }
    Ok(sig_buf)
}

// ---- Main handler ----

/// Process a MakeCredential CBOR request.
///
/// `data` is the raw CBOR payload (after the command byte).
/// `response` receives the encoded CBOR response.
/// Returns the number of bytes written to `response`.
pub fn handle_make_credential(
    data: &[u8],
    response: &mut [u8],
    credential_store: &mut CredentialStore,
    aaguid: &[u8; 16],
    rng: &mut (impl rand_core::CryptoRng + rand_core::RngCore),
    pin_uv_auth_verified: bool,
) -> Result<usize, CtapError> {
    let request = parse_make_credential_request(data)?;

    // 1. Compute rp_id_hash
    let rp_id_hash = crypto::sha256(request.rp_id.as_bytes());

    // 2. Check exclude list
    for excluded_id in &request.exclude_list {
        if credential_store.find_by_credential_id(excluded_id).is_some() {
            return Err(CtapError::CredentialExcluded);
        }
    }

    // 3. If rk requested, check space
    if request.options.rk && credential_store.count() >= credential_store.max_capacity() {
        return Err(CtapError::KeyStoreFull);
    }

    // 4. Check UV requirements
    let uv = if request.options.uv {
        if !pin_uv_auth_verified {
            return Err(CtapError::PinAuthInvalid);
        }
        true
    } else {
        pin_uv_auth_verified
    };

    // 5. Select algorithm
    let alg = select_algorithm(&request.pub_key_cred_params)?;

    // 6. Generate key pair
    let (priv_key, pub_key) = match alg {
        CoseAlgorithm::Es256 => ecc::generate_p256(rng).map_err(|_| CtapError::Other)?,
        CoseAlgorithm::Es256K => ecc::generate_k256(rng).map_err(|_| CtapError::Other)?,
        CoseAlgorithm::EdDsa => ecc::generate_ed25519(rng).map_err(|_| CtapError::Other)?,
        _ => return Err(CtapError::InvalidParameter),
    };

    // 7. Encode COSE public key
    let mut cose_pub_key_buf = [0u8; 256];
    let cose_pub_key_len = encode_cose_public_key(alg, &pub_key, &mut cose_pub_key_buf)?;
    let cose_pub_key = &cose_pub_key_buf[..cose_pub_key_len];

    // 8. Generate credential ID (encrypted private key + rp_id_hash)
    let mut nonce = [0u8; 16];
    rng.fill_bytes(&mut nonce);
    // Use a zero MKEK-derived key for now — in production the KEK comes from the MKEK
    let cred_encryption_key = [0u8; 32]; // placeholder; real impl derives from MKEK
    let credential_id =
        crate::credential::id::generate_credential_id(&priv_key.bytes, &rp_id_hash, &nonce, &cred_encryption_key);

    // 9. Process extensions
    let mut hmac_secret_random: Option<[u8; 64]> = None;
    if request.extensions.hmac_secret {
        let mut random = [0u8; 64];
        rng.fill_bytes(&mut random);
        hmac_secret_random = Some(random);
    }

    let mut large_blob_key_value: Option<[u8; 32]> = None;
    if request.extensions.large_blob_key {
        let mut lbk = [0u8; 32];
        rng.fill_bytes(&mut lbk);
        large_blob_key_value = Some(lbk);
    }

    let has_extensions = request.extensions.hmac_secret
        || request.extensions.cred_protect.is_some()
        || request.extensions.cred_blob.is_some()
        || request.extensions.large_blob_key
        || request.extensions.min_pin_length;

    let mut ext_cbor_buf = [0u8; 128];
    let ext_cbor_len = encode_extensions(
        &request.extensions,
        hmac_secret_random.as_ref(),
        large_blob_key_value.as_ref(),
        &mut ext_cbor_buf,
    )?;
    let ext_cbor = if ext_cbor_len > 0 {
        Some(&ext_cbor_buf[..ext_cbor_len])
    } else {
        None
    };

    // 10. Build auth_data
    let mut auth_data_buf = [0u8; 512];
    let auth_data_len = build_auth_data(
        &rp_id_hash,
        aaguid,
        &credential_id,
        cose_pub_key,
        uv,
        has_extensions,
        ext_cbor,
        &mut auth_data_buf,
    )?;
    let auth_data = &auth_data_buf[..auth_data_len];

    // 11. Self-attestation signature: sign(authData || clientDataHash)
    let mut sig_input = [0u8; 600];
    if auth_data_len + 32 > sig_input.len() {
        return Err(CtapError::InvalidLength);
    }
    sig_input[..auth_data_len].copy_from_slice(auth_data);
    sig_input[auth_data_len..auth_data_len + 32].copy_from_slice(request.client_data_hash);
    let sig_input_len = auth_data_len + 32;

    let signature = sign_with_algorithm(alg, &priv_key.bytes, &sig_input[..sig_input_len])?;

    // 12. Store credential if rk
    if request.options.rk {
        let mut cred = ResidentCredential::new();
        cred.rp_id_hash = rp_id_hash;
        cred.credential_id
            .extend_from_slice(&credential_id)
            .map_err(|_| CtapError::InvalidLength)?;
        cred.user_id
            .extend_from_slice(request.user_id)
            .map_err(|_| CtapError::InvalidLength)?;
        if let Some(name) = request.user_name {
            cred.user_name
                .push_str(name)
                .map_err(|_| CtapError::InvalidLength)?;
        }
        if let Some(display) = request.user_display_name {
            cred.display_name
                .push_str(display)
                .map_err(|_| CtapError::InvalidLength)?;
        }
        cred.private_key = PrivateKeyMaterial::from_slice(&priv_key.bytes)
            .map_err(|_| CtapError::Other)?;
        cred.public_key_cose
            .extend_from_slice(cose_pub_key)
            .map_err(|_| CtapError::InvalidLength)?;
        cred.sign_count = 0;
        cred.discoverable = true;
        cred.cred_protect_level = request.extensions.cred_protect.unwrap_or(0);
        cred.hmac_secret = hmac_secret_random;
        if let Some(ref blob) = request.extensions.cred_blob {
            let mut cred_blob = Vec::new();
            cred_blob
                .extend_from_slice(blob)
                .map_err(|_| CtapError::InvalidLength)?;
            cred.cred_blob = Some(cred_blob);
        }
        cred.large_blob_key = large_blob_key_value;

        credential_store
            .store_credential(&cred)
            .map_err(|_| CtapError::KeyStoreFull)?;
    }

    // 13. Build attestation object CBOR response:
    //     { 1: "packed", 2: authData, 3: {alg: ..., sig: ...} }
    let mut enc = CborEncoder::new(response);
    enc.write_map_header(3)?;

    // 1 (fmt): "packed"
    enc.write_unsigned(1)?;
    enc.write_text("packed")?;

    // 2 (authData): byte string
    enc.write_unsigned(2)?;
    enc.write_bytes(auth_data)?;

    // 3 (attStmt): map with alg + sig
    enc.write_unsigned(3)?;
    enc.write_map_header(2)?;
    enc.write_text("alg")?;
    enc.write_negative(alg as i32)?;
    enc.write_text("sig")?;
    enc.write_bytes(&signature)?;

    // Zeroize sensitive local buffers
    let mut sig_input_z = sig_input;
    sig_input_z.zeroize();

    Ok(enc.position())
}
