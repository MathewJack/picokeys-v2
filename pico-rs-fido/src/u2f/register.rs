//! U2F Register command (INS = 0x01).
//!
//! Response format per FIDO U2F Raw Message Format spec:
//! `0x05 | pubkey(65) | key_handle_len(1) | key_handle | attestation_cert | signature`

use super::{SW_WRONG_DATA, SW_WRONG_LENGTH};
use crate::credential::id::generate_credential_id;
use pico_rs_sdk::crypto::ecc::generate_p256;
use pico_rs_sdk::crypto::sha256;

/// Self-signed attestation certificate (minimal X.509 v3 structure).
///
/// This is a placeholder self-signed cert. In production, use a real attestation
/// certificate stored in flash at FileId::AttestationCert.
fn build_self_signed_attestation_cert(
    public_key: &[u8; 65],
    signing_key: &[u8],
) -> heapless::Vec<u8, 512> {
    let mut cert: heapless::Vec<u8, 512> = heapless::Vec::new();

    // Minimal X.509 v3 DER structure:
    // SEQUENCE {
    //   SEQUENCE { -- TBSCertificate
    //     [0] EXPLICIT INTEGER 2  -- version v3
    //     INTEGER 1               -- serial
    //     SEQUENCE { OID sha256WithECDSA }
    //     SEQUENCE { SET { SEQUENCE { OID CN, UTF8 "PicoKeys" }}}  -- issuer
    //     SEQUENCE { UTCTime, UTCTime }  -- validity
    //     SEQUENCE { SET { SEQUENCE { OID CN, UTF8 "PicoKeys" }}}  -- subject
    //     SEQUENCE { -- SubjectPublicKeyInfo
    //       SEQUENCE { OID ecPublicKey, OID prime256v1 }
    //       BIT STRING (public key)
    //     }
    //   }
    //   SEQUENCE { OID sha256WithECDSA }
    //   BIT STRING (signature)
    // }

    // Pre-built DER for the TBS certificate preamble (version, serial, alg, issuer, validity, subject)
    #[rustfmt::skip]
    let tbs_prefix: &[u8] = &[
        // [0] EXPLICIT version v3
        0xA0, 0x03, 0x02, 0x01, 0x02,
        // serial number = 1
        0x02, 0x01, 0x01,
        // algorithm: sha256WithECDSA (1.2.840.10045.4.3.2)
        0x30, 0x0A, 0x06, 0x08,
        0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02,
        // issuer: CN=PicoKeys
        0x30, 0x15, 0x31, 0x13, 0x30, 0x11,
        0x06, 0x03, 0x55, 0x04, 0x03,
        0x0C, 0x08, b'P', b'i', b'c', b'o', b'K', b'e', b'y', b's',
        // validity: 2024-01-01 to 2034-01-01
        0x30, 0x1E,
        0x17, 0x0D, b'2', b'4', b'0', b'1', b'0', b'1', b'0', b'0', b'0', b'0', b'0', b'0', b'Z',
        0x17, 0x0D, b'3', b'4', b'0', b'1', b'0', b'1', b'0', b'0', b'0', b'0', b'0', b'0', b'Z',
        // subject: CN=PicoKeys
        0x30, 0x15, 0x31, 0x13, 0x30, 0x11,
        0x06, 0x03, 0x55, 0x04, 0x03,
        0x0C, 0x08, b'P', b'i', b'c', b'o', b'K', b'e', b'y', b's',
    ];

    // SubjectPublicKeyInfo for EC P-256
    #[rustfmt::skip]
    let spki_prefix: &[u8] = &[
        0x30, 0x59, // SEQUENCE (89 bytes)
        0x30, 0x13, // SEQUENCE (19 bytes) - algorithm
        0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, // OID ecPublicKey
        0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, // OID prime256v1
        0x03, 0x42, 0x00, // BIT STRING (66 bytes, 0 unused bits)
    ];

    // Build TBS certificate
    let tbs_content_len = tbs_prefix.len() + spki_prefix.len() + 65; // 65 = uncompressed point
    let mut tbs = [0u8; 300];
    let mut tbs_len = 0;

    // TBS SEQUENCE header
    tbs[0] = 0x30;
    if tbs_content_len < 128 {
        tbs[1] = tbs_content_len as u8;
        tbs_len = 2;
    } else {
        tbs[1] = 0x81;
        tbs[2] = tbs_content_len as u8;
        tbs_len = 3;
    }

    tbs[tbs_len..tbs_len + tbs_prefix.len()].copy_from_slice(tbs_prefix);
    tbs_len += tbs_prefix.len();

    tbs[tbs_len..tbs_len + spki_prefix.len()].copy_from_slice(spki_prefix);
    tbs_len += spki_prefix.len();

    tbs[tbs_len..tbs_len + 65].copy_from_slice(public_key);
    tbs_len += 65;

    // Sign TBS with the attestation key
    let tbs_hash = sha256(&tbs[..tbs_len]);
    let sig_der = pico_rs_sdk::crypto::ecc::ecdsa_sign_p256(signing_key, &tbs_hash)
        .unwrap_or_else(|_| heapless::Vec::new());

    // Algorithm identifier for outer cert
    #[rustfmt::skip]
    let alg_id: &[u8] = &[
        0x30, 0x0A, 0x06, 0x08,
        0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02,
    ];

    // BIT STRING wrapping signature
    let sig_bitstring_len = 1 + sig_der.len(); // 1 for unused bits byte

    // Total outer SEQUENCE content
    let outer_content = tbs_len + alg_id.len() + 2 + sig_bitstring_len;

    // Outer SEQUENCE header
    if outer_content < 128 {
        let _ = cert.push(0x30);
        let _ = cert.push(outer_content as u8);
    } else if outer_content < 256 {
        let _ = cert.push(0x30);
        let _ = cert.push(0x81);
        let _ = cert.push(outer_content as u8);
    } else {
        let _ = cert.push(0x30);
        let _ = cert.push(0x82);
        let _ = cert.push((outer_content >> 8) as u8);
        let _ = cert.push((outer_content & 0xFF) as u8);
    }

    // TBS certificate
    let _ = cert.extend_from_slice(&tbs[..tbs_len]);

    // Algorithm identifier
    let _ = cert.extend_from_slice(alg_id);

    // Signature as BIT STRING
    let _ = cert.push(0x03); // BIT STRING tag
    if sig_bitstring_len < 128 {
        let _ = cert.push(sig_bitstring_len as u8);
    } else {
        let _ = cert.push(0x81);
        let _ = cert.push(sig_bitstring_len as u8);
    }
    let _ = cert.push(0x00); // zero unused bits
    let _ = cert.extend_from_slice(&sig_der);

    cert
}

/// U2F Register command handler.
///
/// Generates a P-256 key pair, builds an encrypted key handle (credential ID),
/// and returns the registration response per FIDO U2F spec.
///
/// Response: `0x05 | pubkey(65) | key_handle_len(1) | key_handle | attestation_cert | signature`
pub fn u2f_register(
    challenge: &[u8; 32],
    app_id: &[u8; 32],
    response: &mut [u8],
    rng: &mut (impl rand_core::CryptoRng + rand_core::RngCore),
    encryption_key: &[u8; 32],
) -> Result<usize, u16> {
    // Generate P-256 key pair
    let (priv_key, pub_key) = generate_p256(rng).map_err(|_| SW_WRONG_DATA)?;

    // The public key must be 65 bytes (uncompressed P-256 point: 0x04 || x || y)
    if pub_key.bytes.len() != 65 {
        return Err(SW_WRONG_DATA);
    }
    let mut pub_key_bytes = [0u8; 65];
    pub_key_bytes.copy_from_slice(&pub_key.bytes);

    // Generate random nonce for credential ID encryption
    let mut nonce = [0u8; 16];
    rng.fill_bytes(&mut nonce);

    // Build key handle = encrypted credential ID
    let key_handle = generate_credential_id(&priv_key.bytes, app_id, &nonce, encryption_key);
    let kh_len = key_handle.len();

    if kh_len > 255 {
        return Err(SW_WRONG_DATA);
    }

    // Build attestation cert (self-signed with the generated key for now)
    let attestation_cert = build_self_signed_attestation_cert(&pub_key_bytes, &priv_key.bytes);

    // Build data to sign: 0x00 | app_id(32) | challenge(32) | key_handle | pubkey(65)
    let sign_data_len = 1 + 32 + 32 + kh_len + 65;
    let mut sign_data = [0u8; 512];
    if sign_data_len > sign_data.len() {
        return Err(SW_WRONG_DATA);
    }

    let mut pos = 0;
    sign_data[pos] = 0x00; // reserved byte
    pos += 1;
    sign_data[pos..pos + 32].copy_from_slice(app_id);
    pos += 32;
    sign_data[pos..pos + 32].copy_from_slice(challenge);
    pos += 32;
    sign_data[pos..pos + kh_len].copy_from_slice(&key_handle);
    pos += kh_len;
    sign_data[pos..pos + 65].copy_from_slice(&pub_key_bytes);

    let sign_hash = sha256(&sign_data[..sign_data_len]);
    let signature = pico_rs_sdk::crypto::ecc::ecdsa_sign_p256(&priv_key.bytes, &sign_hash)
        .map_err(|_| SW_WRONG_DATA)?;

    // Build response: 0x05 | pubkey(65) | key_handle_len(1) | key_handle | cert | signature
    let total_len = 1 + 65 + 1 + kh_len + attestation_cert.len() + signature.len();
    if response.len() < total_len {
        return Err(SW_WRONG_LENGTH);
    }

    let mut out_pos = 0;
    response[out_pos] = 0x05; // reserved byte per U2F spec
    out_pos += 1;

    response[out_pos..out_pos + 65].copy_from_slice(&pub_key_bytes);
    out_pos += 65;

    response[out_pos] = kh_len as u8;
    out_pos += 1;

    response[out_pos..out_pos + kh_len].copy_from_slice(&key_handle);
    out_pos += kh_len;

    response[out_pos..out_pos + attestation_cert.len()].copy_from_slice(&attestation_cert);
    out_pos += attestation_cert.len();

    response[out_pos..out_pos + signature.len()].copy_from_slice(&signature);
    out_pos += signature.len();

    Ok(out_pos)
}
