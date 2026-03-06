//! U2F Authenticate command (INS = 0x02).
//!
//! Decrypts the key handle to recover the private key, verifies the app_id,
//! and produces a signature over `app_id | presence | counter | challenge`.

use super::{SW_CONDITIONS_NOT_SATISFIED, SW_WRONG_DATA, SW_WRONG_LENGTH};
use crate::credential::id::decrypt_credential_id;
use pico_rs_sdk::crypto::ecc::ecdsa_sign_p256;
use pico_rs_sdk::crypto::sha256;
use subtle::ConstantTimeEq;

/// U2F Authenticate command handler.
///
/// # Control byte semantics
/// - `0x07` (CheckOnly): return `SW_CONDITIONS_NOT_SATISFIED` if key handle is valid
///   (this means "yes, I know this key handle" per U2F spec)
/// - `0x03` (EnforcePresence): sign and return response
/// - `0x08` (DontEnforce): sign without requiring user presence
///
/// # Response format
/// `user_presence(1) | counter(4 BE) | signature(DER)`
pub fn u2f_authenticate(
    control: u8,
    challenge: &[u8; 32],
    app_id: &[u8; 32],
    key_handle: &[u8],
    response: &mut [u8],
    encryption_key: &[u8; 32],
    sign_counter: &mut u32,
) -> Result<usize, u16> {
    // Decrypt the key handle to recover private key and rp_id_hash
    let (private_key, rp_id_hash) =
        decrypt_credential_id(key_handle, encryption_key).map_err(|_| SW_WRONG_DATA)?;

    // Verify app_id matches the rp_id_hash embedded in the key handle (constant-time)
    if app_id.ct_eq(&rp_id_hash).unwrap_u8() != 1 {
        return Err(SW_WRONG_DATA);
    }

    // CheckOnly mode: key handle is valid, return conditions not satisfied per spec
    if control == 0x07 {
        return Err(SW_CONDITIONS_NOT_SATISFIED);
    }

    // For EnforcePresence (0x03), we should wait for user presence.
    // The actual button-press waiting is handled at the transport layer;
    // here we assume presence has already been confirmed by the caller.
    let user_presence: u8 = if control == 0x03 { 0x01 } else { 0x00 };

    // Increment and read counter
    *sign_counter = sign_counter.wrapping_add(1);
    let counter_bytes = sign_counter.to_be_bytes();

    // Build data to sign: app_id(32) | user_presence(1) | counter(4) | challenge(32)
    let mut sign_data = [0u8; 69]; // 32 + 1 + 4 + 32
    sign_data[..32].copy_from_slice(app_id);
    sign_data[32] = user_presence;
    sign_data[33..37].copy_from_slice(&counter_bytes);
    sign_data[37..69].copy_from_slice(challenge);

    let sign_hash = sha256(&sign_data);
    let signature = ecdsa_sign_p256(&private_key, &sign_hash).map_err(|_| SW_WRONG_DATA)?;

    // Build response: presence(1) | counter(4) | signature(DER)
    let total_len = 1 + 4 + signature.len();
    if response.len() < total_len {
        return Err(SW_WRONG_LENGTH);
    }

    let mut pos = 0;
    response[pos] = user_presence;
    pos += 1;

    response[pos..pos + 4].copy_from_slice(&counter_bytes);
    pos += 4;

    response[pos..pos + signature.len()].copy_from_slice(&signature);
    pos += signature.len();

    Ok(pos)
}
