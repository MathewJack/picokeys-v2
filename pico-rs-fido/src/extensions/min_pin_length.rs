//! CTAP2 `minPinLength` extension (FIDO2 §12.7).
//!
//! Allows selected relying parties to query the authenticator's
//! minimum PIN length policy and prevents setting PINs shorter
//! than the configured minimum.

use heapless::{String, Vec};

/// Default minimum PIN length (Unicode code points).
pub const DEFAULT_MIN_PIN_LENGTH: u8 = 4;

/// Maximum PIN length (Unicode code points).
pub const MAX_PIN_LENGTH: u8 = 63;

/// Validate that a PIN meets the minimum length requirement.
///
/// `pin` is the raw PIN bytes (UTF-8 encoded). The check counts
/// Unicode scalar values (code points), not bytes.
///
/// Returns `Err(())` if the PIN is shorter than `min_length` code points
/// or exceeds [`MAX_PIN_LENGTH`].
pub fn validate_pin_length(pin: &[u8], min_length: u8) -> Result<(), ()> {
    let pin_str = core::str::from_utf8(pin).map_err(|_| ())?;
    let char_count = pin_str.chars().count();

    if char_count < min_length as usize {
        return Err(());
    }
    if char_count > MAX_PIN_LENGTH as usize {
        return Err(());
    }

    Ok(())
}

/// Return the set of RP IDs that are permitted to read the
/// `minPinLength` value via the extension.
///
/// In production, this list is persisted in authenticator configuration.
/// This function returns the default (empty) set.
pub fn get_min_pin_length_rp_ids() -> Vec<String<64>, 8> {
    Vec::new()
}
