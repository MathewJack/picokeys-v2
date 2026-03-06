//! CTAP2 authenticatorReset handler.
//!
//! Per the FIDO spec, reset must be invoked within 10 seconds of power-up
//! and requires user presence (button press).

use super::ctap::CtapError;

/// Maximum elapsed time (milliseconds) since boot during which reset is allowed.
const RESET_WINDOW_MS: u64 = 10_000;

/// Handle an authenticatorReset request.
///
/// * `button_pressed` — whether the user has confirmed presence.
/// * `elapsed_since_boot_ms` — milliseconds since the device powered on.
///
/// Actual credential/PIN wipe is performed by the caller (`FidoApp`) after
/// this function returns `Ok(())`.
pub fn handle_reset(button_pressed: bool, elapsed_since_boot_ms: u64) -> Result<(), CtapError> {
    if elapsed_since_boot_ms > RESET_WINDOW_MS {
        return Err(CtapError::NotAllowed);
    }
    if !button_pressed {
        return Err(CtapError::OperationDenied);
    }
    Ok(())
}
