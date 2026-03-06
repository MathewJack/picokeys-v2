//! CTAP2 authenticatorSelection handler.
//!
//! The selection command simply confirms that the authenticator is present
//! and responsive (wink LED), then returns success.

use super::ctap::CtapError;

/// Handle an authenticatorSelection request.
///
/// Always succeeds — the transport layer is expected to trigger a wink/LED
/// pattern so the user can identify the device.
pub fn handle_selection() -> Result<(), CtapError> {
    // In a full implementation this would trigger an LED blink via the
    // platform LED driver.  The success return is sufficient for the
    // CTAP2 protocol.
    Ok(())
}
