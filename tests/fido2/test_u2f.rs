//! U2F / CTAP1 backward compatibility test suite (host-side)
//!
//! These tests verify that PicoKeys correctly handles legacy U2F (CTAP1)
//! commands over USB HID. U2F uses raw APDU-style messages inside CTAPHID_MSG
//! frames rather than the CBOR encoding used by CTAP2.
//!
//! Run with: `cargo test --test test_u2f -- --ignored`
//!
//! Prerequisites:
//! - A PicoKeys device connected via USB
//! - The device must support U2F_V2 (advertised in GetInfo versions)

/// U2F command bytes (INS field in the APDU).
const U2F_REGISTER: u8 = 0x01;
const U2F_AUTHENTICATE: u8 = 0x02;
const U2F_VERSION: u8 = 0x03;

/// U2F authenticate control bytes (P1).
const U2F_CHECK_ONLY: u8 = 0x07;
const U2F_ENFORCE_PRESENCE: u8 = 0x03;
const U2F_DONT_ENFORCE: u8 = 0x08;

/// U2F status words.
const SW_NO_ERROR: u16 = 0x9000;
const SW_CONDITIONS_NOT_SATISFIED: u16 = 0x6985;
const SW_WRONG_DATA: u16 = 0x6A80;
const SW_INS_NOT_SUPPORTED: u16 = 0x6D00;

#[test]
#[ignore = "requires connected PicoKeys device"]
fn test_u2f_version() {
    // Send U2F_VERSION command (INS=0x03, no data).
    // Verify: response is the ASCII string "U2F_V2" with SW=0x9000.
    todo!("Implement U2F version test")
}

#[test]
#[ignore = "requires connected PicoKeys device"]
fn test_u2f_register() {
    // U2F Register with:
    //   - challenge: 32 random bytes
    //   - application: SHA-256 of "https://test.example.com"
    //
    // Verify:
    //   - Status word == 0x9000
    //   - Response starts with 0x05 (reserved byte)
    //   - Contains a 65-byte uncompressed P-256 public key
    //   - Contains a key handle (length-prefixed)
    //   - Contains an X.509 attestation certificate
    //   - ECDSA signature over the registration data is valid
    todo!("Implement U2F register test")
}

#[test]
#[ignore = "requires connected PicoKeys device"]
fn test_u2f_authenticate_enforce_presence() {
    // Prerequisites: a key handle from test_u2f_register.
    //
    // U2F Authenticate with P1=ENFORCE_PRESENCE (0x03):
    //   - challenge: 32 random bytes
    //   - application: same as registration
    //   - key handle: from registration
    //
    // Verify:
    //   - Status word == 0x9000
    //   - User presence byte == 0x01
    //   - Counter is a big-endian u32, > 0
    //   - ECDSA signature is valid over application || presence || counter || challenge
    todo!("Implement U2F authenticate (enforce presence) test")
}

#[test]
#[ignore = "requires connected PicoKeys device"]
fn test_u2f_authenticate_check_only() {
    // U2F Authenticate with P1=CHECK_ONLY (0x07):
    // Verify: if key handle is valid, status == SW_CONDITIONS_NOT_SATISFIED (0x6985)
    //         (meaning "key is known but user presence not confirmed")
    // If key handle is invalid, status == SW_WRONG_DATA (0x6A80)
    todo!("Implement U2F authenticate (check only) test")
}

#[test]
#[ignore = "requires connected PicoKeys device"]
fn test_u2f_authenticate_invalid_key_handle() {
    // U2F Authenticate with a fabricated/invalid key handle.
    // Verify: status == SW_WRONG_DATA (0x6A80)
    todo!("Implement U2F authenticate with invalid key handle test")
}

#[test]
#[ignore = "requires connected PicoKeys device"]
fn test_u2f_authenticate_wrong_application() {
    // U2F Authenticate with a valid key handle but wrong application parameter.
    // Verify: status == SW_WRONG_DATA (0x6A80)
    todo!("Implement U2F authenticate with wrong application test")
}

#[test]
#[ignore = "requires connected PicoKeys device"]
fn test_u2f_register_multiple() {
    // Register multiple credentials for the same application.
    // Verify: each registration produces a unique key handle and public key.
    todo!("Implement multiple U2F registration test")
}

#[test]
#[ignore = "requires connected PicoKeys device"]
fn test_u2f_counter_increment() {
    // Perform two consecutive U2F authentications.
    // Verify: the counter value in the second response is strictly greater
    // than in the first response.
    todo!("Implement U2F counter increment test")
}

#[test]
#[ignore = "requires connected PicoKeys device"]
fn test_u2f_unsupported_ins() {
    // Send a U2F APDU with an unsupported INS byte (e.g., 0xFF).
    // Verify: status == SW_INS_NOT_SUPPORTED (0x6D00)
    todo!("Implement U2F unsupported INS test")
}
