//! OATH (YKOATH) TOTP/HOTP integration test suite (host-side)
//!
//! These tests verify PicoKeys OATH applet functionality over USB CCID.
//! The OATH implementation follows the YubiKey OATH Application (YKOATH) protocol
//! using APDU commands over the ISO 7816 smart card interface.
//!
//! OATH AID: A0 00 00 05 27 21 01
//!
//! Run with: `cargo test --test test_oath -- --ignored`
//!
//! Prerequisites:
//! - A PicoKeys device connected via USB
//! - PC/SC middleware installed (pcsclite on Linux, native on macOS/Windows)
//! - No other application holding the smart card reader open

/// OATH APDU instruction codes.
const INS_PUT: u8 = 0x01;
const INS_DELETE: u8 = 0x02;
const INS_SET_CODE: u8 = 0x03;
const INS_RESET: u8 = 0x04;
const INS_RENAME: u8 = 0x05;
const INS_LIST: u8 = 0xA1;
const INS_CALCULATE: u8 = 0xA2;
const INS_CALCULATE_ALL: u8 = 0xA4;

/// OATH type tags.
const OATH_TYPE_HOTP: u8 = 0x10;
const OATH_TYPE_TOTP: u8 = 0x20;

/// OATH algorithm tags.
const OATH_ALG_SHA1: u8 = 0x01;
const OATH_ALG_SHA256: u8 = 0x02;
const OATH_ALG_SHA512: u8 = 0x03;

/// ISO 7816 status words.
const SW_SUCCESS: u16 = 0x9000;
const SW_NOT_FOUND: u16 = 0x6A82;
const SW_WRONG_DATA: u16 = 0x6A80;

/// OATH AID for SELECT command.
const OATH_AID: [u8; 7] = [0xA0, 0x00, 0x00, 0x05, 0x27, 0x21, 0x01];

#[test]
#[ignore = "requires connected PicoKeys device"]
fn test_oath_select() {
    // Send SELECT APDU with OATH AID.
    // Verify:
    //   - Status word == 0x9000
    //   - Response contains version info and device identifier
    todo!("Implement OATH SELECT test")
}

#[test]
#[ignore = "requires connected PicoKeys device"]
fn test_oath_add_totp_sha1() {
    // PUT a new TOTP credential:
    //   - Name: "test-totp-sha1"
    //   - Type: TOTP (0x20)
    //   - Algorithm: SHA1 (0x01)
    //   - Digits: 6
    //   - Period: 30s
    //   - Secret: known 20-byte HMAC-SHA1 key
    //
    // Verify: Status word == 0x9000
    todo!("Implement OATH add TOTP SHA1 test")
}

#[test]
#[ignore = "requires connected PicoKeys device"]
fn test_oath_add_totp_sha256() {
    // PUT a TOTP credential with SHA-256 algorithm.
    // Verify: Status word == 0x9000
    todo!("Implement OATH add TOTP SHA256 test")
}

#[test]
#[ignore = "requires connected PicoKeys device"]
fn test_oath_add_hotp() {
    // PUT an HOTP credential:
    //   - Name: "test-hotp"
    //   - Type: HOTP (0x10)
    //   - Algorithm: SHA1 (0x01)
    //   - Digits: 6
    //   - Counter: 0
    //   - Secret: known key
    //
    // Verify: Status word == 0x9000
    todo!("Implement OATH add HOTP test")
}

#[test]
#[ignore = "requires connected PicoKeys device"]
fn test_oath_list() {
    // Prerequisites: at least one credential added.
    //
    // Send LIST command (INS=0xA1).
    // Verify:
    //   - Status word == 0x9000
    //   - Response contains TLV entries with credential names and types
    //   - Previously added credentials appear in the list
    todo!("Implement OATH LIST test")
}

#[test]
#[ignore = "requires connected PicoKeys device"]
fn test_oath_calculate_totp() {
    // Prerequisites: TOTP credential "test-totp-sha1" added with known secret.
    //
    // Send CALCULATE (INS=0xA2) with:
    //   - Name: "test-totp-sha1"
    //   - Challenge: current time / 30 (as 8-byte big-endian)
    //
    // Verify:
    //   - Status word == 0x9000
    //   - Response contains a truncated OTP code
    //   - Code matches RFC 6238 test vector (if using known time + secret)
    todo!("Implement OATH CALCULATE TOTP test")
}

#[test]
#[ignore = "requires connected PicoKeys device"]
fn test_oath_calculate_hotp() {
    // Prerequisites: HOTP credential "test-hotp" added with known secret.
    //
    // Send CALCULATE for HOTP credential.
    // Verify:
    //   - Code matches RFC 4226 test vector for counter=0
    //   - A second CALCULATE produces a different code (counter incremented)
    todo!("Implement OATH CALCULATE HOTP test")
}

#[test]
#[ignore = "requires connected PicoKeys device"]
fn test_oath_calculate_all() {
    // Prerequisites: multiple credentials added.
    //
    // Send CALCULATE ALL (INS=0xA4).
    // Verify:
    //   - Status word == 0x9000
    //   - Response contains codes for all TOTP credentials
    //   - HOTP credentials are listed but not calculated (require explicit CALCULATE)
    todo!("Implement OATH CALCULATE ALL test")
}

#[test]
#[ignore = "requires connected PicoKeys device"]
fn test_oath_delete() {
    // Prerequisites: credential "test-totp-sha1" exists.
    //
    // Send DELETE (INS=0x02) with credential name.
    // Verify:
    //   - Status word == 0x9000
    //   - Subsequent LIST does not contain the deleted credential
    todo!("Implement OATH DELETE test")
}

#[test]
#[ignore = "requires connected PicoKeys device"]
fn test_oath_delete_nonexistent() {
    // Send DELETE for a credential name that does not exist.
    // Verify: Status word == SW_NOT_FOUND (0x6A82)
    todo!("Implement OATH DELETE nonexistent test")
}

#[test]
#[ignore = "requires connected PicoKeys device"]
fn test_oath_rename() {
    // Prerequisites: credential exists.
    //
    // Send RENAME (INS=0x05) with old name and new name.
    // Verify:
    //   - Status word == 0x9000
    //   - LIST shows new name, old name is gone
    //   - CALCULATE with new name produces valid code
    todo!("Implement OATH RENAME test")
}

#[test]
#[ignore = "requires connected PicoKeys device"]
fn test_oath_reset() {
    // Send RESET (INS=0x04).
    // Verify:
    //   - Status word == 0x9000
    //   - LIST returns empty (all credentials deleted)
    //   - Access code (if set) is cleared
    todo!("Implement OATH RESET test")
}

#[test]
#[ignore = "requires connected PicoKeys device"]
fn test_oath_set_code() {
    // Send SET CODE (INS=0x03) to set an access code (HMAC-based).
    // Verify:
    //   - Status word == 0x9000
    //   - Subsequent LIST/CALCULATE requires validation with the code
    todo!("Implement OATH SET CODE test")
}

#[test]
#[ignore = "requires connected PicoKeys device"]
fn test_oath_max_credentials() {
    // Add credentials until hitting the maximum (32).
    // Verify:
    //   - First 32 additions succeed
    //   - The 33rd addition fails (storage full)
    todo!("Implement OATH max credentials test")
}
