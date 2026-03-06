//! CTAP2 conformance test suite (host-side)
//!
//! These tests require a connected PicoKeys device and exercise the FIDO2/CTAP2
//! protocol over USB HID. Each test communicates with the authenticator using
//! raw CTAPHID frames carrying CBOR-encoded CTAP2 commands.
//!
//! Run with: `cargo test --test test_ctap2 -- --ignored`
//!
//! Prerequisites:
//! - A PicoKeys device connected via USB
//! - The `hidapi` system library installed
//! - No other application holding the HID device open

/// USB identifiers for PicoKeys devices.
const USB_VID: u16 = 0x20A0;
const USB_PID: u16 = 0x4287;

/// CTAPHID command bytes.
const CTAPHID_INIT: u8 = 0xBF;
const CTAPHID_CBOR: u8 = 0x90;
const CTAPHID_MSG: u8 = 0x83;
const CTAPHID_WINK: u8 = 0xBD;

/// CTAP2 command bytes.
const CTAP2_MAKE_CREDENTIAL: u8 = 0x01;
const CTAP2_GET_ASSERTION: u8 = 0x02;
const CTAP2_GET_INFO: u8 = 0x04;
const CTAP2_CLIENT_PIN: u8 = 0x06;
const CTAP2_RESET: u8 = 0x07;
const CTAP2_GET_NEXT_ASSERTION: u8 = 0x08;
const CTAP2_CREDENTIAL_MANAGEMENT: u8 = 0x0A;

/// CTAP2 status codes.
const CTAP2_OK: u8 = 0x00;
const CTAP2_ERR_INVALID_COMMAND: u8 = 0x01;
const CTAP2_ERR_CBOR_UNEXPECTED_TYPE: u8 = 0x11;
const CTAP2_ERR_OPERATION_DENIED: u8 = 0x27;
const CTAP2_ERR_PIN_NOT_SET: u8 = 0x35;
const CTAP2_ERR_NO_CREDENTIALS: u8 = 0x2E;

#[test]
#[ignore = "requires connected PicoKeys device"]
fn test_get_info() {
    // Send authenticatorGetInfo (0x04) with no parameters.
    // Verify the response contains:
    //   - versions: ["FIDO_2_0", "FIDO_2_1", "U2F_V2"]
    //   - extensions: ["credBlob", "credProtect", "hmac-secret", ...]
    //   - aaguid: 16-byte non-zero value
    //   - options.rk = true
    //   - options.up = true
    //   - maxCredentialCountInList >= 1
    //   - pinUvAuthProtocols: [1, 2]
    //   - transports: ["usb"]
    todo!("Implement CTAP2 GetInfo test")
}

#[test]
#[ignore = "requires connected PicoKeys device"]
fn test_get_info_versions() {
    // Verify the authenticator advertises FIDO_2_0, FIDO_2_1, and U2F_V2.
    todo!("Implement GetInfo version check")
}

#[test]
#[ignore = "requires connected PicoKeys device"]
fn test_make_credential_es256() {
    // MakeCredential with:
    //   - clientDataHash: SHA-256 of a test challenge
    //   - rp: { id: "test.example.com", name: "Test RP" }
    //   - user: { id: random, name: "testuser", displayName: "Test User" }
    //   - pubKeyCredParams: [{ alg: -7 (ES256), type: "public-key" }]
    //   - options: { rk: true }
    //
    // Verify:
    //   - Status == CTAP2_OK
    //   - attestationObject contains authData with AT flag set
    //   - credentialPublicKey is a valid P-256 COSE key (kty=2, alg=-7, crv=1)
    //   - signCount starts at 0
    todo!("Implement MakeCredential ES256 test")
}

#[test]
#[ignore = "requires connected PicoKeys device"]
fn test_make_credential_eddsa() {
    // MakeCredential with pubKeyCredParams: [{ alg: -8 (EdDSA), type: "public-key" }]
    // Verify credentialPublicKey is an Ed25519 COSE key (kty=1, alg=-8, crv=6)
    todo!("Implement MakeCredential EdDSA test")
}

#[test]
#[ignore = "requires connected PicoKeys device"]
fn test_get_assertion() {
    // Prerequisites: a credential created by test_make_credential_es256.
    //
    // GetAssertion with:
    //   - rpId: "test.example.com"
    //   - clientDataHash: SHA-256 of a new challenge
    //   - allowList: [{ type: "public-key", id: <credentialId> }]
    //
    // Verify:
    //   - Status == CTAP2_OK
    //   - credential.id matches the created credential
    //   - authData has UP flag set
    //   - signCount > 0
    //   - signature is valid ECDSA-P256 over authData || clientDataHash
    todo!("Implement GetAssertion test")
}

#[test]
#[ignore = "requires connected PicoKeys device"]
fn test_get_assertion_no_credentials() {
    // GetAssertion for an RP ID with no registered credentials.
    // Verify: Status == CTAP2_ERR_NO_CREDENTIALS (0x2E)
    todo!("Implement GetAssertion no-credentials test")
}

#[test]
#[ignore = "requires connected PicoKeys device"]
fn test_credential_management_list() {
    // Prerequisites: PIN set, at least one discoverable credential.
    //
    // Send authenticatorCredentialManagement enumerateRPsBegin,
    // then enumerateCredentialsBegin for each RP.
    //
    // Verify:
    //   - Each credential has valid rpIdHash, user entity, credentialId
    //   - Total count matches expectations
    todo!("Implement CredentialManagement list test")
}

#[test]
#[ignore = "requires connected PicoKeys device"]
fn test_credential_management_delete() {
    // Prerequisites: PIN set, at least one discoverable credential.
    //
    // Delete a credential by ID via authenticatorCredentialManagement.
    // Verify it no longer appears in enumeration.
    todo!("Implement CredentialManagement delete test")
}

#[test]
#[ignore = "requires connected PicoKeys device"]
fn test_client_pin_set() {
    // Prerequisites: no PIN set on device.
    //
    // ClientPIN subcommand setPIN:
    //   1. GetKeyAgreement → authenticator public key (P-256)
    //   2. Compute shared secret via ECDH
    //   3. Encrypt new PIN with shared secret
    //   4. Send setPIN with encrypted PIN + pinUvAuthParam
    //
    // Verify: Status == CTAP2_OK
    // Subsequent GetInfo should show options.clientPin = true
    todo!("Implement ClientPIN setPIN test")
}

#[test]
#[ignore = "requires connected PicoKeys device"]
fn test_client_pin_change() {
    // Prerequisites: PIN already set.
    //
    // ClientPIN subcommand changePIN with correct current PIN.
    // Verify: Status == CTAP2_OK
    todo!("Implement ClientPIN changePIN test")
}

#[test]
#[ignore = "requires connected PicoKeys device"]
fn test_client_pin_wrong_pin() {
    // Send getPinToken with an incorrect PIN.
    // Verify: Status == CTAP2_ERR_PIN_INVALID (0x31)
    // Verify: retries decremented
    todo!("Implement ClientPIN wrong PIN test")
}

#[test]
#[ignore = "requires connected PicoKeys device"]
fn test_reset() {
    // authenticatorReset (0x07).
    //
    // Verify:
    //   - Status == CTAP2_OK (if within 10s of power-on + user confirms)
    //   - All credentials deleted
    //   - PIN cleared
    //   - GetInfo shows clientPin = false
    //
    // WARNING: This destroys all credentials on the device!
    todo!("Implement Reset test")
}

#[test]
#[ignore = "requires connected PicoKeys device"]
fn test_hmac_secret_extension() {
    // MakeCredential with extensions: { "hmac-secret": true }
    // Verify: attestation contains extensions map with hmac-secret = true
    //
    // GetAssertion with extensions: { "hmac-secret": { keyAgreement, saltEnc, saltAuth } }
    // Verify: response contains hmac-secret output (32 or 64 bytes)
    todo!("Implement hmac-secret extension test")
}

#[test]
#[ignore = "requires connected PicoKeys device"]
fn test_cred_protect_extension() {
    // MakeCredential with extensions: { "credProtect": 2 }
    // Verify: credential created with credProtect level 2
    //
    // GetAssertion without PIN token should fail for level 2 credential
    // when not in allowList.
    todo!("Implement credProtect extension test")
}

#[test]
#[ignore = "requires connected PicoKeys device"]
fn test_cred_blob_extension() {
    // MakeCredential with extensions: { "credBlob": <32 bytes> }
    // GetAssertion with extensions: { "getCredBlob": true }
    // Verify: returned credBlob matches what was stored
    todo!("Implement credBlob extension test")
}

#[test]
#[ignore = "requires connected PicoKeys device"]
fn test_large_blob_key_extension() {
    // MakeCredential with extensions: { "largeBlobKey": true }
    // Verify: largeBlobKey is present in the credential
    todo!("Implement largeBlobKey extension test")
}

#[test]
#[ignore = "requires connected PicoKeys device"]
fn test_wink() {
    // Send CTAPHID_WINK command.
    // Verify: device responds with success (no error).
    // Visual verification: LED should blink distinctively.
    todo!("Implement CTAPHID Wink test")
}

#[test]
#[ignore = "requires connected PicoKeys device"]
fn test_invalid_cbor_command() {
    // Send a CTAPHID_CBOR frame with invalid CBOR payload.
    // Verify: authenticator returns CTAP2_ERR_CBOR_UNEXPECTED_TYPE or similar.
    todo!("Implement invalid CBOR test")
}

#[test]
#[ignore = "requires connected PicoKeys device"]
fn test_concurrent_channels() {
    // Open two CTAPHID channels (INIT on broadcast CID).
    // Send GetInfo on both channels.
    // Verify: both channels receive valid, independent responses.
    todo!("Implement concurrent channel test")
}
