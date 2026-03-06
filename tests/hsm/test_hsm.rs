//! SmartCard-HSM integration test suite (host-side)
//!
//! These tests verify the PicoKeys SmartCard-HSM applet functionality over USB CCID.
//! The HSM implementation follows the SmartCard-HSM protocol specification, supporting
//! key generation, cryptographic operations, DKEK management, and PKCS#15 file access.
//!
//! HSM AID: E8 2B 06 01 04 01 81 C3 1F 02 01
//!
//! Run with: `cargo test --test test_hsm -- --ignored`
//!
//! Prerequisites:
//! - A PicoKeys device connected via USB (not SAMD21 — HSM is excluded on SAMD21)
//! - PC/SC middleware installed (pcsclite on Linux, native on macOS/Windows)
//! - No other application holding the smart card reader open

/// HSM APDU instruction codes.
const INS_SELECT: u8 = 0xA4;
const INS_INITIALIZE: u8 = 0x50;
const INS_IMPORT_DKEK: u8 = 0x52;
const INS_GENERATE_KEY: u8 = 0x46;
const INS_LIST_KEYS: u8 = 0x58;
const INS_DELETE_KEY: u8 = 0xE4;
const INS_PSO: u8 = 0x2A;
const INS_VERIFY_PIN: u8 = 0x20;
const INS_CHANGE_PIN: u8 = 0x24;
const INS_RESET_RETRY: u8 = 0x2C;
const INS_WRAP_KEY: u8 = 0x72;
const INS_UNWRAP_KEY: u8 = 0x74;
const INS_GET_CHALLENGE: u8 = 0x84;
const INS_READ_BINARY: u8 = 0xB0;
const INS_UPDATE_BINARY: u8 = 0xD6;

/// PSO (Perform Security Operation) sub-operation P1/P2 pairs.
const PSO_CDS_P1: u8 = 0x9E; // Compute Digital Signature
const PSO_CDS_P2: u8 = 0x9A;
const PSO_DEC_P1: u8 = 0x80; // Decipher
const PSO_DEC_P2: u8 = 0x86;
const PSO_ECDH_P1: u8 = 0x80; // ECDH key agreement
const PSO_ECDH_P2: u8 = 0x84;

/// Algorithm identifiers for key generation and operations.
const ALG_RSA_PKCS1: u8 = 0x01;
const ALG_RSA_PSS: u8 = 0x02;
const ALG_ECDSA: u8 = 0x03;
const ALG_EDDSA: u8 = 0x04;
const ALG_RSA_OAEP: u8 = 0x05;
const ALG_RSA_DECRYPT: u8 = 0x06;
const ALG_AES_CBC: u8 = 0x10;
const ALG_AES_GCM: u8 = 0x11;

/// ISO 7816 status words.
const SW_SUCCESS: u16 = 0x9000;
const SW_WRONG_LENGTH: u16 = 0x6700;
const SW_SECURITY_NOT_SATISFIED: u16 = 0x6982;
const SW_PIN_BLOCKED: u16 = 0x6983;
const SW_CONDITIONS_NOT_SATISFIED: u16 = 0x6985;
const SW_WRONG_DATA: u16 = 0x6A80;
const SW_FILE_NOT_FOUND: u16 = 0x6A82;
const SW_KEY_NOT_FOUND: u16 = 0x6A88;
const SW_INS_NOT_SUPPORTED: u16 = 0x6D00;

/// HSM AID for SELECT command.
const HSM_AID: [u8; 11] = [0xE8, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x81, 0xC3, 0x1F, 0x02, 0x01];

// ────────────────────────────────────────────────────────────────────────────
// Initialization & SELECT
// ────────────────────────────────────────────────────────────────────────────

#[test]
#[ignore = "requires connected PicoKeys device"]
fn test_hsm_select() {
    // Send SELECT APDU with HSM AID.
    // Verify:
    //   - Status word == 0x9000
    //   - Response contains version info and device capabilities
    todo!("Implement HSM SELECT test")
}

#[test]
#[ignore = "requires connected PicoKeys device"]
fn test_hsm_initialize() {
    // Send INITIALIZE (INS=0x50) with SO-PIN and user PIN.
    // Verify:
    //   - Status word == 0x9000
    //   - Device is in initialized state
    //   - All previous keys are erased
    //
    // WARNING: This resets the entire HSM state!
    todo!("Implement HSM INITIALIZE test")
}

#[test]
#[ignore = "requires connected PicoKeys device"]
fn test_hsm_get_challenge() {
    // Send GET CHALLENGE (INS=0x84) requesting N random bytes.
    // Verify:
    //   - Status word == 0x9000
    //   - Response contains exactly N random bytes
    //   - Two consecutive calls produce different output
    todo!("Implement HSM GET CHALLENGE test")
}

// ────────────────────────────────────────────────────────────────────────────
// PIN Management
// ────────────────────────────────────────────────────────────────────────────

#[test]
#[ignore = "requires connected PicoKeys device"]
fn test_hsm_verify_pin() {
    // Prerequisites: HSM initialized with known PIN.
    //
    // Send VERIFY PIN (INS=0x20) with correct PIN.
    // Verify: Status word == 0x9000
    todo!("Implement HSM VERIFY PIN test")
}

#[test]
#[ignore = "requires connected PicoKeys device"]
fn test_hsm_verify_pin_wrong() {
    // Send VERIFY PIN with incorrect PIN.
    // Verify:
    //   - Status word indicates wrong PIN
    //   - Retry counter decremented
    todo!("Implement HSM VERIFY PIN wrong test")
}

#[test]
#[ignore = "requires connected PicoKeys device"]
fn test_hsm_change_pin() {
    // Send CHANGE PIN (INS=0x24) with old and new PIN.
    // Verify:
    //   - Status word == 0x9000
    //   - New PIN works for VERIFY PIN
    //   - Old PIN no longer works
    todo!("Implement HSM CHANGE PIN test")
}

#[test]
#[ignore = "requires connected PicoKeys device"]
fn test_hsm_reset_retry_counter() {
    // Send RESET RETRY COUNTER (INS=0x2C) with SO-PIN.
    // Verify:
    //   - Status word == 0x9000
    //   - PIN retry counter restored to maximum (8)
    todo!("Implement HSM RESET RETRY COUNTER test")
}

// ────────────────────────────────────────────────────────────────────────────
// Key Generation
// ────────────────────────────────────────────────────────────────────────────

#[test]
#[ignore = "requires connected PicoKeys device"]
fn test_hsm_generate_ec_p256() {
    // Prerequisites: PIN verified.
    //
    // GENERATE KEY (INS=0x46) for EC P-256.
    // Verify:
    //   - Status word == 0x9000
    //   - Response contains a 65-byte uncompressed P-256 public key
    //   - Key appears in LIST KEYS output
    todo!("Implement HSM generate EC P-256 key test")
}

#[test]
#[ignore = "requires connected PicoKeys device"]
fn test_hsm_generate_ec_p384() {
    // GENERATE KEY for EC P-384.
    // Verify: valid 97-byte uncompressed P-384 public key returned.
    todo!("Implement HSM generate EC P-384 key test")
}

#[test]
#[ignore = "requires connected PicoKeys device"]
fn test_hsm_generate_ec_p521() {
    // GENERATE KEY for EC P-521.
    // Verify: valid 133-byte uncompressed P-521 public key returned.
    todo!("Implement HSM generate EC P-521 key test")
}

#[test]
#[ignore = "requires connected PicoKeys device"]
fn test_hsm_generate_ed25519() {
    // GENERATE KEY for Ed25519.
    // Verify: valid 32-byte Ed25519 public key returned.
    todo!("Implement HSM generate Ed25519 key test")
}

#[test]
#[ignore = "requires connected PicoKeys device"]
fn test_hsm_generate_rsa_2048() {
    // GENERATE KEY for RSA-2048.
    // Verify:
    //   - Status word == 0x9000
    //   - Response contains RSA public key (modulus + exponent)
    //   - Modulus is exactly 256 bytes
    //
    // Note: RSA key generation can take several seconds.
    todo!("Implement HSM generate RSA-2048 key test")
}

#[test]
#[ignore = "requires connected PicoKeys device"]
fn test_hsm_generate_aes_256() {
    // GENERATE KEY for AES-256.
    // Verify:
    //   - Status word == 0x9000
    //   - Key appears in LIST KEYS
    //   - Key is usable for encrypt/decrypt operations
    todo!("Implement HSM generate AES-256 key test")
}

#[test]
#[ignore = "requires connected PicoKeys device"]
fn test_hsm_list_keys() {
    // Prerequisites: at least one key generated.
    //
    // LIST KEYS (INS=0x58).
    // Verify:
    //   - Status word == 0x9000
    //   - Response contains key metadata (ID, type, label)
    //   - Previously generated keys are listed
    todo!("Implement HSM LIST KEYS test")
}

#[test]
#[ignore = "requires connected PicoKeys device"]
fn test_hsm_delete_key() {
    // Prerequisites: a key generated.
    //
    // DELETE KEY (INS=0xE4) by key ID.
    // Verify:
    //   - Status word == 0x9000
    //   - Key no longer appears in LIST KEYS
    //   - PSO operations with deleted key ID return KEY_NOT_FOUND
    todo!("Implement HSM DELETE KEY test")
}

// ────────────────────────────────────────────────────────────────────────────
// Cryptographic Operations (PSO)
// ────────────────────────────────────────────────────────────────────────────

#[test]
#[ignore = "requires connected PicoKeys device"]
fn test_hsm_sign_ecdsa_p256() {
    // Prerequisites: EC P-256 key generated, PIN verified.
    //
    // PSO Compute Digital Signature (P1=0x9E, P2=0x9A) with ECDSA.
    // Input: SHA-256 hash of test data (32 bytes).
    // Verify:
    //   - Status word == 0x9000
    //   - Signature is valid DER-encoded ECDSA signature
    //   - Signature verifies against the public key and hash
    todo!("Implement HSM ECDSA P-256 sign test")
}

#[test]
#[ignore = "requires connected PicoKeys device"]
fn test_hsm_sign_eddsa() {
    // Prerequisites: Ed25519 key generated, PIN verified.
    //
    // PSO Compute Digital Signature with EdDSA.
    // Verify: valid 64-byte Ed25519 signature.
    todo!("Implement HSM EdDSA sign test")
}

#[test]
#[ignore = "requires connected PicoKeys device"]
fn test_hsm_sign_rsa_pkcs1() {
    // Prerequisites: RSA-2048 key generated, PIN verified.
    //
    // PSO Compute Digital Signature with RSA PKCS#1 v1.5.
    // Input: DigestInfo-wrapped SHA-256 hash.
    // Verify:
    //   - Signature is 256 bytes (2048 bits)
    //   - Signature verifies with the public key
    todo!("Implement HSM RSA PKCS#1 sign test")
}

#[test]
#[ignore = "requires connected PicoKeys device"]
fn test_hsm_sign_rsa_pss() {
    // PSO with RSA-PSS algorithm.
    // Verify: valid RSA-PSS signature that verifies with public key.
    todo!("Implement HSM RSA-PSS sign test")
}

#[test]
#[ignore = "requires connected PicoKeys device"]
fn test_hsm_decrypt_rsa_oaep() {
    // Prerequisites: RSA-2048 key generated, PIN verified.
    //
    // Encrypt test data with the RSA public key (OAEP, SHA-256).
    // PSO Decipher (P1=0x80, P2=0x86) with RSA-OAEP.
    // Verify:
    //   - Status word == 0x9000
    //   - Decrypted plaintext matches original test data
    todo!("Implement HSM RSA-OAEP decrypt test")
}

#[test]
#[ignore = "requires connected PicoKeys device"]
fn test_hsm_decrypt_rsa_pkcs1() {
    // PSO Decipher with RSA PKCS#1 v1.5 decryption.
    // Verify: decrypted plaintext matches original.
    todo!("Implement HSM RSA PKCS#1 decrypt test")
}

#[test]
#[ignore = "requires connected PicoKeys device"]
fn test_hsm_ecdh_p256() {
    // Prerequisites: EC P-256 key generated, PIN verified.
    //
    // PSO ECDH (P1=0x80, P2=0x84) with a test peer public key.
    // Verify:
    //   - Status word == 0x9000
    //   - Derived shared secret is 32 bytes
    //   - Matches expected ECDH output for the key pair
    todo!("Implement HSM ECDH P-256 test")
}

#[test]
#[ignore = "requires connected PicoKeys device"]
fn test_hsm_aes_encrypt_decrypt() {
    // Prerequisites: AES-256 key generated, PIN verified.
    //
    // Encrypt test data with AES-GCM.
    // Decrypt the ciphertext.
    // Verify: round-trip produces the original plaintext.
    todo!("Implement HSM AES encrypt/decrypt test")
}

// ────────────────────────────────────────────────────────────────────────────
// DKEK (Device Key Encryption Key)
// ────────────────────────────────────────────────────────────────────────────

#[test]
#[ignore = "requires connected PicoKeys device"]
fn test_hsm_import_dkek_share() {
    // Prerequisites: HSM initialized with DKEK shares configured (e.g., 2-of-3).
    //
    // IMPORT DKEK SHARE (INS=0x52) with a valid share.
    // Verify:
    //   - Status word == 0x9000
    //   - Response indicates shares imported / shares required
    todo!("Implement HSM IMPORT DKEK SHARE test")
}

#[test]
#[ignore = "requires connected PicoKeys device"]
fn test_hsm_dkek_threshold() {
    // Import enough DKEK shares to reach the threshold.
    // Verify:
    //   - After reaching n-of-m threshold, key operations are unlocked
    //   - Wrap/unwrap operations succeed
    todo!("Implement HSM DKEK threshold test")
}

#[test]
#[ignore = "requires connected PicoKeys device"]
fn test_hsm_wrap_key() {
    // Prerequisites: DKEK established, key generated.
    //
    // WRAP KEY (INS=0x72) to export a key wrapped under DKEK.
    // Verify:
    //   - Status word == 0x9000
    //   - Response contains wrapped key blob (AES-256-GCM encrypted)
    //   - Blob is non-trivially different from the raw key material
    todo!("Implement HSM WRAP KEY test")
}

#[test]
#[ignore = "requires connected PicoKeys device"]
fn test_hsm_unwrap_key() {
    // Prerequisites: DKEK established, wrapped key blob from WRAP KEY.
    //
    // UNWRAP KEY (INS=0x74) to import a wrapped key.
    // Verify:
    //   - Status word == 0x9000
    //   - Imported key appears in LIST KEYS
    //   - Sign/decrypt operations produce correct results
    todo!("Implement HSM UNWRAP KEY test")
}

#[test]
#[ignore = "requires connected PicoKeys device"]
fn test_hsm_wrap_unwrap_roundtrip() {
    // Generate a key, wrap it, delete it, unwrap it.
    // Verify: signing with the re-imported key produces the same results.
    todo!("Implement HSM wrap/unwrap round-trip test")
}

// ────────────────────────────────────────────────────────────────────────────
// PKCS#15 File System
// ────────────────────────────────────────────────────────────────────────────

#[test]
#[ignore = "requires connected PicoKeys device"]
fn test_hsm_read_binary() {
    // READ BINARY (INS=0xB0) for the EF.DIR or EF.TokenInfo file.
    // Verify:
    //   - Status word == 0x9000
    //   - Response contains valid PKCS#15 ASN.1 data
    todo!("Implement HSM READ BINARY test")
}

#[test]
#[ignore = "requires connected PicoKeys device"]
fn test_hsm_update_binary() {
    // UPDATE BINARY (INS=0xD6) to write a certificate.
    // READ BINARY to read it back.
    // Verify: data matches what was written.
    todo!("Implement HSM UPDATE BINARY test")
}

#[test]
#[ignore = "requires connected PicoKeys device"]
fn test_hsm_store_certificate() {
    // Store an X.509 certificate associated with a key.
    // Read it back via READ BINARY.
    // Verify: certificate data is intact.
    todo!("Implement HSM certificate storage test")
}

// ────────────────────────────────────────────────────────────────────────────
// Error Handling
// ────────────────────────────────────────────────────────────────────────────

#[test]
#[ignore = "requires connected PicoKeys device"]
fn test_hsm_sign_without_pin() {
    // Attempt PSO without prior VERIFY PIN.
    // Verify: Status word == SW_SECURITY_NOT_SATISFIED (0x6982)
    todo!("Implement HSM sign without PIN test")
}

#[test]
#[ignore = "requires connected PicoKeys device"]
fn test_hsm_unsupported_ins() {
    // Send an APDU with unsupported INS byte.
    // Verify: Status word == SW_INS_NOT_SUPPORTED (0x6D00)
    todo!("Implement HSM unsupported INS test")
}

#[test]
#[ignore = "requires connected PicoKeys device"]
fn test_hsm_pin_lockout() {
    // Send VERIFY PIN with wrong PIN 8 times.
    // Verify:
    //   - Retry counter reaches 0
    //   - Subsequent VERIFY returns SW_PIN_BLOCKED (0x6983)
    //   - Operations requiring PIN fail with SECURITY_NOT_SATISFIED
    //
    // Recovery: RESET RETRY COUNTER with SO-PIN, or re-initialize.
    todo!("Implement HSM PIN lockout test")
}
