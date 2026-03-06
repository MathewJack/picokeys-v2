//! APDU instruction bytes and status word constants for SmartCard-HSM.

// --- Instruction bytes ---

/// Initialize device
pub const INS_INITIALIZE: u8 = 0x50;
/// Import DKEK share
pub const INS_IMPORT_DKEK: u8 = 0x52;
/// List key identifiers
pub const INS_LIST_KEYS: u8 = 0x58;
/// Generate asymmetric key pair
pub const INS_GENERATE_KEY: u8 = 0x46;
/// PERFORM SECURITY OPERATION (sign / decrypt / derive — distinguished by P1/P2)
pub const INS_PSO: u8 = 0x2A;
/// Verify PIN
pub const INS_VERIFY_PIN: u8 = 0x20;
/// Change PIN
pub const INS_CHANGE_PIN: u8 = 0x24;
/// Reset retry counter (unblock PIN)
pub const INS_RESET_RETRY: u8 = 0x2C;
/// Wrap (export) key under DKEK
pub const INS_WRAP_KEY: u8 = 0x72;
/// Unwrap (import) key under DKEK
pub const INS_UNWRAP_KEY: u8 = 0x74;
/// SELECT file / application
pub const INS_SELECT: u8 = 0xA4;
/// READ BINARY
pub const INS_READ_BINARY: u8 = 0xB0;
/// UPDATE BINARY
pub const INS_UPDATE_BINARY: u8 = 0xD6;
/// DELETE file / key
pub const INS_DELETE_KEY: u8 = 0xE4;
/// Get random challenge
pub const INS_GET_CHALLENGE: u8 = 0x84;

// --- PSO P1/P2 sub-commands ---

/// Compute Digital Signature: P1=0x9E, P2=0x9A
pub const PSO_CDS_P1: u8 = 0x9E;
pub const PSO_CDS_P2: u8 = 0x9A;
/// Decipher: P1=0x80, P2=0x86
pub const PSO_DEC_P1: u8 = 0x80;
pub const PSO_DEC_P2: u8 = 0x86;
/// ECDH key agreement: P1=0x80, P2=0x84
pub const PSO_ECDH_P1: u8 = 0x80;
pub const PSO_ECDH_P2: u8 = 0x84;

// --- ISO 7816-4 status words ---

pub const SW_SUCCESS: u16 = 0x9000;
pub const SW_WRONG_LENGTH: u16 = 0x6700;
pub const SW_SECURITY_NOT_SATISFIED: u16 = 0x6982;
pub const SW_PIN_BLOCKED: u16 = 0x6983;
pub const SW_INVALID_DATA: u16 = 0x6984;
pub const SW_CONDITIONS_NOT_SATISFIED: u16 = 0x6985;
pub const SW_INCORRECT_P1P2: u16 = 0x6A86;
pub const SW_FUNC_NOT_SUPPORTED: u16 = 0x6A81;
pub const SW_FILE_NOT_FOUND: u16 = 0x6A82;
pub const SW_FILE_FULL: u16 = 0x6A84;
pub const SW_KEY_NOT_FOUND: u16 = 0x6A88;
pub const SW_WRONG_DATA: u16 = 0x6A80;
pub const SW_INS_NOT_SUPPORTED: u16 = 0x6D00;
pub const SW_CLA_NOT_SUPPORTED: u16 = 0x6E00;

// --- Algorithm identifiers (used in PSO data field) ---

pub const ALGO_RSA_PKCS1: u8 = 0x01;
pub const ALGO_RSA_PSS: u8 = 0x02;
pub const ALGO_ECDSA: u8 = 0x03;
pub const ALGO_EDDSA: u8 = 0x04;
pub const ALGO_RSA_OAEP: u8 = 0x05;
pub const ALGO_RSA_DECRYPT: u8 = 0x06;
pub const ALGO_AES_CBC: u8 = 0x10;
pub const ALGO_AES_GCM: u8 = 0x11;
