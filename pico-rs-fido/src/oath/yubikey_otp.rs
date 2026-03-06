//! YubiKey OTP — classic Yubico OTP, static passwords, and HMAC challenge-response.

use heapless::Vec;

/// ModHex alphabet used by YubiKey OTP encoding.
const MODHEX: [u8; 16] = *b"cbdefghijklnrtuv";

/// Slot index constants.
pub const OTP_SLOT_1: u8 = 0;
pub const OTP_SLOT_2: u8 = 1;

/// OTP slot type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlotType {
    Empty,
    YubicoOtp,
    StaticPassword,
    HotpSlot,
    ChallengeResponse,
}

/// A YubiKey OTP slot configuration.
pub struct OtpSlot {
    pub slot_type: SlotType,
    /// AES-128 secret key.
    pub secret: [u8; 16],
    /// Private identity (6 bytes, embedded in encrypted OTP token).
    pub private_id: [u8; 6],
    /// Public identity (prepended in cleartext, ModHex encoded).
    pub public_id: Vec<u8, 16>,
    /// Non-volatile use counter (persisted across power cycles).
    pub counter: u16,
    /// Volatile session counter (reset on power cycle).
    pub session_counter: u8,
}

impl OtpSlot {
    pub fn new() -> Self {
        Self {
            slot_type: SlotType::Empty,
            secret: [0u8; 16],
            private_id: [0u8; 6],
            public_id: Vec::new(),
            counter: 0,
            session_counter: 0,
        }
    }
}

impl Default for OtpSlot {
    fn default() -> Self {
        Self::new()
    }
}

/// Generate a YubiKey OTP token string (ModHex encoded).
///
/// The token format is `public_id_modhex || encrypted_modhex`.
/// The encrypted block (16 bytes) contains:
///   `private_id(6) || counter(2 LE) || timestamp(3 LE) || session_counter(1) || random(2) || crc16(2 LE)`
///
/// **Note:** `timestamp` is derived from a platform 8 Hz timer; this implementation
/// uses 0. Production firmware must supply the real timer value externally.
pub fn generate_yubikey_otp(slot: &OtpSlot) -> Vec<u8, 44> {
    let mut plaintext = [0u8; 16];

    // Bytes 0–5: private ID
    plaintext[..6].copy_from_slice(&slot.private_id);
    // Bytes 6–7: use counter (little-endian)
    plaintext[6..8].copy_from_slice(&slot.counter.to_le_bytes());
    // Bytes 8–10: timestamp (little-endian, 3 bytes) — 0 placeholder
    plaintext[8] = 0;
    plaintext[9] = 0;
    plaintext[10] = 0;
    // Byte 11: session counter
    plaintext[11] = slot.session_counter;
    // Bytes 12–13: pseudo-random (0 placeholder)
    plaintext[12] = 0;
    plaintext[13] = 0;
    // Bytes 14–15: CRC-16 over bytes 0–13
    let crc = crc16(&plaintext[..14]);
    plaintext[14] = crc as u8;
    plaintext[15] = (crc >> 8) as u8;

    // AES-128-ECB encrypt the single 16-byte block
    aes128_ecb_encrypt(&slot.secret, &mut plaintext);

    // ModHex encode: public_id bytes + encrypted bytes
    let mut output: Vec<u8, 44> = Vec::new();
    let mut buf = [0u8; 44];
    let mut pos = 0;

    let pub_len = modhex_encode(&slot.public_id, &mut buf[pos..]);
    pos += pub_len;

    let enc_len = modhex_encode(&plaintext, &mut buf[pos..]);
    pos += enc_len;

    let _ = output.extend_from_slice(&buf[..pos]);
    output
}

/// Encode bytes to ModHex characters. Returns number of output bytes written.
///
/// Each input byte produces 2 ModHex characters. `output` must be at least
/// `2 * data.len()` bytes.
pub fn modhex_encode(data: &[u8], output: &mut [u8]) -> usize {
    let mut pos = 0;
    for &byte in data {
        if pos + 2 > output.len() {
            break;
        }
        output[pos] = MODHEX[(byte >> 4) as usize];
        output[pos + 1] = MODHEX[(byte & 0x0F) as usize];
        pos += 2;
    }
    pos
}

/// HMAC-SHA1 challenge-response (Yubico slot mode 2).
pub fn challenge_response_hmac(secret: &[u8], challenge: &[u8]) -> [u8; 20] {
    use hmac::{Hmac, Mac};
    type HmacSha1 = Hmac<sha1::Sha1>;

    let mut mac = HmacSha1::new_from_slice(secret).expect("HMAC key length");
    mac.update(challenge);
    let result = mac.finalize().into_bytes();
    let mut out = [0u8; 20];
    out.copy_from_slice(&result);
    out
}

/// CRC-16/ISO 13239 used by YubiKey OTP.
///
/// A valid decrypted OTP block satisfies `crc16(block[0..16]) == 0xF0B8`.
fn crc16(data: &[u8]) -> u16 {
    let mut crc: u16 = 0xFFFF;
    for &byte in data {
        crc ^= byte as u16;
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0x8408;
            } else {
                crc >>= 1;
            }
        }
    }
    crc
}

/// AES-128-ECB single-block encrypt in place.
fn aes128_ecb_encrypt(key: &[u8; 16], block: &mut [u8; 16]) {
    use aes::Aes128;
    use aes::cipher::{BlockEncrypt, KeyInit, generic_array::GenericArray};

    let cipher = Aes128::new(GenericArray::from_slice(key));
    let mut blk = GenericArray::clone_from_slice(block);
    cipher.encrypt_block(&mut blk);
    block.copy_from_slice(&blk);
}
