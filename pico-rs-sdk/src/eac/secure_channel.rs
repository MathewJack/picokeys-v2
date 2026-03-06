//! SCP03 secure-channel implementation.
//!
//! Provides symmetric secure messaging (AES-128-CBC encryption + AES-CMAC)
//! between the host and the device once a mutual authentication ceremony
//! completes.

use aes::Aes128;
use cbc::cipher::{block_padding::NoPadding, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use cmac::{digest::FixedOutput, Mac};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// SCP03 error conditions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, defmt::Format)]
pub enum CryptoError {
    /// The supplied cryptogram does not match the expected value.
    CryptogramMismatch,
    /// The MAC verification failed on an incoming APDU.
    MacVerification,
    /// A buffer was too small for the operation.
    BufferTooSmall,
    /// The secure channel has not been established yet.
    NotEstablished,
    /// Input data has an invalid length (must be block-aligned, etc.).
    InvalidLength,
}

type Aes128CbcEnc = cbc::Encryptor<Aes128>;
type Aes128CbcDec = cbc::Decryptor<Aes128>;
type Aes128Cmac = cmac::Cmac<Aes128>;

const BLOCK_SIZE: usize = 16;
const MAC_LEN: usize = 8; // SCP03 truncated MAC

/// SCP03-compatible symmetric secure channel.
///
/// Holds session keys derived during `INITIALIZE UPDATE` / `EXTERNAL
/// AUTHENTICATE`.  All key material is automatically zeroized on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecureChannel {
    enc_key: [u8; 16],
    mac_key: [u8; 16],
    rmac_key: [u8; 16],
    mac_chaining: [u8; 16],
    #[zeroize(skip)]
    counter: u32,
    #[zeroize(skip)]
    is_established: bool,
}

impl SecureChannel {
    /// Create an uninitialised channel (all keys zeroed, not yet established).
    pub const fn new() -> Self {
        Self {
            enc_key: [0u8; 16],
            mac_key: [0u8; 16],
            rmac_key: [0u8; 16],
            mac_chaining: [0u8; 16],
            counter: 0,
            is_established: false,
        }
    }

    /// Returns `true` once [`establish`](Self::establish) has succeeded.
    pub fn is_established(&self) -> bool {
        self.is_established
    }

    /// Establish the secure channel from the mutual-auth ceremony inputs.
    ///
    /// * `host_challenge` — 8-byte random from the host
    /// * `card_challenge` — 8-byte random from the card
    /// * `card_cryptogram` — 8-byte MAC proving the card holds the keys
    ///
    /// On success the session keys are installed and the **host cryptogram**
    /// (8 bytes) is returned so the caller can send EXTERNAL AUTHENTICATE.
    pub fn establish(
        &mut self,
        host_challenge: &[u8],
        card_challenge: &[u8],
        card_cryptogram: &[u8],
    ) -> Result<[u8; 8], CryptoError> {
        if host_challenge.len() != 8 || card_challenge.len() != 8 || card_cryptogram.len() != 8 {
            return Err(CryptoError::InvalidLength);
        }

        // Build derivation context: host_challenge ∥ card_challenge
        let mut context = [0u8; 16];
        context[..8].copy_from_slice(host_challenge);
        context[8..].copy_from_slice(card_challenge);

        // Derive session keys (simplified SCP03 KDF: CMAC of context under static key)
        self.enc_key = Self::derive_key(&self.enc_key, &context, 0x04);
        self.mac_key = Self::derive_key(&self.mac_key, &context, 0x06);
        self.rmac_key = Self::derive_key(&self.rmac_key, &context, 0x07);

        // Verify card cryptogram
        let expected_card_crypt =
            Self::compute_cryptogram(&self.mac_key, host_challenge, card_challenge);
        if !Self::constant_time_eq(&expected_card_crypt, card_cryptogram) {
            self.reset();
            return Err(CryptoError::CryptogramMismatch);
        }

        // Compute host cryptogram
        let host_crypt = Self::compute_cryptogram(&self.mac_key, card_challenge, host_challenge);
        self.counter = 1;
        self.mac_chaining = [0u8; 16];
        self.is_established = true;

        let mut out = [0u8; 8];
        out.copy_from_slice(&host_crypt[..8]);
        Ok(out)
    }

    /// Encrypt and MAC an outgoing C-APDU.
    ///
    /// The header (CLA INS P1 P2) and data from `apdu` are wrapped into
    /// `output`.  Returns the number of bytes written.
    pub fn wrap_apdu(&mut self, apdu: &[u8], output: &mut [u8]) -> Result<usize, CryptoError> {
        if !self.is_established {
            return Err(CryptoError::NotEstablished);
        }
        if apdu.len() < 4 {
            return Err(CryptoError::InvalidLength);
        }

        let header = &apdu[..4];
        let data = if apdu.len() > 5 {
            let lc = apdu[4] as usize;
            let end = 5 + lc;
            if apdu.len() < end {
                return Err(CryptoError::InvalidLength);
            }
            &apdu[5..end]
        } else {
            &[]
        };

        // Pad data to block boundary
        let padded = Self::iso9797_pad(data);

        // Encrypt padded data (AES-128-CBC, IV = counter block)
        let iv = self.counter_iv();
        let encrypted = Self::aes_cbc_encrypt(&self.enc_key, &iv, &padded)?;

        // Compute MAC over mac_chaining ∥ modified header ∥ Lc ∥ encrypted data
        let mut mac_input = heapless::Vec::<u8, 512>::new();
        let _ = mac_input.extend_from_slice(&self.mac_chaining);
        // Set CLA byte bit 3 to indicate secure messaging
        let _ = mac_input.push(header[0] | 0x04);
        let _ = mac_input.extend_from_slice(&header[1..4]);
        // Lc = encrypted data length + MAC_LEN
        let new_lc = encrypted.len() + MAC_LEN;
        let _ = mac_input.push(new_lc as u8);
        let _ = mac_input.extend_from_slice(&encrypted);
        let full_mac = Self::compute_mac(&self.mac_key, &mac_input);

        // Update MAC chaining value
        self.mac_chaining = full_mac;

        // Build output: header (with updated CLA) ∥ Lc ∥ encrypted ∥ MAC
        let total = 4 + 1 + encrypted.len() + MAC_LEN;
        if output.len() < total {
            return Err(CryptoError::BufferTooSmall);
        }

        output[0] = header[0] | 0x04;
        output[1..4].copy_from_slice(&header[1..4]);
        output[4] = new_lc as u8;
        output[5..5 + encrypted.len()].copy_from_slice(&encrypted);
        output[5 + encrypted.len()..total].copy_from_slice(&full_mac[..MAC_LEN]);

        Ok(total)
    }

    /// Decrypt and verify MAC on an incoming R-APDU.
    ///
    /// The status word and any encrypted payload from `apdu` are unwrapped
    /// into `output`.  Returns the number of plaintext bytes written.
    pub fn unwrap_apdu(&mut self, apdu: &[u8], output: &mut [u8]) -> Result<usize, CryptoError> {
        if !self.is_established {
            return Err(CryptoError::NotEstablished);
        }
        // Minimum: MAC (8) + SW (2)
        if apdu.len() < MAC_LEN + 2 {
            return Err(CryptoError::InvalidLength);
        }

        let sw_offset = apdu.len() - 2;
        let mac_offset = sw_offset - MAC_LEN;
        let encrypted = &apdu[..mac_offset];
        let received_mac = &apdu[mac_offset..sw_offset];
        let sw = &apdu[sw_offset..];

        // Verify RMAC (include mac_chaining in the input)
        let mut mac_input = heapless::Vec::<u8, 512>::new();
        let _ = mac_input.extend_from_slice(&self.mac_chaining);
        let _ = mac_input.extend_from_slice(encrypted);
        let _ = mac_input.extend_from_slice(sw);
        let expected_mac = Self::compute_mac(&self.rmac_key, &mac_input);
        if !Self::constant_time_eq(&expected_mac[..MAC_LEN], received_mac) {
            return Err(CryptoError::MacVerification);
        }

        // Update MAC chaining value after successful verification
        self.mac_chaining = expected_mac;

        if encrypted.is_empty() {
            // No data, just status word
            if output.len() < 2 {
                return Err(CryptoError::BufferTooSmall);
            }
            output[..2].copy_from_slice(sw);
            return Ok(2);
        }

        // Decrypt
        let iv = self.counter_iv();
        let plaintext = Self::aes_cbc_decrypt(&self.enc_key, &iv, encrypted)?;

        // Remove ISO 9797 M2 padding
        let unpadded_len = Self::iso9797_unpad_len(&plaintext)?;

        let total = unpadded_len + 2;
        if output.len() < total {
            return Err(CryptoError::BufferTooSmall);
        }
        output[..unpadded_len].copy_from_slice(&plaintext[..unpadded_len]);
        output[unpadded_len..total].copy_from_slice(sw);
        Ok(total)
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    fn reset(&mut self) {
        self.enc_key.zeroize();
        self.mac_key.zeroize();
        self.rmac_key.zeroize();
        self.mac_chaining.zeroize();
        self.counter = 0;
        self.is_established = false;
    }

    fn counter_iv(&self) -> [u8; BLOCK_SIZE] {
        let mut iv = [0u8; BLOCK_SIZE];
        let bytes = self.counter.to_be_bytes();
        iv[BLOCK_SIZE - 4..].copy_from_slice(&bytes);
        iv
    }

    /// Simplified SCP03 key derivation: CMAC(base_key, label ∥ context).
    fn derive_key(base_key: &[u8; 16], context: &[u8; 16], label: u8) -> [u8; 16] {
        let mut data = [0u8; 32];
        // First 16 bytes: 12 zero bytes ∥ label (1) ∥ 0x00 ∥ length(2)
        data[12] = label;
        data[13] = 0x00;
        data[14] = 0x00;
        data[15] = 0x80; // 128-bit key
        data[16..32].copy_from_slice(context);

        let mut mac = <Aes128Cmac as Mac>::new_from_slice(base_key).unwrap();
        mac.update(&data);
        let result = mac.finalize_fixed();
        let mut key = [0u8; 16];
        key.copy_from_slice(&result[..16]);
        key
    }

    /// Compute an 8-byte SCP03 cryptogram: CMAC(key, a ∥ b), truncated.
    fn compute_cryptogram(key: &[u8; 16], a: &[u8], b: &[u8]) -> [u8; 8] {
        let mut mac = <Aes128Cmac as Mac>::new_from_slice(key).unwrap();
        mac.update(a);
        mac.update(b);
        let result = mac.finalize_fixed();
        let mut out = [0u8; 8];
        out.copy_from_slice(&result[..8]);
        out
    }

    fn compute_mac(key: &[u8; 16], data: &[u8]) -> [u8; BLOCK_SIZE] {
        let mut mac = <Aes128Cmac as Mac>::new_from_slice(key).unwrap();
        mac.update(data);
        let result = mac.finalize_fixed();
        let mut out = [0u8; BLOCK_SIZE];
        out.copy_from_slice(&result[..BLOCK_SIZE]);
        out
    }

    fn aes_cbc_encrypt(
        key: &[u8; 16],
        iv: &[u8; BLOCK_SIZE],
        data: &[u8],
    ) -> Result<heapless::Vec<u8, 512>, CryptoError> {
        if data.is_empty() || data.len() % BLOCK_SIZE != 0 {
            return Err(CryptoError::InvalidLength);
        }
        let mut buf = heapless::Vec::<u8, 512>::new();
        buf.extend_from_slice(data)
            .map_err(|_| CryptoError::BufferTooSmall)?;
        let enc = Aes128CbcEnc::new_from_slices(key, iv).map_err(|_| CryptoError::InvalidLength)?;
        let ct = enc
            .encrypt_padded_mut::<NoPadding>(&mut buf, data.len())
            .map_err(|_| CryptoError::InvalidLength)?;
        let mut out = heapless::Vec::<u8, 512>::new();
        out.extend_from_slice(ct)
            .map_err(|_| CryptoError::BufferTooSmall)?;
        Ok(out)
    }

    fn aes_cbc_decrypt(
        key: &[u8; 16],
        iv: &[u8; BLOCK_SIZE],
        data: &[u8],
    ) -> Result<heapless::Vec<u8, 512>, CryptoError> {
        if data.is_empty() || data.len() % BLOCK_SIZE != 0 {
            return Err(CryptoError::InvalidLength);
        }
        let mut buf = heapless::Vec::<u8, 512>::new();
        buf.extend_from_slice(data)
            .map_err(|_| CryptoError::BufferTooSmall)?;
        let dec = Aes128CbcDec::new_from_slices(key, iv).map_err(|_| CryptoError::InvalidLength)?;
        let pt = dec
            .decrypt_padded_mut::<NoPadding>(&mut buf)
            .map_err(|_| CryptoError::InvalidLength)?;
        let mut out = heapless::Vec::<u8, 512>::new();
        out.extend_from_slice(pt)
            .map_err(|_| CryptoError::BufferTooSmall)?;
        Ok(out)
    }

    /// ISO 9797 Method 2 padding: append 0x80 then zeros to block boundary.
    fn iso9797_pad(data: &[u8]) -> heapless::Vec<u8, 512> {
        let mut padded = heapless::Vec::<u8, 512>::new();
        let _ = padded.extend_from_slice(data);
        let _ = padded.push(0x80);
        while padded.len() % BLOCK_SIZE != 0 {
            let _ = padded.push(0x00);
        }
        padded
    }

    /// Find the unpadded length inside ISO 9797 M2 padded data.
    fn iso9797_unpad_len(data: &[u8]) -> Result<usize, CryptoError> {
        for i in (0..data.len()).rev() {
            if data[i] == 0x80 {
                return Ok(i);
            }
            if data[i] != 0x00 {
                return Err(CryptoError::InvalidLength);
            }
        }
        Err(CryptoError::InvalidLength)
    }

    fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
        if a.len() != b.len() {
            return false;
        }
        use subtle::ConstantTimeEq;
        a.ct_eq(b).into()
    }
}
