//! AES encryption operations: GCM, CBC modes.

use super::CryptoError;

/// AES-256-GCM encrypt. Writes ciphertext to `output` (same length as `plaintext`).
/// Returns the 16-byte authentication tag.
pub fn aes256_gcm_encrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    plaintext: &[u8],
    aad: &[u8],
    output: &mut [u8],
) -> Result<[u8; 16], CryptoError> {
    use aes_gcm::{Aes256Gcm, KeyInit, AeadInPlace, Nonce};

    if output.len() < plaintext.len() {
        return Err(CryptoError::BufferTooSmall);
    }
    output[..plaintext.len()].copy_from_slice(plaintext);

    let cipher = Aes256Gcm::new(key.into());
    let nonce = Nonce::from_slice(nonce);

    let tag = cipher
        .encrypt_in_place_detached(nonce, aad, &mut output[..plaintext.len()])
        .map_err(|_| CryptoError::InternalError)?;

    let mut tag_bytes = [0u8; 16];
    tag_bytes.copy_from_slice(&tag);
    Ok(tag_bytes)
}

/// AES-256-GCM decrypt. Writes plaintext to `output` (same length as `ciphertext`).
pub fn aes256_gcm_decrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    ciphertext: &[u8],
    aad: &[u8],
    tag: &[u8; 16],
    output: &mut [u8],
) -> Result<(), CryptoError> {
    use aes_gcm::{Aes256Gcm, KeyInit, AeadInPlace, Nonce, Tag};

    if output.len() < ciphertext.len() {
        return Err(CryptoError::BufferTooSmall);
    }
    output[..ciphertext.len()].copy_from_slice(ciphertext);

    let cipher = Aes256Gcm::new(key.into());
    let nonce = Nonce::from_slice(nonce);
    let tag = Tag::from_slice(tag);

    cipher
        .decrypt_in_place_detached(nonce, aad, &mut output[..ciphertext.len()], tag)
        .map_err(|_| CryptoError::DecryptionFailed)
}

/// AES-256-CBC encrypt with PKCS#7 padding. Returns number of bytes written to `output`.
/// `output` must be at least `plaintext.len() + 16` bytes (for padding block).
pub fn aes256_cbc_encrypt(
    key: &[u8; 32],
    iv: &[u8; 16],
    plaintext: &[u8],
    output: &mut [u8],
) -> Result<usize, CryptoError> {
    use aes::Aes256;
    use cbc::cipher::{BlockEncryptMut, KeyIvInit, block_padding::Pkcs7};

    type Aes256CbcEnc = cbc::Encryptor<Aes256>;

    let padded_len = ((plaintext.len() / 16) + 1) * 16;
    if output.len() < padded_len {
        return Err(CryptoError::BufferTooSmall);
    }
    output[..plaintext.len()].copy_from_slice(plaintext);

    let ct = Aes256CbcEnc::new(key.into(), iv.into())
        .encrypt_padded_mut::<Pkcs7>(output, plaintext.len())
        .map_err(|_| CryptoError::InternalError)?;

    Ok(ct.len())
}

/// AES-256-CBC decrypt with PKCS#7 unpadding. Returns number of plaintext bytes.
pub fn aes256_cbc_decrypt(
    key: &[u8; 32],
    iv: &[u8; 16],
    ciphertext: &[u8],
    output: &mut [u8],
) -> Result<usize, CryptoError> {
    use aes::Aes256;
    use cbc::cipher::{BlockDecryptMut, KeyIvInit, block_padding::Pkcs7};

    type Aes256CbcDec = cbc::Decryptor<Aes256>;

    if ciphertext.len() % 16 != 0 || output.len() < ciphertext.len() {
        return Err(CryptoError::InvalidLength);
    }
    output[..ciphertext.len()].copy_from_slice(ciphertext);

    let pt = Aes256CbcDec::new(key.into(), iv.into())
        .decrypt_padded_mut::<Pkcs7>(&mut output[..ciphertext.len()])
        .map_err(|_| CryptoError::InvalidPadding)?;

    Ok(pt.len())
}

/// Raw AES-128-CBC encrypt (no padding) for SCP03. Input must be block-aligned.
pub fn aes128_cbc_encrypt_no_pad(
    key: &[u8; 16],
    iv: &[u8; 16],
    data: &mut [u8],
) -> Result<(), CryptoError> {
    use aes::Aes128;
    use cbc::cipher::{BlockEncryptMut, KeyIvInit, block_padding::NoPadding};

    type Aes128CbcEnc = cbc::Encryptor<Aes128>;

    if data.len() % 16 != 0 {
        return Err(CryptoError::InvalidLength);
    }
    let len = data.len();
    Aes128CbcEnc::new(key.into(), iv.into())
        .encrypt_padded_mut::<NoPadding>(data, len)
        .map_err(|_| CryptoError::InternalError)?;
    Ok(())
}
