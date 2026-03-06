//! AES symmetric operations: ECB, CBC, CTR, GCM, ChaCha20-Poly1305.

use super::apdu_router::*;
use super::dkek::DkekState;
use super::key_management::{KeyObject, KeyType};
use heapless::Vec;
use zeroize::Zeroize;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AesMode {
    Ecb,
    Cbc,
    Ctr,
    Gcm,
    ChaCha20Poly1305,
}

impl AesMode {
    pub fn from_u8(v: u8) -> Result<Self, u16> {
        match v {
            0 => Ok(AesMode::Ecb),
            1 => Ok(AesMode::Cbc),
            2 => Ok(AesMode::Ctr),
            3 => Ok(AesMode::Gcm),
            4 => Ok(AesMode::ChaCha20Poly1305),
            _ => Err(SW_FUNC_NOT_SUPPORTED),
        }
    }
}

/// AES encrypt dispatcher.
pub fn aes_encrypt(
    key: &KeyObject,
    dkek: &DkekState,
    mode: AesMode,
    iv: Option<&[u8]>,
    plaintext: &[u8],
    output: &mut [u8],
) -> Result<usize, u16> {
    let mut raw_key = dkek.unwrap_key(&key.private_key_wrapped)?;
    let result = aes_encrypt_raw(&raw_key, key.key_type, mode, iv, plaintext, output);
    for b in raw_key.iter_mut() {
        *b = 0;
    }
    raw_key.clear();
    result
}

/// AES decrypt dispatcher.
pub fn aes_decrypt(
    key: &KeyObject,
    dkek: &DkekState,
    mode: AesMode,
    iv: Option<&[u8]>,
    ciphertext: &[u8],
    output: &mut [u8],
) -> Result<usize, u16> {
    let mut raw_key = dkek.unwrap_key(&key.private_key_wrapped)?;
    let result = aes_decrypt_raw(&raw_key, key.key_type, mode, iv, ciphertext, output);
    for b in raw_key.iter_mut() {
        *b = 0;
    }
    raw_key.clear();
    result
}

// ---------------------------------------------------------------------------
// Raw AES operations with unwrapped key
// ---------------------------------------------------------------------------

fn aes_encrypt_raw(
    key: &[u8],
    key_type: KeyType,
    mode: AesMode,
    iv: Option<&[u8]>,
    plaintext: &[u8],
    output: &mut [u8],
) -> Result<usize, u16> {
    match mode {
        AesMode::Ecb => aes_ecb_encrypt(key, plaintext, output),
        AesMode::Cbc => {
            let iv_bytes = iv.ok_or(SW_WRONG_LENGTH)?;
            aes_cbc_encrypt(key, iv_bytes, plaintext, output)
        }
        AesMode::Ctr => {
            let nonce = iv.ok_or(SW_WRONG_LENGTH)?;
            aes_ctr(key, nonce, plaintext, output)
        }
        AesMode::Gcm => {
            let nonce = iv.ok_or(SW_WRONG_LENGTH)?;
            aes_gcm_encrypt(key, nonce, plaintext, output)
        }
        AesMode::ChaCha20Poly1305 => {
            let nonce = iv.ok_or(SW_WRONG_LENGTH)?;
            chacha20poly1305_encrypt(key, nonce, plaintext, output)
        }
    }
}

fn aes_decrypt_raw(
    key: &[u8],
    key_type: KeyType,
    mode: AesMode,
    iv: Option<&[u8]>,
    ciphertext: &[u8],
    output: &mut [u8],
) -> Result<usize, u16> {
    match mode {
        AesMode::Ecb => aes_ecb_decrypt(key, ciphertext, output),
        AesMode::Cbc => {
            let iv_bytes = iv.ok_or(SW_WRONG_LENGTH)?;
            aes_cbc_decrypt(key, iv_bytes, ciphertext, output)
        }
        AesMode::Ctr => {
            // CTR mode: encrypt == decrypt
            let nonce = iv.ok_or(SW_WRONG_LENGTH)?;
            aes_ctr(key, nonce, ciphertext, output)
        }
        AesMode::Gcm => {
            let nonce = iv.ok_or(SW_WRONG_LENGTH)?;
            aes_gcm_decrypt(key, nonce, ciphertext, output)
        }
        AesMode::ChaCha20Poly1305 => {
            let nonce = iv.ok_or(SW_WRONG_LENGTH)?;
            chacha20poly1305_decrypt(key, nonce, ciphertext, output)
        }
    }
}

// ---------------------------------------------------------------------------
// ECB mode — raw block cipher, no padding
// ---------------------------------------------------------------------------

fn aes_ecb_encrypt(key: &[u8], plaintext: &[u8], output: &mut [u8]) -> Result<usize, u16> {
    use aes::cipher::generic_array::GenericArray;
    use aes::cipher::{BlockEncrypt, KeyInit};

    if plaintext.len() % 16 != 0 || output.len() < plaintext.len() {
        return Err(SW_WRONG_LENGTH);
    }
    output[..plaintext.len()].copy_from_slice(plaintext);

    match key.len() {
        16 => {
            let cipher = aes::Aes128::new(GenericArray::from_slice(key));
            for chunk in output[..plaintext.len()].chunks_exact_mut(16) {
                let block = GenericArray::from_mut_slice(chunk);
                cipher.encrypt_block(block);
            }
        }
        24 => {
            let cipher = aes::Aes192::new(GenericArray::from_slice(key));
            for chunk in output[..plaintext.len()].chunks_exact_mut(16) {
                let block = GenericArray::from_mut_slice(chunk);
                cipher.encrypt_block(block);
            }
        }
        32 => {
            let cipher = aes::Aes256::new(GenericArray::from_slice(key));
            for chunk in output[..plaintext.len()].chunks_exact_mut(16) {
                let block = GenericArray::from_mut_slice(chunk);
                cipher.encrypt_block(block);
            }
        }
        _ => return Err(SW_WRONG_LENGTH),
    }

    Ok(plaintext.len())
}

fn aes_ecb_decrypt(key: &[u8], ciphertext: &[u8], output: &mut [u8]) -> Result<usize, u16> {
    use aes::cipher::generic_array::GenericArray;
    use aes::cipher::{BlockDecrypt, KeyInit};

    if ciphertext.len() % 16 != 0 || output.len() < ciphertext.len() {
        return Err(SW_WRONG_LENGTH);
    }
    output[..ciphertext.len()].copy_from_slice(ciphertext);

    match key.len() {
        16 => {
            let cipher = aes::Aes128::new(GenericArray::from_slice(key));
            for chunk in output[..ciphertext.len()].chunks_exact_mut(16) {
                let block = GenericArray::from_mut_slice(chunk);
                cipher.decrypt_block(block);
            }
        }
        24 => {
            let cipher = aes::Aes192::new(GenericArray::from_slice(key));
            for chunk in output[..ciphertext.len()].chunks_exact_mut(16) {
                let block = GenericArray::from_mut_slice(chunk);
                cipher.decrypt_block(block);
            }
        }
        32 => {
            let cipher = aes::Aes256::new(GenericArray::from_slice(key));
            for chunk in output[..ciphertext.len()].chunks_exact_mut(16) {
                let block = GenericArray::from_mut_slice(chunk);
                cipher.decrypt_block(block);
            }
        }
        _ => return Err(SW_WRONG_LENGTH),
    }

    Ok(ciphertext.len())
}

// ---------------------------------------------------------------------------
// CBC mode (PKCS#7 padding)
// ---------------------------------------------------------------------------

fn aes_cbc_encrypt(
    key: &[u8],
    iv: &[u8],
    plaintext: &[u8],
    output: &mut [u8],
) -> Result<usize, u16> {
    if iv.len() != 16 {
        return Err(SW_WRONG_LENGTH);
    }
    let iv_arr: &[u8; 16] = iv.try_into().map_err(|_| SW_WRONG_LENGTH)?;

    match key.len() {
        32 => {
            let key_arr: &[u8; 32] = key.try_into().map_err(|_| SW_WRONG_LENGTH)?;
            pico_rs_sdk::crypto::aes::aes256_cbc_encrypt(key_arr, iv_arr, plaintext, output)
                .map_err(|_| SW_INVALID_DATA)
        }
        16 => {
            // AES-128-CBC with PKCS#7 padding
            use aes::Aes128;
            use cbc::cipher::{block_padding::Pkcs7, BlockEncryptMut, KeyIvInit};
            type Aes128CbcEnc = cbc::Encryptor<Aes128>;

            let padded_len = ((plaintext.len() / 16) + 1) * 16;
            if output.len() < padded_len {
                return Err(SW_WRONG_LENGTH);
            }
            output[..plaintext.len()].copy_from_slice(plaintext);
            let ct = Aes128CbcEnc::new(key.into(), iv.into())
                .encrypt_padded_mut::<Pkcs7>(output, plaintext.len())
                .map_err(|_| SW_INVALID_DATA)?;
            Ok(ct.len())
        }
        24 => {
            // AES-192-CBC with PKCS#7 padding
            use aes::Aes192;
            use cbc::cipher::{block_padding::Pkcs7, BlockEncryptMut, KeyIvInit};
            type Aes192CbcEnc = cbc::Encryptor<Aes192>;

            let padded_len = ((plaintext.len() / 16) + 1) * 16;
            if output.len() < padded_len {
                return Err(SW_WRONG_LENGTH);
            }
            output[..plaintext.len()].copy_from_slice(plaintext);
            let ct = Aes192CbcEnc::new(key.into(), iv.into())
                .encrypt_padded_mut::<Pkcs7>(output, plaintext.len())
                .map_err(|_| SW_INVALID_DATA)?;
            Ok(ct.len())
        }
        _ => Err(SW_WRONG_LENGTH),
    }
}

fn aes_cbc_decrypt(
    key: &[u8],
    iv: &[u8],
    ciphertext: &[u8],
    output: &mut [u8],
) -> Result<usize, u16> {
    if iv.len() != 16 || ciphertext.len() % 16 != 0 {
        return Err(SW_WRONG_LENGTH);
    }
    let iv_arr: &[u8; 16] = iv.try_into().map_err(|_| SW_WRONG_LENGTH)?;

    match key.len() {
        32 => {
            let key_arr: &[u8; 32] = key.try_into().map_err(|_| SW_WRONG_LENGTH)?;
            pico_rs_sdk::crypto::aes::aes256_cbc_decrypt(key_arr, iv_arr, ciphertext, output)
                .map_err(|_| SW_INVALID_DATA)
        }
        16 => {
            use aes::Aes128;
            use cbc::cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};
            type Aes128CbcDec = cbc::Decryptor<Aes128>;

            if output.len() < ciphertext.len() {
                return Err(SW_WRONG_LENGTH);
            }
            output[..ciphertext.len()].copy_from_slice(ciphertext);
            let pt = Aes128CbcDec::new(key.into(), iv.into())
                .decrypt_padded_mut::<Pkcs7>(&mut output[..ciphertext.len()])
                .map_err(|_| SW_INVALID_DATA)?;
            Ok(pt.len())
        }
        24 => {
            use aes::Aes192;
            use cbc::cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};
            type Aes192CbcDec = cbc::Decryptor<Aes192>;

            if output.len() < ciphertext.len() {
                return Err(SW_WRONG_LENGTH);
            }
            output[..ciphertext.len()].copy_from_slice(ciphertext);
            let pt = Aes192CbcDec::new(key.into(), iv.into())
                .decrypt_padded_mut::<Pkcs7>(&mut output[..ciphertext.len()])
                .map_err(|_| SW_INVALID_DATA)?;
            Ok(pt.len())
        }
        _ => Err(SW_WRONG_LENGTH),
    }
}

// ---------------------------------------------------------------------------
// CTR mode — implemented via AES block cipher + counter XOR
// ---------------------------------------------------------------------------

fn aes_ctr(key: &[u8], nonce: &[u8], input: &[u8], output: &mut [u8]) -> Result<usize, u16> {
    use aes::cipher::generic_array::GenericArray;
    use aes::cipher::{BlockEncrypt, KeyInit};

    if nonce.len() != 16 || output.len() < input.len() {
        return Err(SW_WRONG_LENGTH);
    }

    let mut counter = [0u8; 16];
    counter.copy_from_slice(nonce);

    let len = input.len();
    let mut offset = 0usize;

    // Helper: encrypt one counter block
    macro_rules! ctr_process {
        ($cipher:expr) => {
            while offset < len {
                let mut block = GenericArray::clone_from_slice(&counter);
                $cipher.encrypt_block(&mut block);

                let remaining = len - offset;
                let chunk = if remaining < 16 { remaining } else { 16 };
                for i in 0..chunk {
                    output[offset + i] = input[offset + i] ^ block[i];
                }
                offset += chunk;

                // Increment 128-bit counter (big-endian)
                for j in (0..16).rev() {
                    counter[j] = counter[j].wrapping_add(1);
                    if counter[j] != 0 {
                        break;
                    }
                }
            }
        };
    }

    match key.len() {
        16 => {
            let cipher = aes::Aes128::new(GenericArray::from_slice(key));
            ctr_process!(cipher);
        }
        24 => {
            let cipher = aes::Aes192::new(GenericArray::from_slice(key));
            ctr_process!(cipher);
        }
        32 => {
            let cipher = aes::Aes256::new(GenericArray::from_slice(key));
            ctr_process!(cipher);
        }
        _ => return Err(SW_WRONG_LENGTH),
    }

    Ok(len)
}

// ---------------------------------------------------------------------------
// GCM mode — output = ciphertext || tag(16)  /  input = ciphertext || tag(16)
// ---------------------------------------------------------------------------

fn aes_gcm_encrypt(
    key: &[u8],
    nonce: &[u8],
    plaintext: &[u8],
    output: &mut [u8],
) -> Result<usize, u16> {
    if nonce.len() != 12 || output.len() < plaintext.len() + 16 {
        return Err(SW_WRONG_LENGTH);
    }
    let nonce_arr: &[u8; 12] = nonce.try_into().map_err(|_| SW_WRONG_LENGTH)?;

    match key.len() {
        32 => {
            let key_arr: &[u8; 32] = key.try_into().map_err(|_| SW_WRONG_LENGTH)?;
            let tag = pico_rs_sdk::crypto::aes::aes256_gcm_encrypt(
                key_arr,
                nonce_arr,
                plaintext,
                &[],
                &mut output[..plaintext.len()],
            )
            .map_err(|_| SW_INVALID_DATA)?;
            output[plaintext.len()..plaintext.len() + 16].copy_from_slice(&tag);
            Ok(plaintext.len() + 16)
        }
        16 => {
            use aes_gcm::{AeadInPlace, Aes128Gcm, KeyInit, Nonce};
            let cipher = Aes128Gcm::new(key.into());
            let gcm_nonce = Nonce::from_slice(nonce);
            output[..plaintext.len()].copy_from_slice(plaintext);
            let tag = cipher
                .encrypt_in_place_detached(gcm_nonce, &[], &mut output[..plaintext.len()])
                .map_err(|_| SW_INVALID_DATA)?;
            output[plaintext.len()..plaintext.len() + 16].copy_from_slice(&tag);
            Ok(plaintext.len() + 16)
        }
        _ => Err(SW_WRONG_LENGTH),
    }
}

fn aes_gcm_decrypt(
    key: &[u8],
    nonce: &[u8],
    ciphertext_with_tag: &[u8],
    output: &mut [u8],
) -> Result<usize, u16> {
    if nonce.len() != 12 || ciphertext_with_tag.len() < 16 {
        return Err(SW_WRONG_LENGTH);
    }
    let ct_len = ciphertext_with_tag.len() - 16;
    if output.len() < ct_len {
        return Err(SW_WRONG_LENGTH);
    }
    let nonce_arr: &[u8; 12] = nonce.try_into().map_err(|_| SW_WRONG_LENGTH)?;
    let ciphertext = &ciphertext_with_tag[..ct_len];
    let tag: &[u8; 16] = ciphertext_with_tag[ct_len..]
        .try_into()
        .map_err(|_| SW_WRONG_LENGTH)?;

    match key.len() {
        32 => {
            let key_arr: &[u8; 32] = key.try_into().map_err(|_| SW_WRONG_LENGTH)?;
            pico_rs_sdk::crypto::aes::aes256_gcm_decrypt(
                key_arr,
                nonce_arr,
                ciphertext,
                &[],
                tag,
                &mut output[..ct_len],
            )
            .map_err(|_| SW_SECURITY_NOT_SATISFIED)?;
            Ok(ct_len)
        }
        16 => {
            use aes_gcm::{AeadInPlace, Aes128Gcm, KeyInit, Nonce, Tag};
            let cipher = Aes128Gcm::new(key.into());
            let gcm_nonce = Nonce::from_slice(nonce);
            output[..ct_len].copy_from_slice(ciphertext);
            cipher
                .decrypt_in_place_detached(
                    gcm_nonce,
                    &[],
                    &mut output[..ct_len],
                    Tag::from_slice(tag),
                )
                .map_err(|_| SW_SECURITY_NOT_SATISFIED)?;
            Ok(ct_len)
        }
        _ => Err(SW_WRONG_LENGTH),
    }
}

// ---------------------------------------------------------------------------
// ChaCha20-Poly1305  — output = ciphertext || tag(16)
// ---------------------------------------------------------------------------

fn chacha20poly1305_encrypt(
    key: &[u8],
    nonce: &[u8],
    plaintext: &[u8],
    output: &mut [u8],
) -> Result<usize, u16> {
    use chacha20poly1305::{AeadInPlace, ChaCha20Poly1305, KeyInit, Nonce};

    if key.len() != 32 || nonce.len() != 12 || output.len() < plaintext.len() + 16 {
        return Err(SW_WRONG_LENGTH);
    }
    let cipher = ChaCha20Poly1305::new(key.into());
    let n = Nonce::from_slice(nonce);
    output[..plaintext.len()].copy_from_slice(plaintext);
    let tag = cipher
        .encrypt_in_place_detached(n, &[], &mut output[..plaintext.len()])
        .map_err(|_| SW_INVALID_DATA)?;
    output[plaintext.len()..plaintext.len() + 16].copy_from_slice(&tag);
    Ok(plaintext.len() + 16)
}

fn chacha20poly1305_decrypt(
    key: &[u8],
    nonce: &[u8],
    ciphertext_with_tag: &[u8],
    output: &mut [u8],
) -> Result<usize, u16> {
    use chacha20poly1305::{AeadInPlace, ChaCha20Poly1305, KeyInit, Nonce, Tag};

    if key.len() != 32 || nonce.len() != 12 || ciphertext_with_tag.len() < 16 {
        return Err(SW_WRONG_LENGTH);
    }
    let ct_len = ciphertext_with_tag.len() - 16;
    if output.len() < ct_len {
        return Err(SW_WRONG_LENGTH);
    }

    let cipher = ChaCha20Poly1305::new(key.into());
    let n = Nonce::from_slice(nonce);
    output[..ct_len].copy_from_slice(&ciphertext_with_tag[..ct_len]);
    let tag = Tag::from_slice(&ciphertext_with_tag[ct_len..]);
    cipher
        .decrypt_in_place_detached(n, &[], &mut output[..ct_len], tag)
        .map_err(|_| SW_SECURITY_NOT_SATISFIED)?;
    Ok(ct_len)
}
