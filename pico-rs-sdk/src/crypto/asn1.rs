//! Minimal ASN.1/DER encoding helpers for ECDSA signatures and key structures.

use super::CryptoError;

/// Encode a DER INTEGER from a big-endian unsigned byte slice.
/// Prepends 0x00 if the high bit is set (to keep the value positive).
pub fn encode_der_integer(value: &[u8], output: &mut [u8]) -> Result<usize, CryptoError> {
    let needs_pad = !value.is_empty() && (value[0] & 0x80) != 0;
    let content_len = value.len() + if needs_pad { 1 } else { 0 };
    let total = 2 + content_len; // tag + length + content

    if output.len() < total {
        return Err(CryptoError::BufferTooSmall);
    }

    output[0] = 0x02; // INTEGER tag
    output[1] = content_len as u8;

    let mut pos = 2;
    if needs_pad {
        output[pos] = 0x00;
        pos += 1;
    }
    output[pos..pos + value.len()].copy_from_slice(value);

    Ok(total)
}

/// Encode an ECDSA signature from raw (r, s) components into DER SEQUENCE format.
/// Both r and s should be big-endian unsigned integers (typically 32 bytes for P-256).
pub fn encode_ecdsa_signature_der(
    r: &[u8],
    s: &[u8],
    output: &mut [u8],
) -> Result<usize, CryptoError> {
    // Encode r and s as DER INTEGERs into temp buffers
    let mut r_buf = [0u8; 36]; // 32 + pad + tag + length
    let r_len = encode_der_integer(r, &mut r_buf)?;

    let mut s_buf = [0u8; 36];
    let s_len = encode_der_integer(s, &mut s_buf)?;

    let seq_content_len = r_len + s_len;
    let total = 2 + seq_content_len; // SEQUENCE tag + length + content

    if output.len() < total {
        return Err(CryptoError::BufferTooSmall);
    }

    output[0] = 0x30; // SEQUENCE tag
    output[1] = seq_content_len as u8;
    output[2..2 + r_len].copy_from_slice(&r_buf[..r_len]);
    output[2 + r_len..2 + r_len + s_len].copy_from_slice(&s_buf[..s_len]);

    Ok(total)
}

/// Decode a DER SEQUENCE, returning (content_bytes, remaining_input).
pub fn decode_der_sequence(input: &[u8]) -> Result<(&[u8], &[u8]), CryptoError> {
    if input.len() < 2 || input[0] != 0x30 {
        return Err(CryptoError::InvalidLength);
    }

    let (content_len, header_len) = decode_der_length(&input[1..])?;
    let total = header_len + 1 + content_len;

    if input.len() < total {
        return Err(CryptoError::InvalidLength);
    }

    let content_start = 1 + header_len;
    Ok((
        &input[content_start..content_start + content_len],
        &input[total..],
    ))
}

/// Decode a DER length field. Returns (length_value, bytes_consumed).
fn decode_der_length(input: &[u8]) -> Result<(usize, usize), CryptoError> {
    if input.is_empty() {
        return Err(CryptoError::InvalidLength);
    }

    if input[0] < 0x80 {
        Ok((input[0] as usize, 1))
    } else if input[0] == 0x81 {
        if input.len() < 2 {
            return Err(CryptoError::InvalidLength);
        }
        Ok((input[1] as usize, 2))
    } else if input[0] == 0x82 {
        if input.len() < 3 {
            return Err(CryptoError::InvalidLength);
        }
        let len = ((input[1] as usize) << 8) | (input[2] as usize);
        Ok((len, 3))
    } else {
        Err(CryptoError::InvalidLength)
    }
}

/// Encode a simple DER SEQUENCE wrapping raw content items.
pub fn encode_der_sequence(items: &[&[u8]], output: &mut [u8]) -> Result<usize, CryptoError> {
    let total_content: usize = items.iter().map(|i| i.len()).sum();
    let total = 2 + total_content;

    if output.len() < total {
        return Err(CryptoError::BufferTooSmall);
    }

    output[0] = 0x30;
    output[1] = total_content as u8;

    let mut pos = 2;
    for item in items {
        output[pos..pos + item.len()].copy_from_slice(item);
        pos += item.len();
    }

    Ok(total)
}
