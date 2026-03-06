//! DKEK (Device Key Encryption Key) management with n-of-m Shamir threshold.
//!
//! The DKEK protects all private key material at rest. It can be split into
//! shares via Shamir Secret Sharing over GF(2⁸) so that any `required` of
//! `total` shares suffice to reconstruct the key.

use heapless::Vec;
use zeroize::Zeroize;

use super::apdu_router::*;

// ---------------------------------------------------------------------------
// GF(256) arithmetic (irreducible polynomial x⁸ + x⁴ + x³ + x + 1 = 0x11B)
// ---------------------------------------------------------------------------

#[inline]
fn gf256_add(a: u8, b: u8) -> u8 {
    a ^ b
}

fn gf256_mul(mut a: u8, mut b: u8) -> u8 {
    let mut result: u8 = 0;
    for _ in 0..8 {
        if b & 1 != 0 {
            result ^= a;
        }
        let high = a & 0x80;
        a = a.wrapping_shl(1);
        if high != 0 {
            a ^= 0x1B; // reduction modulo x⁸+x⁴+x³+x+1
        }
        b >>= 1;
    }
    result
}

fn gf256_pow(mut base: u8, mut exp: u8) -> u8 {
    let mut result: u8 = 1;
    while exp > 0 {
        if exp & 1 != 0 {
            result = gf256_mul(result, base);
        }
        base = gf256_mul(base, base);
        exp >>= 1;
    }
    result
}

/// Multiplicative inverse via Fermat's little theorem: a⁻¹ = a²⁵⁴ in GF(256).
fn gf256_inv(a: u8) -> u8 {
    if a == 0 {
        return 0;
    }
    gf256_pow(a, 254)
}

#[inline]
fn gf256_div(a: u8, b: u8) -> u8 {
    gf256_mul(a, gf256_inv(b))
}

// ---------------------------------------------------------------------------
// Shamir Secret Sharing
// ---------------------------------------------------------------------------

/// Split a 32-byte `secret` into `total` shares with a threshold of `required`.
///
/// Each returned share is 33 bytes: `[x_coordinate (1) | y_values (32)]`.
/// Evaluation points are 1 …= total (never 0, since f(0) = secret).
fn split_secret(
    secret: &[u8; 32],
    total: u8,
    required: u8,
    rng: &mut (impl rand_core::RngCore + rand_core::CryptoRng),
) -> Vec<[u8; 33], 8> {
    let mut shares: Vec<[u8; 33], 8> = Vec::new();
    // Random coefficients for polynomial of degree (required-1), one set per byte.
    // coefficients[byte_idx][coeff_idx], coeff 0 = secret byte.
    // We generate coefficients on the fly per-byte to save RAM.

    // Pre-generate random polynomial coefficients: one set per secret byte.
    // coefficients[byte_idx][coeff_idx] where coeff_idx ∈ 0..(required-1)
    // coeff 0 (the constant term) is the secret byte itself.
    let num_coeffs = (required - 1) as usize;
    let mut coefficients = [[0u8; 7]; 32]; // max required=8 → 7 random coefficients
    for byte_idx in 0..32 {
        for coeff_idx in 0..num_coeffs {
            let mut buf = [0u8; 1];
            rng.fill_bytes(&mut buf);
            coefficients[byte_idx][coeff_idx] = buf[0];
        }
    }

    // Evaluate the polynomial at each share point x = 1..=total
    for x in 1..=total {
        let mut share = [0u8; 33];
        share[0] = x; // evaluation point

        for byte_idx in 0..32 {
            // f(X) = secret[byte_idx] + a1·X + a2·X² + …
            let mut y = secret[byte_idx];
            let mut x_pow = x; // x^1

            for coeff_idx in 0..num_coeffs {
                y = gf256_add(y, gf256_mul(coefficients[byte_idx][coeff_idx], x_pow));
                x_pow = gf256_mul(x_pow, x);
            }

            share[1 + byte_idx] = y;
        }

        let _ = shares.push(share);
    }

    // Zeroize coefficients
    for row in coefficients.iter_mut() {
        row.zeroize();
    }

    shares
}

/// Reconstruct a 32-byte secret from `shares` using Lagrange interpolation at x = 0.
///
/// Each share is `(x, [y₀, y₁, …, y₃₁])`.
fn reconstruct_secret(shares: &[([u8; 32], u8)]) -> [u8; 32] {
    let k = shares.len();
    let mut secret = [0u8; 32];

    for byte_idx in 0..32 {
        let mut value: u8 = 0;

        for j in 0..k {
            let (ref yj_data, xj) = shares[j];
            let yj = yj_data[byte_idx];

            // Lagrange basis polynomial L_j(0) = ∏_{m≠j} (0 - x_m) / (x_j - x_m)
            //   In GF(2⁸): subtraction = XOR, and 0 ⊕ x_m = x_m
            //   L_j(0) = ∏_{m≠j} x_m / (x_j ⊕ x_m)
            let mut basis: u8 = 1;
            for m in 0..k {
                if m == j {
                    continue;
                }
                let (_, xm) = shares[m];
                let num = xm;
                let den = gf256_add(xj, xm);
                basis = gf256_mul(basis, gf256_div(num, den));
            }

            value = gf256_add(value, gf256_mul(yj, basis));
        }

        secret[byte_idx] = value;
    }

    secret
}

// ---------------------------------------------------------------------------
// DKEK state machine
// ---------------------------------------------------------------------------

pub struct DkekState {
    pub dkek: Option<[u8; 32]>,
    pub total_shares: u8,
    pub required_shares: u8,
    pub imported_shares: u8,
    /// Stored as (share_data[32], x_coordinate)
    pub shares_buffer: Vec<([u8; 32], u8), 8>,
}

impl Drop for DkekState {
    fn drop(&mut self) {
        // Use write_volatile to prevent compiler from eliding zeroization
        if let Some(ref mut k) = self.dkek {
            for byte in k.iter_mut() {
                unsafe { core::ptr::write_volatile(byte, 0) };
            }
        }
        for (ref mut data, _) in self.shares_buffer.iter_mut() {
            for byte in data.iter_mut() {
                unsafe { core::ptr::write_volatile(byte, 0) };
            }
        }
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
}

impl DkekState {
    pub fn new() -> Self {
        Self {
            dkek: None,
            total_shares: 0,
            required_shares: 0,
            imported_shares: 0,
            shares_buffer: Vec::new(),
        }
    }

    /// Configure the n-of-m threshold scheme. Clears any previous state.
    pub fn init(&mut self, total: u8, required: u8) -> Result<(), u16> {
        if required == 0 || total == 0 || required > total || total > 8 {
            return Err(SW_INVALID_DATA);
        }

        // Zeroize previous DKEK
        if let Some(ref mut k) = self.dkek {
            k.zeroize();
        }
        for (ref mut data, _) in self.shares_buffer.iter_mut() {
            data.zeroize();
        }
        self.shares_buffer.clear();

        self.dkek = None;
        self.total_shares = total;
        self.required_shares = required;
        self.imported_shares = 0;
        Ok(())
    }

    /// Import one share. Returns `true` when the DKEK has been reconstructed.
    ///
    /// Share format: `[x_coordinate (1) | data (32)]` = 33 bytes.
    /// If `total == required == 1`, the 32-byte data IS the DKEK directly
    /// (pass x = 0 or any value; the data is used as-is).
    pub fn import_share(&mut self, share: &[u8]) -> Result<bool, u16> {
        if self.dkek.is_some() {
            return Err(SW_CONDITIONS_NOT_SATISFIED);
        }

        if self.total_shares == 1 && self.required_shares == 1 {
            // Direct key import — no Shamir
            if share.len() < 32 {
                return Err(SW_WRONG_LENGTH);
            }
            let mut key = [0u8; 32];
            key.copy_from_slice(&share[..32]);
            self.dkek = Some(key);
            self.imported_shares = 1;
            return Ok(true);
        }

        // Shamir mode: share must be 33 bytes [x | data32]
        if share.len() < 33 {
            return Err(SW_WRONG_LENGTH);
        }
        let x = share[0];
        if x == 0 {
            return Err(SW_INVALID_DATA);
        }
        let mut data = [0u8; 32];
        data.copy_from_slice(&share[1..33]);

        if self.shares_buffer.is_full() {
            return Err(SW_FILE_FULL);
        }
        self.shares_buffer
            .push((data, x))
            .map_err(|_| SW_FILE_FULL)?;
        self.imported_shares += 1;

        if self.imported_shares >= self.required_shares {
            // Reconstruct
            let secret = reconstruct_secret(&self.shares_buffer);
            // Zeroize share buffer
            for (ref mut d, _) in self.shares_buffer.iter_mut() {
                d.zeroize();
            }
            self.shares_buffer.clear();
            self.dkek = Some(secret);
            return Ok(true);
        }

        Ok(false)
    }

    /// Generate a fresh random DKEK and optionally split it into shares.
    /// Returns the shares (each 33 bytes). If total/required == 1, returns
    /// the raw 32-byte DKEK as a single "share" with x=0.
    pub fn generate(
        &mut self,
        total: u8,
        required: u8,
        rng: &mut (impl rand_core::RngCore + rand_core::CryptoRng),
    ) -> Result<Vec<[u8; 33], 8>, u16> {
        self.init(total, required)?;

        let mut secret = [0u8; 32];
        rng.fill_bytes(&mut secret);

        if total == 1 && required == 1 {
            self.dkek = Some(secret);
            self.imported_shares = 1;
            let mut out: Vec<[u8; 33], 8> = Vec::new();
            let mut share = [0u8; 33];
            share[0] = 0; // no index needed
            share[1..33].copy_from_slice(&secret);
            secret.zeroize();
            let _ = out.push(share);
            return Ok(out);
        }

        let shares = split_secret(&secret, total, required, rng);
        self.dkek = Some(secret);
        secret.zeroize();
        self.imported_shares = required; // mark as ready
        Ok(shares)
    }

    pub fn is_ready(&self) -> bool {
        self.dkek.is_some()
    }

    /// Wrap key material under the DKEK using AES-256-GCM.
    ///
    /// Output format: `[nonce (12) | ciphertext (N) | tag (16)]`
    pub fn wrap_key(
        &self,
        key_data: &[u8],
        rng: &mut (impl rand_core::RngCore + rand_core::CryptoRng),
    ) -> Result<Vec<u8, 512>, u16> {
        let dkek = self.dkek.as_ref().ok_or(SW_CONDITIONS_NOT_SATISFIED)?;

        // Generate a random nonce — never reuse with the same key
        let mut nonce = [0u8; 12];
        rng.fill_bytes(&mut nonce);

        let ct_len = key_data.len();
        let total_len = 12 + ct_len + 16;

        let mut output: Vec<u8, 512> = Vec::new();
        // Reserve space
        output.resize(total_len, 0).map_err(|_| SW_WRONG_LENGTH)?;

        // Copy nonce
        output[..12].copy_from_slice(&nonce);

        // Encrypt in-place
        let tag = pico_rs_sdk::crypto::aes::aes256_gcm_encrypt(
            dkek,
            &nonce,
            key_data,
            &[], // no AAD
            &mut output[12..12 + ct_len],
        )
        .map_err(|_| SW_INVALID_DATA)?;

        output[12 + ct_len..12 + ct_len + 16].copy_from_slice(&tag);
        Ok(output)
    }

    /// Unwrap key material. Input format: `[nonce (12) | ciphertext (N) | tag (16)]`
    pub fn unwrap_key(&self, wrapped: &[u8]) -> Result<Vec<u8, 512>, u16> {
        let dkek = self.dkek.as_ref().ok_or(SW_CONDITIONS_NOT_SATISFIED)?;

        if wrapped.len() < 12 + 16 {
            return Err(SW_WRONG_LENGTH);
        }

        let nonce_bytes: &[u8; 12] = wrapped[..12].try_into().map_err(|_| SW_WRONG_LENGTH)?;
        let ct_len = wrapped.len() - 12 - 16;
        let ciphertext = &wrapped[12..12 + ct_len];
        let tag: &[u8; 16] = wrapped[12 + ct_len..]
            .try_into()
            .map_err(|_| SW_WRONG_LENGTH)?;

        let mut plaintext: Vec<u8, 512> = Vec::new();
        plaintext.resize(ct_len, 0).map_err(|_| SW_WRONG_LENGTH)?;

        pico_rs_sdk::crypto::aes::aes256_gcm_decrypt(
            dkek,
            nonce_bytes,
            ciphertext,
            &[],
            tag,
            &mut plaintext,
        )
        .map_err(|_| SW_SECURITY_NOT_SATISFIED)?;

        Ok(plaintext)
    }
}
