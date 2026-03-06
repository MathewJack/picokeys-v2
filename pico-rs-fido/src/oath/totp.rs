//! TOTP — Time-Based One-Time Password (RFC 6238).

use super::OathAlgorithm;

/// Generate a TOTP code.
///
/// - `secret`: shared secret key
/// - `time`: current Unix timestamp in seconds
/// - `period`: time step in seconds (typically 30)
/// - `digits`: number of OTP digits (typically 6 or 8)
/// - `algorithm`: HMAC hash algorithm
///
/// Internally computes `counter = time / period` and delegates to HOTP.
pub fn generate_totp(
    secret: &[u8],
    time: u64,
    period: u32,
    digits: u8,
    algorithm: OathAlgorithm,
) -> u32 {
    let counter = time / period as u64;
    super::hotp::generate_hotp(secret, counter, digits, algorithm)
}
