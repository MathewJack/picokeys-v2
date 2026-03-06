//! Random number generation abstractions.

use rand_core::{CryptoRng, RngCore};

/// Marker trait combining RngCore + CryptoRng.
pub trait RngSource: RngCore + CryptoRng {}
impl<T: RngCore + CryptoRng> RngSource for T {}

/// Software-based RNG for testing (NOT cryptographically secure in production).
/// Uses a simple xorshift64 PRNG seeded from an initial value.
pub struct SoftwareRng {
    state: u64,
}

impl SoftwareRng {
    pub fn new(seed: u64) -> Self {
        Self { state: if seed == 0 { 1 } else { seed } }
    }
}

impl RngCore for SoftwareRng {
    fn next_u32(&mut self) -> u32 {
        self.next_u64() as u32
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        x
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        let mut i = 0;
        while i < dest.len() {
            let val = self.next_u64().to_le_bytes();
            let remaining = dest.len() - i;
            let to_copy = if remaining < 8 { remaining } else { 8 };
            dest[i..i + to_copy].copy_from_slice(&val[..to_copy]);
            i += to_copy;
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl CryptoRng for SoftwareRng {}
