//! PIN management with constant-time comparison and PBKDF2 hashing.

use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use super::apdu_router::*;

const MAX_USER_RETRIES: u8 = 3;
const MAX_SO_RETRIES: u8 = 15;
const PBKDF2_ITERATIONS: u32 = 10_000;

pub struct PinManager {
    pub user_pin_set: bool,
    pub user_pin_hash: [u8; 32],
    pub user_pin_salt: [u8; 16],
    pub user_retries: u8,
    pub so_pin_hash: [u8; 32],
    pub so_pin_salt: [u8; 16],
    pub so_retries: u8,
    pub session_authenticated: bool,
    pub transport_pin_set: bool,
}

impl PinManager {
    pub fn new() -> Self {
        Self {
            user_pin_set: false,
            user_pin_hash: [0u8; 32],
            user_pin_salt: [0u8; 16],
            user_retries: MAX_USER_RETRIES,
            so_pin_hash: [0u8; 32],
            so_pin_salt: [0u8; 16],
            so_retries: MAX_SO_RETRIES,
            session_authenticated: false,
            transport_pin_set: false,
        }
    }

    fn hash_pin(pin: &[u8], salt: &[u8; 16]) -> [u8; 32] {
        let mut hash = [0u8; 32];
        pico_rs_sdk::crypto::symmetric::pbkdf2_sha256(pin, salt, PBKDF2_ITERATIONS, &mut hash);
        hash
    }

    pub fn set_user_pin(
        &mut self,
        pin: &[u8],
        rng: &mut (impl rand_core::RngCore + rand_core::CryptoRng),
    ) {
        rng.fill_bytes(&mut self.user_pin_salt);
        self.user_pin_hash = Self::hash_pin(pin, &self.user_pin_salt);
        self.user_pin_set = true;
        self.user_retries = MAX_USER_RETRIES;
    }

    pub fn set_so_pin(
        &mut self,
        pin: &[u8],
        rng: &mut (impl rand_core::RngCore + rand_core::CryptoRng),
    ) {
        rng.fill_bytes(&mut self.so_pin_salt);
        self.so_pin_hash = Self::hash_pin(pin, &self.so_pin_salt);
        self.so_retries = MAX_SO_RETRIES;
    }

    pub fn verify_user_pin(&mut self, pin: &[u8]) -> Result<(), u16> {
        if !self.user_pin_set {
            return Err(SW_CONDITIONS_NOT_SATISFIED);
        }
        if self.user_retries == 0 {
            return Err(SW_PIN_BLOCKED);
        }

        let mut computed = Self::hash_pin(pin, &self.user_pin_salt);
        let matches: bool = computed.ct_eq(&self.user_pin_hash).into();
        computed.zeroize();

        if matches {
            self.user_retries = MAX_USER_RETRIES;
            self.session_authenticated = true;
            Ok(())
        } else {
            self.user_retries = self.user_retries.saturating_sub(1);
            // Return 0x63Cx where x = remaining retries
            Err(0x63C0 | self.user_retries as u16)
        }
    }

    pub fn change_user_pin(
        &mut self,
        old: &[u8],
        new: &[u8],
        rng: &mut (impl rand_core::RngCore + rand_core::CryptoRng),
    ) -> Result<(), u16> {
        self.verify_user_pin(old)?;

        // Generate fresh salt for the new PIN
        rng.fill_bytes(&mut self.user_pin_salt);
        let mut new_hash = Self::hash_pin(new, &self.user_pin_salt);
        self.user_pin_hash.copy_from_slice(&new_hash);
        new_hash.zeroize();
        Ok(())
    }

    pub fn verify_so_pin(&mut self, pin: &[u8]) -> Result<(), u16> {
        if self.so_retries == 0 {
            return Err(SW_PIN_BLOCKED);
        }

        let mut computed = Self::hash_pin(pin, &self.so_pin_salt);
        let matches: bool = computed.ct_eq(&self.so_pin_hash).into();
        computed.zeroize();

        if matches {
            self.so_retries = MAX_SO_RETRIES;
            Ok(())
        } else {
            self.so_retries = self.so_retries.saturating_sub(1);
            Err(0x63C0 | self.so_retries as u16)
        }
    }

    pub fn reset_user_pin(
        &mut self,
        so_pin: &[u8],
        new_user_pin: &[u8],
        rng: &mut (impl rand_core::RngCore + rand_core::CryptoRng),
    ) -> Result<(), u16> {
        self.verify_so_pin(so_pin)?;

        rng.fill_bytes(&mut self.user_pin_salt);
        let mut new_hash = Self::hash_pin(new_user_pin, &self.user_pin_salt);
        self.user_pin_hash.copy_from_slice(&new_hash);
        new_hash.zeroize();

        self.user_retries = MAX_USER_RETRIES;
        self.user_pin_set = true;
        self.session_authenticated = false;
        Ok(())
    }

    pub fn logout(&mut self) {
        self.session_authenticated = false;
    }
}
