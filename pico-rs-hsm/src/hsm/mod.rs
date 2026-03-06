//! SmartCard-HSM application — APDU router and top-level state.

pub mod aes_ops;
pub mod apdu_router;
pub mod certificates;
pub mod decrypt;
pub mod derive;
pub mod dkek;
pub mod ecdh;
pub mod key_management;
pub mod pin;
pub mod pkcs15;
pub mod sign;

use heapless::Vec;

use apdu_router::*;

/// SmartCard-HSM AID: `E8 2B 06 01 04 01 81 C3 1F 02 01`
pub const HSM_AID: [u8; 11] = [
    0xE8, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x81, 0xC3, 0x1F, 0x02, 0x01,
];

pub struct HsmApp {
    pub initialized: bool,
    pub pin_state: pin::PinManager,
    pub key_store: key_management::KeyStore,
    pub dkek_state: dkek::DkekState,
    pub cert_store: certificates::CertificateStore,
    pub pkcs15: pkcs15::Pkcs15Fs,
}

impl HsmApp {
    pub fn new() -> Self {
        Self {
            initialized: false,
            pin_state: pin::PinManager::new(),
            key_store: key_management::KeyStore::new(),
            dkek_state: dkek::DkekState::new(),
            cert_store: certificates::CertificateStore::new(),
            pkcs15: pkcs15::Pkcs15Fs::new(),
        }
    }

    /// Route an incoming APDU to the appropriate handler.
    ///
    /// On success the response payload is written into `response` and the
    /// number of bytes written is returned. The caller must append SW 90 00.
    /// On error the returned `u16` is the status word to send back.
    pub fn process_apdu<R: rand_core::CryptoRng + rand_core::RngCore>(
        &mut self,
        cla: u8,
        ins: u8,
        p1: u8,
        p2: u8,
        data: &[u8],
        response: &mut [u8],
        rng: &mut R,
    ) -> Result<usize, u16> {
        // Only class 0x00 and 0x80 supported
        if cla != 0x00 && cla != 0x80 {
            return Err(SW_CLA_NOT_SUPPORTED);
        }

        match ins {
            INS_SELECT => self.handle_select(p1, p2, data, response),
            INS_INITIALIZE => self.handle_initialize(data, rng),
            INS_GET_CHALLENGE => self.handle_get_challenge(p2, response, rng),
            INS_VERIFY_PIN => self.handle_verify_pin(p2, data),
            INS_CHANGE_PIN => self.handle_change_pin(p2, data, rng),
            INS_RESET_RETRY => self.handle_reset_retry(data, rng),
            INS_IMPORT_DKEK => self.handle_import_dkek(p1, p2, data),
            INS_GENERATE_KEY => self.handle_generate_key(p2, data, rng),
            INS_DELETE_KEY => self.handle_delete_key(p2),
            INS_LIST_KEYS => self.handle_list_keys(response),
            INS_WRAP_KEY => self.handle_wrap_key(p2, response),
            INS_UNWRAP_KEY => self.handle_unwrap_key(data),
            INS_PSO => self.handle_pso(p1, p2, data, response, rng),
            INS_READ_BINARY => self.handle_read_binary(p1, p2, data, response),
            INS_UPDATE_BINARY => self.handle_update_binary(p1, p2, data),
            _ => Err(SW_INS_NOT_SUPPORTED),
        }
    }

    // ------------------------------------------------------------------
    // SELECT
    // ------------------------------------------------------------------

    fn handle_select(
        &mut self,
        _p1: u8,
        _p2: u8,
        data: &[u8],
        response: &mut [u8],
    ) -> Result<usize, u16> {
        // SELECT by AID
        if data.len() >= HSM_AID.len() && data[..HSM_AID.len()] == HSM_AID {
            // Return a minimal FCI with the AID
            let mut fci: Vec<u8, 64> = Vec::new();
            let _ = fci.push(0x6F); // FCI template
            let _ = fci.push(0x00); // length placeholder
            let _ = fci.push(0x84); // DF name tag
            let _ = fci.push(HSM_AID.len() as u8);
            let _ = fci.extend_from_slice(&HSM_AID);
            let inner = fci.len() - 2;
            fci[1] = inner as u8;

            let len = fci.len().min(response.len());
            response[..len].copy_from_slice(&fci[..len]);
            return Ok(len);
        }

        // SELECT by file identifier (2 bytes)
        if data.len() >= 2 {
            let fid = u16::from_be_bytes([data[0], data[1]]);
            let fci = self.pkcs15.select_file(fid)?;
            let len = fci.len().min(response.len());
            response[..len].copy_from_slice(&fci[..len]);
            return Ok(len);
        }

        Err(SW_FILE_NOT_FOUND)
    }

    // ------------------------------------------------------------------
    // INITIALIZE
    // ------------------------------------------------------------------

    fn handle_initialize<R: rand_core::CryptoRng + rand_core::RngCore>(
        &mut self,
        data: &[u8],
        rng: &mut R,
    ) -> Result<usize, u16> {
        // Format: [dkek_total(1) | dkek_required(1) | so_pin_len(1) | so_pin(N)]
        if data.len() < 4 {
            return Err(SW_WRONG_LENGTH);
        }

        let dkek_total = data[0];
        let dkek_required = data[1];
        let so_pin_len = data[2] as usize;

        if data.len() < 3 + so_pin_len {
            return Err(SW_WRONG_LENGTH);
        }
        let so_pin = &data[3..3 + so_pin_len];

        // Reset device state
        self.key_store.clear();
        self.cert_store.clear();
        self.pin_state = pin::PinManager::new();
        self.pkcs15 = pkcs15::Pkcs15Fs::new();

        // Set SO-PIN
        self.pin_state.set_so_pin(so_pin, rng);

        // Optional user PIN after SO-PIN
        let after_so = 3 + so_pin_len;
        if data.len() > after_so {
            let user_pin_len = data[after_so] as usize;
            if data.len() >= after_so + 1 + user_pin_len {
                let user_pin = &data[after_so + 1..after_so + 1 + user_pin_len];
                self.pin_state.set_user_pin(user_pin, rng);
            }
        }

        // Initialize DKEK
        self.dkek_state.init(dkek_total, dkek_required)?;

        self.initialized = true;
        Ok(0)
    }

    // ------------------------------------------------------------------
    // GET CHALLENGE
    // ------------------------------------------------------------------

    fn handle_get_challenge<R: rand_core::CryptoRng + rand_core::RngCore>(
        &mut self,
        p2: u8,
        response: &mut [u8],
        rng: &mut R,
    ) -> Result<usize, u16> {
        let len = if p2 == 0 { 8 } else { p2 as usize };
        if response.len() < len {
            return Err(SW_WRONG_LENGTH);
        }
        rng.fill_bytes(&mut response[..len]);
        Ok(len)
    }

    // ------------------------------------------------------------------
    // PIN management
    // ------------------------------------------------------------------

    fn handle_verify_pin(&mut self, p2: u8, data: &[u8]) -> Result<usize, u16> {
        match p2 {
            0x01 => self.pin_state.verify_user_pin(data)?,
            0x02 => self.pin_state.verify_so_pin(data)?,
            _ => return Err(SW_INCORRECT_P1P2),
        }
        Ok(0)
    }

    fn handle_change_pin<R: rand_core::CryptoRng + rand_core::RngCore>(
        &mut self,
        p2: u8,
        data: &[u8],
        rng: &mut R,
    ) -> Result<usize, u16> {
        if p2 != 0x01 {
            return Err(SW_INCORRECT_P1P2);
        }
        // Format: [old_pin_len(1) | old_pin(N) | new_pin(remaining)]
        if data.is_empty() {
            return Err(SW_WRONG_LENGTH);
        }
        let old_len = data[0] as usize;
        if data.len() < 1 + old_len {
            return Err(SW_WRONG_LENGTH);
        }
        let old_pin = &data[1..1 + old_len];
        let new_pin = &data[1 + old_len..];
        self.pin_state.change_user_pin(old_pin, new_pin, rng)?;
        Ok(0)
    }

    fn handle_reset_retry<R: rand_core::CryptoRng + rand_core::RngCore>(
        &mut self,
        data: &[u8],
        rng: &mut R,
    ) -> Result<usize, u16> {
        // Format: [so_pin_len(1) | so_pin(N) | new_user_pin(remaining)]
        if data.is_empty() {
            return Err(SW_WRONG_LENGTH);
        }
        let so_len = data[0] as usize;
        if data.len() < 1 + so_len {
            return Err(SW_WRONG_LENGTH);
        }
        let so_pin = &data[1..1 + so_len];
        let new_pin = &data[1 + so_len..];
        self.pin_state.reset_user_pin(so_pin, new_pin, rng)?;
        Ok(0)
    }

    // ------------------------------------------------------------------
    // DKEK share import
    // ------------------------------------------------------------------

    fn handle_import_dkek(&mut self, p1: u8, p2: u8, data: &[u8]) -> Result<usize, u16> {
        self.require_auth()?;

        // On first call (imported_shares == 0), p1=total, p2=required configure the scheme
        if self.dkek_state.imported_shares == 0 && !self.dkek_state.is_ready() {
            self.dkek_state.init(p1, p2)?;
        }

        let _ready = self.dkek_state.import_share(data)?;
        Ok(0)
    }

    // ------------------------------------------------------------------
    // Key management
    // ------------------------------------------------------------------

    fn handle_generate_key<R: rand_core::CryptoRng + rand_core::RngCore>(
        &mut self,
        p2: u8,
        data: &[u8],
        rng: &mut R,
    ) -> Result<usize, u16> {
        self.require_auth()?;

        // P2 = key_type, data = [domain(1) | label(remaining)]
        let key_type = key_management::KeyType::from_u8(p2)?;
        let domain = if data.is_empty() { 0 } else { data[0] };
        let label = if data.len() > 1 { &data[1..] } else { &[] };

        let _id = self
            .key_store
            .generate_key(key_type, label, domain, &self.dkek_state, rng)?;
        Ok(0)
    }

    fn handle_delete_key(&mut self, p2: u8) -> Result<usize, u16> {
        self.require_auth()?;
        self.key_store.delete_key(p2)?;
        Ok(0)
    }

    fn handle_list_keys(&self, response: &mut [u8]) -> Result<usize, u16> {
        let keys = self.key_store.list_keys();
        // Return: [count(1) | entries...] where each entry = [id(1) | type(1) | domain(1)]
        let entry_len = 3;
        let total = 1 + keys.len() * entry_len;
        if response.len() < total {
            return Err(SW_WRONG_LENGTH);
        }
        response[0] = keys.len() as u8;
        for (i, key) in keys.iter().enumerate() {
            let off = 1 + i * entry_len;
            response[off] = key.id;
            response[off + 1] = key.key_type as u8;
            response[off + 2] = key.domain;
        }
        Ok(total)
    }

    fn handle_wrap_key(&self, p2: u8, response: &mut [u8]) -> Result<usize, u16> {
        if !self.pin_state.session_authenticated {
            return Err(SW_SECURITY_NOT_SATISFIED);
        }
        let blob = self.key_store.wrap_key_for_export(p2, &self.dkek_state)?;
        let len = blob.len().min(response.len());
        response[..len].copy_from_slice(&blob[..len]);
        Ok(len)
    }

    fn handle_unwrap_key(&mut self, data: &[u8]) -> Result<usize, u16> {
        self.require_auth()?;
        let _id = self.key_store.import_wrapped_key(data, &self.dkek_state)?;
        Ok(0)
    }

    // ------------------------------------------------------------------
    // PERFORM SECURITY OPERATION (PSO)
    // ------------------------------------------------------------------

    fn handle_pso<R: rand_core::CryptoRng + rand_core::RngCore>(
        &mut self,
        p1: u8,
        p2: u8,
        data: &[u8],
        response: &mut [u8],
        rng: &mut R,
    ) -> Result<usize, u16> {
        self.require_auth()?;

        match (p1, p2) {
            // Compute Digital Signature
            (PSO_CDS_P1, PSO_CDS_P2) => {
                // data = [key_id(1) | algo(1) | digest(remaining)]
                if data.len() < 3 {
                    return Err(SW_WRONG_LENGTH);
                }
                let key_id = data[0];
                let algo = data[1];
                let digest = &data[2..];

                self.key_store.check_and_increment_usage(key_id)?;
                let key = self.key_store.get_key(key_id).ok_or(SW_KEY_NOT_FOUND)?;
                let sig = sign::sign(key, &self.dkek_state, digest, algo, rng)?;

                let len = sig.len().min(response.len());
                response[..len].copy_from_slice(&sig[..len]);
                Ok(len)
            }

            // Decipher
            (PSO_DEC_P1, PSO_DEC_P2) => {
                // data = [key_id(1) | algo(1) | ciphertext(remaining)]
                if data.len() < 3 {
                    return Err(SW_WRONG_LENGTH);
                }
                let key_id = data[0];
                let algo = data[1];
                let ciphertext = &data[2..];

                self.key_store.check_and_increment_usage(key_id)?;
                let key = self.key_store.get_key(key_id).ok_or(SW_KEY_NOT_FOUND)?;
                let pt = decrypt::decrypt(key, &self.dkek_state, ciphertext, algo, rng)?;

                let len = pt.len().min(response.len());
                response[..len].copy_from_slice(&pt[..len]);
                Ok(len)
            }

            // ECDH key agreement
            (PSO_ECDH_P1, PSO_ECDH_P2) => {
                // data = [key_id(1) | peer_public_key(remaining)]
                if data.len() < 2 {
                    return Err(SW_WRONG_LENGTH);
                }
                let key_id = data[0];
                let peer_pk = &data[1..];

                self.key_store.check_and_increment_usage(key_id)?;
                let key = self.key_store.get_key(key_id).ok_or(SW_KEY_NOT_FOUND)?;
                let shared = ecdh::ecdh_derive(key, &self.dkek_state, peer_pk)?;

                let len = shared.len().min(response.len());
                response[..len].copy_from_slice(&shared[..len]);
                Ok(len)
            }

            _ => Err(SW_INCORRECT_P1P2),
        }
    }

    // ------------------------------------------------------------------
    // Binary file I/O
    // ------------------------------------------------------------------

    fn handle_read_binary(
        &mut self,
        p1: u8,
        p2: u8,
        _data: &[u8],
        response: &mut [u8],
    ) -> Result<usize, u16> {
        // P1 high bit clear: P1P2 = offset, read from selected EF
        // P1 high bit set: short file identifier in P1 bits 0-4
        let offset = u16::from_be_bytes([p1 & 0x7F, p2]);
        let length = response.len() as u16;

        let content = self.pkcs15.read_binary(offset, length)?;
        let len = content.len().min(response.len());
        response[..len].copy_from_slice(&content[..len]);
        Ok(len)
    }

    fn handle_update_binary(&mut self, p1: u8, p2: u8, data: &[u8]) -> Result<usize, u16> {
        self.require_auth()?;
        let offset = u16::from_be_bytes([p1 & 0x7F, p2]);
        self.pkcs15.update_binary(offset, data)?;
        Ok(0)
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    fn require_auth(&self) -> Result<(), u16> {
        if !self.pin_state.session_authenticated {
            return Err(SW_SECURITY_NOT_SATISFIED);
        }
        Ok(())
    }
}
