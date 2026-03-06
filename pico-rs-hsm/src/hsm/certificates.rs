//! Certificate storage and management (X.509, CV certificates).

use heapless::Vec;

use super::apdu_router::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertType {
    X509,
    Cv,
}

pub struct Certificate {
    pub id: u8,
    pub key_id: u8,
    pub cert_type: CertType,
    pub data: Vec<u8, 2048>,
}

pub struct CertificateStore {
    certs: Vec<Certificate, 16>,
    next_id: u8,
}

impl CertificateStore {
    pub fn new() -> Self {
        Self {
            certs: Vec::new(),
            next_id: 1,
        }
    }

    pub fn import_cert(
        &mut self,
        key_id: u8,
        cert_data: &[u8],
        cert_type: CertType,
    ) -> Result<u8, u16> {
        if self.certs.is_full() {
            return Err(SW_FILE_FULL);
        }
        if cert_data.len() > 2048 {
            return Err(SW_WRONG_LENGTH);
        }

        let id = self.allocate_id()?;
        let mut data: Vec<u8, 2048> = Vec::new();
        data.extend_from_slice(cert_data)
            .map_err(|_| SW_WRONG_LENGTH)?;

        let cert = Certificate {
            id,
            key_id,
            cert_type,
            data,
        };
        self.certs.push(cert).map_err(|_| SW_FILE_FULL)?;
        Ok(id)
    }

    pub fn export_cert(&self, cert_id: u8) -> Option<&Certificate> {
        self.certs.iter().find(|c| c.id == cert_id)
    }

    pub fn find_by_key(&self, key_id: u8) -> Option<&Certificate> {
        self.certs.iter().find(|c| c.key_id == key_id)
    }

    pub fn delete_cert(&mut self, cert_id: u8) -> Result<(), u16> {
        let pos = self
            .certs
            .iter()
            .position(|c| c.id == cert_id)
            .ok_or(SW_FILE_NOT_FOUND)?;
        self.certs.swap_remove(pos);
        Ok(())
    }

    pub fn list_certs(&self) -> &[Certificate] {
        &self.certs
    }

    pub fn clear(&mut self) {
        self.certs.clear();
        self.next_id = 1;
    }

    fn allocate_id(&mut self) -> Result<u8, u16> {
        let start = self.next_id;
        loop {
            if !self.certs.iter().any(|c| c.id == self.next_id) {
                let id = self.next_id;
                self.next_id = self.next_id.wrapping_add(1);
                if self.next_id == 0 {
                    self.next_id = 1;
                }
                return Ok(id);
            }
            self.next_id = self.next_id.wrapping_add(1);
            if self.next_id == 0 {
                self.next_id = 1;
            }
            if self.next_id == start {
                return Err(SW_FILE_FULL);
            }
        }
    }
}
