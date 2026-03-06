//! PKCS#15 virtual file system.
//!
//! Provides minimal EF/DF navigation and binary read/update for the
//! SmartCard-HSM PKCS#15 application structure.

use heapless::Vec;

use super::apdu_router::*;

// --- Well-known file identifiers ---

pub const MF: u16 = 0x3F00;
pub const EF_DIR: u16 = 0x2F00;
pub const DF_PKCS15: u16 = 0x5015;
pub const EF_TOKENINFO: u16 = 0x5032;
pub const EF_OD: u16 = 0x5031;

// --- Token info constants ---

const TOKEN_LABEL: &[u8] = b"PicoKeys HSM";
const TOKEN_SERIAL: &[u8] = b"PKRSV2-00000001";
const TOKEN_MANUFACTURER: &[u8] = b"PicoKeys";

pub struct Pkcs15Fs {
    pub current_df: u16,
    pub selected_ef: Option<u16>,
}

impl Pkcs15Fs {
    pub fn new() -> Self {
        Self {
            current_df: MF,
            selected_ef: None,
        }
    }

    /// SELECT a file by file identifier. Returns the FCI (File Control Information).
    pub fn select_file(&mut self, fid: u16) -> Result<Vec<u8, 256>, u16> {
        match fid {
            MF => {
                self.current_df = MF;
                self.selected_ef = None;
                Ok(encode_fci(fid, 0))
            }
            DF_PKCS15 => {
                self.current_df = DF_PKCS15;
                self.selected_ef = None;
                Ok(encode_fci(fid, 0))
            }
            EF_DIR => {
                self.selected_ef = Some(EF_DIR);
                let dir = self.encode_ef_dir();
                Ok(encode_fci(fid, dir.len() as u16))
            }
            EF_TOKENINFO => {
                if self.current_df != DF_PKCS15 {
                    return Err(SW_FILE_NOT_FOUND);
                }
                self.selected_ef = Some(EF_TOKENINFO);
                let ti = self.encode_token_info();
                Ok(encode_fci(fid, ti.len() as u16))
            }
            EF_OD => {
                if self.current_df != DF_PKCS15 {
                    return Err(SW_FILE_NOT_FOUND);
                }
                self.selected_ef = Some(EF_OD);
                let od = self.encode_object_directory();
                Ok(encode_fci(fid, od.len() as u16))
            }
            _ => Err(SW_FILE_NOT_FOUND),
        }
    }

    /// READ BINARY from the currently selected EF.
    pub fn read_binary(&self, offset: u16, length: u16) -> Result<Vec<u8, 512>, u16> {
        let fid = self.selected_ef.ok_or(SW_CONDITIONS_NOT_SATISFIED)?;
        let data = self.file_contents(fid)?;

        let start = offset as usize;
        if start > data.len() {
            return Err(SW_WRONG_LENGTH);
        }
        let end = (start + length as usize).min(data.len());

        let mut out: Vec<u8, 512> = Vec::new();
        out.extend_from_slice(&data[start..end])
            .map_err(|_| SW_WRONG_LENGTH)?;
        Ok(out)
    }

    /// UPDATE BINARY — only allowed on mutable EFs (currently none).
    pub fn update_binary(&mut self, _offset: u16, _data: &[u8]) -> Result<(), u16> {
        // The virtual PKCS#15 files are read-only in this implementation.
        // Actual key/cert storage goes through KeyStore/CertificateStore.
        Err(SW_CONDITIONS_NOT_SATISFIED)
    }

    // ------------------------------------------------------------------
    // File content generators
    // ------------------------------------------------------------------

    fn file_contents(&self, fid: u16) -> Result<Vec<u8, 512>, u16> {
        match fid {
            EF_DIR => {
                let d = self.encode_ef_dir();
                let mut out: Vec<u8, 512> = Vec::new();
                out.extend_from_slice(&d).map_err(|_| SW_WRONG_LENGTH)?;
                Ok(out)
            }
            EF_TOKENINFO => {
                let ti = self.encode_token_info();
                let mut out: Vec<u8, 512> = Vec::new();
                out.extend_from_slice(&ti).map_err(|_| SW_WRONG_LENGTH)?;
                Ok(out)
            }
            EF_OD => {
                let od = self.encode_object_directory();
                let mut out: Vec<u8, 512> = Vec::new();
                out.extend_from_slice(&od).map_err(|_| SW_WRONG_LENGTH)?;
                Ok(out)
            }
            _ => Err(SW_FILE_NOT_FOUND),
        }
    }

    /// EF.DIR — application template pointing to DF.PKCS15.
    /// Simplified ASN.1 DER encoding.
    fn encode_ef_dir(&self) -> Vec<u8, 256> {
        let mut buf: Vec<u8, 256> = Vec::new();
        // Application template (tag 0x61)
        let _ = buf.push(0x61);
        let _ = buf.push(0x00); // placeholder for length

        // Application identifier (tag 0x4F) — PKCS#15 AID
        let pkcs15_aid: &[u8] = &[
            0xA0, 0x00, 0x00, 0x00, 0x63, 0x50, 0x4B, 0x43, 0x53, 0x2D, 0x31, 0x35,
        ];
        let _ = buf.push(0x4F);
        let _ = buf.push(pkcs15_aid.len() as u8);
        let _ = buf.extend_from_slice(pkcs15_aid);

        // Application label (tag 0x50)
        let _ = buf.push(0x50);
        let _ = buf.push(TOKEN_LABEL.len() as u8);
        let _ = buf.extend_from_slice(TOKEN_LABEL);

        // Path (tag 0x51) — DF_PKCS15 = 0x5015
        let _ = buf.push(0x51);
        let _ = buf.push(0x02);
        let _ = buf.extend_from_slice(&DF_PKCS15.to_be_bytes());

        // Fix length
        let inner_len = buf.len() - 2;
        buf[1] = inner_len as u8;
        buf
    }

    /// EF.TokenInfo — PKCS#15 TokenInfo structure.
    pub fn encode_token_info(&self) -> Vec<u8, 256> {
        let mut buf: Vec<u8, 256> = Vec::new();

        // SEQUENCE (tag 0x30)
        let _ = buf.push(0x30);
        let _ = buf.push(0x00); // placeholder

        // version INTEGER (v1 = 0)
        let _ = buf.push(0x02);
        let _ = buf.push(0x01);
        let _ = buf.push(0x00);

        // serialNumber OCTET STRING
        let _ = buf.push(0x04);
        let _ = buf.push(TOKEN_SERIAL.len() as u8);
        let _ = buf.extend_from_slice(TOKEN_SERIAL);

        // manufacturerID UTF8String
        let _ = buf.push(0x0C);
        let _ = buf.push(TOKEN_MANUFACTURER.len() as u8);
        let _ = buf.extend_from_slice(TOKEN_MANUFACTURER);

        // label UTF8String
        let _ = buf.push(0x80); // context [0] implicit
        let _ = buf.push(TOKEN_LABEL.len() as u8);
        let _ = buf.extend_from_slice(TOKEN_LABEL);

        // tokenflags BIT STRING — { readOnly(0), loginRequired(2) }
        let _ = buf.push(0x03);
        let _ = buf.push(0x02);
        let _ = buf.push(0x06); // 6 unused bits
        let _ = buf.push(0xA0); // bits: readOnly=1, loginRequired=1

        let inner_len = buf.len() - 2;
        buf[1] = inner_len as u8;
        buf
    }

    /// EF.OD — Object Directory referencing PrKD, PuKD, CD files.
    fn encode_object_directory(&self) -> Vec<u8, 256> {
        let mut buf: Vec<u8, 256> = Vec::new();

        // privateKeys [0] — path to EF.PrKD
        encode_od_entry(&mut buf, 0xA0, 0xC000);
        // publicKeys [1] — path to EF.PuKD (certificates)
        encode_od_entry(&mut buf, 0xA1, 0xC001);
        // certificates [4]
        encode_od_entry(&mut buf, 0xA4, 0xC008);

        buf
    }
}

/// Encode a simple FCI (File Control Information) TLV.
fn encode_fci(fid: u16, file_size: u16) -> Vec<u8, 256> {
    let mut buf: Vec<u8, 256> = Vec::new();
    // FCI template (tag 0x6F)
    let _ = buf.push(0x6F);
    let _ = buf.push(0x00); // placeholder

    // File identifier (tag 0x83)
    let _ = buf.push(0x83);
    let _ = buf.push(0x02);
    let _ = buf.extend_from_slice(&fid.to_be_bytes());

    // File size (tag 0x81)
    if file_size > 0 {
        let _ = buf.push(0x81);
        let _ = buf.push(0x02);
        let _ = buf.extend_from_slice(&file_size.to_be_bytes());
    }

    let inner_len = buf.len() - 2;
    buf[1] = inner_len as u8;
    buf
}

/// Encode a single Object Directory entry: context-tagged SEQUENCE { Path }.
fn encode_od_entry(buf: &mut Vec<u8, 256>, tag: u8, path: u16) {
    let _ = buf.push(tag);
    let _ = buf.push(0x06); // inner length
                            // SEQUENCE
    let _ = buf.push(0x30);
    let _ = buf.push(0x04);
    // Path OCTET STRING
    let _ = buf.push(0x04);
    let _ = buf.push(0x02);
    let _ = buf.extend_from_slice(&path.to_be_bytes());
}
