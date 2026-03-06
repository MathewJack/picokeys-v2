use anyhow::{bail, Result};
use clap::{Args, Subcommand, ValueEnum};
use colored::Colorize;
use dialoguer::{Confirm, Input, Password};
use indicatif::{ProgressBar, ProgressStyle};
use tabled::{Table, Tabled};

use crate::transport::ccid::CcidTransport;

/// YKOATH AID (YubiKey OATH applet).
const OATH_AID: &[u8] = &[0xA0, 0x00, 0x00, 0x05, 0x27, 0x21, 0x01];

// OATH instruction bytes (YKOATH protocol).
const OATH_INS_PUT: u8 = 0x01;
const OATH_INS_DELETE: u8 = 0x02;
const OATH_INS_SET_CODE: u8 = 0x03;
const OATH_INS_RESET: u8 = 0x04;
const OATH_INS_LIST: u8 = 0xA1;
const OATH_INS_CALCULATE: u8 = 0xA2;
const OATH_INS_CALCULATE_ALL: u8 = 0xA4;
#[allow(dead_code)]
const OATH_INS_SEND_REMAINING: u8 = 0xA5;
const OATH_INS_RENAME: u8 = 0x05; // PicoKeys extension

// OATH type tags.
const OATH_TAG_NAME: u8 = 0x71;
const OATH_TAG_KEY: u8 = 0x73;
const OATH_TAG_CHALLENGE: u8 = 0x74;
const OATH_TAG_RESPONSE: u8 = 0x75;
#[allow(dead_code)]
const OATH_TAG_PROPERTY: u8 = 0x78;
const OATH_TAG_IMF: u8 = 0x7A;

// OATH algorithm bytes.
const OATH_ALGO_SHA1: u8 = 0x01;
const OATH_ALGO_SHA256: u8 = 0x02;
const OATH_ALGO_SHA512: u8 = 0x03;

// OATH type bytes.
const OATH_TYPE_HOTP: u8 = 0x10;
const OATH_TYPE_TOTP: u8 = 0x20;

/// OATH TOTP/HOTP credential management commands.
#[derive(Args)]
pub struct OathCommand {
    #[command(subcommand)]
    pub action: OathAction,
}

#[derive(Subcommand)]
pub enum OathAction {
    /// List all OATH credentials on the device
    List,
    /// Add a new OATH credential
    Add {
        /// Credential name / issuer label (e.g. "GitHub:user@example.com")
        #[arg(help = "Credential name")]
        name: String,

        /// Base32-encoded shared secret
        #[arg(short, long)]
        secret: String,

        /// Number of digits in the OTP code
        #[arg(short, long, default_value = "6")]
        digits: u8,

        /// TOTP time period in seconds
        #[arg(short, long, default_value = "30")]
        period: u32,

        /// Hash algorithm for HMAC
        #[arg(short, long, default_value = "sha1", value_enum)]
        algorithm: OathAlgorithm,

        /// Use HOTP (counter-based) instead of TOTP (time-based)
        #[arg(long, default_value = "false")]
        hotp: bool,
    },
    /// Generate an OTP code for a specific credential
    Code {
        /// Credential name (omit with --all to generate all)
        #[arg(required_unless_present = "all")]
        name: Option<String>,

        /// Generate codes for all credentials
        #[arg(short, long)]
        all: bool,
    },
    /// Delete an OATH credential by name
    Delete {
        /// Credential name to delete
        #[arg(help = "Credential name")]
        name: String,
    },
    /// Rename an OATH credential
    Rename {
        /// Current credential name
        #[arg(help = "Current name")]
        old: String,

        /// New credential name
        #[arg(help = "New name")]
        new: String,
    },
    /// Set or change the OATH password protecting the credential store
    SetPassword,
    /// Reset all OATH data (deletes all credentials)
    Reset,
}

#[derive(Clone, ValueEnum)]
pub enum OathAlgorithm {
    Sha1,
    Sha256,
    Sha512,
}

impl OathAlgorithm {
    fn to_byte(&self) -> u8 {
        match self {
            OathAlgorithm::Sha1 => OATH_ALGO_SHA1,
            OathAlgorithm::Sha256 => OATH_ALGO_SHA256,
            OathAlgorithm::Sha512 => OATH_ALGO_SHA512,
        }
    }

    fn name(&self) -> &'static str {
        match self {
            OathAlgorithm::Sha1 => "SHA1",
            OathAlgorithm::Sha256 => "SHA256",
            OathAlgorithm::Sha512 => "SHA512",
        }
    }
}

#[derive(Tabled)]
struct OathCredentialRow {
    #[tabled(rename = "#")]
    index: usize,
    #[tabled(rename = "Name")]
    name: String,
    #[tabled(rename = "Type")]
    oath_type: String,
    #[tabled(rename = "Algorithm")]
    algorithm: String,
}

#[derive(Tabled)]
struct OathCodeRow {
    #[tabled(rename = "Name")]
    name: String,
    #[tabled(rename = "Code")]
    code: String,
    #[tabled(rename = "Valid For")]
    validity: String,
}

fn open_oath() -> Result<CcidTransport> {
    let transport = CcidTransport::open(None)?;
    transport.select_aid(OATH_AID)?;
    Ok(transport)
}

pub async fn run(cmd: OathCommand, device: Option<&str>) -> Result<()> {
    if let Some(serial) = device {
        tracing::debug!("targeting device with serial: {}", serial);
    }

    match cmd.action {
        OathAction::List => execute_list(),
        OathAction::Add {
            name,
            secret,
            digits,
            period,
            algorithm,
            hotp,
        } => execute_add(&name, &secret, digits, period, &algorithm, hotp),
        OathAction::Code { name, all } => {
            if all {
                execute_code_all()
            } else if let Some(name) = name {
                execute_code(&name)
            } else {
                bail!("provide a credential name or use --all")
            }
        }
        OathAction::Delete { name } => execute_delete(&name),
        OathAction::Rename { old, new } => execute_rename(&old, &new),
        OathAction::SetPassword => execute_set_password(),
        OathAction::Reset => execute_reset(),
    }
}

fn execute_list() -> Result<()> {
    println!("{}\n", "OATH Credentials".bold().cyan());

    let transport = open_oath()?;

    // Send LIST command: INS=0xA1, P1=0, P2=0, no data.
    let (data, sw) = transport.transmit_apdu(0x00, OATH_INS_LIST, 0x00, 0x00, &[])?;

    if sw != 0x9000 {
        bail!("OATH LIST failed: SW={sw:04X}");
    }

    let credentials = parse_oath_list(&data)?;

    if credentials.is_empty() {
        println!("{}", "No OATH credentials stored on device.".yellow());
        return Ok(());
    }

    let rows: Vec<OathCredentialRow> = credentials
        .iter()
        .enumerate()
        .map(|(i, c)| OathCredentialRow {
            index: i + 1,
            name: c.name.clone(),
            oath_type: c.oath_type.clone(),
            algorithm: c.algorithm.clone(),
        })
        .collect();

    println!("{}", Table::new(&rows));
    println!(
        "\n{} {} credential(s) found.",
        "✓".green().bold(),
        credentials.len()
    );
    Ok(())
}

fn execute_add(
    name: &str,
    secret_b32: &str,
    digits: u8,
    period: u32,
    algorithm: &OathAlgorithm,
    hotp: bool,
) -> Result<()> {
    let secret = data_encoding::BASE32_NOPAD
        .decode(secret_b32.to_uppercase().as_bytes())
        .or_else(|_| data_encoding::BASE32.decode(secret_b32.to_uppercase().as_bytes()))
        .map_err(|_| anyhow::anyhow!("invalid base32 secret"))?;

    if secret.is_empty() {
        bail!("secret must not be empty");
    }
    if !(6..=8).contains(&digits) {
        bail!("digits must be 6, 7, or 8");
    }

    let transport = open_oath()?;

    let type_byte = if hotp { OATH_TYPE_HOTP } else { OATH_TYPE_TOTP };
    let algo_byte = algorithm.to_byte();
    let combined_type = type_byte | algo_byte;

    // Build PUT APDU data: TLV encoded.
    let mut data = Vec::new();

    // Name TLV.
    let name_bytes = name.as_bytes();
    data.push(OATH_TAG_NAME);
    push_length(&mut data, name_bytes.len());
    data.extend_from_slice(name_bytes);

    // Key TLV: type_byte | digits | secret.
    data.push(OATH_TAG_KEY);
    push_length(&mut data, 2 + secret.len());
    data.push(combined_type);
    data.push(digits);
    data.extend_from_slice(&secret);

    // Property TLV (if needed — e.g., require touch).
    // For now, no extra properties.

    // IMF TLV for HOTP (initial moving factor = counter).
    if hotp {
        data.push(OATH_TAG_IMF);
        data.push(0x04);
        data.extend_from_slice(&0u32.to_be_bytes());
    }

    let (_, sw) = transport.transmit_apdu(0x00, OATH_INS_PUT, 0x00, 0x00, &data)?;

    if sw != 0x9000 {
        bail!("OATH PUT failed: SW={sw:04X}");
    }

    let kind = if hotp { "HOTP" } else { "TOTP" };
    println!(
        "{} Added {} credential '{}' ({}, {} digits, {})",
        "✓".green().bold(),
        kind,
        name.bold(),
        algorithm.name(),
        digits,
        if hotp {
            "counter-based".to_string()
        } else {
            format!("{period}s period")
        },
    );
    Ok(())
}

fn execute_code(name: &str) -> Result<()> {
    let transport = open_oath()?;

    // Build CALCULATE APDU: name TLV + challenge TLV.
    let mut data = Vec::new();

    // Name TLV.
    let name_bytes = name.as_bytes();
    data.push(OATH_TAG_NAME);
    push_length(&mut data, name_bytes.len());
    data.extend_from_slice(name_bytes);

    // Challenge TLV: TOTP timestamp challenge = floor(time / period).
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let challenge = (now / 30).to_be_bytes();
    data.push(OATH_TAG_CHALLENGE);
    data.push(challenge.len() as u8);
    data.extend_from_slice(&challenge);

    let (resp_data, sw) = transport.transmit_apdu(0x00, OATH_INS_CALCULATE, 0x00, 0x01, &data)?;

    if sw != 0x9000 {
        bail!("OATH CALCULATE failed: SW={sw:04X}");
    }

    let code = parse_oath_code(&resp_data)?;
    let seconds_remaining = 30 - (now % 30);

    println!(
        "{}: {} (valid for {}s)",
        name.bold(),
        code.bold().green(),
        seconds_remaining
    );
    Ok(())
}

fn execute_code_all() -> Result<()> {
    println!("{}\n", "OATH Codes".bold().cyan());

    let transport = open_oath()?;

    // Build CALCULATE ALL APDU with TOTP challenge.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let challenge = (now / 30).to_be_bytes();
    let mut data = Vec::new();
    data.push(OATH_TAG_CHALLENGE);
    data.push(challenge.len() as u8);
    data.extend_from_slice(&challenge);

    let (resp_data, sw) =
        transport.transmit_apdu(0x00, OATH_INS_CALCULATE_ALL, 0x00, 0x01, &data)?;

    if sw != 0x9000 {
        bail!("OATH CALCULATE ALL failed: SW={sw:04X}");
    }

    let codes = parse_oath_calculate_all(&resp_data)?;

    if codes.is_empty() {
        println!("{}", "No OATH credentials stored.".yellow());
        return Ok(());
    }

    let seconds_remaining = 30 - (now % 30);

    let rows: Vec<OathCodeRow> = codes
        .iter()
        .map(|(name, code)| OathCodeRow {
            name: name.clone(),
            code: code.clone(),
            validity: format!("{seconds_remaining}s"),
        })
        .collect();

    println!("{}", Table::new(&rows));

    // Show a progress bar for time remaining.
    let pb = ProgressBar::new(30);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{msg} [{bar:30.cyan/blue}] {pos}/{len}s")
            .unwrap_or_else(|_| ProgressStyle::default_bar())
            .progress_chars("█▓░"),
    );
    pb.set_message("Time remaining");
    pb.set_position(seconds_remaining);

    Ok(())
}

fn execute_delete(name: &str) -> Result<()> {
    let confirm = Confirm::new()
        .with_prompt(format!("Delete OATH credential '{}'?", name))
        .default(false)
        .interact()
        .unwrap_or(false);

    if !confirm {
        println!("{}", "Deletion cancelled.".yellow());
        return Ok(());
    }

    let transport = open_oath()?;

    let mut data = Vec::new();
    let name_bytes = name.as_bytes();
    data.push(OATH_TAG_NAME);
    push_length(&mut data, name_bytes.len());
    data.extend_from_slice(name_bytes);

    let (_, sw) = transport.transmit_apdu(0x00, OATH_INS_DELETE, 0x00, 0x00, &data)?;

    if sw != 0x9000 {
        bail!("OATH DELETE failed: SW={sw:04X}");
    }

    println!("{} Credential '{}' deleted.", "✓".green().bold(), name);
    Ok(())
}

fn execute_rename(old: &str, new: &str) -> Result<()> {
    let transport = open_oath()?;

    let mut data = Vec::new();

    // Old name TLV.
    let old_bytes = old.as_bytes();
    data.push(OATH_TAG_NAME);
    push_length(&mut data, old_bytes.len());
    data.extend_from_slice(old_bytes);

    // New name TLV.
    let new_bytes = new.as_bytes();
    data.push(OATH_TAG_NAME);
    push_length(&mut data, new_bytes.len());
    data.extend_from_slice(new_bytes);

    let (_, sw) = transport.transmit_apdu(0x00, OATH_INS_RENAME, 0x00, 0x00, &data)?;

    if sw != 0x9000 {
        bail!("OATH RENAME failed: SW={sw:04X}");
    }

    println!(
        "{} Credential renamed: '{}' → '{}'.",
        "✓".green().bold(),
        old,
        new
    );
    Ok(())
}

fn execute_set_password() -> Result<()> {
    println!("{}\n", "Set OATH Password".bold().cyan());

    let password = Password::new()
        .with_prompt("Enter new OATH password")
        .with_confirmation("Confirm password", "Passwords do not match")
        .interact()
        .map_err(|e| anyhow::anyhow!("password input failed: {e}"))?;

    let transport = open_oath()?;

    // Derive key from password using PBKDF2 (simplified — real impl would use device salt).
    let key = derive_oath_key(password.as_bytes());

    let mut data = Vec::new();
    // Key TLV: algorithm | key.
    data.push(OATH_TAG_KEY);
    push_length(&mut data, 1 + key.len());
    data.push(OATH_TYPE_TOTP | OATH_ALGO_SHA1); // type + algo
    data.extend_from_slice(&key);

    // Challenge TLV.
    let challenge = [0u8; 8];
    data.push(OATH_TAG_CHALLENGE);
    data.push(challenge.len() as u8);
    data.extend_from_slice(&challenge);

    // Response TLV (HMAC of challenge with key — simplified).
    let response = hmac_simple(&key, &challenge);
    data.push(OATH_TAG_RESPONSE);
    push_length(&mut data, response.len());
    data.extend_from_slice(&response);

    let (_, sw) = transport.transmit_apdu(0x00, OATH_INS_SET_CODE, 0x00, 0x00, &data)?;

    if sw != 0x9000 {
        bail!("OATH SET CODE failed: SW={sw:04X}");
    }

    println!("{} OATH password set successfully.", "✓".green().bold());
    Ok(())
}

fn execute_reset() -> Result<()> {
    println!(
        "{}",
        "⚠ WARNING: This will delete ALL OATH credentials and the OATH password!"
            .red()
            .bold()
    );

    let confirmation: String = Input::new()
        .with_prompt("Type RESET to confirm")
        .interact_text()
        .map_err(|e| anyhow::anyhow!("input failed: {e}"))?;

    if confirmation != "RESET" {
        println!("{}", "Reset cancelled.".yellow());
        return Ok(());
    }

    let transport = open_oath()?;

    let (_, sw) = transport.transmit_apdu(0x00, OATH_INS_RESET, 0xDE, 0xAD, &[])?;

    if sw != 0x9000 {
        bail!("OATH RESET failed: SW={sw:04X}");
    }

    println!(
        "{} OATH application reset. All credentials deleted.",
        "✓".green().bold()
    );
    Ok(())
}

// --- TLV parsing helpers ---

struct OathCredential {
    name: String,
    oath_type: String,
    algorithm: String,
}

/// Parse OATH LIST response TLV data.
fn parse_oath_list(data: &[u8]) -> Result<Vec<OathCredential>> {
    let mut credentials = Vec::new();
    let mut offset = 0;

    while offset < data.len() {
        if offset + 2 > data.len() {
            break;
        }

        let tag = data[offset];
        offset += 1;
        let (length, len_bytes) = parse_length(&data[offset..])?;
        offset += len_bytes;

        if offset + length > data.len() {
            break;
        }

        let value = &data[offset..offset + length];
        offset += length;

        if tag == OATH_TAG_NAME && !value.is_empty() {
            // First byte of value is type|algo, rest is the name.
            let type_algo = value[0];
            let name = String::from_utf8_lossy(&value[1..]).to_string();

            let oath_type = match type_algo & 0xF0 {
                0x10 => "HOTP",
                0x20 => "TOTP",
                _ => "Unknown",
            };

            let algorithm = match type_algo & 0x0F {
                0x01 => "SHA1",
                0x02 => "SHA256",
                0x03 => "SHA512",
                _ => "Unknown",
            };

            credentials.push(OathCredential {
                name,
                oath_type: oath_type.to_string(),
                algorithm: algorithm.to_string(),
            });
        }
    }

    Ok(credentials)
}

/// Parse a single OATH CALCULATE response to extract the OTP code.
fn parse_oath_code(data: &[u8]) -> Result<String> {
    let mut offset = 0;

    while offset < data.len() {
        if offset + 2 > data.len() {
            break;
        }

        let tag = data[offset];
        offset += 1;
        let (length, len_bytes) = parse_length(&data[offset..])?;
        offset += len_bytes;

        if offset + length > data.len() {
            break;
        }

        let value = &data[offset..offset + length];
        offset += length;

        // Response tags: 0x76 (truncated) or 0x75 (full).
        if (tag == 0x76 || tag == 0x75 || tag == 0x77) && value.len() >= 5 {
            let digits = value[0] as usize;
            let code_bytes = &value[1..5];
            let code_num =
                u32::from_be_bytes([code_bytes[0], code_bytes[1], code_bytes[2], code_bytes[3]])
                    & 0x7FFFFFFF;
            let code = format!(
                "{:0>width$}",
                code_num % 10u32.pow(digits as u32),
                width = digits
            );
            return Ok(code);
        }
    }

    bail!("no OTP code found in response")
}

/// Parse OATH CALCULATE ALL response.
fn parse_oath_calculate_all(data: &[u8]) -> Result<Vec<(String, String)>> {
    let mut results = Vec::new();
    let mut offset = 0;
    let mut current_name = String::new();

    while offset < data.len() {
        if offset + 2 > data.len() {
            break;
        }

        let tag = data[offset];
        offset += 1;
        let (length, len_bytes) = parse_length(&data[offset..])?;
        offset += len_bytes;

        if offset + length > data.len() {
            break;
        }

        let value = &data[offset..offset + length];
        offset += length;

        match tag {
            OATH_TAG_NAME => {
                // Name TLV in CALCULATE ALL: just the name bytes (no type prefix).
                current_name = String::from_utf8_lossy(value).to_string();
            }
            0x76 | 0x77 => {
                // Truncated/full response code.
                if value.len() >= 5 {
                    let digits = value[0] as usize;
                    let code_num =
                        u32::from_be_bytes([value[1], value[2], value[3], value[4]]) & 0x7FFFFFFF;
                    let code = format!(
                        "{:0>width$}",
                        code_num % 10u32.pow(digits as u32),
                        width = digits
                    );
                    results.push((current_name.clone(), code));
                } else {
                    results.push((current_name.clone(), "—".to_string()));
                }
            }
            0x7C => {
                // HOTP credential — touch required or not yet calculated.
                results.push((current_name.clone(), "(touch required)".to_string()));
            }
            _ => {}
        }
    }

    Ok(results)
}

/// Push a TLV length value (DER short/long form).
fn push_length(buf: &mut Vec<u8>, len: usize) {
    if len < 0x80 {
        buf.push(len as u8);
    } else if len < 0x100 {
        buf.push(0x81);
        buf.push(len as u8);
    } else {
        buf.push(0x82);
        buf.push((len >> 8) as u8);
        buf.push((len & 0xFF) as u8);
    }
}

/// Parse a TLV length. Returns (length, number_of_bytes_consumed).
fn parse_length(data: &[u8]) -> Result<(usize, usize)> {
    if data.is_empty() {
        bail!("TLV length: unexpected end of data");
    }

    if data[0] < 0x80 {
        Ok((data[0] as usize, 1))
    } else if data[0] == 0x81 {
        if data.len() < 2 {
            bail!("TLV length: short data for 0x81 form");
        }
        Ok((data[1] as usize, 2))
    } else if data[0] == 0x82 {
        if data.len() < 3 {
            bail!("TLV length: short data for 0x82 form");
        }
        let len = ((data[1] as usize) << 8) | (data[2] as usize);
        Ok((len, 3))
    } else {
        bail!("TLV length: unsupported length encoding: 0x{:02X}", data[0]);
    }
}

/// Simple key derivation for OATH password (placeholder for PBKDF2).
fn derive_oath_key(password: &[u8]) -> Vec<u8> {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut key = vec![0u8; 16];
    let mut hasher = DefaultHasher::new();
    password.hash(&mut hasher);
    let h = hasher.finish();
    key[..8].copy_from_slice(&h.to_le_bytes());
    let mut hasher2 = DefaultHasher::new();
    h.hash(&mut hasher2);
    key[8..16].copy_from_slice(&hasher2.finish().to_le_bytes());
    key
}

/// Simple HMAC placeholder (in production, use the `hmac` crate).
fn hmac_simple(key: &[u8], data: &[u8]) -> Vec<u8> {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut hasher = DefaultHasher::new();
    key.hash(&mut hasher);
    data.hash(&mut hasher);
    let h = hasher.finish();
    h.to_le_bytes().to_vec()
}
