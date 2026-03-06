use anyhow::{bail, Context, Result};
use clap::{Args, Subcommand};
use colored::Colorize;
use dialoguer::{Confirm, Password};
use tabled::{Table, Tabled};

use crate::transport::ccid::CcidTransport;

// SmartCard-HSM AID (D2 76 00 01 24 01).
const HSM_AID: &[u8] = &[0xD2, 0x76, 0x00, 0x01, 0x24, 0x01];

// SmartCard-HSM instruction bytes.
const INS_INITIALIZE: u8 = 0x50;
const INS_GENERATE_KEY: u8 = 0x46;
const INS_LIST_KEYS: u8 = 0x58;
const INS_DELETE_KEY: u8 = 0xE4;
const INS_WRAP_KEY: u8 = 0x72;
const INS_UNWRAP_KEY: u8 = 0x74;
const INS_SIGN: u8 = 0x68;
const INS_DECRYPT: u8 = 0x62;
const INS_VERIFY_PIN: u8 = 0x20;
#[allow(unused)]
const INS_CHANGE_PIN: u8 = 0x24;
const INS_IMPORT_DKEK: u8 = 0x52;

// P2 constants for key types.
const KEY_TYPE_RSA_2048: u8 = 0x0B;
const KEY_TYPE_RSA_4096: u8 = 0x0F;
const KEY_TYPE_ECC_P256: u8 = 0x10;
const KEY_TYPE_ECC_P384: u8 = 0x11;
const KEY_TYPE_ECC_P521: u8 = 0x12;
const KEY_TYPE_AES_128: u8 = 0x18;
const KEY_TYPE_AES_256: u8 = 0x19;
const KEY_TYPE_ED25519: u8 = 0x20;

// PIN reference bytes.
const PIN_REF_USER: u8 = 0x81;
const PIN_REF_SO: u8 = 0x88;

const SW_OK: u16 = 0x9000;

/// SmartCard-HSM management commands.
#[derive(Args)]
pub struct HsmCommand {
    #[command(subcommand)]
    pub action: HsmAction,
}

#[derive(Subcommand)]
pub enum HsmAction {
    /// Show HSM device info and status
    Info,
    /// Initialize the HSM (set SO-PIN and user PIN, configure DKEK)
    Init {
        /// Security Officer PIN (prompted if not provided)
        #[arg(long)]
        so_pin: Option<String>,
        /// Number of DKEK shares
        #[arg(long, default_value = "1")]
        dkek_shares: u8,
        /// DKEK threshold for reconstruction
        #[arg(long, default_value = "1")]
        dkek_threshold: u8,
    },
    /// Manage HSM keys (generate, list, import, export, delete)
    Keys {
        #[command(subcommand)]
        action: HsmKeyAction,
    },
    /// Manage the Device Key Encryption Key (DKEK)
    Dkek {
        #[command(subcommand)]
        action: DkekAction,
    },
    /// Sign data using an HSM-stored key
    Sign {
        /// Key ID on the HSM (decimal)
        #[arg(short, long)]
        key_id: u8,
        /// Signing algorithm (ecdsa-sha256, rsa-pkcs1-sha256, ed25519)
        #[arg(short, long)]
        algorithm: String,
        /// Input file to sign (reads from stdin if omitted)
        #[arg(short, long)]
        input: Option<String>,
        /// Output file for signature
        #[arg(short, long)]
        output: Option<String>,
    },
    /// Verify a signature using an HSM-stored key
    Verify {
        /// Key ID on the HSM (decimal)
        #[arg(short, long)]
        key_id: u8,
        /// Verification algorithm
        #[arg(short, long)]
        algorithm: String,
        /// Input data file
        #[arg(short, long)]
        input: String,
        /// Signature file
        #[arg(short, long)]
        signature: String,
    },
    /// Encrypt data using an HSM-stored key
    Encrypt {
        /// Key ID on the HSM (decimal)
        #[arg(short, long)]
        key_id: u8,
        /// Input plaintext file
        #[arg(short, long)]
        input: String,
        /// Output ciphertext file
        #[arg(short, long)]
        output: Option<String>,
    },
    /// Decrypt data using an HSM-stored key
    Decrypt {
        /// Key ID on the HSM (decimal)
        #[arg(short, long)]
        key_id: u8,
        /// Input ciphertext file
        #[arg(short, long)]
        input: String,
        /// Output plaintext file
        #[arg(short, long)]
        output: Option<String>,
    },
}

#[derive(Subcommand)]
pub enum HsmKeyAction {
    /// List all keys stored on the HSM
    List,
    /// Generate a new key pair on the HSM
    Generate {
        /// Key type: rsa2048, rsa4096, ecp256, ecp384, ecp521, ed25519, aes128, aes256
        #[arg(short = 't', long)]
        key_type: String,
        /// Key label
        #[arg(short, long)]
        label: String,
        /// Specific key ID to assign (auto-assigned if omitted)
        #[arg(short, long)]
        key_id: Option<u8>,
    },
    /// Delete a key from the HSM
    Delete {
        /// Key ID to delete
        #[arg(long)]
        key_id: u8,
    },
    /// Export a key (DKEK-wrapped) from the HSM
    Export {
        /// Key ID to export
        #[arg(long)]
        key_id: u8,
        /// Output file path for the wrapped key blob
        #[arg(long)]
        output: String,
    },
    /// Import a DKEK-wrapped key into the HSM
    Import {
        /// Path to the wrapped key file
        #[arg(long)]
        input: String,
    },
    /// Show info about a specific key
    Info {
        /// Key ID to inspect
        #[arg(long)]
        key_id: u8,
    },
}

#[derive(Subcommand)]
pub enum DkekAction {
    /// Initialize DKEK with n-of-m threshold scheme
    Init {
        /// Number of DKEK key shares
        #[arg(long, default_value = "1")]
        shares: u8,
        /// Threshold of shares needed for reconstruction
        #[arg(long, default_value = "1")]
        threshold: u8,
    },
    /// Import a DKEK share from file
    ImportShare {
        /// Path to the DKEK share file
        #[arg(long)]
        file: String,
    },
    /// Show DKEK status (shares remaining, etc.)
    Status,
}

// ---- Display helpers ----

#[derive(Tabled)]
struct KeyRow {
    #[tabled(rename = "ID")]
    id: u8,
    #[tabled(rename = "Type")]
    key_type: String,
    #[tabled(rename = "Label")]
    label: String,
    #[tabled(rename = "Size")]
    size: String,
}

// ---- Transport helpers ----

/// Open CCID transport and select HSM applet.
fn connect_hsm(device: Option<&str>) -> Result<CcidTransport> {
    let transport = CcidTransport::open(device)
        .context("failed to open CCID smartcard reader")?;
    transport.select_aid(HSM_AID)
        .context("failed to select SmartCard-HSM applet — is the HSM firmware installed?")?;
    tracing::debug!("SmartCard-HSM applet selected on {}", transport.reader_name());
    Ok(transport)
}

/// Prompt for user PIN via hidden input and verify it on the card.
fn verify_user_pin(transport: &CcidTransport) -> Result<()> {
    let pin = Password::new()
        .with_prompt("User PIN")
        .interact()
        .context("failed to read PIN")?;

    let (_, sw) = transport.transmit_apdu(0x00, INS_VERIFY_PIN, 0x00, PIN_REF_USER, pin.as_bytes())?;
    if sw != SW_OK {
        let retries = sw & 0x000F;
        if (sw & 0xFFF0) == 0x63C0 {
            bail!("wrong PIN ({retries} retries remaining)");
        }
        bail!("PIN verification failed: SW={sw:04X}");
    }
    Ok(())
}

/// Parse key type string to the HSM algorithm ID byte.
fn parse_key_type(s: &str) -> Result<(u8, &'static str, &'static str)> {
    match s.to_lowercase().as_str() {
        "rsa2048" | "rsa-2048" => Ok((KEY_TYPE_RSA_2048, "RSA", "2048")),
        "rsa4096" | "rsa-4096" => Ok((KEY_TYPE_RSA_4096, "RSA", "4096")),
        "ecp256" | "ec-p256" | "p256" => Ok((KEY_TYPE_ECC_P256, "EC", "P-256")),
        "ecp384" | "ec-p384" | "p384" => Ok((KEY_TYPE_ECC_P384, "EC", "P-384")),
        "ecp521" | "ec-p521" | "p521" => Ok((KEY_TYPE_ECC_P521, "EC", "P-521")),
        "ed25519" => Ok((KEY_TYPE_ED25519, "EdDSA", "Ed25519")),
        "aes128" | "aes-128" => Ok((KEY_TYPE_AES_128, "AES", "128")),
        "aes256" | "aes-256" => Ok((KEY_TYPE_AES_256, "AES", "256")),
        _ => bail!("unknown key type '{s}' — use one of: rsa2048, rsa4096, ecp256, ecp384, ecp521, ed25519, aes128, aes256"),
    }
}

/// Decode the key type byte from the card into a human-readable string.
fn key_type_name(algo_byte: u8) -> &'static str {
    match algo_byte {
        KEY_TYPE_RSA_2048 => "RSA-2048",
        KEY_TYPE_RSA_4096 => "RSA-4096",
        KEY_TYPE_ECC_P256 => "EC-P256",
        KEY_TYPE_ECC_P384 => "EC-P384",
        KEY_TYPE_ECC_P521 => "EC-P521",
        KEY_TYPE_AES_128 => "AES-128",
        KEY_TYPE_AES_256 => "AES-256",
        KEY_TYPE_ED25519 => "Ed25519",
        _ => "Unknown",
    }
}

/// Parse signing/encryption algorithm to the SmartCard-HSM algorithm reference byte.
fn parse_algorithm(s: &str) -> Result<u8> {
    match s.to_lowercase().as_str() {
        "ecdsa-sha256" | "ecdsa" => Ok(0x70),
        "ecdsa-sha384" => Ok(0x71),
        "rsa-pkcs1-sha256" | "rsa-pkcs1" => Ok(0x20),
        "rsa-pkcs1-sha384" => Ok(0x30),
        "rsa-pkcs1-sha512" => Ok(0x40),
        "rsa-pss-sha256" | "rsa-pss" => Ok(0x21),
        "ed25519" | "eddsa" => Ok(0x72),
        "aes-cbc" => Ok(0x80),
        "aes-ecb" => Ok(0x81),
        _ => bail!("unknown algorithm '{s}' — use one of: ecdsa-sha256, rsa-pkcs1-sha256, rsa-pss-sha256, ed25519, aes-cbc"),
    }
}

// ---- Command implementations ----

pub async fn run(cmd: HsmCommand, device: Option<&str>) -> Result<()> {
    match cmd.action {
        HsmAction::Info => run_info(device),
        HsmAction::Init { so_pin, dkek_shares, dkek_threshold } => {
            run_init(device, so_pin, dkek_shares, dkek_threshold)
        }
        HsmAction::Keys { action } => run_keys(action, device),
        HsmAction::Dkek { action } => run_dkek(action, device),
        HsmAction::Sign { key_id, algorithm, input, output } => {
            run_sign(device, key_id, &algorithm, input.as_deref(), output.as_deref())
        }
        HsmAction::Verify { key_id, algorithm, input, signature } => {
            run_verify(device, key_id, &algorithm, &input, &signature)
        }
        HsmAction::Encrypt { key_id, input, output } => {
            run_encrypt(device, key_id, &input, output.as_deref())
        }
        HsmAction::Decrypt { key_id, input, output } => {
            run_decrypt(device, key_id, &input, output.as_deref())
        }
    }
}

fn run_info(device: Option<&str>) -> Result<()> {
    let transport = connect_hsm(device)?;

    // Read device capabilities via GET DATA (P1=0x01, P2=0xC4 — C_DevAuth)
    let (data, sw) = transport.transmit_apdu(0x80, 0x54, 0x00, 0x00, &[])?;
    if sw != SW_OK {
        bail!("failed to read HSM status: SW={sw:04X}");
    }

    println!("{}", "SmartCard-HSM Device Info".bold().green());
    println!("  Reader:  {}", transport.reader_name());
    if data.len() >= 4 {
        println!("  Version: {}.{}", data[0], data[1]);
        println!("  Config:  {} (options: 0x{:02X}{:02X})", 
            if data[2] & 0x01 != 0 { "initialized" } else { "uninitialized" },
            data[2], data[3]);
    }

    // List key count
    let (keys_data, keys_sw) = transport.transmit_apdu(0x00, INS_LIST_KEYS, 0x00, 0x00, &[])?;
    if keys_sw == SW_OK {
        let key_count = keys_data.len() / 2;
        println!("  Keys:    {key_count}");
    }

    Ok(())
}

fn run_init(
    device: Option<&str>,
    so_pin_arg: Option<String>,
    dkek_shares: u8,
    dkek_threshold: u8,
) -> Result<()> {
    let transport = connect_hsm(device)?;

    // Get SO-PIN
    let so_pin = if let Some(pin) = so_pin_arg {
        pin
    } else {
        let pin = Password::new()
            .with_prompt("SO-PIN (Security Officer)")
            .with_confirmation("Confirm SO-PIN", "SO-PINs do not match")
            .interact()
            .context("failed to read SO-PIN")?;
        pin
    };

    if so_pin.len() < 6 || so_pin.len() > 16 {
        bail!("SO-PIN must be 6–16 characters");
    }

    // Get user PIN
    let user_pin = Password::new()
        .with_prompt("User PIN")
        .with_confirmation("Confirm User PIN", "PINs do not match")
        .interact()
        .context("failed to read User PIN")?;

    if user_pin.len() < 4 || user_pin.len() > 16 {
        bail!("User PIN must be 4–16 characters");
    }

    // Confirm destructive operation
    let confirmed = Confirm::new()
        .with_prompt(format!(
            "{} This will erase all existing keys and data. Continue?",
            "WARNING:".red().bold()
        ))
        .default(false)
        .interact()
        .context("confirmation failed")?;

    if !confirmed {
        println!("{}", "Aborted.".yellow());
        return Ok(());
    }

    // Build INITIALIZE command data:
    // TLV: [options (2 bytes)] [SO-PIN] [user PIN] [DKEK shares] [key shares threshold]
    let mut init_data = Vec::new();
    // Configuration options: DKEK shares count
    init_data.push(0x80); // Tag: initialization options
    init_data.push(0x02); // Length
    init_data.push(dkek_shares);
    init_data.push(dkek_threshold);
    // SO-PIN
    init_data.push(0x81); // Tag: SO-PIN
    init_data.push(so_pin.len() as u8);
    init_data.extend_from_slice(so_pin.as_bytes());
    // User PIN
    init_data.push(0x82); // Tag: user PIN
    init_data.push(user_pin.len() as u8);
    init_data.extend_from_slice(user_pin.as_bytes());

    let (_, sw) = transport.transmit_apdu(0x80, INS_INITIALIZE, 0x00, 0x00, &init_data)?;
    if sw != SW_OK {
        bail!("HSM initialization failed: SW={sw:04X}");
    }

    println!("{}", "✓ HSM initialized successfully".green().bold());
    println!("  DKEK shares:    {dkek_shares}");
    println!("  DKEK threshold: {dkek_threshold}");
    println!("  {}", "Import DKEK shares before generating keys.".yellow());

    Ok(())
}

fn run_keys(action: HsmKeyAction, device: Option<&str>) -> Result<()> {
    match action {
        HsmKeyAction::List => run_keys_list(device),
        HsmKeyAction::Generate { key_type, label, key_id } => {
            run_keys_generate(device, &key_type, &label, key_id)
        }
        HsmKeyAction::Delete { key_id } => run_keys_delete(device, key_id),
        HsmKeyAction::Export { key_id, output } => run_keys_export(device, key_id, &output),
        HsmKeyAction::Import { input } => run_keys_import(device, &input),
        HsmKeyAction::Info { key_id } => run_keys_info(device, key_id),
    }
}

fn run_keys_list(device: Option<&str>) -> Result<()> {
    let transport = connect_hsm(device)?;
    verify_user_pin(&transport)?;

    let (data, sw) = transport.transmit_apdu(0x00, INS_LIST_KEYS, 0x00, 0x00, &[])?;
    if sw != SW_OK {
        bail!("failed to list keys: SW={sw:04X}");
    }

    if data.is_empty() {
        println!("{}", "No keys stored on the HSM.".yellow());
        return Ok(());
    }

    // Response: pairs of (key_id, key_type) bytes
    let mut rows = Vec::new();
    for chunk in data.chunks_exact(2) {
        let kid = chunk[0];
        let ktype = chunk[1];
        rows.push(KeyRow {
            id: kid,
            key_type: key_type_name(ktype).to_string(),
            label: format!("key-{kid}"),
            size: match ktype {
                KEY_TYPE_RSA_2048 => "2048 bit".into(),
                KEY_TYPE_RSA_4096 => "4096 bit".into(),
                KEY_TYPE_ECC_P256 => "256 bit".into(),
                KEY_TYPE_ECC_P384 => "384 bit".into(),
                KEY_TYPE_ECC_P521 => "521 bit".into(),
                KEY_TYPE_AES_128 => "128 bit".into(),
                KEY_TYPE_AES_256 => "256 bit".into(),
                KEY_TYPE_ED25519 => "256 bit".into(),
                _ => "?".into(),
            },
        });
    }

    println!("{}", "HSM Keys".bold().green());
    println!("{}", Table::new(rows));
    Ok(())
}

fn run_keys_generate(device: Option<&str>, key_type: &str, label: &str, key_id: Option<u8>) -> Result<()> {
    let transport = connect_hsm(device)?;
    verify_user_pin(&transport)?;

    let (algo_byte, type_family, size_str) = parse_key_type(key_type)?;
    let kid = key_id.unwrap_or(0x00); // 0x00 = auto-assign

    // Build GENERATE KEY command
    // P1 = key_id (0 for auto), P2 = algorithm reference
    let mut gen_data = Vec::new();
    // CRT template for key generation
    gen_data.push(0x30); // SEQUENCE tag
    let label_bytes = label.as_bytes();
    let inner_len = 2 + 2 + label_bytes.len();
    gen_data.push(inner_len as u8);
    gen_data.push(0x80); // Algorithm reference tag
    gen_data.push(0x01); // Length
    gen_data.push(algo_byte); // Skipped — use P2 for main algo
    gen_data.extend_from_slice(label_bytes);

    let (resp_data, sw) = transport.transmit_apdu(0x00, INS_GENERATE_KEY, kid, algo_byte, &gen_data)?;
    if sw != SW_OK {
        bail!("key generation failed: SW={sw:04X}");
    }

    let assigned_id = if !resp_data.is_empty() { resp_data[0] } else { kid };
    println!("{}", "✓ Key generated successfully".green().bold());
    println!("  Key ID: {assigned_id}");
    println!("  Type:   {type_family} {size_str}");
    println!("  Label:  {label}");

    if type_family == "RSA" {
        println!("  {}", "(RSA key generation may take several seconds)".dimmed());
    }

    Ok(())
}

fn run_keys_delete(device: Option<&str>, key_id: u8) -> Result<()> {
    let transport = connect_hsm(device)?;
    verify_user_pin(&transport)?;

    let confirmed = Confirm::new()
        .with_prompt(format!(
            "{} Delete key ID {key_id}? This is irreversible.",
            "WARNING:".red().bold()
        ))
        .default(false)
        .interact()
        .context("confirmation failed")?;

    if !confirmed {
        println!("{}", "Aborted.".yellow());
        return Ok(());
    }

    let (_, sw) = transport.transmit_apdu(0x00, INS_DELETE_KEY, key_id, 0x00, &[])?;
    if sw != SW_OK {
        bail!("key deletion failed: SW={sw:04X}");
    }

    println!("{} key ID {key_id} deleted", "✓".green().bold());
    Ok(())
}

fn run_keys_export(device: Option<&str>, key_id: u8, output_path: &str) -> Result<()> {
    let transport = connect_hsm(device)?;
    verify_user_pin(&transport)?;

    // WRAP KEY: INS=0x72, P1=key_id, P2=0x92 (DKEK-wrapped)
    let (wrapped_data, sw) = transport.transmit_apdu(0x00, INS_WRAP_KEY, key_id, 0x92, &[])?;
    if sw != SW_OK {
        bail!("key export failed: SW={sw:04X}");
    }

    std::fs::write(output_path, &wrapped_data)
        .with_context(|| format!("failed to write wrapped key to '{output_path}'"))?;

    println!("{} key ID {key_id} exported to {}", "✓".green().bold(), output_path.bold());
    println!("  Wrapped blob size: {} bytes", wrapped_data.len());
    Ok(())
}

fn run_keys_import(device: Option<&str>, input_path: &str) -> Result<()> {
    let transport = connect_hsm(device)?;
    verify_user_pin(&transport)?;

    let wrapped_data = std::fs::read(input_path)
        .with_context(|| format!("failed to read wrapped key from '{input_path}'"))?;

    // UNWRAP KEY: INS=0x74, P1=0x00 (auto-assign), P2=0x93
    let (resp_data, sw) = transport.transmit_apdu(0x00, INS_UNWRAP_KEY, 0x00, 0x93, &wrapped_data)?;
    if sw != SW_OK {
        bail!("key import failed: SW={sw:04X}");
    }

    let assigned_id = if !resp_data.is_empty() { resp_data[0] } else { 0 };
    println!("{} key imported from {} (assigned ID: {assigned_id})", "✓".green().bold(), input_path.bold());
    Ok(())
}

fn run_keys_info(device: Option<&str>, key_id: u8) -> Result<()> {
    let transport = connect_hsm(device)?;
    verify_user_pin(&transport)?;

    // Read key attributes via GET DATA
    let (data, sw) = transport.transmit_apdu(0x00, 0xCA, 0x01, key_id, &[])?;
    if sw != SW_OK {
        bail!("failed to read key info for ID {key_id}: SW={sw:04X}");
    }

    println!("{}", format!("Key ID {key_id}").bold().green());
    if data.len() >= 2 {
        println!("  Type:   {}", key_type_name(data[0]));
        println!("  Usage:  0x{:02X}", data[1]);
    }
    if data.len() > 2 {
        println!("  Raw:    {}", hex::encode(&data));
    }
    Ok(())
}

fn run_dkek(action: DkekAction, device: Option<&str>) -> Result<()> {
    match action {
        DkekAction::Init { shares, threshold } => run_dkek_init(device, shares, threshold),
        DkekAction::ImportShare { file } => run_dkek_import_share(device, &file),
        DkekAction::Status => run_dkek_status(device),
    }
}

fn run_dkek_init(device: Option<&str>, shares: u8, threshold: u8) -> Result<()> {
    let transport = connect_hsm(device)?;

    // Verify SO-PIN for DKEK operations
    let so_pin = Password::new()
        .with_prompt("SO-PIN")
        .interact()
        .context("failed to read SO-PIN")?;

    let (_, sw) = transport.transmit_apdu(0x00, INS_VERIFY_PIN, 0x00, PIN_REF_SO, so_pin.as_bytes())?;
    if sw != SW_OK {
        bail!("SO-PIN verification failed: SW={sw:04X}");
    }

    // Configure DKEK shares: INITIALIZE with DKEK config only
    let mut data = Vec::new();
    data.push(0x80); // DKEK config tag
    data.push(0x02);
    data.push(shares);
    data.push(threshold);

    let (_, sw) = transport.transmit_apdu(0x80, INS_IMPORT_DKEK, 0x00, 0x00, &data)?;
    if sw != SW_OK {
        bail!("DKEK initialization failed: SW={sw:04X}");
    }

    println!("{}", "✓ DKEK configured".green().bold());
    println!("  Shares:    {shares}");
    println!("  Threshold: {threshold}");
    println!("  {}", "Import share(s) to activate key wrapping.".yellow());
    Ok(())
}

fn run_dkek_import_share(device: Option<&str>, file_path: &str) -> Result<()> {
    let transport = connect_hsm(device)?;

    // Read the DKEK share file (32-byte AES-256 key share)
    let share_data = std::fs::read(file_path)
        .with_context(|| format!("failed to read DKEK share from '{file_path}'"))?;

    if share_data.len() != 32 {
        bail!("DKEK share must be exactly 32 bytes, got {}", share_data.len());
    }

    // IMPORT DKEK SHARE: INS=0x52, P1=0x00, P2=0x00
    let (resp_data, sw) = transport.transmit_apdu(0x80, INS_IMPORT_DKEK, 0x00, 0x01, &share_data)?;
    if sw != SW_OK {
        bail!("DKEK share import failed: SW={sw:04X}");
    }

    let remaining = if resp_data.len() >= 2 { resp_data[0] } else { 0 };
    println!("{} DKEK share imported from {}", "✓".green().bold(), file_path.bold());
    if remaining > 0 {
        println!("  {} more share(s) required", remaining);
    } else {
        println!("  {}", "DKEK fully assembled — key wrapping active".green());
    }
    Ok(())
}

fn run_dkek_status(device: Option<&str>) -> Result<()> {
    let transport = connect_hsm(device)?;

    // Query DKEK status: GET DATA with DKEK info tag
    let (data, sw) = transport.transmit_apdu(0x80, INS_IMPORT_DKEK, 0x00, 0x02, &[])?;
    if sw != SW_OK {
        bail!("failed to read DKEK status: SW={sw:04X}");
    }

    println!("{}", "DKEK Status".bold().green());
    if data.len() >= 2 {
        println!("  Total shares:    {}", data[0]);
        println!("  Shares imported: {}", data[1]);
        let remaining = data[0].saturating_sub(data[1]);
        if remaining > 0 {
            println!("  Status: {} ({remaining} share(s) remaining)", "pending".yellow());
        } else {
            println!("  Status: {}", "active".green());
        }
    } else {
        println!("  {}", "No DKEK configured".yellow());
    }
    Ok(())
}

fn run_sign(
    device: Option<&str>,
    key_id: u8,
    algorithm: &str,
    input: Option<&str>,
    output: Option<&str>,
) -> Result<()> {
    let transport = connect_hsm(device)?;
    verify_user_pin(&transport)?;

    let algo_ref = parse_algorithm(algorithm)?;

    // Read input data
    let data = if let Some(path) = input {
        std::fs::read(path).with_context(|| format!("failed to read input file '{path}'"))?
    } else {
        use std::io::Read;
        let mut buf = Vec::new();
        std::io::stdin().read_to_end(&mut buf).context("failed to read from stdin")?;
        buf
    };

    if data.is_empty() {
        bail!("no input data to sign");
    }

    // SIGN: INS=0x68, P1=key_id, P2=algorithm_ref
    let (signature, sw) = transport.transmit_apdu(0x00, INS_SIGN, key_id, algo_ref, &data)?;
    if sw != SW_OK {
        bail!("signing failed: SW={sw:04X}");
    }

    if let Some(out_path) = output {
        std::fs::write(out_path, &signature)
            .with_context(|| format!("failed to write signature to '{out_path}'"))?;
        println!("{} signature written to {}", "✓".green().bold(), out_path.bold());
    } else {
        println!("{}", hex::encode(&signature));
    }

    println!("  Algorithm: {algorithm}");
    println!("  Key ID:    {key_id}");
    println!("  Sig size:  {} bytes", signature.len());
    Ok(())
}

fn run_verify(
    device: Option<&str>,
    key_id: u8,
    algorithm: &str,
    input_path: &str,
    sig_path: &str,
) -> Result<()> {
    let transport = connect_hsm(device)?;
    verify_user_pin(&transport)?;

    let algo_ref = parse_algorithm(algorithm)?;

    let data = std::fs::read(input_path)
        .with_context(|| format!("failed to read input file '{input_path}'"))?;
    let signature = std::fs::read(sig_path)
        .with_context(|| format!("failed to read signature file '{sig_path}'"))?;

    // Build verify payload: data || signature with length prefix
    let mut payload = Vec::with_capacity(data.len() + signature.len() + 4);
    // Tag 0x81: hash/data
    payload.push(0x81);
    push_length(&mut payload, data.len());
    payload.extend_from_slice(&data);
    // Tag 0x82: signature
    payload.push(0x82);
    push_length(&mut payload, signature.len());
    payload.extend_from_slice(&signature);

    let (_, sw) = transport.transmit_apdu(0x00, 0x2A, key_id, algo_ref, &payload)?;
    if sw == SW_OK {
        println!("{}", "✓ Signature is VALID".green().bold());
    } else if sw == 0x6982 {
        println!("{}", "✗ Signature is INVALID".red().bold());
    } else {
        bail!("verification failed: SW={sw:04X}");
    }
    Ok(())
}

fn run_encrypt(
    device: Option<&str>,
    key_id: u8,
    input_path: &str,
    output: Option<&str>,
) -> Result<()> {
    let transport = connect_hsm(device)?;
    verify_user_pin(&transport)?;

    let plaintext = std::fs::read(input_path)
        .with_context(|| format!("failed to read input file '{input_path}'"))?;

    // PSO: ENCIPHER — CLA=0x00, INS=0x2A, P1=0x86, P2=key_id
    let (ciphertext, sw) = transport.transmit_apdu(0x00, 0x2A, 0x86, key_id, &plaintext)?;
    if sw != SW_OK {
        bail!("encryption failed: SW={sw:04X}");
    }

    let out_path = output.unwrap_or("encrypted.bin");
    std::fs::write(out_path, &ciphertext)
        .with_context(|| format!("failed to write ciphertext to '{out_path}'"))?;

    println!("{} encrypted data written to {}", "✓".green().bold(), out_path.bold());
    println!("  Input:  {} bytes", plaintext.len());
    println!("  Output: {} bytes", ciphertext.len());
    Ok(())
}

fn run_decrypt(
    device: Option<&str>,
    key_id: u8,
    input_path: &str,
    output: Option<&str>,
) -> Result<()> {
    let transport = connect_hsm(device)?;
    verify_user_pin(&transport)?;

    let ciphertext = std::fs::read(input_path)
        .with_context(|| format!("failed to read ciphertext from '{input_path}'"))?;

    // PSO: DECIPHER — CLA=0x00, INS=0x62, P1=key_id, P2=algorithm_ref
    let (plaintext, sw) = transport.transmit_apdu(0x00, INS_DECRYPT, key_id, 0x00, &ciphertext)?;
    if sw != SW_OK {
        bail!("decryption failed: SW={sw:04X}");
    }

    if let Some(out_path) = output {
        std::fs::write(out_path, &plaintext)
            .with_context(|| format!("failed to write plaintext to '{out_path}'"))?;
        println!("{} decrypted data written to {}", "✓".green().bold(), out_path.bold());
    } else {
        // Write to stdout
        use std::io::Write;
        std::io::stdout().write_all(&plaintext).context("failed to write to stdout")?;
    }

    println!("  Input:  {} bytes", ciphertext.len());
    println!("  Output: {} bytes", plaintext.len());
    Ok(())
}

/// Push a BER-TLV length encoding.
fn push_length(buf: &mut Vec<u8>, len: usize) {
    if len < 0x80 {
        buf.push(len as u8);
    } else if len <= 0xFF {
        buf.push(0x81);
        buf.push(len as u8);
    } else {
        buf.push(0x82);
        buf.push((len >> 8) as u8);
        buf.push((len & 0xFF) as u8);
    }
}
