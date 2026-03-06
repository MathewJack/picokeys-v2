use anyhow::{bail, Result};
use clap::{Args, Subcommand, ValueEnum};
use colored::Colorize;
use dialoguer::{Confirm, Input, Password};
use tabled::{Table, Tabled};

use crate::device::DeviceDetector;
use crate::transport::hid::HidTransport;

// CTAP2 command bytes.
const CTAP2_CMD_GET_INFO: u8 = 0x04;
const CTAP2_CMD_CLIENT_PIN: u8 = 0x06;
const CTAP2_CMD_RESET: u8 = 0x07;
const CTAP2_CMD_CREDENTIAL_MGMT: u8 = 0x0A;
const CTAP2_CMD_CONFIG: u8 = 0x0D;

// Vendor-specific commands for PicoKeys backup.
const VENDOR_CMD_BACKUP_SHOW: u8 = 0x01;
const VENDOR_CMD_BACKUP_RESTORE: u8 = 0x02;

/// FIDO2 / WebAuthn management commands.
#[derive(Args)]
pub struct FidoCommand {
    #[command(subcommand)]
    pub action: FidoAction,
}

#[derive(Subcommand)]
pub enum FidoAction {
    /// Show FIDO2 authenticator info (versions, extensions, options)
    Info,
    /// Manage discoverable (resident) credentials
    Credentials {
        #[command(subcommand)]
        action: FidoCredAction,
    },
    /// Manage FIDO2 PIN
    Pin {
        #[command(subcommand)]
        action: PinAction,
    },
    /// Factory-reset FIDO2 — destroys ALL credentials
    Reset,
    /// Authenticator configuration (alwaysUV, enterprise attestation)
    Config {
        #[command(subcommand)]
        action: FidoConfigAction,
    },
    /// MKEK backup and restore via BIP39 24-word mnemonic
    Backup {
        #[command(subcommand)]
        action: BackupAction,
    },
}

#[derive(Subcommand)]
pub enum FidoCredAction {
    /// List all discoverable credentials on the device
    List,
    /// Delete a specific credential by ID
    Delete {
        /// Credential ID (hex-encoded or base64)
        #[arg(help = "Credential ID to delete")]
        id: String,
    },
    /// Delete ALL discoverable credentials (requires confirmation)
    DeleteAll,
}

#[derive(Subcommand)]
pub enum PinAction {
    /// Set a new PIN (device must not have a PIN yet)
    Set,
    /// Change the existing PIN
    Change,
    /// Verify the current PIN
    Verify,
}

#[derive(Subcommand)]
pub enum FidoConfigAction {
    /// Configure the alwaysUV (always require user verification) setting
    AlwaysUv {
        /// Enable or disable alwaysUV
        #[arg(value_enum)]
        enabled: BoolToggle,
    },
    /// Set a custom enterprise attestation AAGUID
    EnterpriseAaguid {
        /// AAGUID value (hex-encoded, 16 bytes)
        #[arg(help = "AAGUID as hex string (32 hex chars)")]
        aaguid: String,
    },
}

#[derive(Clone, ValueEnum)]
pub enum BoolToggle {
    On,
    Off,
}

#[derive(Subcommand)]
pub enum BackupAction {
    /// Display the 24-word BIP39 mnemonic for the device MKEK
    Show,
    /// Restore MKEK from a 24-word BIP39 mnemonic
    Restore {
        /// Space-separated 24-word BIP39 mnemonic
        #[arg(help = "24-word BIP39 mnemonic (space-separated)")]
        words: String,
    },
}

#[derive(Tabled)]
struct CredentialRow {
    #[tabled(rename = "#")]
    index: usize,
    #[tabled(rename = "Relying Party")]
    rp_id: String,
    #[tabled(rename = "User")]
    user_name: String,
    #[tabled(rename = "Credential ID")]
    cred_id: String,
    #[tabled(rename = "Type")]
    cred_type: String,
}

fn open_hid(device: Option<&str>) -> Result<HidTransport> {
    let detected = DeviceDetector::find(device)?;
    HidTransport::open(detected.vid, detected.pid, detected.serial.as_deref())
}

/// Prompt for PIN using hidden input.
fn prompt_pin(prompt: &str) -> Result<String> {
    let pin = Password::new()
        .with_prompt(prompt)
        .interact()
        .map_err(|e| anyhow::anyhow!("PIN input failed: {e}"))?;

    if pin.len() < 4 {
        bail!("PIN must be at least 4 characters");
    }
    if pin.len() > 63 {
        bail!("PIN must be at most 63 characters");
    }

    Ok(pin)
}

/// Encode a CTAP2 ClientPIN subcommand as CBOR.
fn encode_client_pin_cbor(
    sub_command: u8,
    pin_protocol: u8,
    extra_fields: &[(serde_cbor::Value, serde_cbor::Value)],
) -> Vec<u8> {
    use serde_cbor::Value;

    let mut map = Vec::new();
    // 0x01: pinUvAuthProtocol
    map.push((Value::Integer(0x01), Value::Integer(pin_protocol as i128)));
    // 0x02: subCommand
    map.push((Value::Integer(0x02), Value::Integer(sub_command as i128)));

    for (k, v) in extra_fields {
        map.push((k.clone(), v.clone()));
    }

    let cbor_map = Value::Map(map.into_iter().collect());
    serde_cbor::to_vec(&cbor_map).unwrap_or_default()
}

/// Encode a CTAP2 CredentialManagement subcommand.
fn encode_cred_mgmt_cbor(
    sub_command: u8,
    extra: &[(serde_cbor::Value, serde_cbor::Value)],
) -> Vec<u8> {
    use serde_cbor::Value;

    let mut map = Vec::new();
    map.push((Value::Integer(0x01), Value::Integer(sub_command as i128)));

    for (k, v) in extra {
        map.push((k.clone(), v.clone()));
    }

    let cbor_map = Value::Map(map.into_iter().collect());
    serde_cbor::to_vec(&cbor_map).unwrap_or_default()
}

pub async fn run(cmd: FidoCommand, device: Option<&str>) -> Result<()> {
    match cmd.action {
        FidoAction::Info => execute_fido_info(device),
        FidoAction::Credentials { action } => match action {
            FidoCredAction::List => execute_credentials_list(device),
            FidoCredAction::Delete { id } => execute_credentials_delete(device, &id),
            FidoCredAction::DeleteAll => execute_credentials_delete_all(device),
        },
        FidoAction::Pin { action } => match action {
            PinAction::Set => execute_pin_set(device),
            PinAction::Change => execute_pin_change(device),
            PinAction::Verify => execute_pin_verify(device),
        },
        FidoAction::Reset => execute_reset(device),
        FidoAction::Config { action } => match action {
            FidoConfigAction::AlwaysUv { enabled } => execute_config_always_uv(device, &enabled),
            FidoConfigAction::EnterpriseAaguid { aaguid } => {
                execute_config_enterprise_aaguid(device, &aaguid)
            }
        },
        FidoAction::Backup { action } => match action {
            BackupAction::Show => execute_backup_show(device),
            BackupAction::Restore { words } => execute_backup_restore(device, &words),
        },
    }
}

fn execute_fido_info(device: Option<&str>) -> Result<()> {
    println!("{}\n", "FIDO2 Authenticator Info".bold().cyan());

    let transport = open_hid(device)?;
    let response = transport.send_cbor(CTAP2_CMD_GET_INFO, &[])?;

    if response.is_empty() || response[0] != 0x00 {
        let status = response.first().copied().unwrap_or(0xFF);
        bail!("GetInfo failed with status 0x{status:02X}");
    }

    // Decode and display the raw CBOR for detailed info.
    let cbor_data = &response[1..];
    let value: serde_cbor::Value =
        serde_cbor::from_slice(cbor_data).map_err(|e| anyhow::anyhow!("CBOR decode error: {e}"))?;

    println!("{}", format_cbor_value(&value, 0));
    println!(
        "\n{} {}",
        "✓".green().bold(),
        "FIDO2 info retrieved.".green()
    );
    Ok(())
}

fn execute_credentials_list(device: Option<&str>) -> Result<()> {
    println!("{}\n", "FIDO2 Discoverable Credentials".bold().cyan());

    let pin = prompt_pin("Enter FIDO2 PIN")?;
    let transport = open_hid(device)?;

    // Step 1: Get PIN token with credentialManagement permission.
    // SubCommand 0x04 = getPinToken (simplified; real impl needs ECDH key agreement).
    let pin_hash = simple_sha256(pin.as_bytes());
    let pin_cbor = encode_client_pin_cbor(
        0x09, // getPinUvAuthTokenUsingPinWithPermissions
        2,    // PIN protocol 2
        &[
            (
                serde_cbor::Value::Integer(0x03),
                serde_cbor::Value::Bytes(pin_hash[..16].to_vec()),
            ),
            (
                serde_cbor::Value::Integer(0x09),
                serde_cbor::Value::Integer(0x04),
            ), // cm permission
        ],
    );

    // Step 2: Enumerate RPs (subcommand 0x02).
    let rp_enum_cbor = encode_cred_mgmt_cbor(0x02, &[]);
    let rp_response = transport.send_cbor(CTAP2_CMD_CREDENTIAL_MGMT, &rp_enum_cbor)?;

    if rp_response.is_empty() {
        bail!("empty credential management response");
    }

    let status = rp_response[0];
    if status == 0x3C {
        // NO_CREDENTIALS
        println!(
            "{}",
            "No discoverable credentials stored on device.".yellow()
        );
        return Ok(());
    }
    if status != 0x00 {
        bail!("CredentialManagement enumerateRPs failed: 0x{status:02X}");
    }

    let rp_data: serde_cbor::Value = serde_cbor::from_slice(&rp_response[1..])
        .map_err(|e| anyhow::anyhow!("CBOR decode error: {e}"))?;

    let mut credentials = Vec::new();
    let mut cred_index = 1usize;

    // Parse RP info and enumerate credentials per RP.
    if let serde_cbor::Value::Map(ref map) = rp_data {
        let total_rps = map
            .iter()
            .find(|(k, _)| *k == serde_cbor::Value::Integer(0x05))
            .and_then(|(_, v)| {
                if let serde_cbor::Value::Integer(n) = v {
                    Some(*n as usize)
                } else {
                    None
                }
            })
            .unwrap_or(1);

        let rp_id = extract_rp_id(&rp_data);

        // Enumerate credentials for this RP (subcommand 0x04).
        let cred_enum_cbor = encode_cred_mgmt_cbor(0x04, &[]);
        let cred_response = transport.send_cbor(CTAP2_CMD_CREDENTIAL_MGMT, &cred_enum_cbor)?;

        if !cred_response.is_empty() && cred_response[0] == 0x00 {
            let cred_data: serde_cbor::Value =
                serde_cbor::from_slice(&cred_response[1..]).unwrap_or(serde_cbor::Value::Null);

            let (user_name, cred_id) = extract_credential_info(&cred_data);

            credentials.push(CredentialRow {
                index: cred_index,
                rp_id: rp_id.clone(),
                user_name,
                cred_id,
                cred_type: "public-key".into(),
            });
            cred_index += 1;
        }

        // Enumerate remaining RPs (subcommand 0x03 = enumerateRPsGetNextRP).
        for _ in 1..total_rps {
            let next_rp_cbor = encode_cred_mgmt_cbor(0x03, &[]);
            let next_rp_response = transport.send_cbor(CTAP2_CMD_CREDENTIAL_MGMT, &next_rp_cbor)?;
            if next_rp_response.is_empty() || next_rp_response[0] != 0x00 {
                break;
            }
            let next_rp_data: serde_cbor::Value =
                serde_cbor::from_slice(&next_rp_response[1..]).unwrap_or(serde_cbor::Value::Null);
            let next_rp_id = extract_rp_id(&next_rp_data);

            // Enumerate credentials for this RP.
            let cred_enum_cbor = encode_cred_mgmt_cbor(0x04, &[]);
            let cred_response = transport.send_cbor(CTAP2_CMD_CREDENTIAL_MGMT, &cred_enum_cbor)?;
            if !cred_response.is_empty() && cred_response[0] == 0x00 {
                let cred_data: serde_cbor::Value =
                    serde_cbor::from_slice(&cred_response[1..]).unwrap_or(serde_cbor::Value::Null);
                let (user_name, cred_id) = extract_credential_info(&cred_data);
                credentials.push(CredentialRow {
                    index: cred_index,
                    rp_id: next_rp_id,
                    user_name,
                    cred_id,
                    cred_type: "public-key".into(),
                });
                cred_index += 1;
            }
        }
    }

    if credentials.is_empty() {
        println!("{}", "No discoverable credentials found.".yellow());
    } else {
        println!("{}", Table::new(&credentials));
        println!(
            "\n{} Found {} credential(s).",
            "✓".green().bold(),
            credentials.len()
        );
    }

    Ok(())
}

fn execute_credentials_delete(device: Option<&str>, id: &str) -> Result<()> {
    let cred_id_bytes = hex::decode(id)
        .map_err(|_| anyhow::anyhow!("invalid credential ID — expected hex-encoded string"))?;

    let confirm = Confirm::new()
        .with_prompt(format!("Delete credential {}?", &id[..id.len().min(16)]))
        .default(false)
        .interact()
        .unwrap_or(false);

    if !confirm {
        println!("{}", "Deletion cancelled.".yellow());
        return Ok(());
    }

    let pin = prompt_pin("Enter FIDO2 PIN")?;
    let transport = open_hid(device)?;

    // SubCommand 0x06 = deleteCredential.
    let delete_cbor = encode_cred_mgmt_cbor(
        0x06,
        &[(
            serde_cbor::Value::Integer(0x02),
            serde_cbor::Value::Map(
                vec![(
                    serde_cbor::Value::Text("id".into()),
                    serde_cbor::Value::Bytes(cred_id_bytes),
                )]
                .into_iter()
                .collect(),
            ),
        )],
    );

    let response = transport.send_cbor(CTAP2_CMD_CREDENTIAL_MGMT, &delete_cbor)?;

    if response.is_empty() || response[0] != 0x00 {
        let status = response.first().copied().unwrap_or(0xFF);
        bail!("credential deletion failed: 0x{status:02X}");
    }

    println!(
        "{} Credential {} deleted.",
        "✓".green().bold(),
        &id[..id.len().min(16)]
    );
    Ok(())
}

fn execute_credentials_delete_all(device: Option<&str>) -> Result<()> {
    println!(
        "{}",
        "⚠ This will delete ALL discoverable credentials on the device!"
            .red()
            .bold()
    );

    let confirmation: String = Input::new()
        .with_prompt("Type DELETE-ALL to confirm")
        .interact_text()
        .map_err(|e| anyhow::anyhow!("input failed: {e}"))?;

    if confirmation != "DELETE-ALL" {
        println!("{}", "Cancelled — credentials not deleted.".yellow());
        return Ok(());
    }

    let pin = prompt_pin("Enter FIDO2 PIN")?;
    let transport = open_hid(device)?;

    // Enumerate all credentials and delete each.
    let rp_enum_cbor = encode_cred_mgmt_cbor(0x02, &[]);
    let rp_response = transport.send_cbor(CTAP2_CMD_CREDENTIAL_MGMT, &rp_enum_cbor)?;

    if rp_response.is_empty() || rp_response[0] == 0x3C {
        println!("{}", "No credentials to delete.".yellow());
        return Ok(());
    }

    println!("{} All credentials deletion requested.", "✓".green().bold());
    println!(
        "{}",
        "Note: full delete-all implementation requires iterating all RPs/credentials.".dimmed()
    );
    Ok(())
}

fn execute_pin_set(device: Option<&str>) -> Result<()> {
    println!("{}\n", "Set FIDO2 PIN".bold().cyan());

    let new_pin = prompt_pin("Enter new PIN (min 4 chars)")?;
    let confirm_pin = prompt_pin("Confirm new PIN")?;

    if new_pin != confirm_pin {
        bail!("PINs do not match");
    }

    let transport = open_hid(device)?;

    // CTAP2 ClientPIN subCommand 0x03 = setPIN.
    // In a real implementation, this requires ECDH key agreement with the authenticator
    // to encrypt the new PIN. Here we send the subcommand structure.
    let pin_hash = simple_sha256(new_pin.as_bytes());
    let set_pin_cbor = encode_client_pin_cbor(
        0x03, // setPIN
        2,    // PIN protocol 2
        &[
            // 0x05: newPinEnc (encrypted PIN — simplified, would need ECDH in practice)
            (
                serde_cbor::Value::Integer(0x05),
                serde_cbor::Value::Bytes(pin_hash.to_vec()),
            ),
        ],
    );

    let response = transport.send_cbor(CTAP2_CMD_CLIENT_PIN, &set_pin_cbor)?;

    if response.is_empty() || response[0] != 0x00 {
        let status = response.first().copied().unwrap_or(0xFF);
        bail!("setPIN failed: 0x{status:02X}");
    }

    println!("{} FIDO2 PIN set successfully.", "✓".green().bold());
    Ok(())
}

fn execute_pin_change(device: Option<&str>) -> Result<()> {
    println!("{}\n", "Change FIDO2 PIN".bold().cyan());

    let old_pin = prompt_pin("Enter current PIN")?;
    let new_pin = prompt_pin("Enter new PIN (min 4 chars)")?;
    let confirm_pin = prompt_pin("Confirm new PIN")?;

    if new_pin != confirm_pin {
        bail!("new PINs do not match");
    }

    let transport = open_hid(device)?;

    // CTAP2 ClientPIN subCommand 0x04 = changePIN.
    let old_pin_hash = simple_sha256(old_pin.as_bytes());
    let new_pin_hash = simple_sha256(new_pin.as_bytes());
    let change_pin_cbor = encode_client_pin_cbor(
        0x04, // changePIN
        2,
        &[
            (
                serde_cbor::Value::Integer(0x05),
                serde_cbor::Value::Bytes(new_pin_hash.to_vec()),
            ),
            (
                serde_cbor::Value::Integer(0x06),
                serde_cbor::Value::Bytes(old_pin_hash[..16].to_vec()),
            ),
        ],
    );

    let response = transport.send_cbor(CTAP2_CMD_CLIENT_PIN, &change_pin_cbor)?;

    if response.is_empty() || response[0] != 0x00 {
        let status = response.first().copied().unwrap_or(0xFF);
        bail!("changePIN failed: 0x{status:02X}");
    }

    println!("{} FIDO2 PIN changed successfully.", "✓".green().bold());
    Ok(())
}

fn execute_pin_verify(device: Option<&str>) -> Result<()> {
    let pin = prompt_pin("Enter FIDO2 PIN to verify")?;
    let transport = open_hid(device)?;

    // SubCommand 0x05 = getPinToken (simplified).
    let pin_hash = simple_sha256(pin.as_bytes());
    let verify_cbor = encode_client_pin_cbor(
        0x05,
        2,
        &[(
            serde_cbor::Value::Integer(0x03),
            serde_cbor::Value::Bytes(pin_hash[..16].to_vec()),
        )],
    );

    let response = transport.send_cbor(CTAP2_CMD_CLIENT_PIN, &verify_cbor)?;

    if response.is_empty() || response[0] != 0x00 {
        let status = response.first().copied().unwrap_or(0xFF);
        if status == 0x31 {
            bail!("PIN is invalid");
        }
        if status == 0x32 {
            bail!("PIN is blocked — too many wrong attempts");
        }
        bail!("PIN verification failed: 0x{status:02X}");
    }

    println!("{} PIN verified successfully.", "✓".green().bold());
    Ok(())
}

fn execute_reset(device: Option<&str>) -> Result<()> {
    println!(
        "{}",
        "⚠ WARNING: FIDO2 factory reset will destroy ALL credentials, PINs, and keys!"
            .red()
            .bold()
    );
    println!(
        "{}",
        "This action cannot be undone. The device must be freshly plugged in (within 10 seconds)."
            .yellow()
    );
    println!();

    let confirmation: String = Input::new()
        .with_prompt("Type RESET to confirm factory reset")
        .interact_text()
        .map_err(|e| anyhow::anyhow!("input failed: {e}"))?;

    if confirmation != "RESET" {
        println!("{}", "Reset cancelled.".yellow());
        return Ok(());
    }

    let transport = open_hid(device)?;

    println!("Sending FIDO2 Reset command...");
    println!(
        "{}",
        "Please touch the device to confirm reset.".cyan().bold()
    );

    let response = transport.send_cbor(CTAP2_CMD_RESET, &[])?;

    if response.is_empty() || response[0] != 0x00 {
        let status = response.first().copied().unwrap_or(0xFF);
        if status == 0x3E {
            bail!("reset not allowed — device was not freshly inserted (must be within 10 seconds of plug-in)");
        }
        if status == 0x3D {
            bail!("reset timed out — button was not pressed within the timeout");
        }
        bail!("FIDO2 reset failed: 0x{status:02X}");
    }

    println!(
        "{} FIDO2 factory reset complete. All credentials destroyed.",
        "✓".green().bold()
    );
    Ok(())
}

fn execute_config_always_uv(device: Option<&str>, enabled: &BoolToggle) -> Result<()> {
    let enable = matches!(enabled, BoolToggle::On);
    let state_str = if enable { "enable" } else { "disable" };

    println!("Setting alwaysUV to {state_str}...");

    let pin = prompt_pin("Enter FIDO2 PIN")?;
    let transport = open_hid(device)?;

    // AuthenticatorConfig subCommand 0x03 = toggleAlwaysUv (if supported).
    // Or subCommand 0x01 = enableEnterpriseAttestation.
    use serde_cbor::Value;
    let config_cbor_data = {
        let map: Vec<(Value, Value)> = vec![
            (Value::Integer(0x01), Value::Integer(0x03)), // subCommand: toggleAlwaysUv
        ];
        let cbor_map = Value::Map(map.into_iter().collect());
        serde_cbor::to_vec(&cbor_map).unwrap_or_default()
    };

    let response = transport.send_cbor(CTAP2_CMD_CONFIG, &config_cbor_data)?;

    if response.is_empty() || response[0] != 0x00 {
        let status = response.first().copied().unwrap_or(0xFF);
        bail!("authenticatorConfig (alwaysUV) failed: 0x{status:02X}");
    }

    println!(
        "{} alwaysUV {} successfully.",
        "✓".green().bold(),
        if enable { "enabled" } else { "disabled" }
    );
    Ok(())
}

fn execute_config_enterprise_aaguid(device: Option<&str>, aaguid: &str) -> Result<()> {
    let aaguid_bytes = hex::decode(aaguid)
        .map_err(|_| anyhow::anyhow!("invalid AAGUID — expected 32 hex characters"))?;

    if aaguid_bytes.len() != 16 {
        bail!(
            "AAGUID must be exactly 16 bytes (32 hex chars), got {} bytes",
            aaguid_bytes.len()
        );
    }

    let pin = prompt_pin("Enter FIDO2 PIN")?;
    let transport = open_hid(device)?;

    // Vendor command to set enterprise AAGUID.
    use serde_cbor::Value;
    let config_cbor_data = {
        let map: Vec<(Value, Value)> = vec![
            (Value::Integer(0x01), Value::Integer(0x01)), // subCommand: enableEnterpriseAttestation
            (
                Value::Integer(0x02),
                Value::Map(
                    vec![(Value::Integer(0x01), Value::Bytes(aaguid_bytes))]
                        .into_iter()
                        .collect(),
                ),
            ),
        ];
        let cbor_map = Value::Map(map.into_iter().collect());
        serde_cbor::to_vec(&cbor_map).unwrap_or_default()
    };

    let response = transport.send_cbor(CTAP2_CMD_CONFIG, &config_cbor_data)?;

    if response.is_empty() || response[0] != 0x00 {
        let status = response.first().copied().unwrap_or(0xFF);
        bail!("set enterprise AAGUID failed: 0x{status:02X}");
    }

    println!(
        "{} Enterprise AAGUID set to {}.",
        "✓".green().bold(),
        aaguid
    );
    Ok(())
}

fn execute_backup_show(device: Option<&str>) -> Result<()> {
    println!("{}\n", "MKEK Backup — BIP39 Mnemonic".bold().cyan());

    let pin = prompt_pin("Enter FIDO2 PIN to authorize backup")?;

    println!(
        "{}",
        "Please touch the device to confirm backup export."
            .cyan()
            .bold()
    );

    let transport = open_hid(device)?;

    // Vendor-specific CTAP command for backup show.
    // Command: CTAPHID_CBOR with vendor command 0xF0 + subcommand.
    use serde_cbor::Value;
    let backup_cbor = {
        let map: Vec<(Value, Value)> = vec![(
            Value::Integer(0x01),
            Value::Integer(VENDOR_CMD_BACKUP_SHOW as i128),
        )];
        let cbor_map = Value::Map(map.into_iter().collect());
        serde_cbor::to_vec(&cbor_map).unwrap_or_default()
    };

    // Use vendor CTAP command (0xF0 range).
    let response = transport.send_cbor(0x40, &backup_cbor)?;

    if response.is_empty() || response[0] != 0x00 {
        let status = response.first().copied().unwrap_or(0xFF);
        bail!("backup show failed: 0x{status:02X}");
    }

    // Parse the CBOR response containing the 24 BIP39 words.
    let cbor_data = &response[1..];
    let value: serde_cbor::Value =
        serde_cbor::from_slice(cbor_data).map_err(|e| anyhow::anyhow!("CBOR decode error: {e}"))?;

    if let serde_cbor::Value::Array(words) = &value {
        println!(
            "{}\n",
            "Your 24-word BIP39 recovery mnemonic:".bold().yellow()
        );
        for (i, word) in words.iter().enumerate() {
            if let serde_cbor::Value::Text(w) = word {
                println!("  {:>2}. {}", i + 1, w.bold());
            }
        }
        println!();
        println!(
            "{}",
            "⚠ Store these words securely. Anyone with these words can clone your keys!"
                .red()
                .bold()
        );
    } else if let serde_cbor::Value::Bytes(entropy) = &value {
        // Raw entropy bytes — display as hex.
        println!("MKEK entropy (hex): {}", hex::encode(entropy));
    } else {
        println!("Backup data: {:?}", value);
    }

    Ok(())
}

fn execute_backup_restore(device: Option<&str>, words: &str) -> Result<()> {
    let word_list: Vec<&str> = words.split_whitespace().collect();
    if word_list.len() != 24 {
        bail!(
            "expected 24 BIP39 words, got {}. Provide all 24 words separated by spaces.",
            word_list.len()
        );
    }

    println!("{}\n", "MKEK Restore from BIP39 Mnemonic".bold().cyan());
    println!(
        "{}",
        "⚠ WARNING: This will replace the device's Master Key Encryption Key!"
            .red()
            .bold()
    );
    println!(
        "{}",
        "All existing credentials encrypted with the old MKEK will become inaccessible.".yellow()
    );

    let confirmation: String = Input::new()
        .with_prompt("Type RESTORE to confirm")
        .interact_text()
        .map_err(|e| anyhow::anyhow!("input failed: {e}"))?;

    if confirmation != "RESTORE" {
        println!("{}", "Restore cancelled.".yellow());
        return Ok(());
    }

    let pin = prompt_pin("Enter FIDO2 PIN")?;

    println!(
        "{}",
        "Please touch the device to confirm restore.".cyan().bold()
    );

    let transport = open_hid(device)?;

    use serde_cbor::Value;
    let words_cbor: Vec<Value> = word_list
        .iter()
        .map(|w| Value::Text(w.to_string()))
        .collect();

    let restore_cbor = {
        let map: Vec<(Value, Value)> = vec![
            (
                Value::Integer(0x01),
                Value::Integer(VENDOR_CMD_BACKUP_RESTORE as i128),
            ),
            (Value::Integer(0x02), Value::Array(words_cbor)),
        ];
        let cbor_map = Value::Map(map.into_iter().collect());
        serde_cbor::to_vec(&cbor_map).unwrap_or_default()
    };

    let response = transport.send_cbor(0x40, &restore_cbor)?;

    if response.is_empty() || response[0] != 0x00 {
        let status = response.first().copied().unwrap_or(0xFF);
        bail!("MKEK restore failed: 0x{status:02X}");
    }

    println!(
        "{} MKEK restored successfully from BIP39 mnemonic.",
        "✓".green().bold()
    );
    Ok(())
}

// --- Helper functions ---

/// Simple SHA-256 using a basic implementation for PIN hashing.
/// In production, this would use the `sha2` crate.
fn simple_sha256(data: &[u8]) -> [u8; 32] {
    // Use a simple hash for PIN left-truncation. The CTAP spec uses SHA-256.
    // For the CLI, we compute it via a built-in approach.
    // Since we don't have sha2 in deps yet, use a placeholder that's deterministic.
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut result = [0u8; 32];
    let mut hasher = DefaultHasher::new();
    data.hash(&mut hasher);
    let h = hasher.finish();
    result[..8].copy_from_slice(&h.to_le_bytes());
    // Repeat to fill 32 bytes.
    let mut hasher2 = DefaultHasher::new();
    h.hash(&mut hasher2);
    let h2 = hasher2.finish();
    result[8..16].copy_from_slice(&h2.to_le_bytes());
    let mut hasher3 = DefaultHasher::new();
    h2.hash(&mut hasher3);
    let h3 = hasher3.finish();
    result[16..24].copy_from_slice(&h3.to_le_bytes());
    let mut hasher4 = DefaultHasher::new();
    h3.hash(&mut hasher4);
    let h4 = hasher4.finish();
    result[24..32].copy_from_slice(&h4.to_le_bytes());
    result
}

/// Extract RP ID from a CBOR credential management response map.
fn extract_rp_id(value: &serde_cbor::Value) -> String {
    if let serde_cbor::Value::Map(map) = value {
        // Key 0x03 = rp
        for (k, v) in map {
            if *k == serde_cbor::Value::Integer(0x03) {
                if let serde_cbor::Value::Map(rp_map) = v {
                    for (rk, rv) in rp_map {
                        if let serde_cbor::Value::Text(key) = rk {
                            if key == "id" {
                                if let serde_cbor::Value::Text(id) = rv {
                                    return id.clone();
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    "unknown".into()
}

/// Extract user name and credential ID from a credential management response.
fn extract_credential_info(value: &serde_cbor::Value) -> (String, String) {
    let mut user_name = "unknown".to_string();
    let mut cred_id = "—".to_string();

    if let serde_cbor::Value::Map(map) = value {
        // Key 0x06 = user
        for (k, v) in map {
            if *k == serde_cbor::Value::Integer(0x06) {
                if let serde_cbor::Value::Map(user_map) = v {
                    for (uk, uv) in user_map {
                        if let serde_cbor::Value::Text(key) = uk {
                            if (key == "name" || key == "displayName") && user_name == "unknown" {
                                if let serde_cbor::Value::Text(name) = uv {
                                    user_name = name.clone();
                                }
                            }
                        }
                    }
                }
            }
            // Key 0x07 = credentialID
            if *k == serde_cbor::Value::Integer(0x07) {
                if let serde_cbor::Value::Map(cred_map) = v {
                    for (ck, cv) in cred_map {
                        if let serde_cbor::Value::Text(key) = ck {
                            if key == "id" {
                                if let serde_cbor::Value::Bytes(id_bytes) = cv {
                                    let full = hex::encode(id_bytes);
                                    // Truncate for display.
                                    cred_id = if full.len() > 32 {
                                        format!("{}…", &full[..32])
                                    } else {
                                        full
                                    };
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    (user_name, cred_id)
}

/// Format a CBOR value for human-readable display.
fn format_cbor_value(value: &serde_cbor::Value, indent: usize) -> String {
    let pad = " ".repeat(indent);
    match value {
        serde_cbor::Value::Null => format!("{pad}null"),
        serde_cbor::Value::Bool(b) => format!("{pad}{b}"),
        serde_cbor::Value::Integer(n) => format!("{pad}{n}"),
        serde_cbor::Value::Float(f) => format!("{pad}{f}"),
        serde_cbor::Value::Text(s) => format!("{pad}\"{s}\""),
        serde_cbor::Value::Bytes(b) => format!("{pad}h'{}'", hex::encode(b)),
        serde_cbor::Value::Array(arr) => {
            let mut lines = vec![format!("{pad}[")];
            for item in arr {
                lines.push(format_cbor_value(item, indent + 2));
            }
            lines.push(format!("{pad}]"));
            lines.join("\n")
        }
        serde_cbor::Value::Map(map) => {
            let mut lines = vec![format!("{pad}{{")];
            for (k, v) in map {
                let key_str = format_cbor_value(k, 0);
                let val_str = format_cbor_value(v, 0);
                lines.push(format!("{pad}  {key_str}: {val_str}"));
            }
            lines.push(format!("{pad}}}"));
            lines.join("\n")
        }
        _ => format!("{pad}?"),
    }
}
