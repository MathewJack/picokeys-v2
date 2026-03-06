use anyhow::{bail, Result};
use clap::{Args, Subcommand};
use colored::Colorize;
use dialoguer::Confirm;
use tabled::{Table, Tabled};

use crate::device::DeviceDetector;
use crate::transport::hid::HidTransport;

// YubiKey OTP management uses CTAPHID MSG with a specific frame format.
// Slot management uses the YubiKey Management protocol over HID.

/// Vendor CTAP command for OTP management (PicoKeys vendor range).
const VENDOR_CMD_OTP: u8 = 0x41;

// OTP subcommands.
const OTP_SUB_INFO: u8 = 0x01;
const OTP_SUB_SET_STATIC: u8 = 0x02;
const OTP_SUB_SET_HOTP: u8 = 0x03;
const OTP_SUB_DELETE: u8 = 0x04;
const OTP_SUB_SWAP: u8 = 0x05;

/// YubiKey-compatible OTP slot management commands.
#[derive(Args)]
pub struct OtpCommand {
    #[command(subcommand)]
    pub action: OtpAction,
}

#[derive(Subcommand)]
pub enum OtpAction {
    /// Show OTP slot configuration status
    Info,
    /// Configure an HOTP (counter-based) OTP slot
    SetHotp {
        /// Slot number (1 or 2)
        #[arg(value_parser = clap::value_parser!(u8).range(1..=2))]
        slot: u8,

        /// Base32-encoded HOTP secret
        #[arg(short, long)]
        secret: String,

        /// Number of digits in the OTP code
        #[arg(short, long, default_value = "6")]
        digits: u8,

        /// Initial counter value
        #[arg(short, long, default_value = "0")]
        counter: u64,
    },
    /// Configure a static password slot
    SetStatic {
        /// Slot number (1 or 2)
        #[arg(value_parser = clap::value_parser!(u8).range(1..=2))]
        slot: u8,

        /// Static password to program
        #[arg(help = "Password string")]
        password: String,
    },
    /// Swap the configuration of slot 1 and slot 2
    Swap,
    /// Delete (clear) an OTP slot
    Delete {
        /// Slot number (1 or 2)
        #[arg(value_parser = clap::value_parser!(u8).range(1..=2))]
        slot: u8,
    },
    /// Update an existing OTP slot configuration
    Update {
        /// Slot number (1 or 2)
        #[arg(value_parser = clap::value_parser!(u8).range(1..=2))]
        slot: u8,
    },
}

#[derive(Tabled)]
struct OtpSlotRow {
    #[tabled(rename = "Slot")]
    slot: String,
    #[tabled(rename = "Type")]
    slot_type: String,
    #[tabled(rename = "Status")]
    status: String,
}

fn open_hid(device: Option<&str>) -> Result<HidTransport> {
    let detected = DeviceDetector::find(device)?;
    HidTransport::open(detected.vid, detected.pid, detected.serial.as_deref())
}

pub async fn run(cmd: OtpCommand, device: Option<&str>) -> Result<()> {
    match cmd.action {
        OtpAction::Info => execute_info(device),
        OtpAction::SetHotp {
            slot,
            secret,
            digits,
            counter,
        } => execute_set_hotp(device, slot, &secret, digits, counter),
        OtpAction::SetStatic { slot, password } => execute_set_static(device, slot, &password),
        OtpAction::Swap => execute_swap(device),
        OtpAction::Delete { slot } => execute_delete(device, slot),
        OtpAction::Update { slot } => execute_update(device, slot),
    }
}

fn execute_info(device: Option<&str>) -> Result<()> {
    println!("{}\n", "OTP Slot Configuration".bold().cyan());

    let transport = open_hid(device)?;

    // Send vendor OTP info command.
    let mut cmd_data = Vec::new();
    cmd_data.push(OTP_SUB_INFO);

    let response = transport.send_cbor(VENDOR_CMD_OTP, &cmd_data)?;

    if response.is_empty() || response[0] != 0x00 {
        let status = response.first().copied().unwrap_or(0xFF);
        bail!("OTP info failed: 0x{status:02X}");
    }

    // Parse response: CBOR map with slot info.
    let cbor_data = &response[1..];
    let slots = parse_otp_info(cbor_data)?;

    let rows: Vec<OtpSlotRow> = slots
        .iter()
        .map(|s| OtpSlotRow {
            slot: s.slot_name.clone(),
            slot_type: s.slot_type.clone(),
            status: if s.configured {
                "Configured".green().to_string()
            } else {
                "Empty".dimmed().to_string()
            },
        })
        .collect();

    println!("{}", Table::new(&rows));
    Ok(())
}

fn execute_set_hotp(
    device: Option<&str>,
    slot: u8,
    secret_b32: &str,
    digits: u8,
    counter: u64,
) -> Result<()> {
    let secret = data_encoding::BASE32_NOPAD
        .decode(secret_b32.to_uppercase().as_bytes())
        .or_else(|_| data_encoding::BASE32.decode(secret_b32.to_uppercase().as_bytes()))
        .map_err(|_| anyhow::anyhow!("invalid base32 secret"))?;

    if secret.is_empty() || secret.len() > 64 {
        bail!("HOTP secret must be 1-64 bytes (after base32 decoding)");
    }
    if !(6..=8).contains(&digits) {
        bail!("digits must be 6, 7, or 8");
    }

    let transport = open_hid(device)?;

    // Build CBOR payload: { 1: subcommand, 2: slot, 3: secret, 4: digits, 5: counter }.
    use serde_cbor::Value;
    let map: Vec<(Value, Value)> = vec![
        (
            Value::Integer(0x01),
            Value::Integer(OTP_SUB_SET_HOTP as i128),
        ),
        (Value::Integer(0x02), Value::Integer(slot as i128)),
        (Value::Integer(0x03), Value::Bytes(secret)),
        (Value::Integer(0x04), Value::Integer(digits as i128)),
        (Value::Integer(0x05), Value::Integer(counter as i128)),
    ];
    let cbor_map = Value::Map(map.into_iter().collect());
    let cbor_data = serde_cbor::to_vec(&cbor_map).unwrap_or_default();

    let response = transport.send_cbor(VENDOR_CMD_OTP, &cbor_data)?;

    if response.is_empty() || response[0] != 0x00 {
        let status = response.first().copied().unwrap_or(0xFF);
        bail!("OTP set-hotp failed: 0x{status:02X}");
    }

    println!(
        "{} HOTP configured on slot {} ({} digits, counter={})",
        "✓".green().bold(),
        slot,
        digits,
        counter
    );
    Ok(())
}

fn execute_set_static(device: Option<&str>, slot: u8, password: &str) -> Result<()> {
    if password.is_empty() {
        bail!("static password must not be empty");
    }
    if password.len() > 38 {
        bail!("static password must be at most 38 characters");
    }

    let transport = open_hid(device)?;

    use serde_cbor::Value;
    let map: Vec<(Value, Value)> = vec![
        (
            Value::Integer(0x01),
            Value::Integer(OTP_SUB_SET_STATIC as i128),
        ),
        (Value::Integer(0x02), Value::Integer(slot as i128)),
        (
            Value::Integer(0x03),
            Value::Bytes(password.as_bytes().to_vec()),
        ),
    ];
    let cbor_map = Value::Map(map.into_iter().collect());
    let cbor_data = serde_cbor::to_vec(&cbor_map).unwrap_or_default();

    let response = transport.send_cbor(VENDOR_CMD_OTP, &cbor_data)?;

    if response.is_empty() || response[0] != 0x00 {
        let status = response.first().copied().unwrap_or(0xFF);
        bail!("OTP set-static failed: 0x{status:02X}");
    }

    println!(
        "{} Static password programmed on slot {}",
        "✓".green().bold(),
        slot
    );
    Ok(())
}

fn execute_swap(device: Option<&str>) -> Result<()> {
    let transport = open_hid(device)?;

    use serde_cbor::Value;
    let map: Vec<(Value, Value)> =
        vec![(Value::Integer(0x01), Value::Integer(OTP_SUB_SWAP as i128))];
    let cbor_map = Value::Map(map.into_iter().collect());
    let cbor_data = serde_cbor::to_vec(&cbor_map).unwrap_or_default();

    let response = transport.send_cbor(VENDOR_CMD_OTP, &cbor_data)?;

    if response.is_empty() || response[0] != 0x00 {
        let status = response.first().copied().unwrap_or(0xFF);
        bail!("OTP swap failed: 0x{status:02X}");
    }

    println!("{} OTP slots 1 and 2 swapped.", "✓".green().bold());
    Ok(())
}

fn execute_delete(device: Option<&str>, slot: u8) -> Result<()> {
    let confirm = Confirm::new()
        .with_prompt(format!("Delete OTP slot {slot}?"))
        .default(false)
        .interact()
        .unwrap_or(false);

    if !confirm {
        println!("{}", "Deletion cancelled.".yellow());
        return Ok(());
    }

    let transport = open_hid(device)?;

    use serde_cbor::Value;
    let map: Vec<(Value, Value)> = vec![
        (Value::Integer(0x01), Value::Integer(OTP_SUB_DELETE as i128)),
        (Value::Integer(0x02), Value::Integer(slot as i128)),
    ];
    let cbor_map = Value::Map(map.into_iter().collect());
    let cbor_data = serde_cbor::to_vec(&cbor_map).unwrap_or_default();

    let response = transport.send_cbor(VENDOR_CMD_OTP, &cbor_data)?;

    if response.is_empty() || response[0] != 0x00 {
        let status = response.first().copied().unwrap_or(0xFF);
        bail!("OTP delete failed: 0x{status:02X}");
    }

    println!("{} OTP slot {} cleared.", "✓".green().bold(), slot);
    Ok(())
}

fn execute_update(device: Option<&str>, slot: u8) -> Result<()> {
    println!(
        "{} OTP slot {} update — interactive configuration not yet supported.",
        "⚠".yellow(),
        slot
    );
    println!(
        "{}",
        "Use set-hotp or set-static to reconfigure the slot.".dimmed()
    );
    Ok(())
}

// --- Parsing helpers ---

struct OtpSlotInfo {
    slot_name: String,
    slot_type: String,
    configured: bool,
}

fn parse_otp_info(data: &[u8]) -> Result<Vec<OtpSlotInfo>> {
    if data.is_empty() {
        // No CBOR data — return default empty slots.
        return Ok(vec![
            OtpSlotInfo {
                slot_name: "Slot 1 (short press)".into(),
                slot_type: "—".into(),
                configured: false,
            },
            OtpSlotInfo {
                slot_name: "Slot 2 (long press)".into(),
                slot_type: "—".into(),
                configured: false,
            },
        ]);
    }

    let value: serde_cbor::Value =
        serde_cbor::from_slice(data).map_err(|e| anyhow::anyhow!("CBOR decode error: {e}"))?;

    let mut slots = Vec::new();

    if let serde_cbor::Value::Map(map) = &value {
        for (key, val) in map {
            let slot_num = match key {
                serde_cbor::Value::Integer(n) => *n,
                _ => continue,
            };

            let slot_name = match slot_num {
                1 => "Slot 1 (short press)",
                2 => "Slot 2 (long press)",
                _ => continue,
            };

            if let serde_cbor::Value::Map(slot_map) = val {
                let configured = slot_map
                    .iter()
                    .any(|(_, v)| !matches!(v, serde_cbor::Value::Null));

                let slot_type = slot_map
                    .iter()
                    .find(|(k, _)| *k == serde_cbor::Value::Text("type".into()))
                    .and_then(|(_, v)| {
                        if let serde_cbor::Value::Text(t) = v {
                            Some(t.clone())
                        } else {
                            None
                        }
                    })
                    .unwrap_or_else(|| {
                        if configured {
                            "configured".into()
                        } else {
                            "—".into()
                        }
                    });

                slots.push(OtpSlotInfo {
                    slot_name: slot_name.to_string(),
                    slot_type,
                    configured,
                });
            } else {
                slots.push(OtpSlotInfo {
                    slot_name: slot_name.to_string(),
                    slot_type: "—".into(),
                    configured: false,
                });
            }
        }
    }

    if slots.is_empty() {
        slots.push(OtpSlotInfo {
            slot_name: "Slot 1 (short press)".into(),
            slot_type: "—".into(),
            configured: false,
        });
        slots.push(OtpSlotInfo {
            slot_name: "Slot 2 (long press)".into(),
            slot_type: "—".into(),
            configured: false,
        });
    }

    Ok(slots)
}
