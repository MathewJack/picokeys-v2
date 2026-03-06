use anyhow::{bail, Result};
use colored::Colorize;
use tabled::{Table, Tabled};

use crate::device::DeviceDetector;
use crate::transport::hid::HidTransport;

/// CTAP2 authenticatorGetInfo command.
const CTAP2_CMD_GET_INFO: u8 = 0x04;

#[derive(Tabled)]
struct DeviceInfoRow {
    #[tabled(rename = "Property")]
    property: String,
    #[tabled(rename = "Value")]
    value: String,
}

/// Display device firmware version, serial number, capabilities, AAGUID, and platform.
pub async fn run(device: Option<&str>) -> Result<()> {
    println!("{}\n", "PicoKeys Device Information".bold().cyan());

    let detected = DeviceDetector::find(device)?;
    tracing::debug!("found device: {} ({:04X}:{:04X})", detected.name, detected.vid, detected.pid);

    let transport = HidTransport::open(detected.vid, detected.pid, detected.serial.as_deref())?;

    // Send authenticatorGetInfo (CTAP2 command 0x04, no additional CBOR data).
    let response = transport.send_cbor(CTAP2_CMD_GET_INFO, &[])?;

    if response.is_empty() {
        bail!("empty GetInfo response from device");
    }

    // First byte is the CTAP2 status code.
    let status = response[0];
    if status != 0x00 {
        bail!("CTAP2 GetInfo failed with status: 0x{status:02X} ({})", ctap2_status_name(status));
    }

    // Remaining bytes are CBOR-encoded GetInfo response.
    let cbor_data = &response[1..];
    let info = parse_get_info(cbor_data)?;

    let rows = vec![
        DeviceInfoRow {
            property: "Device".into(),
            value: detected.name.clone(),
        },
        DeviceInfoRow {
            property: "Firmware Version".into(),
            value: info.firmware_version.clone(),
        },
        DeviceInfoRow {
            property: "Serial Number".into(),
            value: detected
                .serial
                .clone()
                .unwrap_or_else(|| "—".dimmed().to_string()),
        },
        DeviceInfoRow {
            property: "AAGUID".into(),
            value: info.aaguid.clone(),
        },
        DeviceInfoRow {
            property: "CTAP Versions".into(),
            value: info.versions.join(", "),
        },
        DeviceInfoRow {
            property: "Extensions".into(),
            value: if info.extensions.is_empty() {
                "none".dimmed().to_string()
            } else {
                info.extensions.join(", ")
            },
        },
        DeviceInfoRow {
            property: "Options".into(),
            value: if info.options.is_empty() {
                "none".dimmed().to_string()
            } else {
                info.options.join(", ")
            },
        },
        DeviceInfoRow {
            property: "Max Message Size".into(),
            value: info
                .max_msg_size
                .map(|s| format!("{s} bytes"))
                .unwrap_or_else(|| "default (1024)".into()),
        },
        DeviceInfoRow {
            property: "PIN Protocols".into(),
            value: if info.pin_protocols.is_empty() {
                "none".dimmed().to_string()
            } else {
                info.pin_protocols
                    .iter()
                    .map(|p| p.to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            },
        },
        DeviceInfoRow {
            property: "Max Credential Count (in list)".into(),
            value: info
                .max_cred_count_in_list
                .map(|c| c.to_string())
                .unwrap_or_else(|| "—".into()),
        },
        DeviceInfoRow {
            property: "Max Credential ID Length".into(),
            value: info
                .max_cred_id_length
                .map(|l| format!("{l} bytes"))
                .unwrap_or_else(|| "—".into()),
        },
        DeviceInfoRow {
            property: "Transports".into(),
            value: if info.transports.is_empty() {
                "—".dimmed().to_string()
            } else {
                info.transports.join(", ")
            },
        },
    ];

    let table = Table::new(rows).to_string();
    println!("{table}");

    println!("\n{} {}", "✓".green().bold(), "Device information retrieved successfully.".green());

    Ok(())
}

struct GetInfoResult {
    versions: Vec<String>,
    extensions: Vec<String>,
    aaguid: String,
    options: Vec<String>,
    max_msg_size: Option<u64>,
    pin_protocols: Vec<u64>,
    max_cred_count_in_list: Option<u64>,
    max_cred_id_length: Option<u64>,
    transports: Vec<String>,
    firmware_version: String,
}

/// Parse CTAP2 authenticatorGetInfo CBOR response.
/// The response is a CBOR map with integer keys (1..10+).
fn parse_get_info(data: &[u8]) -> Result<GetInfoResult> {
    let value: serde_cbor::Value =
        serde_cbor::from_slice(data).map_err(|e| anyhow::anyhow!("failed to decode CBOR GetInfo: {e}"))?;

    let map = match &value {
        serde_cbor::Value::Map(m) => m,
        _ => bail!("GetInfo response is not a CBOR map"),
    };

    let mut result = GetInfoResult {
        versions: Vec::new(),
        extensions: Vec::new(),
        aaguid: String::new(),
        options: Vec::new(),
        max_msg_size: None,
        pin_protocols: Vec::new(),
        max_cred_count_in_list: None,
        max_cred_id_length: None,
        transports: Vec::new(),
        firmware_version: "unknown".into(),
    };

    for (key, val) in map {
        let key_num = match key {
            serde_cbor::Value::Integer(n) => *n,
            _ => continue,
        };

        match key_num {
            // 0x01: versions
            0x01 => {
                if let serde_cbor::Value::Array(arr) = val {
                    for item in arr {
                        if let serde_cbor::Value::Text(s) = item {
                            result.versions.push(s.clone());
                        }
                    }
                }
            }
            // 0x02: extensions
            0x02 => {
                if let serde_cbor::Value::Array(arr) = val {
                    for item in arr {
                        if let serde_cbor::Value::Text(s) = item {
                            result.extensions.push(s.clone());
                        }
                    }
                }
            }
            // 0x03: aaguid (byte string, 16 bytes)
            0x03 => {
                if let serde_cbor::Value::Bytes(b) = val {
                    result.aaguid = hex::encode(b);
                    // Format as UUID-style: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
                    if result.aaguid.len() == 32 {
                        result.aaguid = format!(
                            "{}-{}-{}-{}-{}",
                            &result.aaguid[0..8],
                            &result.aaguid[8..12],
                            &result.aaguid[12..16],
                            &result.aaguid[16..20],
                            &result.aaguid[20..32],
                        );
                    }
                }
            }
            // 0x04: options
            0x04 => {
                if let serde_cbor::Value::Map(opts) = val {
                    for (k, v) in opts {
                        if let (serde_cbor::Value::Text(name), serde_cbor::Value::Bool(enabled)) =
                            (k, v)
                        {
                            let status = if *enabled { "✓" } else { "✗" };
                            result.options.push(format!("{name}: {status}"));
                        }
                    }
                }
            }
            // 0x05: maxMsgSize
            0x05 => {
                if let serde_cbor::Value::Integer(n) = val {
                    result.max_msg_size = Some(*n as u64);
                }
            }
            // 0x06: pinUvAuthProtocols
            0x06 => {
                if let serde_cbor::Value::Array(arr) = val {
                    for item in arr {
                        if let serde_cbor::Value::Integer(n) = item {
                            result.pin_protocols.push(*n as u64);
                        }
                    }
                }
            }
            // 0x07: maxCredentialCountInList
            0x07 => {
                if let serde_cbor::Value::Integer(n) = val {
                    result.max_cred_count_in_list = Some(*n as u64);
                }
            }
            // 0x08: maxCredentialIdLength
            0x08 => {
                if let serde_cbor::Value::Integer(n) = val {
                    result.max_cred_id_length = Some(*n as u64);
                }
            }
            // 0x09: transports
            0x09 => {
                if let serde_cbor::Value::Array(arr) = val {
                    for item in arr {
                        if let serde_cbor::Value::Text(s) = item {
                            result.transports.push(s.clone());
                        }
                    }
                }
            }
            // 0x0E (14): firmwareVersion
            0x0E => {
                if let serde_cbor::Value::Integer(n) = val {
                    let major = (*n >> 24) & 0xFF;
                    let minor = (*n >> 16) & 0xFF;
                    let patch = *n & 0xFFFF;
                    result.firmware_version = format!("{major}.{minor}.{patch}");
                }
            }
            _ => {}
        }
    }

    if result.firmware_version == "unknown" && !result.versions.is_empty() {
        result.firmware_version = result.versions.join(", ");
    }

    Ok(result)
}

fn ctap2_status_name(status: u8) -> &'static str {
    match status {
        0x00 => "OK",
        0x01 => "INVALID_COMMAND",
        0x02 => "INVALID_PARAMETER",
        0x03 => "INVALID_LENGTH",
        0x04 => "INVALID_SEQ",
        0x05 => "TIMEOUT",
        0x06 => "CHANNEL_BUSY",
        0x0B => "LOCK_REQUIRED",
        0x0C => "INVALID_CHANNEL",
        0x11 => "CBOR_UNEXPECTED_TYPE",
        0x12 => "INVALID_CBOR",
        0x14 => "MISSING_PARAMETER",
        0x16 => "LIMIT_EXCEEDED",
        0x27 => "UNSUPPORTED_EXTENSION",
        0x29 => "CREDENTIAL_EXCLUDED",
        0x2C => "PROCESSING",
        0x2E => "INVALID_CREDENTIAL",
        0x2F => "USER_ACTION_PENDING",
        0x30 => "OPERATION_PENDING",
        0x31 => "NO_OPERATIONS",
        0x32 => "UNSUPPORTED_ALGORITHM",
        0x33 => "OPERATION_DENIED",
        0x35 => "KEY_STORE_FULL",
        0x36 => "NOT_BUSY",
        0x38 => "NO_OPERATION_PENDING",
        0x39 => "UNSUPPORTED_OPTION",
        0x3A => "INVALID_OPTION",
        0x3B => "KEEPALIVE_CANCEL",
        0x3C => "NO_CREDENTIALS",
        0x3D => "USER_ACTION_TIMEOUT",
        0x3E => "NOT_ALLOWED",
        0x31 => "PIN_INVALID",
        0x32 => "PIN_BLOCKED",
        0x33 => "PIN_AUTH_INVALID",
        0x34 => "PIN_AUTH_BLOCKED",
        0x36 => "PIN_NOT_SET",
        0x38 => "PIN_POLICY_VIOLATION",
        0x3A => "PIN_TOKEN_EXPIRED",
        0x7F => "SPEC_LAST",
        0xDF => "EXTENSION_FIRST",
        0xEF => "EXTENSION_LAST",
        0xF0 => "VENDOR_FIRST",
        0xFF => "VENDOR_LAST",
        _ => "UNKNOWN",
    }
}
