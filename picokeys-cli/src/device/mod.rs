use anyhow::{Context, Result};
use colored::Colorize;
use tabled::{Table, Tabled};

use crate::transport::KNOWN_DEVICES;

/// Detected transport type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportType {
    Hid,
    Ccid,
}

impl std::fmt::Display for TransportType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TransportType::Hid => write!(f, "HID"),
            TransportType::Ccid => write!(f, "CCID"),
        }
    }
}

/// Information about a detected PicoKeys device.
#[derive(Debug, Clone)]
pub struct DetectedDevice {
    pub name: String,
    pub vid: u16,
    pub pid: u16,
    pub serial: Option<String>,
    pub path: String,
    pub transport: TransportType,
    pub has_fido: bool,
    pub has_ccid: bool,
}

#[derive(Tabled)]
struct DeviceRow {
    #[tabled(rename = "#")]
    index: usize,
    #[tabled(rename = "Device")]
    name: String,
    #[tabled(rename = "VID:PID")]
    vid_pid: String,
    #[tabled(rename = "Serial")]
    serial: String,
    #[tabled(rename = "Transport")]
    transport: String,
}

/// Device scanner and selector.
pub struct DeviceDetector;

impl DeviceDetector {
    /// Scan for all connected PicoKeys-compatible devices (HID + CCID).
    pub fn scan() -> Result<Vec<DetectedDevice>> {
        let mut devices = Vec::new();

        // Scan HID devices.
        if let Ok(api) = hidapi::HidApi::new() {
            for info in api.device_list() {
                for known in KNOWN_DEVICES {
                    if info.vendor_id() == known.vid && info.product_id() == known.pid {
                        // Avoid duplicates (same serial).
                        let serial = info.serial_number().map(|s| s.to_string());
                        let already_found = devices.iter().any(|d: &DetectedDevice| {
                            d.vid == known.vid
                                && d.pid == known.pid
                                && d.serial == serial
                                && d.transport == TransportType::Hid
                        });
                        if !already_found {
                            devices.push(DetectedDevice {
                                name: known.name.to_string(),
                                vid: known.vid,
                                pid: known.pid,
                                serial,
                                path: info.path().to_string_lossy().into_owned(),
                                transport: TransportType::Hid,
                                has_fido: known.has_fido,
                                has_ccid: known.has_ccid,
                            });
                        }
                        break;
                    }
                }
            }
        }

        // Scan CCID (PC/SC) readers.
        if let Ok(ctx) = pcsc::Context::establish(pcsc::Scope::System) {
            if let Ok(len) = ctx.list_readers_len() {
                let mut buf = vec![0u8; len];
                if let Ok(readers) = ctx.list_readers(&mut buf) {
                    for reader in readers {
                        let reader_name = reader.to_string_lossy().into_owned();
                        // Check if we can connect (card present).
                        if ctx
                            .connect(reader, pcsc::ShareMode::Shared, pcsc::Protocols::ANY)
                            .is_ok()
                        {
                            // Deduce if it's a known device from the reader name.
                            let detected_name = if reader_name.to_lowercase().contains("picokeys") {
                                "PicoKeys (CCID)"
                            } else if reader_name.to_lowercase().contains("nitrokey") {
                                "Nitrokey (CCID)"
                            } else if reader_name.to_lowercase().contains("yubikey") {
                                "YubiKey (CCID)"
                            } else {
                                "Unknown Smartcard"
                            };

                            devices.push(DetectedDevice {
                                name: detected_name.to_string(),
                                vid: 0,
                                pid: 0,
                                serial: None,
                                path: reader_name,
                                transport: TransportType::Ccid,
                                has_fido: false,
                                has_ccid: true,
                            });
                        }
                    }
                }
            }
        }

        Ok(devices)
    }

    /// Find a specific device by serial number, or return the first one found.
    pub fn find(serial: Option<&str>) -> Result<DetectedDevice> {
        let devices = Self::scan()?;

        if devices.is_empty() {
            anyhow::bail!("no PicoKeys-compatible devices found");
        }

        if let Some(s) = serial {
            devices
                .into_iter()
                .find(|d| d.serial.as_deref() == Some(s))
                .context(format!("no device found with serial '{s}'"))
        } else if devices.len() == 1 {
            Ok(devices.into_iter().next().unwrap())
        } else {
            // Multiple devices — pick first HID device, or just the first.
            let preferred = devices
                .iter()
                .find(|d| d.transport == TransportType::Hid)
                .cloned();
            Ok(preferred.unwrap_or_else(|| devices.into_iter().next().unwrap()))
        }
    }

    /// Find a device preferring CCID transport (for OATH/HSM commands).
    pub fn find_ccid(reader: Option<&str>) -> Result<DetectedDevice> {
        let devices = Self::scan()?;

        if let Some(name) = reader {
            return devices
                .into_iter()
                .find(|d| d.path.contains(name) && d.transport == TransportType::Ccid)
                .context(format!("no CCID reader matching '{name}' found"));
        }

        devices
            .into_iter()
            .find(|d| d.transport == TransportType::Ccid)
            .context("no CCID smartcard reader with card present found")
    }

    /// Display detected devices in a pretty table.
    pub fn print_devices(devices: &[DetectedDevice]) {
        if devices.is_empty() {
            println!("{}", "No devices found.".yellow());
            return;
        }

        let rows: Vec<DeviceRow> = devices
            .iter()
            .enumerate()
            .map(|(i, d)| DeviceRow {
                index: i + 1,
                name: d.name.clone(),
                vid_pid: format!("{:04X}:{:04X}", d.vid, d.pid),
                serial: d.serial.clone().unwrap_or_else(|| "—".into()),
                transport: d.transport.to_string(),
            })
            .collect();

        println!("{}", Table::new(rows));
    }
}
