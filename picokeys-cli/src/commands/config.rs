use anyhow::{bail, Result};
use clap::{Args, Subcommand, ValueEnum};
use colored::Colorize;
use dialoguer::{Confirm, Input};

use crate::device::DeviceDetector;
use crate::transport::hid::HidTransport;

/// Vendor CTAP command for device configuration (PicoKeys vendor range).
const VENDOR_CMD_CONFIG: u8 = 0x42;

// Config subcommands.
const CONFIG_SUB_LED_GPIO: u8 = 0x01;
const CONFIG_SUB_LED_TYPE: u8 = 0x02;
const CONFIG_SUB_LED_COLOR: u8 = 0x03;
const CONFIG_SUB_BUTTON_GPIO: u8 = 0x10;
const CONFIG_SUB_BUTTON_POLARITY: u8 = 0x11;
const CONFIG_SUB_BUTTON_TIMEOUT: u8 = 0x12;
const CONFIG_SUB_PRESS_TO_CONFIRM: u8 = 0x20;
const CONFIG_SUB_VID_PID: u8 = 0x30;
const CONFIG_SUB_SERIAL: u8 = 0x31;
const CONFIG_SUB_LOCK: u8 = 0xFF;

/// Device hardware configuration commands.
#[derive(Args)]
pub struct ConfigCommand {
    #[command(subcommand)]
    pub action: ConfigAction,
}

#[derive(Subcommand)]
pub enum ConfigAction {
    /// Configure the device LED
    Led {
        #[command(subcommand)]
        action: LedConfig,
    },
    /// Configure the user-presence button
    Button {
        #[command(subcommand)]
        action: ButtonConfig,
    },
    /// Enable or disable press-to-confirm for operations
    PressToConfirm {
        /// Enable or disable press-to-confirm
        #[arg(value_enum)]
        enabled: BoolToggle,
    },
    /// Set custom USB VID:PID (e.g. "1209:4823")
    VidPid {
        /// VID:PID value in hex (e.g. "1209:4823")
        #[arg(help = "VID:PID as hex, e.g. 1209:4823")]
        value: String,
    },
    /// Display or set the device serial number
    Serial,
    /// Lock the device configuration (prevents further changes)
    Lock,
}

#[derive(Subcommand)]
pub enum LedConfig {
    /// Set the GPIO pin number for the LED
    Gpio {
        /// GPIO pin number
        #[arg(help = "GPIO pin number")]
        pin: u8,
    },
    /// Set the LED type
    Type {
        /// LED type
        #[arg(value_enum)]
        led_type: LedType,
    },
    /// Set the LED color (for RGB LEDs)
    Set {
        /// Color value (hex RGB, e.g. "FF0000" for red)
        #[arg(help = "Hex RGB color (e.g. FF0000)")]
        color: String,
    },
}

#[derive(Clone, ValueEnum)]
pub enum LedType {
    /// Single-color digital LED
    Single,
    /// WS2812 RGB addressable LED
    Rgb,
}

#[derive(Subcommand)]
pub enum ButtonConfig {
    /// Set the GPIO pin number for the button
    Gpio {
        /// GPIO pin number
        #[arg(help = "GPIO pin number")]
        pin: u8,
    },
    /// Set the button polarity
    Polarity {
        /// Active-high or active-low
        #[arg(value_enum)]
        polarity: ButtonPolarity,
    },
    /// Set the press-to-confirm timeout in seconds
    Timeout {
        /// Timeout in seconds
        #[arg(help = "Timeout in seconds (1-60)")]
        seconds: u8,
    },
}

#[derive(Clone, ValueEnum)]
pub enum ButtonPolarity {
    ActiveHigh,
    ActiveLow,
}

#[derive(Clone, ValueEnum)]
pub enum BoolToggle {
    On,
    Off,
}

fn open_hid(device: Option<&str>) -> Result<HidTransport> {
    let detected = DeviceDetector::find(device)?;
    HidTransport::open(detected.vid, detected.pid, detected.serial.as_deref())
}

/// Send a vendor config command with CBOR payload.
fn send_config_command(
    transport: &HidTransport,
    sub_cmd: u8,
    value_fields: &[(i128, serde_cbor::Value)],
) -> Result<()> {
    use serde_cbor::Value;

    let mut map: Vec<(Value, Value)> =
        vec![(Value::Integer(0x01), Value::Integer(sub_cmd as i128))];

    for (key, val) in value_fields {
        map.push((Value::Integer(*key), val.clone()));
    }

    let cbor_map = Value::Map(map.into_iter().collect());
    let cbor_data = serde_cbor::to_vec(&cbor_map).unwrap_or_default();

    let response = transport.send_cbor(VENDOR_CMD_CONFIG, &cbor_data)?;

    if response.is_empty() || response[0] != 0x00 {
        let status = response.first().copied().unwrap_or(0xFF);
        bail!("config command failed: 0x{status:02X}");
    }

    Ok(())
}

pub async fn run(cmd: ConfigCommand, device: Option<&str>) -> Result<()> {
    match cmd.action {
        ConfigAction::Led { action } => match action {
            LedConfig::Gpio { pin } => {
                let transport = open_hid(device)?;
                send_config_command(
                    &transport,
                    CONFIG_SUB_LED_GPIO,
                    &[(0x02, serde_cbor::Value::Integer(pin as i128))],
                )?;
                println!(
                    "{} LED GPIO pin set to {}.",
                    "✓".green().bold(),
                    pin.to_string().bold()
                );
            }
            LedConfig::Type { led_type } => {
                let transport = open_hid(device)?;
                let type_val = match led_type {
                    LedType::Single => 0,
                    LedType::Rgb => 1,
                };
                send_config_command(
                    &transport,
                    CONFIG_SUB_LED_TYPE,
                    &[(0x02, serde_cbor::Value::Integer(type_val))],
                )?;
                let name = match led_type {
                    LedType::Single => "single",
                    LedType::Rgb => "RGB (WS2812)",
                };
                println!("{} LED type set to {}.", "✓".green().bold(), name.bold());
            }
            LedConfig::Set { color } => {
                let color_bytes = hex::decode(&color)
                    .map_err(|_| anyhow::anyhow!("invalid hex color — use format like FF0000"))?;
                if color_bytes.len() != 3 {
                    bail!(
                        "color must be exactly 3 bytes (6 hex chars), got {}",
                        color_bytes.len()
                    );
                }

                let transport = open_hid(device)?;
                let color_val = ((color_bytes[0] as i128) << 16)
                    | ((color_bytes[1] as i128) << 8)
                    | (color_bytes[2] as i128);
                send_config_command(
                    &transport,
                    CONFIG_SUB_LED_COLOR,
                    &[(0x02, serde_cbor::Value::Integer(color_val))],
                )?;
                println!("{} LED color set to #{}.", "✓".green().bold(), color.bold());
            }
        },
        ConfigAction::Button { action } => match action {
            ButtonConfig::Gpio { pin } => {
                let transport = open_hid(device)?;
                send_config_command(
                    &transport,
                    CONFIG_SUB_BUTTON_GPIO,
                    &[(0x02, serde_cbor::Value::Integer(pin as i128))],
                )?;
                println!(
                    "{} Button GPIO pin set to {}.",
                    "✓".green().bold(),
                    pin.to_string().bold()
                );
            }
            ButtonConfig::Polarity { polarity } => {
                let transport = open_hid(device)?;
                let pol_val = match polarity {
                    ButtonPolarity::ActiveHigh => 1,
                    ButtonPolarity::ActiveLow => 0,
                };
                send_config_command(
                    &transport,
                    CONFIG_SUB_BUTTON_POLARITY,
                    &[(0x02, serde_cbor::Value::Integer(pol_val))],
                )?;
                let name = match polarity {
                    ButtonPolarity::ActiveHigh => "active-high",
                    ButtonPolarity::ActiveLow => "active-low",
                };
                println!(
                    "{} Button polarity set to {}.",
                    "✓".green().bold(),
                    name.bold()
                );
            }
            ButtonConfig::Timeout { seconds } => {
                if seconds == 0 || seconds > 60 {
                    bail!("timeout must be between 1 and 60 seconds");
                }
                let transport = open_hid(device)?;
                send_config_command(
                    &transport,
                    CONFIG_SUB_BUTTON_TIMEOUT,
                    &[(0x02, serde_cbor::Value::Integer(seconds as i128))],
                )?;
                println!("{} Button timeout set to {}s.", "✓".green().bold(), seconds);
            }
        },
        ConfigAction::PressToConfirm { enabled } => {
            let transport = open_hid(device)?;
            let val = match enabled {
                BoolToggle::On => 1,
                BoolToggle::Off => 0,
            };
            send_config_command(
                &transport,
                CONFIG_SUB_PRESS_TO_CONFIRM,
                &[(0x02, serde_cbor::Value::Integer(val))],
            )?;
            let state = match enabled {
                BoolToggle::On => "enabled",
                BoolToggle::Off => "disabled",
            };
            println!("{} Press-to-confirm {}.", "✓".green().bold(), state.bold());
        }
        ConfigAction::VidPid { value } => {
            let parts: Vec<&str> = value.split(':').collect();
            if parts.len() != 2 {
                bail!("VID:PID must be in format XXXX:XXXX (e.g., 1209:4823)");
            }
            let vid = u16::from_str_radix(parts[0], 16)
                .map_err(|_| anyhow::anyhow!("invalid VID hex value: {}", parts[0]))?;
            let pid = u16::from_str_radix(parts[1], 16)
                .map_err(|_| anyhow::anyhow!("invalid PID hex value: {}", parts[1]))?;

            println!(
                "{}",
                format!(
                    "⚠ Changing USB VID:PID to {:04X}:{:04X}. Device will need to be re-plugged.",
                    vid, pid
                )
                .yellow()
            );

            let confirm = Confirm::new()
                .with_prompt("Continue?")
                .default(false)
                .interact()
                .unwrap_or(false);

            if !confirm {
                println!("{}", "Cancelled.".yellow());
                return Ok(());
            }

            let transport = open_hid(device)?;
            let vid_pid_val = ((vid as i128) << 16) | (pid as i128);
            send_config_command(
                &transport,
                CONFIG_SUB_VID_PID,
                &[(0x02, serde_cbor::Value::Integer(vid_pid_val))],
            )?;
            println!(
                "{} USB VID:PID set to {:04X}:{:04X}. Re-plug the device.",
                "✓".green().bold(),
                vid,
                pid
            );
        }
        ConfigAction::Serial => {
            let transport = open_hid(device)?;
            // Read serial — send config serial sub with no value to read.
            let response = {
                use serde_cbor::Value;
                let map: Vec<(Value, Value)> = vec![(
                    Value::Integer(0x01),
                    Value::Integer(CONFIG_SUB_SERIAL as i128),
                )];
                let cbor_map = Value::Map(map.into_iter().collect());
                let cbor_data = serde_cbor::to_vec(&cbor_map).unwrap_or_default();
                transport.send_cbor(VENDOR_CMD_CONFIG, &cbor_data)?
            };

            if response.is_empty() || response[0] != 0x00 {
                let status = response.first().copied().unwrap_or(0xFF);
                bail!("read serial failed: 0x{status:02X}");
            }

            let cbor_data = &response[1..];
            if cbor_data.is_empty() {
                println!("Serial: {}", "(not set)".dimmed());
            } else {
                let value: serde_cbor::Value = serde_cbor::from_slice(cbor_data)
                    .map_err(|e| anyhow::anyhow!("CBOR decode error: {e}"))?;
                if let serde_cbor::Value::Text(serial) = &value {
                    println!("Serial: {}", serial.bold());
                } else if let serde_cbor::Value::Bytes(b) = &value {
                    println!("Serial: {}", hex::encode(b).bold());
                } else {
                    println!("Serial: {:?}", value);
                }
            }
        }
        ConfigAction::Lock => {
            println!(
                "{}",
                "⚠ WARNING: Locking the device configuration is PERMANENT!"
                    .red()
                    .bold()
            );
            println!(
                "{}",
                "After locking, LED pin, button pin, VID:PID, and other hardware settings cannot be changed."
                    .yellow()
            );

            let confirmation: String = Input::new()
                .with_prompt("Type LOCK to confirm")
                .interact_text()
                .map_err(|e| anyhow::anyhow!("input failed: {e}"))?;

            if confirmation != "LOCK" {
                println!("{}", "Lock cancelled.".yellow());
                return Ok(());
            }

            let transport = open_hid(device)?;
            send_config_command(&transport, CONFIG_SUB_LOCK, &[])?;
            println!(
                "{} Device configuration locked permanently.",
                "✓".green().bold()
            );
        }
    }

    Ok(())
}
