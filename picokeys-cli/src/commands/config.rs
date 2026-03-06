use anyhow::Result;
use clap::{Args, Subcommand, ValueEnum};
use colored::Colorize;

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

pub async fn run(cmd: ConfigCommand, device: Option<&str>) -> Result<()> {
    if let Some(serial) = device {
        tracing::debug!("targeting device with serial: {}", serial);
    }

    match cmd.action {
        ConfigAction::Led { action } => match action {
            LedConfig::Gpio { pin } => {
                println!(
                    "Config LED GPIO {}: {}",
                    pin.to_string().bold(),
                    "not yet connected to device".yellow()
                );
            }
            LedConfig::Type { led_type } => {
                let name = match led_type {
                    LedType::Single => "single",
                    LedType::Rgb => "rgb",
                };
                println!(
                    "Config LED type {}: {}",
                    name.bold(),
                    "not yet connected to device".yellow()
                );
            }
            LedConfig::Set { color } => {
                println!(
                    "Config LED color #{}: {}",
                    color.bold(),
                    "not yet connected to device".yellow()
                );
            }
        },
        ConfigAction::Button { action } => match action {
            ButtonConfig::Gpio { pin } => {
                println!(
                    "Config button GPIO {}: {}",
                    pin.to_string().bold(),
                    "not yet connected to device".yellow()
                );
            }
            ButtonConfig::Polarity { polarity } => {
                let name = match polarity {
                    ButtonPolarity::ActiveHigh => "active-high",
                    ButtonPolarity::ActiveLow => "active-low",
                };
                println!(
                    "Config button polarity {}: {}",
                    name.bold(),
                    "not yet connected to device".yellow()
                );
            }
            ButtonConfig::Timeout { seconds } => {
                println!(
                    "Config button timeout {seconds}s: {}",
                    "not yet connected to device".yellow()
                );
            }
        },
        ConfigAction::PressToConfirm { enabled } => {
            let state = match enabled {
                BoolToggle::On => "enabled",
                BoolToggle::Off => "disabled",
            };
            println!(
                "Config press-to-confirm {}: {}",
                state.bold(),
                "not yet connected to device".yellow()
            );
        }
        ConfigAction::VidPid { value } => {
            println!(
                "Config USB VID:PID {}: {}",
                value.bold(),
                "not yet connected to device".yellow()
            );
        }
        ConfigAction::Serial => {
            println!(
                "{}",
                "Config serial: not yet connected to device".yellow()
            );
        }
        ConfigAction::Lock => {
            println!(
                "{}",
                "Config lock: not yet connected to device".yellow()
            );
        }
    }

    Ok(())
}
