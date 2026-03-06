use anyhow::Result;
use clap::{Args, Subcommand};
use colored::Colorize;

/// Firmware flashing, building, and update management commands.
#[derive(Args)]
pub struct FirmwareCommand {
    #[command(subcommand)]
    pub action: FirmwareAction,
}

#[derive(Subcommand)]
pub enum FirmwareAction {
    /// Flash firmware to a device (UF2, ELF, or binary)
    Flash {
        /// Target device platform (e.g. rp2040, rp2350, esp32s3, samd21)
        #[arg(short, long)]
        device: String,

        /// Path to the firmware file (.uf2, .elf, .bin)
        #[arg(short, long)]
        firmware: String,

        /// Serial port for ESP32 flashing (e.g. /dev/ttyUSB0)
        #[arg(short, long)]
        port: Option<String>,

        /// Use SWD debug probe instead of USB mass storage
        #[arg(long)]
        probe: bool,
    },
    /// Erase all firmware and data from a device
    Erase {
        /// Target device platform
        #[arg(short, long)]
        device: String,
    },
    /// Build firmware from source for a target platform
    Build {
        /// Target platform (rp2040, rp2350, esp32s3, esp32c5, esp32c6, samd21)
        #[arg(short, long)]
        target: String,

        /// Application to build (fido, hsm)
        #[arg(short, long, default_value = "fido")]
        app: String,

        /// Additional cargo features to enable
        #[arg(short, long)]
        features: Option<String>,

        /// Output directory for the built firmware
        #[arg(short, long)]
        output: Option<String>,
    },
    /// Verify firmware integrity on a connected device
    Verify,
    /// Update firmware via USB DFU (Device Firmware Upgrade)
    DfuUpdate {
        /// Path to the DFU firmware image
        #[arg(short, long)]
        firmware: String,

        /// USB Vendor ID for DFU device (hex)
        #[arg(long)]
        vid: Option<String>,

        /// USB Product ID for DFU device (hex)
        #[arg(long)]
        pid: Option<String>,
    },
    /// Show firmware version and build info from a connected device
    Info,
}

pub async fn run(cmd: FirmwareCommand) -> Result<()> {
    match cmd.action {
        FirmwareAction::Flash {
            device,
            firmware,
            port,
            probe,
        } => {
            let method = if probe { "SWD probe" } else { "USB" };
            let port_info = port
                .as_deref()
                .map(|p| format!(" on port {p}"))
                .unwrap_or_default();
            println!(
                "Firmware flash {} → {} via {method}{port_info}: {}",
                firmware.bold(),
                device.bold(),
                "not yet implemented".yellow()
            );
        }
        FirmwareAction::Erase { device } => {
            println!(
                "Firmware erase {}: {}",
                device.bold(),
                "not yet implemented".yellow()
            );
        }
        FirmwareAction::Build {
            target,
            app,
            features,
            output,
        } => {
            let feat_str = features.as_deref().unwrap_or("(default)");
            let out_str = output.as_deref().unwrap_or("(default)");
            println!(
                "Firmware build {app} for {} (features: {feat_str}, output: {out_str}): {}",
                target.bold(),
                "not yet implemented".yellow()
            );
        }
        FirmwareAction::Verify => {
            println!(
                "{}",
                "Firmware verify: not yet connected to device".yellow()
            );
        }
        FirmwareAction::DfuUpdate {
            firmware,
            vid,
            pid,
        } => {
            let vid_str = vid.as_deref().unwrap_or("auto");
            let pid_str = pid.as_deref().unwrap_or("auto");
            println!(
                "Firmware DFU update {} (VID:{vid_str} PID:{pid_str}): {}",
                firmware.bold(),
                "not yet implemented".yellow()
            );
        }
        FirmwareAction::Info => {
            println!(
                "{}",
                "Firmware info: not yet connected to device".yellow()
            );
        }
    }

    Ok(())
}
