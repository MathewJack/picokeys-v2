//! # PicoKeys CLI
//!
//! Host-side management tool for PicoKeys v2 security keys.
//!
//! ## Overview
//!
//! `picokeys-cli` is a command-line tool (similar to `ykman`) for managing
//! PicoKeys v2 devices. It communicates via USB HID (CTAPHID) and CCID
//! (PC/SC) transports.
//!
//! ## Commands
//!
//! | Command | Description |
//! |---------|-------------|
//! | `info` | Display device info (firmware, serial, capabilities) |
//! | `fido` | FIDO2 credential management, PIN, reset, config |
//! | `oath` | OATH TOTP/HOTP management (list, add, generate codes) |
//! | `otp` | YubiKey OTP slot management |
//! | `hsm` | HSM key management, signing, encryption |
//! | `config` | Device configuration (LED, button, USB) |
//! | `firmware` | Firmware update and OTP provisioning |
//!
//! ## Usage
//!
//! ```bash
//! # Show device info
//! picokeys-cli info
//!
//! # List FIDO2 credentials
//! picokeys-cli fido credentials list
//!
//! # Generate OATH TOTP code
//! picokeys-cli oath code GitHub
//!
//! # HSM key generation
//! picokeys-cli hsm keys generate --type ec-p256 --label mykey
//! ```
//!
//! ## Transport Auto-Detection
//!
//! The CLI automatically detects connected devices via HID or CCID.
//! Use `--device <SERIAL>` to target a specific device when multiple are connected.

use anyhow::Result;
use clap::Parser;
use colored::Colorize;
use tracing_subscriber::EnvFilter;

mod commands;
mod device;
mod transport;

/// PicoKeys CLI — Firmware management + device interaction tool
#[derive(Parser)]
#[command(name = "picokeys-cli", version, about, long_about = None)]
pub struct Cli {
    /// Select device by serial number when multiple devices are connected
    #[arg(short, long, global = true)]
    device: Option<String>,

    /// Enable verbose debug logging
    #[arg(short, long, global = true)]
    verbose: bool,

    #[command(subcommand)]
    command: commands::Command,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new(if cli.verbose { "debug" } else { "info" })),
        )
        .init();

    tracing::debug!("picokeys-cli v{}", env!("CARGO_PKG_VERSION"));

    match commands::dispatch(cli.command, cli.device.as_deref()).await {
        Ok(()) => Ok(()),
        Err(e) => {
            eprintln!("{} {e:#}", "Error:".red().bold());
            std::process::exit(1);
        }
    }
}
