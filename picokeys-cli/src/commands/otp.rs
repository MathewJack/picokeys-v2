use anyhow::Result;
use clap::{Args, Subcommand};
use colored::Colorize;

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

pub async fn run(cmd: OtpCommand, device: Option<&str>) -> Result<()> {
    if let Some(serial) = device {
        tracing::debug!("targeting device with serial: {}", serial);
    }

    match cmd.action {
        OtpAction::Info => {
            println!(
                "{}",
                "OTP slot info: not yet connected to device".yellow()
            );
        }
        OtpAction::SetHotp {
            slot,
            secret: _,
            digits,
            counter,
        } => {
            println!(
                "OTP set-hotp slot {slot} ({digits} digits, counter={counter}): {}",
                "not yet connected to device".yellow()
            );
        }
        OtpAction::SetStatic { slot, password: _ } => {
            println!(
                "OTP set-static slot {slot}: {}",
                "not yet connected to device".yellow()
            );
        }
        OtpAction::Swap => {
            println!(
                "{}",
                "OTP swap slots: not yet connected to device".yellow()
            );
        }
        OtpAction::Delete { slot } => {
            println!(
                "OTP delete slot {slot}: {}",
                "not yet connected to device".yellow()
            );
        }
        OtpAction::Update { slot } => {
            println!(
                "OTP update slot {slot}: {}",
                "not yet connected to device".yellow()
            );
        }
    }

    Ok(())
}
