pub mod config;
pub mod fido;
pub mod firmware;
pub mod hsm;
pub mod info;
pub mod oath;
pub mod otp;

use anyhow::Result;
use clap::Subcommand;

#[derive(Subcommand)]
pub enum Command {
    /// Show device firmware version, serial, and capabilities
    Info,
    /// FIDO2 / WebAuthn management (credentials, PIN, config, backup)
    Fido(fido::FidoCommand),
    /// OATH TOTP/HOTP credential management
    Oath(oath::OathCommand),
    /// YubiKey-compatible OTP slot management
    Otp(otp::OtpCommand),
    /// Hardware Security Module (SmartCard-HSM) management
    Hsm(hsm::HsmCommand),
    /// Device hardware configuration (LED, button, USB identifiers)
    Config(config::ConfigCommand),
    /// Firmware flashing, building, and update management
    Firmware(firmware::FirmwareCommand),
}

pub async fn dispatch(cmd: Command, device: Option<&str>) -> Result<()> {
    match cmd {
        Command::Info => info::run(device).await,
        Command::Fido(c) => fido::run(c, device).await,
        Command::Oath(c) => oath::run(c, device).await,
        Command::Otp(c) => otp::run(c, device).await,
        Command::Hsm(c) => hsm::run(c, device).await,
        Command::Config(c) => config::run(c, device).await,
        Command::Firmware(c) => firmware::run(c).await,
    }
}
