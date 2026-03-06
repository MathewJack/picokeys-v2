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
            EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                EnvFilter::new(if cli.verbose { "debug" } else { "info" })
            }),
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
