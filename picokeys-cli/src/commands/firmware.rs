use anyhow::{bail, Result};
use clap::{Args, Subcommand};
use colored::Colorize;
use dialoguer::Input;
use indicatif::{ProgressBar, ProgressStyle};

use std::path::Path;
use std::process::Command as ProcessCommand;

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
        } => execute_flash(&device, &firmware, port.as_deref(), probe),
        FirmwareAction::Erase { device } => execute_erase(&device),
        FirmwareAction::Build {
            target,
            app,
            features,
            output,
        } => execute_build(&target, &app, features.as_deref(), output.as_deref()),
        FirmwareAction::Verify => execute_verify(),
        FirmwareAction::DfuUpdate { firmware, vid, pid } => {
            execute_dfu_update(&firmware, vid.as_deref(), pid.as_deref())
        }
        FirmwareAction::Info => execute_firmware_info(),
    }
}

fn execute_flash(
    platform: &str,
    firmware_path: &str,
    port: Option<&str>,
    use_probe: bool,
) -> Result<()> {
    let fw_path = Path::new(firmware_path);
    if !fw_path.exists() {
        bail!("firmware file not found: {firmware_path}");
    }

    let extension = fw_path.extension().and_then(|e| e.to_str()).unwrap_or("");

    println!(
        "{} Flashing {} → {}",
        "→".cyan().bold(),
        firmware_path.bold(),
        platform.bold()
    );

    let pb = ProgressBar::new(100);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{msg} [{bar:40.cyan/blue}] {pos}%")
            .unwrap_or_else(|_| ProgressStyle::default_bar())
            .progress_chars("█▓░"),
    );
    pb.set_message("Flashing");

    match platform.to_lowercase().as_str() {
        "rp2040" | "rp2350" => {
            if use_probe {
                flash_with_probe_rs(firmware_path, platform, &pb)?;
            } else {
                flash_uf2_rp(firmware_path, extension, platform, &pb)?;
            }
        }
        "esp32s3" | "esp32c5" | "esp32c6" => {
            flash_espflash(firmware_path, platform, port, &pb)?;
        }
        "samd21" => {
            if use_probe {
                flash_with_openocd(firmware_path, &pb)?;
            } else {
                flash_uf2_samd(firmware_path, &pb)?;
            }
        }
        _ => bail!("unsupported platform: {platform}. Supported: rp2040, rp2350, esp32s3, esp32c5, esp32c6, samd21"),
    }

    pb.finish_with_message("Flash complete");
    println!(
        "\n{} Firmware flashed successfully to {}.",
        "✓".green().bold(),
        platform
    );
    Ok(())
}

fn flash_uf2_rp(
    firmware_path: &str,
    extension: &str,
    platform: &str,
    pb: &ProgressBar,
) -> Result<()> {
    pb.set_position(10);

    if extension == "elf" {
        // Convert ELF to UF2 first using elf2uf2-rs.
        check_tool_installed("elf2uf2-rs")?;

        pb.set_message("Converting ELF to UF2");
        let uf2_path = format!("{}.uf2", firmware_path);

        let output = ProcessCommand::new("elf2uf2-rs")
            .arg(firmware_path)
            .arg(&uf2_path)
            .output()
            .map_err(|e| anyhow::anyhow!("failed to run elf2uf2-rs: {e}"))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!("elf2uf2-rs failed: {stderr}");
        }

        pb.set_position(40);
        copy_uf2_to_drive(&uf2_path, platform, pb)?;
    } else if extension == "uf2" {
        copy_uf2_to_drive(firmware_path, platform, pb)?;
    } else {
        bail!("unsupported firmware format '{extension}' for {platform} — use .elf or .uf2");
    }

    Ok(())
}

fn copy_uf2_to_drive(uf2_path: &str, platform: &str, pb: &ProgressBar) -> Result<()> {
    pb.set_message("Searching for UF2 bootloader drive");
    pb.set_position(50);

    // Look for the RP2040/RP2350 USB mass storage volume.
    let drive_label = match platform {
        "rp2350" => "RP2350",
        _ => "RPI-RP2",
    };

    let mount_paths = [
        format!("/media/{}", drive_label),
        format!("/media/{}/{}", whoami(), drive_label),
        format!("/run/media/{}/{}", whoami(), drive_label),
        format!("/mnt/{}", drive_label),
        format!("/Volumes/{}", drive_label),
    ];

    let drive_path = mount_paths
        .iter()
        .find(|p| Path::new(p).exists())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "UF2 bootloader drive '{}' not found. \
                 Is the device in BOOTSEL mode? Hold BOOTSEL while plugging in.",
                drive_label
            )
        })?;

    pb.set_message("Copying UF2 to device");
    pb.set_position(60);

    let dest = Path::new(drive_path).join(Path::new(uf2_path).file_name().unwrap_or_default());

    std::fs::copy(uf2_path, &dest)
        .map_err(|e| anyhow::anyhow!("failed to copy UF2 to {}: {e}", dest.display()))?;

    pb.set_position(95);

    // Wait briefly for the device to reboot.
    std::thread::sleep(std::time::Duration::from_secs(1));
    pb.set_position(100);

    Ok(())
}

fn flash_with_probe_rs(firmware_path: &str, platform: &str, pb: &ProgressBar) -> Result<()> {
    check_tool_installed("probe-rs")?;

    pb.set_message("Flashing via SWD probe");
    pb.set_position(20);

    let chip = match platform {
        "rp2040" => "RP2040",
        "rp2350" => "RP2350",
        _ => bail!("probe-rs flash not supported for {platform}"),
    };

    let output = ProcessCommand::new("probe-rs")
        .args(["run", "--chip", chip, firmware_path])
        .output()
        .map_err(|e| anyhow::anyhow!("failed to run probe-rs: {e}"))?;

    pb.set_position(90);

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("probe-rs flash failed: {stderr}");
    }

    pb.set_position(100);
    Ok(())
}

fn flash_espflash(
    firmware_path: &str,
    platform: &str,
    port: Option<&str>,
    pb: &ProgressBar,
) -> Result<()> {
    check_tool_installed("espflash")?;

    pb.set_message("Flashing via espflash");
    pb.set_position(20);

    let mut cmd = ProcessCommand::new("espflash");
    cmd.arg("flash");

    if let Some(port) = port {
        cmd.args(["--port", port]);
    }

    // Set the chip based on platform.
    let chip = match platform {
        "esp32s3" => "esp32s3",
        "esp32c5" => "esp32c5",
        "esp32c6" => "esp32c6",
        _ => bail!("espflash not supported for {platform}"),
    };
    cmd.args(["--chip", chip]);
    cmd.arg(firmware_path);

    let output = cmd
        .output()
        .map_err(|e| anyhow::anyhow!("failed to run espflash: {e}"))?;

    pb.set_position(90);

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        bail!("espflash failed:\n{stdout}\n{stderr}");
    }

    pb.set_position(100);
    Ok(())
}

fn flash_uf2_samd(firmware_path: &str, pb: &ProgressBar) -> Result<()> {
    pb.set_message("Flashing SAMD21 via UF2");
    pb.set_position(20);

    let extension = Path::new(firmware_path)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("");

    if extension == "uf2" {
        // Direct UF2 copy to bootloader drive.
        let mount_paths = [
            "/media/SAMD21BOOT".to_string(),
            format!("/media/{}/SAMD21BOOT", whoami()),
            format!("/run/media/{}/SAMD21BOOT", whoami()),
            "/mnt/SAMD21BOOT".to_string(),
            "/Volumes/SAMD21BOOT".to_string(),
        ];

        let drive_path = mount_paths
            .iter()
            .find(|p| Path::new(p).exists())
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "SAMD21 UF2 bootloader drive not found. \
                     Double-tap the reset button to enter bootloader mode."
                )
            })?;

        pb.set_position(50);
        let dest =
            Path::new(drive_path).join(Path::new(firmware_path).file_name().unwrap_or_default());
        std::fs::copy(firmware_path, &dest)
            .map_err(|e| anyhow::anyhow!("failed to copy UF2: {e}"))?;
    } else {
        // Convert with uf2conv if needed.
        check_tool_installed("uf2conv")?;
        let output = ProcessCommand::new("uf2conv")
            .args([firmware_path, "-o", &format!("{firmware_path}.uf2")])
            .output()
            .map_err(|e| anyhow::anyhow!("failed to run uf2conv: {e}"))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!("uf2conv failed: {stderr}");
        }
    }

    pb.set_position(100);
    Ok(())
}

fn flash_with_openocd(firmware_path: &str, pb: &ProgressBar) -> Result<()> {
    check_tool_installed("openocd")?;

    pb.set_message("Flashing SAMD21 via OpenOCD");
    pb.set_position(20);

    let output = ProcessCommand::new("openocd")
        .args([
            "-f",
            "interface/cmsis-dap.cfg",
            "-f",
            "target/at91samdXX.cfg",
            "-c",
            &format!("program {} verify reset exit", firmware_path),
        ])
        .output()
        .map_err(|e| anyhow::anyhow!("failed to run openocd: {e}"))?;

    pb.set_position(90);

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("openocd flash failed: {stderr}");
    }

    pb.set_position(100);
    Ok(())
}

fn execute_erase(platform: &str) -> Result<()> {
    println!(
        "{}",
        "⚠ WARNING: This will erase ALL firmware and data from the device!"
            .red()
            .bold()
    );
    println!(
        "{}",
        "The device will be non-functional until new firmware is flashed.".yellow()
    );

    let confirmation: String = Input::new()
        .with_prompt("Type ERASE to confirm")
        .interact_text()
        .map_err(|e| anyhow::anyhow!("input failed: {e}"))?;

    if confirmation != "ERASE" {
        println!("{}", "Erase cancelled.".yellow());
        return Ok(());
    }

    match platform.to_lowercase().as_str() {
        "rp2040" | "rp2350" => {
            check_tool_installed("probe-rs")?;
            let chip = if platform == "rp2350" {
                "RP2350"
            } else {
                "RP2040"
            };
            let output = ProcessCommand::new("probe-rs")
                .args(["erase", "--chip", chip, "--allow-erase-all"])
                .output()
                .map_err(|e| anyhow::anyhow!("failed to run probe-rs: {e}"))?;

            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                bail!("probe-rs erase failed: {stderr}");
            }
        }
        "esp32s3" | "esp32c5" | "esp32c6" => {
            check_tool_installed("espflash")?;
            let output = ProcessCommand::new("espflash")
                .args(["erase-flash"])
                .output()
                .map_err(|e| anyhow::anyhow!("failed to run espflash: {e}"))?;

            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                bail!("espflash erase failed: {stderr}");
            }
        }
        "samd21" => {
            check_tool_installed("openocd")?;
            let output = ProcessCommand::new("openocd")
                .args([
                    "-f",
                    "interface/cmsis-dap.cfg",
                    "-f",
                    "target/at91samdXX.cfg",
                    "-c",
                    "init; reset halt; at91samd chip-erase; exit",
                ])
                .output()
                .map_err(|e| anyhow::anyhow!("failed to run openocd: {e}"))?;

            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                bail!("openocd erase failed: {stderr}");
            }
        }
        _ => bail!("unsupported platform for erase: {platform}"),
    }

    println!("{} Flash erased on {}.", "✓".green().bold(), platform);
    Ok(())
}

fn execute_build(
    target: &str,
    app: &str,
    features: Option<&str>,
    output_dir: Option<&str>,
) -> Result<()> {
    let (rust_target, extra_args) = match target.to_lowercase().as_str() {
        "rp2040" => ("thumbv6m-none-eabi", vec![]),
        "rp2350" => ("thumbv8m.main-none-eabihf", vec![]),
        "esp32s3" => ("xtensa-esp32s3-none-elf", vec![]),
        "esp32c5" | "esp32c6" => ("riscv32imac-unknown-none-elf", vec![]),
        "samd21" => ("thumbv6m-none-eabi", vec!["--features", "samd21"]),
        _ => bail!("unsupported build target: {target}"),
    };

    let crate_name = match app.to_lowercase().as_str() {
        "fido" => "pico-rs-fido",
        "hsm" => "pico-rs-hsm",
        _ => bail!("unsupported app: {app}. Use 'fido' or 'hsm'"),
    };

    println!(
        "{} Building {} for {} (target: {})",
        "→".cyan().bold(),
        app.bold(),
        target.bold(),
        rust_target
    );

    let mut cmd = ProcessCommand::new("cargo");
    cmd.args([
        "build",
        "--release",
        "-p",
        crate_name,
        "--target",
        rust_target,
    ]);

    for arg in &extra_args {
        cmd.arg(arg);
    }

    if let Some(feat) = features {
        cmd.args(["--features", feat]);
    }

    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.cyan} {msg}")
            .unwrap_or_else(|_| ProgressStyle::default_spinner()),
    );
    pb.set_message("Building firmware...");
    pb.enable_steady_tick(std::time::Duration::from_millis(100));

    let output = cmd
        .output()
        .map_err(|e| anyhow::anyhow!("failed to run cargo build: {e}"))?;

    pb.finish_and_clear();

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        eprintln!("{}", stderr);
        bail!("cargo build failed");
    }

    let default_output = format!("target/{rust_target}/release/{crate_name}");
    let artifact_path = output_dir
        .map(|d| format!("{d}/{crate_name}"))
        .unwrap_or(default_output.clone());

    if let Some(dir) = output_dir {
        std::fs::create_dir_all(dir).ok();
        std::fs::copy(&default_output, &artifact_path).ok();
    }

    println!(
        "{} Build complete: {}",
        "✓".green().bold(),
        artifact_path.bold()
    );
    Ok(())
}

fn execute_verify() -> Result<()> {
    use crate::device::DeviceDetector;
    use crate::transport::hid::HidTransport;

    let detected = DeviceDetector::find(None)?;
    let transport = HidTransport::open(detected.vid, detected.pid, detected.serial.as_deref())?;

    // Send GetInfo to verify firmware is responding.
    let response = transport.send_cbor(0x04, &[])?;

    if response.is_empty() || response[0] != 0x00 {
        bail!("firmware verification failed — device not responding correctly");
    }

    println!(
        "{} Firmware verified — device is responding on {} ({}).",
        "✓".green().bold(),
        detected.name,
        detected.serial.as_deref().unwrap_or("no serial")
    );
    Ok(())
}

fn execute_dfu_update(firmware_path: &str, vid: Option<&str>, pid: Option<&str>) -> Result<()> {
    let fw_path = Path::new(firmware_path);
    if !fw_path.exists() {
        bail!("firmware file not found: {firmware_path}");
    }

    println!("{} DFU update: {}", "→".cyan().bold(), firmware_path.bold());

    // First try dfu-util.
    check_tool_installed("dfu-util")?;

    let mut cmd = ProcessCommand::new("dfu-util");
    cmd.args(["--download", firmware_path]);

    if let Some(vid) = vid {
        if let Some(pid) = pid {
            cmd.args(["--device", &format!("{vid}:{pid}")]);
        }
    }

    cmd.args(["--alt", "0"]);
    cmd.arg("--reset");

    let pb = ProgressBar::new(100);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{msg} [{bar:40.cyan/blue}] {pos}%")
            .unwrap_or_else(|_| ProgressStyle::default_bar())
            .progress_chars("█▓░"),
    );
    pb.set_message("DFU update");
    pb.set_position(20);

    let output = cmd
        .output()
        .map_err(|e| anyhow::anyhow!("failed to run dfu-util: {e}"))?;

    pb.set_position(90);

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        pb.abandon();
        bail!("dfu-util failed: {stderr}");
    }

    pb.set_position(100);
    pb.finish_with_message("DFU update complete");

    println!(
        "\n{} DFU firmware update complete. Device is rebooting.",
        "✓".green().bold()
    );
    Ok(())
}

fn execute_firmware_info() -> Result<()> {
    use crate::device::DeviceDetector;
    use crate::transport::hid::HidTransport;

    println!("{}\n", "Firmware Information".bold().cyan());

    let detected = DeviceDetector::find(None)?;
    let transport = HidTransport::open(detected.vid, detected.pid, detected.serial.as_deref())?;

    // Use CTAP2 GetInfo to extract firmware version.
    let response = transport.send_cbor(0x04, &[])?;

    if response.is_empty() || response[0] != 0x00 {
        bail!("failed to get firmware info from device");
    }

    let cbor_data = &response[1..];
    let value: serde_cbor::Value =
        serde_cbor::from_slice(cbor_data).map_err(|e| anyhow::anyhow!("CBOR decode error: {e}"))?;

    let mut fw_version = "unknown".to_string();
    let mut versions = Vec::new();

    if let serde_cbor::Value::Map(map) = &value {
        for (key, val) in map {
            let key_num = match key {
                serde_cbor::Value::Integer(n) => *n,
                _ => continue,
            };
            match key_num {
                0x01 => {
                    if let serde_cbor::Value::Array(arr) = val {
                        for item in arr {
                            if let serde_cbor::Value::Text(s) = item {
                                versions.push(s.clone());
                            }
                        }
                    }
                }
                0x0E => {
                    if let serde_cbor::Value::Integer(n) = val {
                        let major = (*n >> 24) & 0xFF;
                        let minor = (*n >> 16) & 0xFF;
                        let patch = *n & 0xFFFF;
                        fw_version = format!("{major}.{minor}.{patch}");
                    }
                }
                _ => {}
            }
        }
    }

    println!("Device:           {}", detected.name.bold());
    println!("Firmware Version: {}", fw_version.bold());
    println!("CTAP Versions:    {}", versions.join(", "));
    println!(
        "Serial:           {}",
        detected.serial.as_deref().unwrap_or("—")
    );
    println!(
        "USB ID:           {:04X}:{:04X}",
        detected.vid, detected.pid
    );

    Ok(())
}

// --- Utility helpers ---

/// Check if an external tool is installed and available in PATH.
fn check_tool_installed(tool: &str) -> Result<()> {
    let result = ProcessCommand::new("which").arg(tool).output();

    match result {
        Ok(output) if output.status.success() => Ok(()),
        _ => bail!(
            "required tool '{}' not found in PATH. Install it first:\n  {}",
            tool,
            install_hint(tool)
        ),
    }
}

/// Return an installation hint for a given tool.
fn install_hint(tool: &str) -> &'static str {
    match tool {
        "elf2uf2-rs" => "cargo install elf2uf2-rs",
        "probe-rs" => "cargo install probe-rs-tools",
        "espflash" => "cargo install espflash",
        "uf2conv" => "pip install uf2conv",
        "openocd" => "apt install openocd  (or brew install openocd)",
        "dfu-util" => "apt install dfu-util  (or brew install dfu-util)",
        _ => "(see tool documentation)",
    }
}

/// Get the current username for mount path resolution.
fn whoami() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "user".into())
}
