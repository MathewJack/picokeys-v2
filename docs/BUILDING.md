# Building PicoKeys v2

## Prerequisites

### Rust Toolchain

PicoKeys v2 requires **Rust nightly** (pinned to `nightly-2026-02-15` in `rust-toolchain.toml`).

```bash
# Automatic setup (installs everything)
./scripts/install-deps.sh

# Or manually:
rustup install nightly
rustup default nightly
rustup component add clippy rustfmt
```

### Embedded Targets

```bash
rustup target add thumbv6m-none-eabi          # RP2040, SAMD21
rustup target add thumbv8m.main-none-eabihf   # RP2350
rustup target add riscv32imac-unknown-none-elf # ESP32-C5, ESP32-C6
```

For **ESP32-S3** (Xtensa architecture), install `espup`:

```bash
cargo install espup
espup install
```

### System Dependencies

**Linux (Debian/Ubuntu):**
```bash
sudo apt install libusb-1.0-0-dev libudev-dev libpcsclite-dev pkg-config
```

**Linux (Arch):**
```bash
sudo pacman -S libusb pcsclite pkg-config
```

**macOS:**
```bash
brew install libusb pcsc-lite pkg-config
```

### Flashing Tools

```bash
cargo install probe-rs-tools   # RP2040, RP2350, SAMD21 (SWD)
cargo install espflash          # ESP32-S3, ESP32-C5, ESP32-C6
cargo install elf2uf2-rs        # UF2 conversion for drag-and-drop flashing
```

## Quick Build

Use the build script for convenient builds:

```bash
./scripts/build.sh cli              # Host CLI tool
./scripts/build.sh rp2040           # RP2040 firmware (debug)
./scripts/build.sh rp2350 --release # RP2350 firmware (release)
./scripts/build.sh all --release    # Everything
```

Or use cargo directly:

```bash
# CLI (runs on host)
cargo build -p picokeys-cli

# RP2040
cargo build -p pico-rs-fido --bin picokeys-fido-rp2040 \
    --target thumbv6m-none-eabi --features rp2040 --no-default-features

# RP2350
cargo build -p pico-rs-fido --bin picokeys-fido-rp2350 \
    --target thumbv8m.main-none-eabihf --features rp2350 --no-default-features

# ESP32-S3
cargo build -p pico-rs-fido --bin picokeys-fido-esp32s3 \
    --target xtensa-esp32s3-none-elf --features esp32s3 --no-default-features

# ESP32-C5
cargo build -p pico-rs-fido --bin picokeys-fido-esp32c5 \
    --target riscv32imac-unknown-none-elf --features esp32c5 --no-default-features

# ESP32-C6 (serial bridge)
cargo build -p pico-rs-fido --bin picokeys-fido-esp32c6 \
    --target riscv32imac-unknown-none-elf --features esp32c6 --no-default-features

# SAMD21 (no RSA/HSM due to 256 KB flash)
cargo build -p pico-rs-fido --bin picokeys-fido-samd21 \
    --target thumbv6m-none-eabi --features samd21 --no-default-features
```

## Release Builds

Release builds enable size optimization (`opt-level = "s"`), LTO, and single codegen unit:

```bash
./scripts/build.sh all --release
```

Output binaries are in `target/<triple>/release/`.

### UF2 Conversion (for drag-and-drop flashing)

```bash
# RP2040
elf2uf2-rs target/thumbv6m-none-eabi/release/picokeys-fido-rp2040 picokeys-rp2040.uf2

# RP2350
elf2uf2-rs target/thumbv8m.main-none-eabihf/release/picokeys-fido-rp2350 picokeys-rp2350.uf2
```

Then copy the `.uf2` file to the device's USB mass storage volume (hold BOOTSEL while connecting).

## Flashing

```bash
# Via the flash script (builds if needed)
./scripts/flash.sh rp2040 --release
./scripts/flash.sh esp32s3 --release

# Via probe-rs (RP2040/RP2350)
probe-rs run --chip RP2040 target/thumbv6m-none-eabi/release/picokeys-fido-rp2040
probe-rs run --chip RP2350 target/thumbv8m.main-none-eabihf/release/picokeys-fido-rp2350

# Via espflash (ESP32)
espflash flash target/xtensa-esp32s3-none-elf/release/picokeys-fido-esp32s3 --monitor
espflash flash target/riscv32imac-unknown-none-elf/release/picokeys-fido-esp32c6 --monitor
```

## Cross-Compilation Notes

### Feature Exclusivity

Only **one** platform feature can be active at a time. The features (`rp2040`, `rp2350`,
`esp32s3`, `esp32c5`, `esp32c6`, `samd21`) are mutually exclusive. Use `--no-default-features`
and specify exactly one.

### Linker Scripts

The `.cargo/config.toml` passes `-Tlink.x` for ARM targets. Platform-specific linker scripts
are provided by the HAL crates (`embassy-rp`, `atsamd-hal`).

### SAMD21 Constraints

SAMD21 has only 256 KB flash (32 KB reserved for storage). RSA and HSM are excluded to fit.
Only FIDO2 + OATH are available.

### ESP32-C6 Serial Bridge

The ESP32-C6 variant uses USB-Serial-JTAG only (no native USB OTG). It acts as a serial
bridge and requires a host-side serial↔HID adapter.

## Testing

```bash
# Unit tests (host-side)
./scripts/test.sh unit

# Fuzz tests (30s per target)
./scripts/test.sh fuzz

# Both
./scripts/test.sh all

# Linting
./scripts/lint.sh          # Check only
./scripts/lint.sh --fix    # Auto-format
```

## Troubleshooting

### `error: no matching package named embassy-rp`

Ensure you're on the correct nightly: `rustup show`. The pinned toolchain in
`rust-toolchain.toml` should be selected automatically.

### `error[E0463]: can't find crate for std`

You're building an embedded target. Use `--no-default-features` and select exactly one
platform feature.

### `error: linker cc not found` (ESP32-S3)

Xtensa requires the `espup`-installed toolchain. Run `source ~/export-esp.sh` or re-run
`espup install`.

### `probe-rs: No probe found`

- Check USB connection and permissions (`/etc/udev/rules.d/`)
- For RP2040/RP2350: ensure a debug probe is connected (picoprobe, CMSIS-DAP)
- Alternative: use UF2 drag-and-drop flashing

### `espflash: serial port not found`

- Check USB connection
- Add user to `dialout` group: `sudo usermod -a -G dialout $USER`
- Try specifying the port: `espflash flash --port /dev/ttyUSB0 ...`

### Build is slow

- First build downloads and compiles all dependencies (~5–10 minutes)
- Use `cargo build` (debug) for faster iteration
- Consider `sccache` for shared compilation cache
