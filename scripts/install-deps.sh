#!/usr/bin/env bash
set -euo pipefail

# Install all required toolchains and dependencies for PicoKeys v2
# Usage: ./scripts/install-deps.sh

echo "📦 Installing PicoKeys v2 dependencies..."
echo ""

# 1. Rust toolchain
echo "=== Rust Toolchain ==="
if ! command -v rustup &>/dev/null; then
    echo "Installing rustup..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source "$HOME/.cargo/env"
fi

echo "Setting up nightly toolchain..."
rustup install nightly
rustup default nightly

# 2. Embedded targets
echo ""
echo "=== Embedded Targets ==="
rustup target add thumbv6m-none-eabi          # RP2040, SAMD21
rustup target add thumbv8m.main-none-eabihf   # RP2350
rustup target add riscv32imac-unknown-none-elf # ESP32-C5, ESP32-C6

# 3. ESP32-S3 (Xtensa) requires espup
echo ""
echo "=== ESP32-S3 Xtensa Support ==="
if ! command -v espup &>/dev/null; then
    echo "Installing espup..."
    cargo install espup
fi
echo "Running espup install..."
espup install || echo "⚠️  espup install failed (may need manual setup for Xtensa)"

# 4. Host tools
echo ""
echo "=== Host Tools ==="
for tool in cargo-fuzz probe-rs-tools elf2uf2-rs espflash cargo-bloat; do
    bin_name="${tool}"
    # Map crate name to binary name where they differ
    case "$tool" in
        probe-rs-tools) bin_name="probe-rs" ;;
    esac
    if command -v "$bin_name" >/dev/null 2>&1; then
        echo "  ✅ $tool already installed"
    else
        echo "  Installing $tool..."
        cargo install "$tool" || echo "  ⚠️  Failed to install $tool (network or build error)"
    fi
done

# 5. Clippy and rustfmt
echo ""
echo "=== Rust Components ==="
rustup component add clippy rustfmt

# 6. System dependencies (Linux)
echo ""
echo "=== System Dependencies ==="
if command -v apt &>/dev/null; then
    echo "Installing system packages (requires sudo)..."
    sudo apt-get update -qq
    sudo apt-get install -y -qq libusb-1.0-0-dev libudev-dev libpcsclite-dev pkg-config
elif command -v pacman &>/dev/null; then
    sudo pacman -S --noconfirm libusb pcsclite pkg-config
elif command -v brew &>/dev/null; then
    brew install libusb pcsc-lite pkg-config
else
    echo "⚠️  Unknown package manager. Please install manually:"
    echo "    libusb, pcsclite (pcsc-lite), pkg-config"
fi

# 7. Download workspace dependencies
echo ""
echo "=== Downloading Crate Dependencies ==="
cd "$(dirname "$0")/.."
cargo fetch

echo ""
echo "🎉 All dependencies installed successfully!"
echo ""
echo "Quick start:"
echo "  ./scripts/build.sh cli          # Build the CLI tool"
echo "  ./scripts/build.sh rp2040       # Build RP2040 firmware"
echo "  ./scripts/build.sh all --release # Build everything (release)"
