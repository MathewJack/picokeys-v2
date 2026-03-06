#!/usr/bin/env bash
set -euo pipefail

# Build PicoKeys v2 firmware and CLI
# Usage: ./scripts/build.sh [target] [--release]
#   targets: rp2040, rp2350, esp32s3, esp32c5, esp32c6, samd21, cli, all
#   --release: build in release mode (default: debug)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_ROOT"

TARGET="${1:-all}"
RELEASE_FLAG=""
PROFILE="debug"
if [[ "${2:-}" == "--release" ]] || [[ "${1:-}" == "--release" ]]; then
    RELEASE_FLAG="--release"
    PROFILE="release"
fi

build_rp2040() {
    echo "🔨 Building pico-rs-fido for RP2040..."
    cargo build -p pico-rs-fido --bin picokeys-fido-rp2040 \
        --target thumbv6m-none-eabi --features rp2040 --no-default-features $RELEASE_FLAG
    echo "✅ RP2040 build complete: target/thumbv6m-none-eabi/$PROFILE/picokeys-fido-rp2040"
}

build_rp2350() {
    echo "🔨 Building pico-rs-fido for RP2350..."
    cargo build -p pico-rs-fido --bin picokeys-fido-rp2350 \
        --target thumbv8m.main-none-eabihf --features rp2350 --no-default-features $RELEASE_FLAG
    echo "✅ RP2350 build complete: target/thumbv8m.main-none-eabihf/$PROFILE/picokeys-fido-rp2350"
}

build_esp32s3() {
    echo "🔨 Building pico-rs-fido for ESP32-S3..."
    cargo build -p pico-rs-fido --bin picokeys-fido-esp32s3 \
        --target xtensa-esp32s3-none-elf --features esp32s3 --no-default-features $RELEASE_FLAG
    echo "✅ ESP32-S3 build complete"
}

build_esp32c5() {
    echo "🔨 Building pico-rs-fido for ESP32-C5..."
    cargo build -p pico-rs-fido --bin picokeys-fido-esp32c5 \
        --target riscv32imac-unknown-none-elf --features esp32c5 --no-default-features $RELEASE_FLAG
    echo "✅ ESP32-C5 build complete"
}

build_esp32c6() {
    echo "🔨 Building pico-rs-fido for ESP32-C6 (serial-bridge)..."
    cargo build -p pico-rs-fido --bin picokeys-fido-esp32c6 \
        --target riscv32imac-unknown-none-elf --features esp32c6 --no-default-features $RELEASE_FLAG
    echo "✅ ESP32-C6 build complete"
}

build_samd21() {
    echo "🔨 Building pico-rs-fido for SAMD21 (no RSA/HSM)..."
    cargo build -p pico-rs-fido --bin picokeys-fido-samd21 \
        --target thumbv6m-none-eabi --features samd21 --no-default-features $RELEASE_FLAG
    echo "✅ SAMD21 build complete"
}

build_cli() {
    echo "🔨 Building picokeys-cli..."
    cargo build -p picokeys-cli $RELEASE_FLAG
    echo "✅ CLI build complete: target/$PROFILE/picokeys-cli"
}

case "$TARGET" in
    rp2040)   build_rp2040 ;;
    rp2350)   build_rp2350 ;;
    esp32s3)  build_esp32s3 ;;
    esp32c5)  build_esp32c5 ;;
    esp32c6)  build_esp32c6 ;;
    samd21)   build_samd21 ;;
    cli)      build_cli ;;
    all)
        build_cli
        build_rp2040
        build_rp2350
        build_esp32s3
        build_esp32c5
        build_esp32c6
        build_samd21
        echo ""
        echo "🎉 All builds complete!"
        ;;
    *)
        echo "Unknown target: $TARGET"
        echo "Usage: $0 [rp2040|rp2350|esp32s3|esp32c5|esp32c6|samd21|cli|all] [--release]"
        exit 1
        ;;
esac
