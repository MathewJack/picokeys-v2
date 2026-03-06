#!/usr/bin/env bash
set -euo pipefail

# Flash firmware to a connected device
# Usage: ./scripts/flash.sh <platform> [--release]
#   platforms: rp2040, rp2350, esp32s3, esp32c5, esp32c6, samd21

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_ROOT"

PLATFORM="${1:?Usage: $0 <platform> [--release]}"
PROFILE="debug"
if [[ "${2:-}" == "--release" ]]; then
    PROFILE="release"
fi

case "$PLATFORM" in
    rp2040)
        ELF="target/thumbv6m-none-eabi/$PROFILE/picokeys-fido-rp2040"
        if [ ! -f "$ELF" ]; then
            echo "Binary not found. Building first..."
            "$SCRIPT_DIR/build.sh" rp2040 ${2:-}
        fi
        echo "🔌 Flashing RP2040 via probe-rs..."
        probe-rs run --chip RP2040 "$ELF"
        ;;
    rp2350)
        ELF="target/thumbv8m.main-none-eabihf/$PROFILE/picokeys-fido-rp2350"
        if [ ! -f "$ELF" ]; then
            "$SCRIPT_DIR/build.sh" rp2350 ${2:-}
        fi
        echo "🔌 Flashing RP2350 via probe-rs..."
        probe-rs run --chip RP2350 "$ELF"
        ;;
    esp32s3|esp32c5|esp32c6)
        echo "🔌 Flashing $PLATFORM via espflash..."
        TARGET_TRIPLE=$( [[ "$PLATFORM" == "esp32s3" ]] && echo "xtensa-esp32s3-none-elf" || echo "riscv32imac-unknown-none-elf" )
        ELF="target/$TARGET_TRIPLE/$PROFILE/picokeys-fido-$PLATFORM"
        if [ ! -f "$ELF" ]; then
            "$SCRIPT_DIR/build.sh" "$PLATFORM" ${2:-}
        fi
        espflash flash "$ELF" --monitor
        ;;
    samd21)
        ELF="target/thumbv6m-none-eabi/$PROFILE/picokeys-fido-samd21"
        if [ ! -f "$ELF" ]; then
            "$SCRIPT_DIR/build.sh" samd21 ${2:-}
        fi
        echo "🔌 Converting to UF2 and flashing SAMD21..."
        elf2uf2-rs "$ELF" "${ELF}.uf2"
        echo "Copy ${ELF}.uf2 to the SAMD21 USB mass storage device"
        ;;
    *)
        echo "Unknown platform: $PLATFORM"
        echo "Usage: $0 [rp2040|rp2350|esp32s3|esp32c5|esp32c6|samd21] [--release]"
        exit 1
        ;;
esac
