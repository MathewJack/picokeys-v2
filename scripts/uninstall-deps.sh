#!/usr/bin/env bash
set -euo pipefail

# Remove all cargo-installed tools and cached dependencies
# Usage: ./scripts/uninstall-deps.sh [--confirm]

if [[ "${1:-}" != "--confirm" ]]; then
    echo "⚠️  This will remove:"
    echo "  - cargo-fuzz, probe-rs, elf2uf2-rs, espflash, cargo-bloat"
    echo "  - espup and Xtensa toolchain"
    echo "  - Embedded Rust targets"
    echo "  - Cargo registry cache for this project"
    echo ""
    echo "Run with --confirm to proceed:"
    echo "  $0 --confirm"
    exit 0
fi

echo "🗑️  Uninstalling PicoKeys v2 dependencies..."

# Remove cargo-installed tools
for tool in cargo-fuzz probe-rs-tools elf2uf2-rs espflash cargo-bloat espup; do
    echo "  Removing $tool..."
    cargo uninstall "$tool" 2>/dev/null || echo "    $tool not found"
done

# Remove Xtensa toolchain
if command -v espup &>/dev/null; then
    echo "  Removing Xtensa toolchain..."
    espup uninstall 2>/dev/null || true
fi

# Remove embedded targets
echo "  Removing embedded targets..."
rustup target remove thumbv6m-none-eabi 2>/dev/null || true
rustup target remove thumbv8m.main-none-eabihf 2>/dev/null || true
rustup target remove riscv32imac-unknown-none-elf 2>/dev/null || true

# Clean project build artifacts
echo "  Cleaning build artifacts..."
cd "$(dirname "$0")/.."
cargo clean 2>/dev/null || true

echo ""
echo "✅ Uninstall complete"
echo "Note: Rust toolchain itself was NOT removed. Use 'rustup self uninstall' if needed."
