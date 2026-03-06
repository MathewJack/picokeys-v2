#!/usr/bin/env bash
set -euo pipefail

# ============================================================================
# PicoKeys v2 — Generate Rust API Documentation
# ============================================================================
#
# Usage:
#   ./scripts/generate-docs.sh [--open] [--all-features]
#
# Generates rustdoc for all workspace crates. Output goes to target/doc/
#
# ============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_ROOT"

OPEN_FLAG=""
FEATURE_FLAG=""

for arg in "$@"; do
    case "$arg" in
        --open) OPEN_FLAG="--open" ;;
        --all-features) FEATURE_FLAG="--all-features" ;;
    esac
done

echo "📚 Generating Rust API documentation for PicoKeys v2..."
echo ""

# Generate docs for the CLI (host target, always works)
echo "  → picokeys-cli (host)..."
cargo doc -p picokeys-cli --no-deps $FEATURE_FLAG 2>/dev/null && echo "    ✅ picokeys-cli" || echo "    ⚠️  picokeys-cli failed (missing deps?)"

# Generate docs for embedded crates (may need target, try host first)
for crate in pico-rs-sdk pico-rs-fido pico-rs-hsm; do
    echo "  → $crate..."
    cargo doc -p "$crate" --no-deps $FEATURE_FLAG 2>/dev/null && echo "    ✅ $crate" || echo "    ⚠️  $crate failed (may need embedded target)"
done

echo ""
echo "📂 Documentation generated at: $PROJECT_ROOT/target/doc/"
echo ""
echo "Entry points:"
echo "  - target/doc/picokeys_cli/index.html"
echo "  - target/doc/pico_rs_sdk/index.html"
echo "  - target/doc/pico_rs_fido/index.html"
echo "  - target/doc/pico_rs_hsm/index.html"

if [ -n "$OPEN_FLAG" ]; then
    # Try to open in browser
    INDEX="$PROJECT_ROOT/target/doc/picokeys_cli/index.html"
    if [ -f "$INDEX" ]; then
        if command -v xdg-open &>/dev/null; then
            xdg-open "$INDEX"
        elif command -v wslview &>/dev/null; then
            wslview "$INDEX"
        elif command -v open &>/dev/null; then
            open "$INDEX"
        else
            echo "Open manually: file://$INDEX"
        fi
    fi
fi

echo ""
echo "🎉 Done!"
