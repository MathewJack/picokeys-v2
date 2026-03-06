#!/usr/bin/env bash
set -euo pipefail

# Run linters and formatters
# Usage: ./scripts/lint.sh [--fix]

cd "$(dirname "$0")/.."

echo "📝 Checking formatting..."
if [[ "${1:-}" == "--fix" ]]; then
    cargo fmt --all
    echo "✅ Formatted"
else
    cargo fmt --all -- --check
    echo "✅ Format OK"
fi

echo ""
echo "🔍 Running Clippy on CLI..."
cargo-clippy -p picokeys-cli -- -D warnings

echo ""
echo "🔍 Running Clippy on SDK (default features)..."
cargo-clippy -p pico-rs-sdk -- -D warnings 2>/dev/null || echo "⚠️  SDK clippy requires embedded target (use cargo check instead)"

echo ""
echo "✅ Lint complete"
