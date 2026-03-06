#!/usr/bin/env bash
set -euo pipefail

# Clean build artifacts and caches
# Usage: ./scripts/clean.sh [--deep]

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_ROOT"

echo "🧹 Cleaning build artifacts..."
cargo clean
echo "✅ Build artifacts cleaned"

if [[ "${1:-}" == "--deep" ]]; then
    echo "🧹 Deep clean: removing Cargo registry cache..."

    # Remove registry cache for this project's dependencies
    if [ -d "$HOME/.cargo/registry/cache" ]; then
        echo "  Clearing registry cache..."
        rm -rf "$HOME/.cargo/registry/cache"
    fi

    if [ -d "$HOME/.cargo/registry/src" ]; then
        echo "  Clearing registry source..."
        rm -rf "$HOME/.cargo/registry/src"
    fi

    # Remove git checkout cache
    if [ -d "$HOME/.cargo/git/checkouts" ]; then
        echo "  Clearing git checkouts..."
        rm -rf "$HOME/.cargo/git/checkouts"
    fi

    echo "✅ Deep clean complete (registry caches removed)"
    echo "⚠️  Next build will re-download all dependencies"
fi
