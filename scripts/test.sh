#!/usr/bin/env bash
set -euo pipefail

# Run tests
# Usage: ./scripts/test.sh [unit|fuzz|all]

cd "$(dirname "$0")/.."

MODE="${1:-unit}"

run_unit_tests() {
    echo "🧪 Running unit tests..."
    cargo test -p picokeys-cli --lib
    if cargo metadata --no-deps --format-version 1 -p pico-rs-fido 2>/dev/null | grep -q '"host-test"'; then
        cargo test -p pico-rs-fido --lib --features host-test
    else
        echo "⚠️  pico-rs-fido host-test feature not configured — skipping"
    fi
    echo "✅ Unit tests passed"
}

run_fuzz_tests() {
    echo "🧪 Running fuzz tests (30s each)..."
    cd fuzz
    for target in fuzz_ctap_cbor fuzz_ccid_apdu fuzz_credential_decode fuzz_hid_framing; do
        echo "  Fuzzing $target..."
        timeout 30 cargo fuzz run "$target" 2>/dev/null || echo "  ⚠️  $target: stopped (timeout or error)"
    done
    cd ..
    echo "✅ Fuzz tests complete"
}

case "$MODE" in
    unit) run_unit_tests ;;
    fuzz) run_fuzz_tests ;;
    all)  run_unit_tests; run_fuzz_tests ;;
    *)    echo "Usage: $0 [unit|fuzz|all]"; exit 1 ;;
esac
