#!/usr/bin/env bash
# scripts/vendor.sh — Manage vendored dependencies for offline / Zscaler-safe builds
#
# COMMANDS:
#   download   Fetch all crates into vendor/ and activate offline mode
#   enable     Activate vendor/ as crate source (skip download)
#   disable    Revert config to use crates.io (non-destructive — vendor/ kept)
#   update     cargo update + re-vendor          (requires internet)
#   status     Show current vendoring state
#
# HOW IT WORKS:
#   'download' runs 'cargo vendor' which stores unpacked crate sources in vendor/.
#   'enable'   appends a [source.crates-io] replacement block to .cargo/config.toml.
#   'disable'  removes that block so normal crates.io lookups resume.
#
# GETTING STARTED (machine with internet):
#   ./scripts/vendor.sh download
#   git add vendor/ && git commit -m "chore: vendor all dependencies"
#
# AFTER CLONING (machine without internet):
#   ./scripts/vendor.sh enable
#
# UPDATING DEPS (machine with internet):
#   ./scripts/vendor.sh update
#   git add vendor/ Cargo.lock && git commit -m "chore: update vendored deps"

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
VENDOR_DIR="$ROOT/vendor"
CARGO_CONFIG="$ROOT/.cargo/config.toml"
CARGO="${CARGO:-$(command -v cargo 2>/dev/null || echo cargo)}"

# Delimiter lines that wrap the vendor block inside .cargo/config.toml
MARKER_START="# --- vendor-start (managed by scripts/vendor.sh) ---"
MARKER_END="# --- vendor-end ---"

# ── helpers ───────────────────────────────────────────────────────────────────

die()  { printf "\nerror: %s\n" "$*" >&2; exit 1; }
info() { printf "  %s\n" "$*"; }
ok()   { printf "  ✓ %s\n" "$*"; }
step() { printf "\n==> %s\n" "$*"; }

vendor_is_enabled() {
    grep -qF "$MARKER_START" "$CARGO_CONFIG" 2>/dev/null
}

require_cmd() {
    command -v "$1" >/dev/null 2>&1 || die "'$1' not found on PATH. Please install it first."
}

# ── subcommands ───────────────────────────────────────────────────────────────

cmd_download() {
    require_cmd python3

    step "Vendoring all dependencies into vendor/ ..."
    cd "$ROOT"

    # cargo vendor prints the config TOML snippet to stdout; we discard that
    # because we write the config ourselves via cmd_enable.
    # Download progress and errors are on stderr and remain visible.
    #
    # --sync fuzz/Cargo.toml     : include the fuzz sub-workspace
    # --versioned-dirs           : name dirs as serde-1.0.217/ for cleaner git diffs
    "$CARGO" vendor \
        --sync fuzz/Cargo.toml \
        --versioned-dirs \
        vendor \
        > /dev/null

    local crate_count
    crate_count=$(find "$VENDOR_DIR" -maxdepth 1 -mindepth 1 -type d | wc -l | tr -d ' ')
    ok "Vendored $crate_count crates into vendor/"

    cmd_enable
}

cmd_enable() {
    require_cmd python3

    step "Enabling vendor source in .cargo/config.toml ..."

    if vendor_is_enabled; then
        info "Already enabled — nothing to do"
        return 0
    fi

    [ -d "$VENDOR_DIR" ] || die "vendor/ directory not found. Run './scripts/vendor.sh download' first."

    # Append the vendor source-replacement block.
    # The 'directory' path must be relative to the workspace root (where
    # .cargo/config.toml lives), which is "vendor".
    cat >> "$CARGO_CONFIG" <<EOF

$MARKER_START
[source.crates-io]
replace-with = "vendored-sources"

[source.vendored-sources]
directory = "vendor"
$MARKER_END
EOF

    ok "Offline vendoring active — crates.io replaced by vendor/"
    info "Tip: builds will now work without internet access"
}

cmd_disable() {
    require_cmd python3

    step "Disabling vendor source ..."

    if ! vendor_is_enabled; then
        info "Vendoring is not currently active — nothing to do"
        return 0
    fi

    # Use Python to strip everything between (and including) the two marker
    # lines.  Avoids sed portability issues with special characters in markers.
    python3 - "$CARGO_CONFIG" "$MARKER_START" "$MARKER_END" <<'PYEOF'
import sys, pathlib

path         = pathlib.Path(sys.argv[1])
start_marker = sys.argv[2].strip()
end_marker   = sys.argv[3].strip()

lines = path.read_text().splitlines()
out, skip = [], False

for line in lines:
    if line.strip() == start_marker:
        skip = True          # start dropping lines (inclusive)
    if not skip:
        out.append(line)
    if line.strip() == end_marker:
        skip = False         # stop dropping (the end marker itself is also dropped)

# Remove trailing blank lines left behind
while out and not out[-1].strip():
    out.pop()

path.write_text("\n".join(out) + "\n")
PYEOF

    ok "Vendor block removed from .cargo/config.toml"
    info "Builds will now use crates.io (vendor/ directory is kept intact)"
}

cmd_update() {
    step "Updating dependencies (internet required) ..."
    cd "$ROOT"

    # If vendoring is active, disable it so 'cargo update' and 'cargo vendor'
    # can reach crates.io.  Re-enable automatically when we are done.
    local was_enabled=false
    if vendor_is_enabled; then
        info "Temporarily disabling vendor source for the update ..."
        cmd_disable
        was_enabled=true
    fi

    # Ensure we re-enable vendor on unexpected exit if it was previously on
    if [[ "$was_enabled" == true ]]; then
        trap 'echo; info "Re-enabling vendor after unexpected exit ..."; cmd_enable' EXIT
    fi

    info "Running cargo update ..."
    "$CARGO" update
    ok "Cargo.lock refreshed"

    # Re-vendor using the new Cargo.lock
    cmd_download   # cmd_download calls cmd_enable at the end

    # Cancel the safety trap — cmd_download already called cmd_enable
    if [[ "$was_enabled" == true ]]; then
        trap - EXIT
    fi

    ok "Update complete — vendor/ and Cargo.lock are in sync"
    info "Commit both with: git add vendor/ Cargo.lock && git commit"
}

cmd_status() {
    echo ""
    if vendor_is_enabled; then
        ok "Vendoring: ENABLED"
        if [ -d "$VENDOR_DIR" ]; then
            local crate_count
            crate_count=$(find "$VENDOR_DIR" -maxdepth 1 -mindepth 1 -type d | wc -l | tr -d ' ')
            info "vendor/ contains $crate_count crate directories"
        else
            info "WARNING: vendor/ directory is missing — run './scripts/vendor.sh download'"
        fi
    else
        info "Vendoring: DISABLED (crates.io used for builds)"
        if [ -d "$VENDOR_DIR" ]; then
            local crate_count
            crate_count=$(find "$VENDOR_DIR" -maxdepth 1 -mindepth 1 -type d | wc -l | tr -d ' ')
            info "vendor/ exists ($crate_count crates) but is not active — run 'enable' to activate"
        else
            info "vendor/ directory does not exist — run 'download' to create it"
        fi
    fi
    echo ""
}

cmd_help() {
    cat <<'EOF'

Manage vendored Rust dependencies for offline builds.

Usage: ./scripts/vendor.sh <command>

Commands:
  download   Fetch all crates into vendor/ and activate offline mode
  enable     Activate vendor/ as crate source (no download, for post-clone use)
  disable    Revert .cargo/config.toml to use crates.io (vendor/ is kept)
  update     Run cargo update + re-vendor to match new Cargo.lock (needs internet)
  status     Show whether vendoring is currently active

Typical workflows:

  First time (machine with internet):
    ./scripts/vendor.sh download
    git add vendor/ Cargo.lock
    git commit -m "chore: vendor all dependencies"

  After cloning behind a proxy (no internet):
    ./scripts/vendor.sh enable
    cargo build ...   # uses vendor/ — no network needed

  Keeping deps up to date (machine with internet):
    ./scripts/vendor.sh update
    git add vendor/ Cargo.lock
    git commit -m "chore: update vendored deps to latest"

EOF
}

# ── main ──────────────────────────────────────────────────────────────────────

case "${1:-help}" in
    download) cmd_download ;;
    enable)   cmd_enable   ;;
    disable)  cmd_disable  ;;
    update)   cmd_update   ;;
    status)   cmd_status   ;;
    help|--help|-h) cmd_help ;;
    *) die "Unknown command: '${1}'. Run './scripts/vendor.sh help' for usage." ;;
esac
