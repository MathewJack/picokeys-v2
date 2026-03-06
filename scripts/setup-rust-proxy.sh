#!/usr/bin/env bash
set -euo pipefail

# ============================================================================
# PicoKeys v2 — Rust Toolchain Setup for Corporate Proxy / WSL Environments
# ============================================================================
#
# This script provides workarounds for installing Rust (rustup + cargo) and
# downloading crates when behind a corporate proxy (e.g., Zscaler) that blocks
# static.crates.io or other Rust infrastructure.
#
# Usage:
#   ./scripts/setup-rust-proxy.sh [command]
#
# Commands:
#   install-rustup      Install rustup via standalone installer (no curl needed)
#   setup-proxy         Configure cargo/git proxy settings
#   setup-certs         Install Zscaler/corporate CA certificates
#   setup-mirror        Configure a sparse registry or alternative crate source
#   vendor-deps         Vendor all dependencies locally (offline builds)
#   diagnose            Check connectivity and diagnose proxy issues
#   all                 Run setup-proxy + setup-certs + setup-mirror
#
# ============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

info()  { echo -e "${BLUE}ℹ️  $*${NC}"; }
ok()    { echo -e "${GREEN}✅ $*${NC}"; }
warn()  { echo -e "${YELLOW}⚠️  $*${NC}"; }
err()   { echo -e "${RED}❌ $*${NC}"; }

# --------------------------------------------------------------------------
# 1. Install rustup without curl (standalone installer method)
# --------------------------------------------------------------------------
install_rustup() {
    info "Installing Rust toolchain (standalone method)..."

    if command -v rustup &>/dev/null; then
        ok "rustup is already installed: $(rustup --version)"
        return 0
    fi

    # Method A: Try apt (Debian/Ubuntu may have rustup packaged)
    if command -v apt &>/dev/null; then
        info "Trying apt install rustup..."
        if sudo apt-get update -qq && sudo apt-get install -y -qq rustup 2>/dev/null; then
            rustup default stable
            ok "rustup installed via apt"
            return 0
        fi
        warn "apt method failed, trying alternatives..."
    fi

    # Method B: Download rustup-init manually
    # If wget works but curl doesn't (some proxies behave differently)
    RUSTUP_URL="https://static.rust-lang.org/rustup/dist/x86_64-unknown-linux-gnu/rustup-init"
    RUSTUP_INIT="/tmp/rustup-init"

    if command -v wget &>/dev/null; then
        info "Downloading rustup-init via wget..."
        if wget -q --no-check-certificate "$RUSTUP_URL" -O "$RUSTUP_INIT" 2>/dev/null; then
            chmod +x "$RUSTUP_INIT"
            "$RUSTUP_INIT" -y --default-toolchain nightly
            ok "rustup installed via wget"
            source "$HOME/.cargo/env"
            return 0
        fi
        warn "wget download failed"
    fi

    if command -v curl &>/dev/null; then
        info "Downloading rustup-init via curl..."
        if curl -fsSLk "$RUSTUP_URL" -o "$RUSTUP_INIT" 2>/dev/null; then
            chmod +x "$RUSTUP_INIT"
            "$RUSTUP_INIT" -y --default-toolchain nightly
            ok "rustup installed via curl"
            source "$HOME/.cargo/env"
            return 0
        fi
        warn "curl download failed"
    fi

    # Method C: Standalone tarball (fully offline if pre-downloaded)
    echo ""
    warn "Automatic download failed. Manual offline installation steps:"
    echo ""
    echo "  1. On a machine WITH internet, download the standalone installer:"
    echo "     https://forge.rust-lang.org/infra/other-installation-methods.html"
    echo ""
    echo "     Direct link (x86_64 Linux):"
    echo "     https://static.rust-lang.org/dist/rust-nightly-x86_64-unknown-linux-gnu.tar.xz"
    echo ""
    echo "  2. Copy the tarball to this WSL environment"
    echo ""
    echo "  3. Extract and install:"
    echo "     tar -xf rust-nightly-x86_64-unknown-linux-gnu.tar.xz"
    echo "     cd rust-nightly-x86_64-unknown-linux-gnu"
    echo "     sudo ./install.sh"
    echo ""
    echo "  4. For rustup itself (optional, gives channel management):"
    echo "     Download rustup-init from: https://rustup.rs"
    echo "     chmod +x rustup-init && ./rustup-init -y"
    echo ""
    echo "  Alternative: Use Docker image 'rust:latest' for a pre-configured environment"
    echo ""
    return 1
}

# --------------------------------------------------------------------------
# 2. Configure cargo & git proxy settings
# --------------------------------------------------------------------------
setup_proxy() {
    info "Configuring proxy settings..."

    # Auto-detect proxy from common environment variables
    PROXY="${https_proxy:-${HTTPS_PROXY:-${http_proxy:-${HTTP_PROXY:-}}}}"

    if [ -z "$PROXY" ]; then
        warn "No proxy environment variable detected (http_proxy, https_proxy)"
        echo ""
        echo "  If you're behind a corporate proxy, set these in ~/.bashrc:"
        echo "    export http_proxy=\"http://proxy.company.com:8080\""
        echo "    export https_proxy=\"http://proxy.company.com:8080\""
        echo "    export no_proxy=\"localhost,127.0.0.1\""
        echo ""
        echo "  Then re-run this script."
        return 0
    fi

    info "Detected proxy: $PROXY"

    # Configure cargo
    CARGO_CONFIG="$HOME/.cargo/config.toml"
    mkdir -p "$HOME/.cargo"

    if grep -q '\[http\]' "$CARGO_CONFIG" 2>/dev/null; then
        warn "Cargo HTTP config already exists in $CARGO_CONFIG"
        echo "  Review manually: $CARGO_CONFIG"
    else
        cat >> "$CARGO_CONFIG" <<EOF

# Corporate proxy settings (added by setup-rust-proxy.sh)
[http]
proxy = "$PROXY"
check-revoke = false
timeout = 60

[net]
retry = 5
git-fetch-with-cli = true
EOF
        ok "Cargo proxy configured in $CARGO_CONFIG"
    fi

    # Configure git
    if ! git config --global http.proxy &>/dev/null; then
        git config --global http.proxy "$PROXY"
        git config --global https.proxy "$PROXY"
        ok "Git proxy configured"
    else
        warn "Git proxy already set: $(git config --global http.proxy)"
    fi
}

# --------------------------------------------------------------------------
# 3. Install corporate CA certificates (Zscaler, etc.)
# --------------------------------------------------------------------------
setup_certs() {
    info "Setting up corporate CA certificates..."

    # Check common locations for corporate CA certs
    CERT_FOUND=false
    for cert_path in \
        /usr/local/share/ca-certificates/zscaler*.crt \
        /etc/ssl/certs/zscaler*.pem \
        "$HOME/.local/share/ca-certificates/"*.crt \
        /mnt/c/Users/*/zscaler*.crt; do
        if [ -f "$cert_path" ] 2>/dev/null; then
            info "Found certificate: $cert_path"
            CERT_FOUND=true
            break
        fi
    done

    if [ "$CERT_FOUND" = false ]; then
        echo ""
        warn "No corporate CA certificate found automatically."
        echo ""
        echo "  To fix SSL/TLS errors with Zscaler or similar proxies:"
        echo ""
        echo "  1. Export your corporate root CA cert from your browser:"
        echo "     - Open browser → Settings → Certificates → Authorities"
        echo "     - Find 'Zscaler Root CA' (or your company's CA)"
        echo "     - Export as PEM/CRT format"
        echo ""
        echo "  2. Install it in WSL:"
        echo "     sudo cp your-corp-ca.crt /usr/local/share/ca-certificates/"
        echo "     sudo update-ca-certificates"
        echo ""
        echo "  3. Tell cargo/git about it:"
        echo "     export SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt"
        echo "     # Or in ~/.cargo/config.toml:"
        echo "     # [http]"
        echo "     # cainfo = \"/etc/ssl/certs/ca-certificates.crt\""
        echo ""
        return 0
    fi

    # If cert found, ensure it's installed system-wide
    if command -v update-ca-certificates &>/dev/null; then
        sudo update-ca-certificates 2>/dev/null || true
        ok "CA certificates updated"
    fi

    # Tell cargo where to find certs
    if [ -f /etc/ssl/certs/ca-certificates.crt ]; then
        export SSL_CERT_FILE="/etc/ssl/certs/ca-certificates.crt"
        export CARGO_HTTP_CAINFO="/etc/ssl/certs/ca-certificates.crt"

        if ! grep -q "SSL_CERT_FILE" "$HOME/.bashrc" 2>/dev/null; then
            echo 'export SSL_CERT_FILE="/etc/ssl/certs/ca-certificates.crt"' >> "$HOME/.bashrc"
            echo 'export CARGO_HTTP_CAINFO="/etc/ssl/certs/ca-certificates.crt"' >> "$HOME/.bashrc"
            ok "Certificate env vars added to ~/.bashrc"
        fi
    fi
}

# --------------------------------------------------------------------------
# 4. Configure alternative crate source / sparse registry
# --------------------------------------------------------------------------
setup_mirror() {
    info "Configuring crate source alternatives..."

    CARGO_CONFIG="$HOME/.cargo/config.toml"
    mkdir -p "$HOME/.cargo"

    # Use sparse registry protocol (often works better behind proxies)
    # Sparse protocol uses HTTPS for individual crate lookups instead of
    # cloning the entire crates.io-index git repository
    if grep -q 'sparse+https' "$CARGO_CONFIG" 2>/dev/null; then
        warn "Sparse registry already configured"
    else
        cat >> "$CARGO_CONFIG" <<'EOF'

# Use sparse registry protocol (better behind proxies)
# This avoids cloning the full crates.io-index git repo
[registries.crates-io]
protocol = "sparse"

# If static.crates.io is blocked, try these alternatives:
# Option 1: Use dl.cloudsmith.io mirror
# [source.crates-io]
# replace-with = "cloudsmith"
# [source.cloudsmith]
# registry = "sparse+https://dl.cloudsmith.io/public/nicira/crates-io/cargo/"
#
# Option 2: Use a local vendored copy (run: cargo vendor)
# [source.crates-io]
# replace-with = "vendored-sources"
# [source.vendored-sources]
# directory = "vendor"
EOF
        ok "Sparse registry protocol configured"
    fi

    echo ""
    info "If crate downloads still fail, try vendoring dependencies:"
    echo "  cd $PROJECT_ROOT && cargo vendor"
    echo "  This downloads all crates to a local 'vendor/' directory."
    echo "  Then uncomment the vendored-sources section in ~/.cargo/config.toml"
}

# --------------------------------------------------------------------------
# 5. Vendor all dependencies locally
# --------------------------------------------------------------------------
vendor_deps() {
    info "Vendoring all dependencies for offline builds..."
    cd "$PROJECT_ROOT"

    if cargo vendor vendor/ 2>/dev/null; then
        ok "Dependencies vendored to $PROJECT_ROOT/vendor/"
        echo ""
        echo "To use vendored dependencies, add to .cargo/config.toml:"
        echo '  [source.crates-io]'
        echo '  replace-with = "vendored-sources"'
        echo '  [source.vendored-sources]'
        echo '  directory = "vendor"'
    else
        warn "Vendoring failed (network issue). Try on a machine with internet access:"
        echo "  1. Clone this repo on a connected machine"
        echo "  2. Run: cargo vendor vendor/"
        echo "  3. Copy the vendor/ directory to this environment"
        echo "  4. Add the config above to .cargo/config.toml"
    fi
}

# --------------------------------------------------------------------------
# 6. Diagnose connectivity
# --------------------------------------------------------------------------
diagnose() {
    info "Diagnosing Rust/Cargo connectivity..."
    echo ""

    # Check tools
    for cmd in cargo rustc rustup git curl wget; do
        if command -v "$cmd" &>/dev/null; then
            ok "$cmd: $($cmd --version 2>/dev/null | head -1)"
        else
            err "$cmd: NOT FOUND"
        fi
    done
    echo ""

    # Check proxy
    for var in http_proxy https_proxy HTTP_PROXY HTTPS_PROXY no_proxy; do
        val="${!var:-<not set>}"
        echo "  $var = $val"
    done
    echo ""

    # Check connectivity
    info "Testing connectivity to Rust infrastructure..."
    for url in \
        "https://crates.io" \
        "https://static.crates.io" \
        "https://static.rust-lang.org" \
        "https://index.crates.io"; do
        status=$(curl -sSo /dev/null -w "%{http_code}" --connect-timeout 5 -k "$url" 2>/dev/null || echo "FAIL")
        if [ "$status" = "200" ] || [ "$status" = "301" ] || [ "$status" = "302" ]; then
            ok "$url → HTTP $status"
        else
            err "$url → HTTP $status (BLOCKED)"
        fi
    done
    echo ""

    # Check cargo config
    CARGO_CONFIG="$HOME/.cargo/config.toml"
    if [ -f "$CARGO_CONFIG" ]; then
        info "Cargo config ($CARGO_CONFIG):"
        cat "$CARGO_CONFIG" | grep -v '^#' | grep -v '^$' | head -20
    else
        warn "No cargo config found at $CARGO_CONFIG"
    fi
}

# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------
CMD="${1:-help}"

case "$CMD" in
    install-rustup)  install_rustup ;;
    setup-proxy)     setup_proxy ;;
    setup-certs)     setup_certs ;;
    setup-mirror)    setup_mirror ;;
    vendor-deps)     vendor_deps ;;
    diagnose)        diagnose ;;
    all)
        setup_proxy
        echo ""
        setup_certs
        echo ""
        setup_mirror
        echo ""
        diagnose
        ;;
    help|--help|-h)
        echo "PicoKeys v2 — Rust Proxy/Offline Setup Helper"
        echo ""
        echo "Usage: $0 <command>"
        echo ""
        echo "Commands:"
        echo "  install-rustup   Install rustup (tries apt/wget/curl, prints offline guide)"
        echo "  setup-proxy      Configure cargo & git proxy from env vars"
        echo "  setup-certs      Install corporate CA certificates for SSL"
        echo "  setup-mirror     Configure sparse registry or crate mirrors"
        echo "  vendor-deps      Vendor all crates locally for offline builds"
        echo "  diagnose         Test connectivity to Rust infrastructure"
        echo "  all              Run setup-proxy + setup-certs + setup-mirror + diagnose"
        echo ""
        echo "Quick start behind a proxy:"
        echo "  export https_proxy=http://proxy:8080"
        echo "  $0 all"
        ;;
    *)
        err "Unknown command: $CMD"
        echo "Run '$0 help' for usage"
        exit 1
        ;;
esac
