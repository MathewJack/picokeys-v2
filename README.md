# PicoKeys v2

Rust-based security key firmware supporting FIDO2/CTAP2, OATH-TOTP/HOTP, and HSM functionality across multiple embedded platforms.

## Supported Platforms

| Platform | MCU | USB | Transport | Notes |
|----------|-----|-----|-----------|-------|
| RP2040 | ARM Cortex-M0+ (dual core, 133 MHz) | USB 1.1 FS | HID + CCID | No OTP fuses, MKEK in flash |
| RP2350 | ARM Cortex-M33 / RISC-V (dual core, 150 MHz) | USB 1.1 FS | HID + CCID | OTP fuses, ARM TrustZone, dedicated TRNG |
| ESP32-S3 | Xtensa LX7 (dual core, 240 MHz) | USB OTG FS | HID + CCID | eFuse MKEK, Secure Boot V2, HW bignum accelerator |
| ESP32-C5 | RISC-V (single core) | USB OTG FS | HID + CCID | eFuse MKEK, Secure Boot V2 |
| ESP32-C6 | RISC-V (single core, 160 MHz) | USB-Serial-JTAG | **Serial bridge only** | ⚠️ No native HID/CCID — CLI-only mode via serial |
| SAMD21 | ARM Cortex-M0+ (48 MHz) | USB FS | HID + CCID | 256 KB flash limit, no RSA, no HSM |

## Feature Matrix

| Feature | RP2040 | RP2350 | ESP32-S3 | ESP32-C5 | ESP32-C6 | SAMD21 |
|---------|--------|--------|----------|----------|----------|--------|
| FIDO2/CTAP2 | ✅ | ✅ | ✅ | ✅ | ✅¹ | ✅ |
| U2F/CTAP1 | ✅ | ✅ | ✅ | ✅ | ✅¹ | ✅ |
| OATH TOTP/HOTP | ✅ | ✅ | ✅ | ✅ | ✅¹ | ✅ |
| HSM (SmartCard-HSM) | ✅ | ✅ | ✅ | ✅ | ✅¹ | ❌² |
| RSA-2048/4096 | ✅ | ✅ | ✅ | ✅ | ✅¹ | ❌² |
| ECC (P-256, P-384, Ed25519) | ✅ | ✅ | ✅ | ✅ | ✅¹ | ✅ |
| Secure Boot | ❌ | ✅ | ✅ | ✅ | ✅ | ❌ |
| Hardware TRNG | ❌³ | ✅ | ✅ | ✅ | ✅ | ❌³ |
| Press-to-Confirm | ✅ | ✅ | ✅ | ✅ | ✅ | ✅⁴ |

¹ ESP32-C6: Serial bridge only — not usable as native FIDO2 authenticator in browsers; requires `picokeys-cli` host-side serial transport.  
² SAMD21: 256 KB flash constraint excludes RSA and HSM application.  
³ RP2040 uses ROSC-based entropy (weak); SAMD21 has limited TRNG.  
⁴ SAMD21: No BOOTSEL button; configurable GPIO, default simulated always-confirmed.

## Quick Start

### Prerequisites

```bash
# Install Rust nightly toolchain (see rust-toolchain.toml)
rustup show

# Install target for your platform
rustup target add thumbv6m-none-eabi          # RP2040, SAMD21
rustup target add thumbv8m.main-none-eabihf   # RP2350
rustup target add riscv32imac-unknown-none-elf # ESP32-C5, ESP32-C6

# For ESP32-S3 (Xtensa)
cargo install espup
espup install
```

### Build

```bash
# RP2040
cargo build --release -p pico-rs-fido --features rp2040

# RP2350
cargo build --release -p pico-rs-fido --features rp2350

# ESP32-S3
cargo build --release -p pico-rs-fido --features esp32s3

# ESP32-C5
cargo build --release -p pico-rs-fido --features esp32c5

# ESP32-C6 (serial bridge mode only)
cargo build --release -p pico-rs-fido --features esp32c6

# SAMD21 (FIDO2 + OATH only, no RSA/HSM)
cargo build --release -p pico-rs-fido --features samd21

# HSM application (not available on SAMD21)
cargo build --release -p pico-rs-hsm --features rp2350
```

### CLI Installation

```bash
cargo install --path picokeys-cli
picokeys-cli info
```

### Fuzz Testing

```bash
cargo install cargo-fuzz
cd fuzz
cargo fuzz run fuzz_ctap_cbor
cargo fuzz run fuzz_ccid_apdu
cargo fuzz run fuzz_credential_decode
cargo fuzz run fuzz_hid_framing
```

## Architecture

```
┌──────────────────────────────────────────────────────┐
│                   picokeys-cli                       │
│           (Host CLI — USB HID / CCID / Serial)       │
└──────────────┬───────────────────────┬───────────────┘
               │ USB HID              │ USB CCID
┌──────────────▼───────────┐ ┌────────▼───────────────┐
│      pico-rs-fido        │ │      pico-rs-hsm       │
│  ┌─────────────────────┐ │ │  ┌──────────────────┐  │
│  │ CTAP2 Command Router│ │ │  │ APDU Dispatcher  │  │
│  ├─────────────────────┤ │ │  ├──────────────────┤  │
│  │ MakeCredential      │ │ │  │ Key Management   │  │
│  │ GetAssertion        │ │ │  │ Crypto Ops       │  │
│  │ ClientPIN v1/v2     │ │ │  │ DKEK / Shamir    │  │
│  │ CredentialMgmt      │ │ │  │ Certificate Mgmt │  │
│  │ OATH TOTP/HOTP      │ │ │  │ Secure Messaging │  │
│  │ U2F Compat          │ │ │  │ PIN Management   │  │
│  └─────────────────────┘ │ │  └──────────────────┘  │
└──────────────┬───────────┘ └────────┬───────────────┘
               │                      │
┌──────────────▼──────────────────────▼───────────────┐
│                    pico-rs-sdk                       │
│  ┌──────────┐ ┌────────┐ ┌───────┐ ┌─────────────┐ │
│  │ Transport│ │ Crypto │ │Storage│ │ LED / Button│ │
│  │ HID+CCID │ │ AES,ECC│ │ Flash │ │ User Pres.  │ │
│  └────┬─────┘ │ RSA,Ed │ └───┬───┘ └──────┬──────┘ │
│       │       └────────┘     │             │        │
│  ┌────▼──────────────────────▼─────────────▼──────┐ │
│  │            Platform Adapters                    │ │
│  │  RP2040 │ RP2350 │ ESP32-S3 │ C5 │ C6 │ SAMD21│ │
│  └─────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────┘
```

## Security

See [SECURITY.md](SECURITY.md) for the full security policy, including:

- Key material protection (`zeroize` + `ZeroizeOnDrop`)
- Constant-time comparisons (`subtle::ConstantTimeEq`)
- Credential encryption (AES-256-GCM)
- PIN storage (PBKDF2-HMAC-SHA256, 256k iterations)
- Known advisory: RUSTSEC-2023-0071 (RSA Marvin Attack)
- Secure boot provisioning for RP2350 and ESP32
- Platform-specific security comparison

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT License ([LICENSE-MIT](LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

at your option.

## Contributing

Contributions are welcome! Please:

1. Fork the repository and create a feature branch
2. Ensure `cargo build` and `cargo test` pass for your target platform
3. Run `cargo clippy` with no warnings
4. Follow the existing code style — `zeroize` on all key material, `subtle` for secret comparisons
5. Open a Pull Request with a clear description of changes

For security-sensitive contributions, please review [SECURITY.md](SECURITY.md) before submitting.
