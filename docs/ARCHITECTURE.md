# PicoKeys v2 Architecture

## Overview

PicoKeys v2 is a multi-platform hardware security key firmware written in Rust, supporting
FIDO2/WebAuthn, OATH TOTP/HOTP, and SmartCard-HSM functionality. It runs on six embedded
platforms and ships with a host-side CLI management tool.

## Workspace Layout

```
picokeys-v2/
├── pico-rs-sdk/       # Core SDK — platform abstraction, crypto, storage, transport
├── pico-rs-fido/      # FIDO2/CTAP2, U2F, and OATH application firmware
├── pico-rs-hsm/       # SmartCard-HSM APDU application
├── picokeys-cli/      # Host-side CLI tool (Linux/macOS/Windows)
├── fuzz/              # Fuzz testing targets
├── scripts/           # Build, flash, lint, and test utilities
├── tests/             # Host-side integration test stubs
└── docs/              # This documentation
```

## Dependency Graph

```
picokeys-cli  (standalone — communicates with device over USB HID / CCID)

pico-rs-fido ──► pico-rs-sdk
pico-rs-hsm  ──► pico-rs-sdk
```

Both `pico-rs-fido` and `pico-rs-hsm` depend on `pico-rs-sdk` for platform abstraction,
crypto primitives, storage, and transport. The `picokeys-cli` crate is independent and
communicates with the device over USB HID (CTAPHID) and CCID (PC/SC smart card).

## Crate Responsibilities

### `pico-rs-sdk` — Core SDK

The foundation layer providing:

| Module | Purpose |
|--------|---------|
| `platform` | `Platform` trait + per-MCU adapters (RP2040, RP2350, ESP32-S3, ESP32-C5, ESP32-C6, SAMD21) |
| `crypto` | ECC (P-256/384/521/K256/Ed25519/X25519), RSA (1024–4096), AES-GCM/CBC, HMAC, PBKDF2, SHA |
| `store` | `FileStore` trait backed by `sequential-storage` on NOR flash, `SecureStorage` for OTP |
| `transport` | HID (CTAPHID, 64-byte reports) and CCID (ISO 7816 smart card) transports |
| `apdu` | APDU command/response parsing (CLA/INS/P1/P2), AID routing, command chaining |
| `led` | LED controller with blink patterns (Idle, Active, Processing, PressToConfirm) |
| `button` | User presence detection via `PresenceDetector` state machine |
| `rescue` | Rescue/recovery mode detection at boot |
| `eac` | Extended Access Control support |

**Key Traits:**

```rust
pub trait Platform {
    type Flash: embedded_storage::nor_flash::NorFlash;
    type Rng: rand_core::RngCore + rand_core::CryptoRng;
    type Led: LedDriver;
    type Button: ButtonReader;
}

pub trait FileStore {
    async fn read_file(&mut self, fid: FileId, buf: &mut [u8]) -> Result<usize, StoreError>;
    async fn write_file(&mut self, fid: FileId, data: &[u8]) -> Result<(), StoreError>;
    async fn delete_file(&mut self, fid: FileId) -> Result<(), StoreError>;
    async fn exists(&mut self, fid: FileId) -> bool;
}

pub trait LedDriver {
    fn set_on(&mut self);
    fn set_off(&mut self);
    fn set_color(&mut self, color: LedColor);
}

pub trait ButtonReader {
    fn is_pressed(&mut self) -> bool;
}

pub trait Transport {
    async fn recv(&mut self, buf: &mut [u8]) -> Result<usize, TransportError>;
    async fn send(&mut self, data: &[u8]) -> Result<(), TransportError>;
    async fn send_keepalive(&mut self, status: u8) -> Result<(), TransportError>;
}
```

### `pico-rs-fido` — FIDO2 + OATH Firmware

Application-level firmware implementing:

- **FIDO2/CTAP2**: MakeCredential, GetAssertion, GetInfo, ClientPIN, Reset,
  CredentialManagement, Selection, LargeBlobs, Config
- **CTAP1/U2F**: Register, Authenticate, Version (backward compatibility)
- **OATH (YKOATH)**: TOTP/HOTP credential management (PUT, DELETE, LIST, CALCULATE)
- **Management**: YubiKey-compatible management applet (AID `A0 00 00 05 27 47 11 17`)
- **Extensions**: cred_blob, cred_protect, hmac_secret, large_blob_key, min_pin_length

Each platform has a dedicated binary entry point (`src/bin/<platform>.rs`) that initializes
hardware, sets up the Embassy async executor, and routes USB traffic to the FIDO/OATH handlers.

### `pico-rs-hsm` — SmartCard-HSM

ISO 7816 APDU-based hardware security module:

- **Key Management**: Generate, import, export, wrap/unwrap (AES-256-GCM)
- **Cryptographic Operations**: ECDSA, EdDSA, RSA PKCS#1 v1.5, RSA-PSS, RSA-OAEP, ECDH, AES
- **DKEK**: Device Key Encryption Key with Shamir n-of-m secret sharing over GF(256)
- **PIN**: Verification, retry counter (8 attempts), PUK reset
- **PKCS#15**: File system abstraction for key/cert storage
- **Certificates**: X.509 certificate storage and retrieval

HSM AID: `E8 2B 06 01 04 01 81 C3 1F 02 01`

### `picokeys-cli` — Host CLI

Management tool using `clap` for argument parsing:

| Command | Description |
|---------|-------------|
| `info` | Device firmware version, serial, capabilities |
| `fido` | FIDO2 credential management, PIN, reset, backup |
| `oath` | OATH TOTP/HOTP add, list, calculate, delete |
| `otp` | YubiKey-compatible OTP slot configuration |
| `hsm` | SmartCard-HSM key generation, signing, DKEK management |
| `config` | LED, button, USB identifier configuration |
| `firmware` | Flash, update, OTP provisioning |

Communicates via `hidapi` (USB HID) and `pcsc` (PC/SC smart card reader).

## Platform Abstraction

Each platform implements the `Platform` trait, providing MCU-specific drivers:

| Platform | CPU | Flash | RNG | LED | OTP | Notes |
|----------|-----|-------|-----|-----|-----|-------|
| RP2040 | Cortex-M0+ 133 MHz | 2 MB QSPI (128 KB storage) | ROSC jitter | GPIO25 | Flash-wrapped | Pico/Pico W |
| RP2350 | Cortex-M33 150 MHz | 4 MB QSPI (128 KB storage) | TRNG (CryptoCell-312) | GPIO25 | Hardware OTP fuses | TrustZone, secure boot |
| ESP32-S3 | Xtensa LX7 240 MHz | 8 MB SPI (128 KB storage) | Hardware TRNG | WS2812 RGB (GPIO48/38) | eFuse block 3 | USB OTG on GPIO19/20 |
| ESP32-C5 | RISC-V 160 MHz | SPI (128 KB storage) | Hardware TRNG | GPIO | eFuse | Single-core |
| ESP32-C6 | RISC-V 160 MHz | SPI (128 KB storage) | Hardware TRNG | GPIO | eFuse | Serial bridge mode |
| SAMD21 | Cortex-M0+ 48 MHz | 256 KB (32 KB storage) | Weak TRNG | Configurable GPIO | None | No RSA, no HSM |

Feature gates in `pico-rs-sdk/Cargo.toml` control which platform adapter compiles:

```toml
[features]
default = []
alloc = ["dep:rsa", "zeroize/alloc"]
rp2040 = ["dep:embassy-rp", "dep:rp2040-boot2", "dep:ws2812-pio", "dep:cortex-m", "dep:cortex-m-rt"]
rp2350 = ["dep:embassy-rp", "dep:ws2812-pio", "dep:cortex-m", "dep:cortex-m-rt"]
esp32s3 = ["dep:esp-hal"]
esp32c5 = ["dep:esp-hal"]
esp32c6 = ["dep:esp-hal"]
samd21 = ["dep:atsamd-hal", "dep:cortex-m", "dep:cortex-m-rt"]
```

## Transport Layer

### HID (CTAPHID)

Used for FIDO2/CTAP2 communication. 64-byte USB HID reports with framing:

```
[CID (4 bytes)] [Command (1 byte)] [Data...]
```

- `HID_REPORT_SIZE` = 64 bytes
- `MAX_MSG_SIZE` = 7680 bytes (max CBOR message)
- Keepalive interval = 10,000 ms

Commands: Init (0xBF), Msg (0x83), Cbor (0x90), Wink (0xBD), Lock (0x84), Error (0xBF)

### CCID (Smart Card)

Used for OATH, Management, and HSM applets. ISO 7816 APDU over USB CCID:

```
Message header (10 bytes, little-endian):
[MsgType (1)] [Length (4 LE)] [Slot (1)] [Seq (1)] [Specific (3)]
```

Message types: IccPowerOn (0x62), IccPowerOff (0x63), GetSlotStatus (0x65), XfrBlock (0x6F)

Applications are selected by AID and dispatched via the `Application` trait.

## Crypto Module

All cryptographic operations are in `pico-rs-sdk::crypto`, built on RustCrypto crates:

| Operation | Algorithms | Notes |
|-----------|-----------|-------|
| ECDSA Sign/Verify | P-256, P-384, P-521, secp256k1 | NIST and Bitcoin curves |
| EdDSA Sign/Verify | Ed25519 | RFC 8032 |
| ECDH | P-256, X25519 | Key agreement |
| RSA | 1024–4096 bit PKCS#1 v1.5, OAEP | Requires `alloc` feature; not on SAMD21 |
| AES | CBC, GCM (256-bit) | 12-byte nonces for GCM |
| HMAC | SHA-256 | Constant-time verification via `subtle` |
| PBKDF2 | HMAC-SHA-256, 256k iterations | PIN hashing |
| Hash | SHA-1, SHA-256, SHA-384, SHA-512 | SHA-1 only for U2F compatibility |

## Storage Design

### FileStore

Wear-levelled key-value storage on NOR flash using the `sequential-storage` crate.

**FileId encoding** (2 bytes: TAG + PARAM):

| FileId | Tag | Param | Description |
|--------|-----|-------|-------------|
| `Aaguid` | 0x01 | 0x00 | FIDO2 Authenticator Attestation GUID |
| `Mkek` | 0x02 | 0x00 | Master Key Encryption Key (wrapped) |
| `Config` | 0x03 | 0x00 | Device configuration |
| `PinRetryCount` | 0x04 | 0x00 | PIN retry counter |
| `AttestationCert` | 0x05 | 0x00 | Attestation certificate |
| `ResidentKey(n)` | 0x10 | n | Discoverable credential slot (0–255) |
| `OathCredential(n)` | 0x20 | n | OATH credential slot (0–255) |
| `OtpSlot(n)` | 0x30 | n | OTP configuration slot (0–255) |

Max file size: 1024 bytes. Max credentials: FIDO2 = 128, OATH = 32.

### SecureStorage (OTP)

Platform-specific OTP/eFuse storage for the MKEK:

- **RP2350**: ARM TrustZone hardware OTP fuses
- **ESP32-S3/C5/C6**: eFuse block 3 (256-bit slot)
- **RP2040/SAMD21**: AES-wrapped MKEK in flash (no hardware OTP)

### Credential Encryption

Resident credentials are encrypted with AES-256-GCM using the MKEK:
- Random 12-byte nonce per credential (never reused)
- TLV serialization with tags for RP ID hash, credential ID, user data, private key, etc.

## Security Model

### MKEK Hierarchy

```
Hardware OTP / eFuse
    └── MKEK (256-bit AES key)
         ├── Wraps resident credential private keys (AES-256-GCM)
         ├── Wraps OATH secrets
         └── Wraps HSM DKEK shares
```

### Key Material Protection

- `zeroize` crate with `ZeroizeOnDrop` on all secrets
- `SecretBox<T>` pattern for long-lived keys
- Explicit zeroization of temporary crypto buffers
- `subtle::ConstantTimeEq` for PIN/HMAC verification
- No branch-on-secret in crypto paths

### PIN Storage

- PBKDF2-HMAC-SHA256 with 256,000 iterations
- Random 16-byte salt per device
- 8 retry attempts, locked at 0, reset on successful auth

### DKEK (HSM)

- Shamir Secret Sharing over GF(256) with n-of-m threshold
- Each share: 33 bytes (1-byte X coordinate + 32-byte Y values)
- Key wrapping: AES-256-GCM with random nonces

### Known Advisories

- RUSTSEC-2023-0071 (RSA Marvin Attack in `rsa` v0.9.x)
- Mitigations: random blinding enabled, press-to-confirm gates RSA decrypt, USB jitter
- Pinned to `rsa = "0.9.10"`

## LED State Machine

The LED module drives visual feedback through four standard patterns:

| State | On (ms) | Off (ms) | Frequency | Meaning |
|-------|---------|----------|-----------|---------|
| Idle | 500 | 500 | 1 Hz | Device powered, awaiting command |
| Active | 125 | 125 | 4 Hz | Processing a request |
| Processing | 25 | 25 | 20 Hz | Crypto operation in progress |
| PressToConfirm | 900 | 100 | ~1 Hz | Waiting for user button press |
| Custom | configurable | configurable | — | User-defined pattern |

LED updates are sent via an Embassy channel (`LED_CHANNEL`) from the application task
to a dedicated LED driver task.

## Build System

### Toolchain

- Rust nightly (`nightly-2026-02-15`) with `rust-src`, `clippy`, `rustfmt`
- Targets configured in `rust-toolchain.toml`

### Release Profile

```toml
[profile.release]
opt-level = "s"    # Optimize for size
lto = true         # Link-time optimization
codegen-units = 1  # Single codegen unit for best optimization
debug = false
```

### Target Matrix

| Target | Triple | Runner | Platforms |
|--------|--------|--------|-----------|
| ARM Cortex-M0+ | `thumbv6m-none-eabi` | `probe-rs run --chip RP2040` | RP2040, SAMD21 |
| ARM Cortex-M33 | `thumbv8m.main-none-eabihf` | `probe-rs run --chip RP2350` | RP2350 |
| Xtensa LX7 | `xtensa-esp32s3-none-elf` | `espflash flash --monitor` | ESP32-S3 |
| RISC-V | `riscv32imac-unknown-none-elf` | `espflash flash --monitor` | ESP32-C5, ESP32-C6 |

### Fuzz Targets

Four fuzz targets in `fuzz/`:
- `fuzz_ctap_cbor` — CTAP2 CBOR message parsing
- `fuzz_ccid_apdu` — CCID APDU frame parsing
- `fuzz_credential_decode` — Credential TLV deserialization
- `fuzz_hid_framing` — CTAPHID packet framing
