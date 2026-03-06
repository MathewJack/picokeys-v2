# PicoKeys v2 — Full Rust Rewrite: Detailed Implementation Plan

> Based on: `RUST_REWRITE_RESEARCH.md` (Rev 2, March 6 2026)  
> Target: Production-grade Rust firmware (no_std) + host CLI tool  

---

## Problem Statement

Rewrite the entire pico-keys ecosystem (pico-keys-sdk + pico-fido + pico-hsm) in Rust, achieving full feature parity with the original C implementations, targeting RP2040, RP2350, ESP32-S3, ESP32-C5, ESP32-C6, and SAMD21. Deliver a `picokeys-cli` host tool as a modern `ykman`-equivalent with firmware management capabilities.

---

## Workspace Overview

```
picokeys-v2/
├── Cargo.toml                  # Workspace root
├── .cargo/config.toml          # Per-target rustflags & linker
├── rust-toolchain.toml         # Pin nightly/stable channel
├── pico-rs-sdk/                # Core SDK (transport, crypto, store, LED, button)
├── pico-rs-fido/               # FIDO2 + OATH application
├── pico-rs-hsm/                # HSM application (Phase 5)
├── picokeys-cli/               # Host management CLI
├── docs/
├── tests/
└── scripts/
```

---

## Phase 1 — Foundation & SDK Core (Weeks 1–4)

### Step 1.1 — Cargo Workspace Bootstrap

**Goal:** Compilable workspace skeleton for all targets.

1. Create `picokeys-v2/Cargo.toml` workspace with members: `pico-rs-sdk`, `pico-rs-fido`, `pico-rs-hsm`, `picokeys-cli`. Set `resolver = "2"`.
2. Create `rust-toolchain.toml` pinning `channel = "nightly"` (required for Embassy + Xtensa target support).
3. Create `.cargo/config.toml` with per-target runners and `rustflags`:
   - `thumbv6m-none-eabi` → `link-arg=-Tlink.x`
   - `thumbv8m.main-none-eabihf` → `link-arg=-Tlink.x`
   - `xtensa-esp32s3-none-elf` → Xtensa linker settings
   - `riscv32imac-unknown-none-elf` → RISC-V linker settings
4. Add workspace-level `[profile.release]`: `opt-level = "s"`, `lto = true`, `codegen-units = 1`.
5. Add `[profile.release.package.num-bigint-dig]` with `opt-level = 3` (RSA speed).
6. Install required Rust targets:
   ```bash
   rustup target add thumbv6m-none-eabi thumbv8m.main-none-eabihf riscv32imac-unknown-none-elf
   # ESP32-S3 Xtensa requires espup:
   cargo install espup && espup install
   ```
7. Set up cross-compile check for all 6 targets, `cargo clippy`, `cargo test` (host-side tests only).

**Deliverable:** `cargo check` succeeds for all workspace members on all targets.

---

### Step 1.2 — `pico-rs-sdk`: Storage Module

**Goal:** Wear-levelled, power-fail-safe flash key-value store behind a platform-agnostic trait.

**Files to create:**
- `pico-rs-sdk/src/store/mod.rs` — `FileStore` trait
- `pico-rs-sdk/src/store/flash.rs` — `sequential-storage`-backed implementation
- `pico-rs-sdk/src/store/file.rs` — `FileId` type enum (numeric IDs matching pico-keys-sdk file IDs)
- `pico-rs-sdk/src/store/otp.rs` — `SecureStorage` trait: `read_otp(slot) -> Option<[u8;32]>`, `write_otp(slot, value)`

**`FileStore` trait:**
```rust
pub trait FileStore {
    fn read_file(&self, fid: FileId) -> Result<&[u8], StoreError>;
    fn write_file(&mut self, fid: FileId, data: &[u8]) -> Result<(), StoreError>;
    fn delete_file(&mut self, fid: FileId) -> Result<(), StoreError>;
    fn exists(&self, fid: FileId) -> bool;
}
```

**`SecureStorage` trait:**
```rust
pub trait SecureStorage {
    fn read_otp(&self, slot: u8) -> Option<[u8; 32]>;
    fn write_otp(&mut self, slot: u8, value: &[u8; 32]) -> Result<(), StoreError>;
}
```

**Key implementation details:**
- `sequential-storage` v7.1.0 for flash KV map and queue
- Define `FileId` variants matching pico-fido file IDs (AAGUID, MKEK, resident key slots, OATH credentials, OTP slots, config)
- Implement `StoreError` type with `NotFound`, `NoSpace`, `Corrupted` variants
- All file writes: zeroize old plaintext buffers after AES wrap (`zeroize` crate, mandatory)
- Flash partition layout: dedicate last 128KB of flash to storage on RP2040 (configurable via linker)

**Dependencies to add to `pico-rs-sdk/Cargo.toml`:**
```toml
sequential-storage = "7.1.0"
embedded-storage = "0.3"
zeroize = { version = "1.8", features = ["derive"] }
heapless = "0.8"
```

---

### Step 1.3 — `pico-rs-sdk`: CTAP HID Transport

**Goal:** Complete CTAPHID channel multiplexing and framing layer.

**Files to create:**
- `pico-rs-sdk/src/transport/mod.rs` — `Transport` trait
- `pico-rs-sdk/src/transport/hid/mod.rs` — CTAPHID framing state machine
- `pico-rs-sdk/src/transport/hid/class.rs` — `embassy-usb` HID class adapter

**Implementation details:**
1. CTAPHID packet size: 64 bytes (USB HID report)
2. Initialization packet format: `CID(4) | CMD(1) | BCNTH(1) | BCNTL(1) | DATA(57)`
3. Continuation packet format: `CID(4) | SEQ(1) | DATA(59)`
4. Implement channel allocation (CID 0xFFFFFFFF = broadcast, allocate per session)
5. Commands to handle: `CTAPHID_MSG` (0x03), `CTAPHID_CBOR` (0x10), `CTAPHID_INIT` (0x06), `CTAPHID_PING` (0x01), `CTAPHID_CANCEL` (0x11), `CTAPHID_ERROR` (0x3F), `CTAPHID_KEEPALIVE` (0x3B), `CTAPHID_WINK` (0x08)
6. Implement timeout/keepalive: send `KEEPALIVE(STATUS_UPNEEDED)` every 10s while waiting for user presence
7. Use `embassy-usb` v0.5.1 HID class; report descriptor: 64-byte usage page `0xF1D0` (FIDO Alliance)
8. Use `usbd-hid` v0.9.0 for report descriptor macros

**`Transport` trait:**
```rust
pub trait Transport {
    async fn recv(&mut self, buf: &mut [u8]) -> Result<usize, TransportError>;
    async fn send(&mut self, data: &[u8]) -> Result<(), TransportError>;
    async fn send_keepalive(&mut self, status: u8) -> Result<(), TransportError>;
}
```

---

### Step 1.4 — `pico-rs-sdk`: CCID USB Class (Custom)

**Goal:** Implement CCID (USB Integrated Circuit Card Devices) class over `embassy-usb` bulk endpoints. No existing Rust crate provides this; ~600 LOC required.

**Files to create:**
- `pico-rs-sdk/src/transport/ccid/mod.rs` — CCID framing and slot management
- `pico-rs-sdk/src/transport/ccid/class.rs` — Custom `embassy-usb` class (2× bulk endpoints + 1 interrupt)

**CCID message types to implement (USB CCID Rev 1.1 spec):**
- `PC_to_RDR_IccPowerOn` (0x62)
- `PC_to_RDR_IccPowerOff` (0x63)
- `PC_to_RDR_GetSlotStatus` (0x65)
- `PC_to_RDR_XfrBlock` (0x6F) — main APDU transfer
- `PC_to_RDR_Abort` (0x72)
- `RDR_to_PC_DataBlock` (0x80) — response with APDU data
- `RDR_to_PC_SlotStatus` (0x81)
- `RDR_to_PC_Parameters` (0x82)

**Implementation details:**
1. Register class with `embassy-usb` using `UsbDeviceBuilder::add_interface()` for Bulk-Only Transport
2. 2 bulk endpoints (OUT for host→device, IN for device→host) + 1 interrupt IN (slot change notification)
3. CCID descriptor: `bInterfaceClass = 0x0B` (smart card), subclass 0, protocol 0
4. Implement extended APDU chaining (up to 65535 byte payloads, chained across multiple XfrBlock messages)
5. One logical slot (slot 0) — single card always present
6. `ATR` (Answer to Reset): return standard short ATR for T=1 protocol

**APDU layer:**
- `pico-rs-sdk/src/apdu/mod.rs` — `Application` dispatch trait
- `pico-rs-sdk/src/apdu/command.rs` — ISO 7816-4 `Command<D>` wrapper over `iso7816` crate
- `pico-rs-sdk/src/apdu/response.rs` — `Response` builder with status words
- `pico-rs-sdk/src/apdu/chaining.rs` — `GET RESPONSE` chain for large responses

**Dependencies:**
```toml
iso7816 = "0.2.0"
embassy-usb = "0.5.1"
embassy-usb-driver = "0.1"
```

---

### Step 1.5 — `pico-rs-sdk`: Crypto Layer

**Goal:** Platform-agnostic crypto provider trait wrapping all RustCrypto primitives.

**Files to create:**
- `pico-rs-sdk/src/crypto/mod.rs` — `CryptoBackend` trait
- `pico-rs-sdk/src/crypto/rng.rs` — `RngSource` trait + platform adapters
- `pico-rs-sdk/src/crypto/ecc.rs` — ECDSA sign/verify, ECDH (P-256/384/521/k256/Ed25519/X25519)
- `pico-rs-sdk/src/crypto/rsa.rs` — RSA keygen + sign + decrypt (with Marvin blinding)
- `pico-rs-sdk/src/crypto/aes.rs` — AES modes: ECB, CBC, CFB, OFB, CTR, GCM, CCM, XTS
- `pico-rs-sdk/src/crypto/symmetric.rs` — HMAC, CMAC, HKDF, PBKDF2, ChaCha20-Poly1305
- `pico-rs-sdk/src/crypto/asn1.rs` — DER encode/decode helpers

**Critical security requirements:**
- ALL private key material: `#[derive(Zeroize, ZeroizeOnDrop)]`
- PIN verification: `subtle::ConstantTimeEq` (never use `==`)
- HMAC comparison: `subtle::ConstantTimeEq`
- RSA decrypt: maintain random blinding (already in `rsa` crate; document advisory RUSTSEC-2023-0071)

**`CryptoBackend` trait (simplified):**
```rust
pub trait CryptoBackend {
    fn ecdsa_sign_p256(&mut self, key: &EcPrivKey, digest: &[u8]) -> Result<Signature, CryptoError>;
    fn ecdsa_sign_ed25519(&mut self, key: &Ed25519Key, msg: &[u8]) -> Result<Signature, CryptoError>;
    fn ecdh_p256(&mut self, priv_key: &EcPrivKey, pub_key: &EcPubKey) -> Result<[u8;32], CryptoError>;
    fn rng_fill(&mut self, buf: &mut [u8]);
    fn aes256_gcm_encrypt(&self, key: &[u8;32], nonce: &[u8;12], plaintext: &[u8], aad: &[u8], ciphertext: &mut [u8], tag: &mut [u8;16]) -> Result<(), CryptoError>;
    fn sha256(&self, data: &[u8]) -> [u8; 32];
    fn hmac_sha256(&self, key: &[u8], data: &[u8]) -> [u8; 32];
    // ... etc
}
```

**Dependencies:**
```toml
p256 = { version = "0.13.2", default-features = false, features = ["ecdsa", "ecdh"] }
p384 = { version = "0.13.2", default-features = false, features = ["ecdsa", "ecdh"] }
p521 = { version = "0.13.2", default-features = false }
k256 = { version = "0.13.3", default-features = false, features = ["ecdsa"] }
ed25519-dalek = { version = "2.2.0", default-features = false, features = ["rand_core"] }
x25519-dalek = { version = "2.0", default-features = false }
rsa = { version = "0.9.10", default-features = false }
aes = "0.8"
aes-gcm = "0.10.3"
chacha20poly1305 = "0.10"
cbc = "0.1"
hmac = "0.12.1"
hkdf = "0.12"
pbkdf2 = "0.12"
sha2 = { version = "0.10", default-features = false }
sha1 = { version = "0.10", default-features = false }
cmac = "0.7"
subtle = { version = "2.6", default-features = false }
zeroize = { version = "1.8", features = ["derive"] }
rand_core = "0.6"
der = { version = "0.7", default-features = false }
pkcs8 = { version = "0.10", default-features = false }
x509-cert = { version = "0.2", default-features = false }
embedded_alloc = "0.6"   # Required for RSA large key buffers
```

---

### Step 1.6 — `pico-rs-sdk`: LED Module

**Goal:** Implement all 4 LED status patterns correctly, for both single-color and WS2812 RGB LEDs.

**Files to create:**
- `pico-rs-sdk/src/led/mod.rs` — `LedStatus` trait + `LedState` enum
- `pico-rs-sdk/src/led/patterns.rs` — Timing logic for 4 states

**LED states (must match pico-fido exactly):**

| `LedState` | Pattern | Timing |
|-----------|---------|--------|
| `Idle` | ON 500ms every second | Mostly OFF, brief ON |
| `Active` | Blink 4Hz | 125ms ON, 125ms OFF |
| `Processing` | Blink 20Hz | 25ms ON, 25ms OFF |
| `PressToConfirm` | OFF 100ms every second | Mostly ON, brief OFF |

**Platform-specific LED drivers (feature-gated):**
- `feature = "rp2040"` / `feature = "rp2350"`: use `ws2812-pio` (PIO state machine on GPIO25 or configured GPIO)
- `feature = "esp32s3"` / `feature = "esp32c5"`: use `esp-hal` RMT driver for WS2812 on GPIO48/GPIO38/GPIO27
- `feature = "samd21"`: simple `embedded-hal` `OutputPin` toggle

**Config storage:** LED GPIO and LED type stored in flash as part of device config file (FileId::Config).

**Dependencies:**
```toml
smart-leds = "0.4"
ws2812-pio = { version = "0.7", optional = true }
ws2812-spi = { version = "0.5", optional = true }
embassy-time = "0.4"
```

---

### Step 1.7 — `pico-rs-sdk`: Button / User Presence Module

**Goal:** Platform-safe press-to-confirm implementation for all boards.

**File:** `pico-rs-sdk/src/button/mod.rs`

**Platform-specific reading:**
- **RP2040/RP2350**: Read `sio_hw->gpio_hi_in & (1 << 1)` (QSPI_SS_N) in a cache-locked loop. Never access flash during this read. Use `embassy-rp`'s `QSPI_SS` GPIO handling.
- **ESP32-S3**: GPIO0, active-low, internal pull-up via `esp-hal`
- **ESP32-C5**: GPIO7, active-low, internal pull-up
- **ESP32-C6**: GPIO9, active-low
- **SAMD21**: Configurable GPIO (stored in Config file), defaults to simulated-always-confirmed

**Wait-for-press logic:**
1. Switch LED to `LedState::PressToConfirm`
2. Start timeout countdown (default 15s, from Config)
3. Every 10s: send `KEEPALIVE(STATUS_UPNEEDED)` via transport
4. If button pressed: return `Ok(UserPresence::Confirmed)`
5. If timeout: return `Err(UserPresenceError::Timeout)` → caller returns `CTAP2_ERR_ACTION_TIMEOUT`

---

### Step 1.8 — `pico-rs-sdk`: Platform Adapters (RP2040 + RP2350)

**Goal:** First complete platform adapter. All other phases build on this.

**Files to create:**
- `pico-rs-sdk/src/platform/rp2040.rs`
- `pico-rs-sdk/src/platform/rp2350.rs`

**Each adapter must provide:**
1. `embassy-rp` USB driver initialization (full-speed device, GPIO26/27)
2. Flash storage adapter (QSPI flash via `embassy-rp::flash`) → `impl embedded-storage::NorFlash`
3. Hardware TRNG access (RP2040: ROSC ring oscillator; RP2350: dedicated TRNG) → `impl rand_core::RngCore`
4. LED driver (WS2812 PIO on GPIO25 via `ws2812-pio`)
5. Button reader (QSPI_SS_N BOOTSEL)
6. `SecureStorage`:
   - RP2040: returns `None` (no OTP) → MKEK stored encrypted in flash
   - RP2350: reads from OTP fuses via `rp2350::otp::read_raw_value()` (unsafe)
7. Secure Boot init for RP2350 (check ARM TrustZone / secure boot state)

**Dependencies (feature-gated):**
```toml
[target.'cfg(feature = "rp2040")'.dependencies]
embassy-rp = { version = "0.9.0", features = ["rp2040", "time-driver"] }
rp2040-boot2 = "0.3"

[target.'cfg(feature = "rp2350")'.dependencies]
embassy-rp = { version = "0.9.0", features = ["rp2350"] }
```

**Smoke test deliverable:** RP2040 binary that enumerates as USB HID device, blinks LED in `Active` pattern, responds to CTAPHID_PING.

---

## Phase 2 — FIDO2 Core Application (Weeks 5–10)

### Step 2.1 — `pico-rs-fido`: Crate Skeleton & Feature Flags

**File:** `pico-rs-fido/Cargo.toml`

```toml
[features]
default = []
rp2040 = ["pico-rs-sdk/rp2040", ...]
rp2350 = ["pico-rs-sdk/rp2350", ...]
esp32s3 = ["pico-rs-sdk/esp32s3", ...]
esp32c5 = ["pico-rs-sdk/esp32c5", ...]
esp32c6 = ["pico-rs-sdk/esp32c6", ...]
samd21 = ["pico-rs-sdk/samd21", ...]
```

**Dependencies:**
```toml
ctap-types = "0.4.0"
cosey = "0.3.0"
cbor4ii = { version = "1.2.2", default-features = false }
totp-lite = "2.0.1"
bip39 = { version = "2.1", default-features = false }
bip32 = { version = "0.5.3", default-features = false }
```

---

### Step 2.2 — CTAP2 Core Command Router

**Files to create:**
- `pico-rs-fido/src/fido/mod.rs` — main FIDO loop: reads CTAPHID frames, dispatches to CTAP2
- `pico-rs-fido/src/fido/ctap.rs` — `CtapCommand` enum, CBOR router

**Command enum:**
```rust
pub enum CtapCommand {
    MakeCredential,      // 0x01
    GetAssertion,        // 0x02
    GetInfo,             // 0x04
    ClientPin,           // 0x06
    Reset,               // 0x07
    GetNextAssertion,    // 0x08
    CredentialManagement,// 0x0A
    Selection,           // 0x0B
    LargeBlobs,          // 0x0C
    Config,              // 0x0D
    VendorFirst,         // 0x40 (vendor-specific range)
}
```

**Dispatch flow:**
1. Read 64-byte HID report
2. Reassemble CTAPHID packet → raw CBOR payload
3. First byte = CTAP command byte → dispatch to handler
4. Handler returns `Result<CborResponse, CtapError>`
5. Encode response + prepend status byte → fragment into 64-byte HID reports

---

### Step 2.3 — Credential Storage & KEK

**Files:**
- `pico-rs-fido/src/credential/mod.rs` — `ResidentCredential` struct + list/add/delete/update
- `pico-rs-fido/src/credential/id.rs` — encrypted credential ID format
- `pico-rs-fido/src/credential/kek.rs` — MKEK loading from OTP (or flash on RP2040/SAMD21)
- `pico-rs-fido/src/credential/backup.rs` — BIP39 24-word backup/restore

**Credential storage:**
- Each credential stored as a separate file in flash (`FileId::ResidentKey(n)`)
- Structure: AES-256-GCM encrypted blob containing `CredentialData { rp_id_hash, user_id, user_name, public_key, private_key_handle, sign_count, ... }`
- Encryption key: derived from MKEK (stored in OTP or encrypted in flash)
- Maximum resident credentials: 128 (configurable, limited by flash)

**KEK / MKEK hierarchy:**
1. `MKEK` (Master Key Encryption Key) — 32 bytes, stored in OTP fuse (RP2350, ESP32) or AES-wrapped in flash (RP2040, SAMD21)
2. `KEK` — derived from MKEK per-credential or per-RP using HKDF
3. Credential private keys: AES-256-GCM encrypted with KEK

**24-word backup (BIP39):**
- MKEK → BIP39 mnemonic (via `bip39` crate)
- `picokeys-cli fido backup show` → display 24 words
- `picokeys-cli fido backup restore <words>` → re-import MKEK

---

### Step 2.4 — MakeCredential Handler

**File:** `pico-rs-fido/src/fido/make_credential.rs`

**Implementation steps:**
1. Decode CBOR request: `clientDataHash`, `rp`, `user`, `pubKeyCredParams`, `excludeList`, `extensions`, `options`
2. Check `excludeList` against stored credentials → return `CTAP2_ERR_CREDENTIAL_EXCLUDED` if match
3. If `rk=true` (resident key): verify storage space available
4. Check user verification (`uv` option): if `alwaysUV` config enabled, enforce PIN
5. If UV required: call `verify_pin_token()`
6. Request user presence (press-to-confirm button)
7. Generate key pair: select algorithm from `pubKeyCredParams` priority list:
   - ES256 (P-256), ES384, ES512, EdDSA (Ed25519), ES256K (secp256k1)
8. Build `authData` = `rpIdHash(32) | flags(1) | signCount(4) | aaguid(16) | credIdLen(2) | credId | cosePublicKey`
9. Sign `clientDataHash || authData` with new private key (self-attestation)
10. Build attestation object CBOR: `{fmt: "packed", attStmt: {alg, sig}, authData}`
11. If enterprise attestation: use enterprise cert instead of self-attestation
12. If `rk=true`: encrypt and write credential to flash
13. Return CBOR response

---

### Step 2.5 — GetAssertion Handler

**File:** `pico-rs-fido/src/fido/get_assertion.rs`

**Implementation steps:**
1. Decode CBOR: `rpId`, `clientDataHash`, `allowList`, `extensions`, `options`
2. Compute `rpIdHash = SHA-256(rpId)`
3. Find matching credentials:
   - If `allowList` provided: match credential IDs
   - If empty (discoverable): enumerate all resident keys matching `rpIdHash`
4. If no match: return `CTAP2_ERR_NO_CREDENTIALS`
5. If `uv` required (alwaysUV or explicit): verify PIN token
6. Request user presence
7. For first credential: sign `authData || clientDataHash` with stored private key
8. Increment `signCount`, write back to flash
9. Build CBOR response with `credential`, `authData`, `signature`, `user` (if rk), `numberOfCredentials`
10. Store remaining credentials for `GetNextAssertion` (if `numberOfCredentials > 1`)

---

### Step 2.6 — GetInfo Handler

**File:** `pico-rs-fido/src/fido/get_info.rs`

**Response fields (must match pico-fido capability set):**
- `versions`: `["FIDO_2_1", "FIDO_2_0", "U2F_V2"]`
- `extensions`: `["hmac-secret", "credProtect", "credBlob", "largeBlobKey", "minPinLength"]`
- `aaguid`: read from flash `FileId::Aaguid`
- `options`: `{rk: true, clientPin: true/false, up: true, uv: false, credMgmt: true, authnrCfg: true, largeBlobs: true}`
- `maxMsgSize`: 1200
- `pinUvAuthProtocols`: `[2, 1]`
- `maxCredentialCountInList`: 8
- `maxCredentialIdLength`: 128
- `transports`: `["usb"]`
- `algorithms`: list of supported cose algorithm IDs
- `firmwareVersion`: from build-time constant

---

### Step 2.7 — PIN Protocol v1 & v2

**File:** `pico-rs-fido/src/fido/client_pin.rs`

**PIN protocol v2 (primary) steps:**
1. `getPinToken`: client sends ECDH ephemeral key → device returns encrypted PIN token
2. Key agreement: P-256 ECDH → shared secret → HKDF → 32-byte shared key
3. PIN verification: `HMAC-SHA256(shared_key, clientDataHash) == pinAuth` (constant-time)
4. PIN storage: `PBKDF2(pin, salt, 256000 iterations)` → stored hash

**PIN protocol v1 (legacy compat):**
- Same flow but simpler AES-CBC key wrapping instead of HKDF

**PIN token permissions (CTAP 2.1):**
- `mc` (MakeCredential), `ga` (GetAssertion), `cm` (CredMgmt), `acfg` (AuthConfig), `lbw` (LargeBlobWrite)
- Permission flags stored in RAM-only PIN token (cleared on reset)

**Retry counter:** stored in flash (`FileId::PinRetryCount`), decremented on failure, reset on success. Lock at 0.

---

### Step 2.8 — CTAP2 Extensions

**Files:**
- `pico-rs-fido/src/extensions/hmac_secret.rs`
- `pico-rs-fido/src/extensions/cred_protect.rs`
- `pico-rs-fido/src/extensions/cred_blob.rs`
- `pico-rs-fido/src/extensions/large_blob_key.rs`
- `pico-rs-fido/src/extensions/min_pin_length.rs`

**HMAC-Secret:**
- During MakeCredential: generate 64-byte `credRandom` stored encrypted with credential
- During GetAssertion: decrypt `credRandom`, compute `HMAC-SHA256(credRandom, salt1)` and optionally `HMAC-SHA256(credRandom, salt2)`
- Return encrypted via PIN protocol shared key

**CredProtect:**
- Levels 1–3 enforced during GetAssertion
- Level 3: never return without UV

**credBlob:** Up to 32 bytes of arbitrary user data stored per credential.

**largeBlobKey:** 32-byte per-credential key, used for `largeBlobs` store access.

**minPinLength:** Report minimum PIN length in GetInfo; enforce during PIN set.

---

### Step 2.9 — Credential Management Extension

**File:** `pico-rs-fido/src/fido/credential_mgmt.rs`

**Commands:**
- `getCredsMetadata`: return `existingResidentCredentialsCount`, `maxPossibleRemainingResidentCredentialsCount`
- `enumerateRPsBegin` / `enumerateRPsGetNextRP`: iterate unique RP IDs
- `enumerateCredentialsBegin` / `enumerateCredentialsGetNextCredential`: iterate credentials per RP
- `deleteCredential`: remove credential by ID from flash
- `updateUserInformation`: update `userName`/`displayName` for a stored credential

All operations require `cm` permission in PIN token.

---

### Step 2.10 — U2F / CTAP1 Backward Compatibility

**Files:**
- `pico-rs-fido/src/u2f/mod.rs`
- `pico-rs-fido/src/u2f/register.rs`
- `pico-rs-fido/src/u2f/authenticate.rs`

**U2F Register (0x01):**
- Generate P-256 key pair
- Build key handle (encrypted private key)
- X.509 attestation certificate (self-signed, stored in flash `FileId::AttestationCert`)
- Response: `0x05 | pubKey(65) | keyHandleLen(1) | keyHandle | cert | signature`

**U2F Authenticate (0x02):**
- Check-only mode (0x07): return presence indication
- Enforce user presence mode (0x03): wait for button press
- Sign: `appIdHash | presence | counter | clientDataHash` with key from key handle
- Response: `presence(1) | counter(4) | signature`

---

### Step 2.11 — OATH / YKOATH Protocol

**Files:**
- `pico-rs-fido/src/oath/mod.rs` — YKOATH APDU dispatcher (AID: `A0 00 00 05 27 21 01`)
- `pico-rs-fido/src/oath/totp.rs` — TOTP (RFC 6238) using `totp-lite`
- `pico-rs-fido/src/oath/hotp.rs` — HOTP (RFC 4226) over `hmac`
- `pico-rs-fido/src/oath/yubikey_otp.rs` — YubiKey static/dynamic OTP slots

**YKOATH APDU commands to implement:**
- `PUT` (0x01): Add credential (name, secret, type TOTP/HOTP, digits, period, algorithm)
- `DELETE` (0x02): Remove credential by name
- `LIST` (0x03): List all credentials
- `CALCULATE` (0x04): Generate code for one credential
- `CALCULATE ALL` (0x05): Generate codes for all credentials
- `SET CODE` (0x03 with tag 0x73): Set OATH password (encrypt store)
- `RESET` (0x04 + INS): Wipe all OATH credentials
- `RENAME` (0x05): Rename credential

**Storage:** Each OATH credential stored as `FileId::OathCredential(n)` in flash, encrypted with AES-256-GCM using MKEK-derived key.

**YubiKey OTP slots (2 slots):**
- Slot 1 / Slot 2: static password OR HOTP OR challenge-response
- Static password: typed via HID Keyboard class
- Challenge-response: HMAC-SHA1 or Yubico OTP (AES-128 counter block)
- Keyboard HID: emulate keystrokes to type OTP directly into host

---

### Step 2.12 — Vendor Commands & AuthenticatorConfig

**Files:**
- `pico-rs-fido/src/fido/vendor.rs`
- `pico-rs-fido/src/fido/config.rs`

**Vendor commands (0x40–0xFF range):**
- LED color/pattern configuration
- Rescue mode trigger
- Custom AAGUID write
- VID/PID override (stored in Config file, used at USB enumeration)

**AuthenticatorConfig (0x0D):**
- `setMinPINLength`: minimum PIN digits (default 4)
- `makeCredUvNotRequired`: allow no-UV MakeCredential for UV=discouraged
- `alwaysUv`: force UV for all operations
- `enterpriseAttestation`: enable enterprise attestation with enterprise cert

---

### Step 2.13 — Rescue Interface

**File:** `pico-rs-sdk/src/rescue/mod.rs`

**Purpose:** When device is unresponsive or undetectable, minimal CCID stack allows recovery.

**Implementation:**
1. Rescue mode triggered by holding BOOTSEL on power-up (detect in boot init)
2. Enumerate as bare CCID device (minimal descriptor)
3. Accept only: `SELECT AID` for rescue AID, `RESCUE_ERASE_ALL` vendor command, `GET_VERSION`
4. `RESCUE_ERASE_ALL`: wipe all flash except bootloader, reboot
5. Allows `picokeys-cli firmware erase` to work even on a bricked device

---

### Step 2.14 — Backup with 24 Words

**File:** `pico-rs-fido/src/credential/backup.rs`

**Flow:**
1. Read MKEK from `SecureStorage`
2. Convert 32-byte MKEK to BIP39 24-word mnemonic using `bip39` crate
3. For restore: validate mnemonic → recover MKEK → re-wrap all credentials
4. CLI: `picokeys-cli fido backup show` → requires PIN + button press

---

### Step 2.15 — Per-Board Binary Entrypoints

**Files:**
- `pico-rs-fido/src/bin/rp2040.rs`
- `pico-rs-fido/src/bin/rp2350.rs`
- `pico-rs-fido/src/bin/esp32s3.rs` (Phase 3)
- `pico-rs-fido/src/bin/esp32c5.rs` (Phase 3)
- `pico-rs-fido/src/bin/esp32c6.rs` (Phase 3, serial-only)
- `pico-rs-fido/src/bin/samd21.rs` (Phase 3)

**Each entrypoint pattern:**
```rust
#[embassy_executor::main]
async fn main(spawner: Spawner) {
    // 1. Init HAL peripherals
    // 2. Init USB device (HID + CCID composite)
    // 3. Init flash store
    // 4. Init TRNG
    // 5. Load config from flash
    // 6. Spawn LED task
    // 7. Spawn FIDO task (reads HID, dispatches CTAP2)
    // 8. Spawn OATH task (reads CCID)
    // 9. Spawn button task
}
```

**Memory linker scripts** (one per platform):
- `pico-rs-fido/memory-rp2040.x` — FLASH: 2MB, partition: last 128KB for storage
- `pico-rs-fido/memory-rp2350.x` — FLASH: 2MB
- `pico-rs-fido/memory-esp32s3.x`
- `pico-rs-fido/memory-samd21.x` — tight: 256KB total, storage uses last 32KB

---

### Step 2.16 — CTAP2 Conformance Testing

**Before proceeding to Phase 3:**

1. Run [FIDO Alliance CTAP2 conformance test suite](https://fidoalliance.org/certification/functional-certification/conformance/) against RP2040 binary.
2. Use `fido2-tests` Python suite against the device via `picokeys-cli` or direct HID.
3. Verify WebAuthn registration + authentication in Chrome and Firefox against `localhost` test page.
4. All CTAP2.1 mandatory tests must pass.

---

## Phase 3 — ESP32 & SAMD21 Platform Support (Weeks 11–14)

### Step 3.1 — ESP32-S3 Platform Adapter

**File:** `pico-rs-sdk/src/platform/esp32s3.rs`

**Implementation:**
1. `esp-hal` v1.0.0 HAL initialization (Xtensa LX7 at 240MHz)
2. USB: DWC2 USB OTG on GPIO19 (D−) / GPIO20 (D+) via `embassy-usb-synopsys-otg`
3. Flash: internal SPI flash via `esp-hal` flash API → `impl NorFlash`
4. TRNG: `esp_hal::rng::Rng` hardware RNG
5. LED: RMT peripheral for WS2812 on GPIO48 (v1.0) or GPIO38 (v1.1) — detect via build feature or config
6. Button: GPIO0, active-low, internal pull-up
7. Secure Boot: check eFuse `ABS_DONE_0`; MKEK from eFuse block 3
8. eFuse `SecureStorage` impl: `esp_hal::efuse::read_bit()` for 256-bit OTP blocks

**Key difference from RP2040:** Hardware bignum accelerator in ESP32-S3 reduces RSA-2048 keygen from ~124s to ~3-5s.

---

### Step 3.2 — ESP32-C5 Platform Adapter

**File:** `pico-rs-sdk/src/platform/esp32c5.rs`

**Implementation:**
1. RISC-V target (`riscv32imac-unknown-none-elf`)
2. USB: USB OTG Full Speed on GPIO13 (D−) / GPIO14 (D+) via `embassy-usb-synopsys-otg`
3. Boot button: GPIO7 (strapping pin, active-low)
4. LED: WS2812 on GPIO27 via RMT

---

### Step 3.3 — ESP32-C6 Platform Adapter (Serial Bridge Mode)

**File:** `pico-rs-sdk/src/platform/esp32c6.rs`

**Limitation:** No native HID/CCID. Implement serial bridge only.

**Implementation:**
1. USB-Serial-JTAG peripheral → CDC-ACM serial
2. Expose CTAP-over-serial protocol (framed CBOR over serial with length prefix)
3. `picokeys-cli` host side: serial transport adapter (detect C6 by VID/PID, route via serial)
4. Mark in docs: C6 cannot be used as native FIDO2 authenticator in browsers; CLI-only mode
5. Boot button: GPIO9

---

### Step 3.4 — SAMD21 Platform Adapter

**File:** `pico-rs-sdk/src/platform/samd21.rs`

**Implementation:**
1. `atsamd-hal` v0.23.3
2. USB: Native USB FS on PA25 (D+) / PA24 (D−)
3. No built-in BOOTSEL button: configurable GPIO from flash Config, default: simulated always-confirmed
4. LED: GPIO13 (single-color digital output)
5. TRNG: limited on SAMD21 (use SAMD51 for dedicated TRNG)
6. No OTP: MKEK stored encrypted in flash
7. Feature-gated exclusions (SAMD21 256KB limit):
   - No RSA (too large; exclude via `#[cfg(not(feature = "samd21"))]`)
   - No HSM application
   - FIDO2 + OATH only build

---

### Step 3.5 — Integration Testing (All Platforms)

For each platform:
1. Flash firmware
2. Verify USB enumeration (lsusb / Device Manager)
3. Run CTAPHID_PING → verify response
4. Test WebAuthn registration in Chrome/Firefox
5. Test OATH TOTP code generation via `picokeys-cli oath code`
6. Test press-to-confirm button detection

---

## Phase 4 — CLI Tool (`picokeys-cli`) (Weeks 15–18)

### Step 4.1 — CLI Skeleton

**File structure:**
```
picokeys-cli/src/
├── main.rs                 # clap CLI root
├── commands/
│   ├── mod.rs
│   ├── info.rs
│   ├── fido.rs
│   ├── oath.rs
│   ├── otp.rs
│   ├── hsm.rs
│   ├── config.rs
│   └── firmware.rs
├── transport/
│   ├── hid.rs              # hidapi + CTAP HID
│   └── ccid.rs             # pcsc CCID
└── device/
    └── mod.rs              # Auto-detect device, select transport
```

**Device auto-detection:**
1. Scan HID devices for known VID/PID profiles (NitroHSM, NitroFIDO2, Yubikey5, etc.)
2. Scan PC/SC readers for CCID devices
3. Match `picokeys-cli --device <SERIAL>` to specific device if multiple connected

**Dependencies:**
```toml
clap = { version = "4.5.60", features = ["derive"] }
hidapi = "2.6.5"
pcsc = "2.9.0"
ctap-hid-fido2 = "3.5.8"
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
tokio = { version = "1.0", features = ["full"] }
anyhow = "1.0"
thiserror = "1.0"
tracing = "0.1"
tracing-subscriber = "0.3"
indicatif = "0.17"
dialoguer = "0.11"
colored = "2.0"
tabled = "0.16"
```

---

### Step 4.2 — `info` Command

```bash
picokeys-cli info
```

Output: firmware version, serial number, supported capabilities (FIDO2, OATH, OTP, HSM), AAGUID, hardware platform.

Implementation: send `CTAPHID_MSG` GetInfo, decode CBOR response.

---

### Step 4.3 — `fido` Commands

**`fido credentials list`:**
1. Prompt for PIN via `dialoguer::Password`
2. Establish PIN token with `cm` permission via `ctap-hid-fido2`
3. Send CredentialManagement enumerate commands
4. Display results in `tabled` ASCII table: RP ID | User | Credential ID (truncated)

**`fido credentials delete <id>`:**
1. PIN auth → delete credential by ID
2. Confirm prompt before deletion

**`fido pin set` / `fido pin change`:**
- Use `dialoguer` for secure PIN entry (hidden input)
- Enforce minimum length (4 digits default, up to `minPinLength` setting)

**`fido reset`:**
- Warn: destroys ALL credentials
- Require interactive confirmation: type "RESET" to confirm
- Sends CTAP2 Reset command; device requires button press within 10s

**`fido config alwaysUV/enterpriseAttestation`:**
- Sends AuthenticatorConfig CBOR commands

---

### Step 4.4 — `oath` Commands

**`oath list`:** Table of NAME | TYPE | PERIOD | ALGORITHM

**`oath add <NAME>`:**
```bash
picokeys-cli oath add GitHub --secret BASE32SECRET --digits 6 --period 30 --algorithm SHA1
```

**`oath code <NAME>`:** Generate current TOTP code (query device for current timestamp)

**`oath code --all`:** Generate all codes, show time remaining per code

**`oath set-password`:** Encrypt OATH credential store with a password

**Transport:** OATH uses CCID (YKOATH protocol AID). CLI auto-detects CCID transport.

---

### Step 4.5 — `otp` Commands

```bash
picokeys-cli otp info
picokeys-cli otp set-static <SLOT> <PASSWORD>
picokeys-cli otp set-hotp <SLOT> --secret BASE32
picokeys-cli otp delete <SLOT>
picokeys-cli otp swap
```

Implementation: YubiKey management protocol over HID.

---

### Step 4.6 — `config` Commands

```bash
picokeys-cli config led gpio 25
picokeys-cli config led type rgb
picokeys-cli config button gpio 0
picokeys-cli config button polarity active-low
picokeys-cli config button timeout 15
picokeys-cli config press-to-confirm on
picokeys-cli config vid-pid 1209:4823
```

Sends vendor-specific CTAP2 commands (`CTAPHID_VENDOR_*`) to update Config file in device flash.

---

### Step 4.7 — `firmware` Commands (Role 1)

**`firmware flash`:**
```bash
picokeys-cli firmware flash --device rp2040 --firmware firmware.uf2
picokeys-cli firmware flash --device esp32s3 --firmware firmware.bin [--port /dev/ttyUSB0]
picokeys-cli firmware flash --device samd21 --firmware firmware.uf2
picokeys-cli firmware flash --device rp2040 --probe --firmware firmware.elf  # SWD
```

**Flash dispatch table:**

| Platform | Method | Tool invoked |
|----------|--------|-------------|
| RP2040 / RP2350 | UF2 copy to USB drive | `elf2uf2-rs` → copy |
| RP2040 / RP2350 (probe) | SWD via probe | `probe-rs run` |
| ESP32-S3 / C5 / C6 | USB serial | `espflash flash` |
| SAMD21 | UF2 bootloader | `uf2conv` → copy |
| SAMD21 (probe) | OpenOCD SWD | `openocd` |
| Any (DFU) | USB DFU class | `dfu-util` |

**`firmware erase`:** Full flash erase (factory reset at hardware level)

**`firmware dfu-update`:** Trigger `embassy-boot` DFU swap, write new firmware image to slot B, reboot

---

### Step 4.8 — Publish CLI (not needed for now)

- `cargo publish` to crates.io as `picokeys-cli`
- GitHub Releases: attach pre-built binaries for Linux x64, macOS arm64, Windows x64 (via GitHub Actions matrix)

---

## Phase 5 — HSM Application (`pico-rs-hsm`) (Weeks 19–28)

### Step 5.1 — CCID Application Skeleton

**Files:**
- `pico-rs-hsm/src/hsm/mod.rs` — HSM main loop (CCID dispatch)
- `pico-rs-hsm/src/hsm/apdu_router.rs` — SmartCard-HSM APDU command router

**AID:** `E8 2B 06 01 04 01 81 C3 1F 02 01` (SmartCard-HSM)

**PKCS#15 file structure** (virtual file system in flash):
- `MF` (Master File)
- `EF.ATR`, `EF.DIR`, `EF.TOKENINFO`
- `DF.PKCS15` — key objects, cert objects, data objects

---

### Step 5.2 — Key Management

**File:** `pico-rs-hsm/src/hsm/key_management.rs`

**Key operations:**
- `GENERATE KEY PAIR` (RSA 1024/2048/3072/4096, EC all curves, AES 128/192/256)
- RSA: use `embedded_alloc` heap for large key buffers; `rsa` crate
- EC: `p256`/`p384`/`p521`/`k256`/`ed25519-dalek`
- `DELETE KEY`
- `KEY USAGE COUNTER`: increment on use, store in flash, enforce limit

**Key storage format:**
- All keys wrapped with DKEK (Device Key Encryption Key) before flash storage
- Key metadata: label, key type, key size, usage flags, counter, domain

---

### Step 5.3 — Cryptographic Operations

**Files:**
- `pico-rs-hsm/src/hsm/sign.rs` — PKCS#1v1.5, PSS, ECDSA, EdDSA
- `pico-rs-hsm/src/hsm/decrypt.rs` — RSA-OAEP, RSA-PKCS1v1.5
- `pico-rs-hsm/src/hsm/ecdh.rs` — ECDH (P-256/384/521, X25519, X448)
- `pico-rs-hsm/src/hsm/aes_ops.rs` — AES ECB/CBC/CFB/OFB/CTR/GCM/CCM/XTS + ChaCha20-Poly1305
- `pico-rs-hsm/src/hsm/derive.rs` — HKDF, PBKDF2, X963-KDF, SLIP10, BIP32

All operations: require PIN authorization (session PIN stored in RAM, cleared on card removal).

---

### Step 5.4 — DKEK (Device Key Encryption Key) & n-of-m Threshold

**File:** `pico-rs-hsm/src/hsm/dkek.rs`

**DKEK scheme:**
- DKEK = 32-byte AES key used to wrap all HSM private keys
- n-of-m threshold: split DKEK into `m` shares using Shamir Secret Sharing
- `n` shares required to reconstruct DKEK
- Share import: `picokeys-cli hsm dkek import-share <FILE>`
- Multiple key domains: separate DKEK per domain

---

### Step 5.5 — Secure Messaging (EAC/SCP)

**File:** `pico-rs-sdk/src/eac/secure_channel.rs`

**Implementation:**
- SCP03-compatible symmetric secure channel (AES-128-CBC + AES-CMAC)
- CV certificates for terminal authentication
- Chip Authentication protocol (ECDH-based)
- All APDU data encrypted when secure channel established

---

### Step 5.6 — PIN Management

**File:** `pico-rs-hsm/src/hsm/pin.rs`

**PIN types:**
- User PIN: 4–16 alphanumeric chars, PBKDF2 hash stored in flash
- SO-PIN (Security Officer PIN): factory reset / unblock
- Transport PIN: one-time PIN for initial device delivery
- Session PIN: RAM-only, cleared on USB removal

---

### Step 5.7 — Certificate Management

**File:** `pico-rs-hsm/src/hsm/certificates.rs`

**Operations:**
- Import X.509 certificate (stored alongside key)
- Export X.509 certificate
- CV certificate import/export (for EAC)
- Key attestation: sign key public key with attestation cert

---

### Step 5.8 — PKCS#11 Validation

**Validation steps:**
1. Install OpenSC with `sc-hsm` driver
2. Connect device via CCID
3. `pkcs11-tool --module opensc-pkcs11.so --list-objects`
4. Test RSA sign/verify, ECDSA sign/verify, AES encrypt/decrypt
5. Test with `openssl` via `engine pkcs11`

---

### Step 5.9 — HSM CLI Commands

Implement all `picokeys-cli hsm` subcommands (see Section 9 of research doc):
- `hsm init`, `hsm keys list/generate/delete/export/import`
- `hsm dkek init/import-share`
- `hsm sign/verify/encrypt/decrypt`

---

## Phase 6 — Security Hardening (Ongoing)

### Step 6.1 — Zeroize Audit

- Every struct containing key material: `#[derive(Zeroize, ZeroizeOnDrop)]`
- All temporary buffers in crypto operations: call `.zeroize()` before drop
- PIN input buffers: zeroize immediately after hashing
- Use `SecretBox<T>` pattern for long-lived secrets

### Step 6.2 — Constant-Time Audit

- All PIN/HMAC comparisons: `subtle::ConstantTimeEq`
- No `if secret == expected` anywhere in codebase
- Use `subtle::Choice` for conditional assignments on secret data

### Step 6.3 — RSA Advisory Mitigation

- Document RUSTSEC-2023-0071 in `README.md` and `SECURITY.md`
- Gate RSA decrypt behind press-to-confirm (user presence)
- Track upstream `rsa` crate issue #390 for timing fix
- Pin `rsa = "0.9.10"` until advisory resolved

### Step 6.4 — Fuzz Testing

```bash
cargo install cargo-fuzz
# Fuzz CBOR parser
cargo fuzz run fuzz_ctap_cbor
# Fuzz APDU parser
cargo fuzz run fuzz_ccid_apdu
# Fuzz credential deserialization
cargo fuzz run fuzz_credential_decode
```

### Step 6.5 — Secure Boot & OTP Provisioning

**RP2350:**
- Document OTP fuse burn procedure for MKEK
- CLI: `picokeys-cli firmware provision-otp --mkek <HEX>` (one-time, irreversible)

**ESP32-S3/C5:**
- eFuse burn procedure via `esptool.py burn_efuse`
- Document secure boot key generation and signing workflow

### Step 6.6 — Security Audit

- External security review of:
  - CTAP2 PIN protocol implementation
  - Credential encryption (AES-GCM nonce reuse prevention)
  - DKEK key wrapping scheme
  - Press-to-confirm timing enforcement

---

## Known VID/PID Profiles

Store in flash `FileId::Config.usb_vid_pid`. Default: `1209:4823` (pico-fido default).

| Profile | VID | PID |
|---------|-----|-----|
| pico-fido default | 0x1209 | 0x4823 |
| NitroHSM | 0x20A0 | 0x42B2 |
| NitroFIDO2 | 0x20A0 | 0x42B1 |
| Yubikey5 | 0x1050 | 0x0407 |
| YubiHSM | 0x1050 | 0x0030 |
| Gnuk | 0x234B | 0x0000 |

---

## Critical Implementation Rules

1. **`zeroize` is mandatory** on ALL types holding key material, PINs, or sensitive state.
2. **`subtle::ConstantTimeEq`** for ALL equality checks on secrets.
3. **`pico-rs-fido` and `pico-rs-hsm`** must never directly import HAL crates — all HAL access through `pico-rs-sdk` traits.
4. **RSA requires `embedded_alloc`** heap (24KB static heap minimum).
5. **CCID is custom-built** (~600 LOC on top of `embassy-usb` raw endpoints).
6. **ESP32-C6** is serial-bridge-only; never claim it supports native HID/CCID in docs.
7. **SAMD21** builds exclude RSA and HSM (256KB flash constraint).
8. **LED patterns must match exactly**: Idle=500ms ON/s, Active=4Hz, Processing=20Hz, PressConfirm=100ms OFF/s.
9. **BIP39 24-word backup** must work offline and be entropy-complete (full MKEK recovery).
10. **All flash writes** go through `sequential-storage`; never write raw flash outside the store module.

---

## Dependency Summary (Embedded — `pico-rs-sdk` + `pico-rs-fido`)

| Crate | Version | Role |
|-------|---------|------|
| `embassy-executor` | 0.7 | Async task executor |
| `embassy-rp` | 0.9.0 | RP2040/RP2350 HAL |
| `embassy-usb` | 0.5.1 | USB device stack |
| `embassy-time` | 0.4 | Timers, delays |
| `embassy-sync` | 0.6 | Cross-task channels |
| `embassy-boot` | 0.4 | DFU/OTA bootloader |
| `esp-hal` | 1.0.0 | ESP32 HAL |
| `atsamd-hal` | 0.23.3 | SAMD21 HAL |
| `sequential-storage` | 7.1.0 | Flash KV store |
| `ctap-types` | 0.4.0 | CTAP2 type definitions |
| `iso7816` | 0.2.0 | APDU types |
| `cosey` | 0.3.0 | COSE key encoding |
| `cbor4ii` | 1.2.2 | CBOR encode/decode |
| `p256/384/521` | 0.13.2 | EC crypto |
| `k256` | 0.13.3 | secp256k1 |
| `ed25519-dalek` | 2.2.0 | Ed25519 |
| `x25519-dalek` | 2.0 | X25519 DH |
| `rsa` | 0.9.10 | RSA (⚠️ RUSTSEC-2023-0071) |
| `aes-gcm` | 0.10.3 | AES-GCM |
| `chacha20poly1305` | 0.10 | ChaCha20 |
| `hmac` | 0.12.1 | HMAC |
| `sha2` | 0.10 | SHA-256/512 |
| `hkdf` | 0.12 | HKDF |
| `pbkdf2` | 0.12 | PBKDF2 |
| `bip32` | 0.5.3 | HD keys |
| `bip39` | 2.1 | 24-word backup |
| `totp-lite` | 2.0.1 | TOTP |
| `zeroize` | 1.8 | Key material zeroize |
| `subtle` | 2.6 | Constant-time ops |
| `heapless` | 0.8 | No-alloc collections |
| `embedded_alloc` | 0.6 | Heap for RSA |
| `defmt` | 0.3 | Embedded logging |
| `ws2812-pio` | 0.7 | WS2812 on RP2040 |
| `smart-leds` | 0.4 | LED abstraction |

---

*Plan authored: March 6, 2026 — based on RUST_REWRITE_RESEARCH.md Rev 2*
