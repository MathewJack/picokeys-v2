# Pico-Keys Full Rust Rewrite — Deep Research & Architecture Report

> Generated: March 6, 2026 — Updated: March 6, 2026 (Rev 2)  
> Source repositories analysed: `pico-fido`, `pico-keys-sdk`, `pico-hsm`  
> Target languages/frameworks: Rust (no_std embedded) + Rust CLI host tool  
> Research method: Direct README/source analysis + official hardware documentation + crates.io audit

---

## Table of Contents

1. [Source Repository Analysis](#1-source-repository-analysis)
2. [Feasibility Assessment](#2-feasibility-assessment)
3. [Target Platform Matrix](#3-target-platform-matrix)
4. [Hardware GPIO Reference — Buttons, LEDs & USB Pins](#4-hardware-gpio-reference--buttons-leds--usb-pins)
5. [Rust Crate Inventory (annotated)](#5-rust-crate-inventory-annotated)
6. [Existing Mature Rust FIDO2/CTAP2 Crates — Reuse Analysis](#6-existing-mature-rust-fido2ctap2-crates--reuse-analysis)
7. [Modular Architecture Design](#7-modular-architecture-design)
8. [Folder & Workspace Structure](#8-folder--workspace-structure)
9. [CLI Tool Design (picokeys-cli) — Two Roles](#9-cli-tool-design-picokeys-cli--two-roles)
10. [Feature Parity Map](#10-feature-parity-map)
11. [Build & Flash Strategy](#11-build--flash-strategy)
12. [Key Technical Challenges & Mitigations](#12-key-technical-challenges--mitigations)
13. [Recommended Development Roadmap](#13-recommended-development-roadmap)

---

## 1. Source Repository Analysis

### 1.1 `pico-keys-sdk` — The Core SDK Layer

The SDK is the shared foundation consumed by both `pico-fido` and `pico-hsm`.

**Language breakdown:** C 93.7%, CMake 6.3%

**Directory structure (src/):**

| Module | Files | Responsibility |
|--------|-------|----------------|
| `usb/hid/` | hid.c, hid.h | FIDO/U2F HID transport (CTAPHID framing) |
| `usb/ccid/` | ccid.c, ccid.h | ISO 7816 CCID smart card over USB |
| `usb/emulation/` | emulation.c | PC-side emulation for testing |
| `usb/` | usb.c/h, usb_descriptors.c/h, tusb_config.h | TinyUSB USB descriptor & IRQ glue |
| `fs/` | file.c/h, files.c, flash.c, low_flash.c, mman.c/h, otp.c/h, phy.c/h | Wear-levelled flash key-value store + OTP |
| `led/` | — | LED status indicator (HAL abstraction) |
| `rng/` | — | Hardware RNG abstraction |
| `src/` (root) | apdu.c/h, asn1.c/h, eac.c/h, crypto_utils.c/h, rescue.c, main.c, board.h | APDU engine, ASN.1, EAC secure channel |

**External submodules:**
- `mbedTLS` — all cryptographic primitives (AES, RSA, ECDSA, SHA, etc.)
- `TinyUSB` — USB device stack (CCID + HID classes)
- `TinyCBOR` — CBOR encode/decode (used in CTAP2)
- `ML-KEM` — Post-quantum key encapsulation (beta/recent addition)

**Supported hardware (via CMake features):**  
RP2040, RP2350, ESP32-S3 (Espressif IDF v5.x), openssl-backend (Linux/macOS host emulation)

---

### 1.2 `pico-fido` — FIDO2 / CTAP2 Application

**Language breakdown:** C 67.9%, Python 28.1%, CMake 2.0%

Builds entirely on `pico-keys-sdk` as a git submodule. All FIDO logic lives in `src/fido/`.

**Source files in `src/fido/`:**

| File | Responsibility |
|------|----------------|
| `fido.c / fido.h` | Main FIDO dispatch loop; routes HID/CTAPHID commands |
| `ctap.h / ctap2_cbor.h` | CTAP type definitions, CBOR layouts |
| `cbor.c` | Top-level CTAP2 CBOR command router |
| `cbor_make_credential.c` | CTAP2 MakeCredential handler |
| `cbor_get_assertion.c` | CTAP2 GetAssertion handler |
| `cbor_get_info.c` | CTAP2 GetInfo handler |
| `cbor_client_pin.c` | PIN protocol (v1 & v2), user verification |
| `cbor_cred_mgmt.c` | Credential management extension |
| `cbor_large_blobs.c` | Large blobs storage extension |
| `cbor_config.c` | AuthenticatorConfig (alwaysUV, minPINLength, etc.) |
| `cbor_vendor.c` | Vendor-specific commands (LED config, rescue, etc.) |
| `cbor_reset.c` | CTAP2 Reset |
| `cbor_selection.c` | Device selection |
| `cmd_authenticate.c` | U2F/CTAP1 authenticate |
| `cmd_register.c` | U2F/CTAP1 register |
| `cmd_version.c` | U2F version string |
| `credential.c / .h` | Resident credential storage, RPId hashing, serialisation |
| `kek.c / .h` | Key encryption key management (master key in OTP) |
| `files.c / .h` | FIDO-specific file IDs (resident keys, AAGUID, etc.) |
| `management.c / .h` | YubiKey management protocol |
| `oath.c` | YKOATH protocol (TOTP/HOTP HMAC-based OTP) |
| `otp.c` | Yubikey OTP (static/dynamic slot-based OTP) |
| `known_apps.c` | Known-app RP ID table for display names |
| `defs.c` | Version strings and AAGUID |

**Full FIDO2/CTAP feature set (verified against README):**
- CTAP 2.1 + CTAP 1/U2F (fully compatible)
- WebAuthn / FIDO2 Level 3
- Extensions: HMAC-Secret, CredProtect, credBlobs, largeBlobKey, minPinLength
- Enterprise attestation (configurable AAGUID)
- Self attestation
- Permissions support: MC (MakeCredential), GA (GetAssertion), CM (CredMgmt), ACFG (AuthConfig), LBW (LargeBlobWrite)
- Authenticator configuration (alwaysUV, minPINLength, enterpriseAttestation)
- Curves: secp256r1, secp384r1, secp521r1, secp256k1, Ed25519
- PIN protocol v1 and v2 (ECDH key agreement over P-256)
- Discoverable credentials / resident keys (AES-256 encrypted in flash)
- Credential management extension (enumerate, delete, update)
- Device selection
- OATH (TOTP/HOTP via YKOATH protocol specification — Yubico Authenticator app compatible)
- Yubikey OTP (static/dynamic slot-based OTP)
- Challenge-response generation
- Keyboard emulation via HID Keyboard class (OTP typed directly)
- YubiKey management protocol compatibility (ykman compatible)
- Nitrokey nitropy and nitroapp compatible
- Secure Boot and Secure Lock (RP2350 and ESP32-S3 only)
- OTP/eFuse-stored MKEK (Master Key Encryption Key) — RP2350 and ESP32-S3 only
- Large blobs storage (2048 bytes max)
- **Backup with 24 words** — BIP39 mnemonic backup of the device master key
- Secure lock — binds device to host via private key (prevents flash dump attacks)
- Rescue interface — recovery of unresponsive/undetectable devices via minimal CCID stack
- LED status indicator (4 states — see LED Patterns below)
- User presence enforcement via physical BOOTSEL button (press-to-confirm)
- Dynamic VID/PID (configurable at build time or via vendor commands)
- Known VID/PID profiles: `NitroHSM`, `NitroFIDO2`, `NitroStart`, `NitroPro`, `Nitro3`, `Yubikey5`, `YubikeyNeo`, `YubiHSM`, `Gnuk`, `GnuPG`
- LED customization via PicoKey App / vendor commands

**LED Status Patterns (from README — must be implemented exactly):**

| State | Pattern | Description |
|-------|---------|-------------|
| Press to confirm | OFF for 100ms every second (mostly ON) | Waiting for user button press |
| Idle mode | ON for 500ms every second (mostly OFF) | Sleeping, waiting for command |
| Active mode | Blinks 4 times per second (4 Hz) | Awake, ready for command |
| Processing | Blinks 20 times per second (20 Hz) | Busy processing command |

---

### 1.3 `pico-hsm` — Hardware Security Module Application

**Language breakdown:** C 63.3%, Python 28.4%, CMake 1.9%

Also builds on `pico-keys-sdk`. Exposes a CCID interface (smart card) instead of HID.

**Capabilities (full list):**
- RSA key gen + sign + decrypt: 1024 / 2048 / 3072 / 4096 bits
- RSA modes: PSS, PKCS#1v1.5, raw
- ECDSA: secp192r1, secp256r1, secp384r1, secp521r1, brainpoolP256r1/384r1/512r1, secp192k1, secp256k1, Curve25519, Curve448
- ECDH (secp*, X25519, X448)
- EC key derivation
- AES key gen + all modes: ECB, CBC, CFB, OFB, CTR, GCM, CCM, XTS, ChaCha20-Poly1305
- CMAC, HMAC (SHA-1/224/256/384/512)
- KDFs: HKDF, PBKDF2, X963-KDF, SLIP10
- BIP32 HD / SLIP10 hierarchical deterministic keys
- SHA digests: SHA-1, SHA-224, SHA-256, SHA-384, SHA-512
- PKCS#11 interface (via OpenSC `sc-hsm` or CardContact `sc-hsm-embedded` driver)
- PKCS#15 internal data structure
- PIN authorization (alphanumeric, session-scoped)
- DKEK shares with n-of-m threshold scheme
- Multiple key domains (per-domain DKEK)
- Key usage counter
- HRNG
- CV certificates + requests
- X.509 attestation (signed by external PKI)
- Import/export (WKY, PKCS#12) — requires DKEK
- Transport PIN
- Press-to-confirm button
- Binary data storage
- Real-time clock (RTC)
- Secure Messaging / EAC (SCP - secure channel protocol)
- Session PIN
- PKI CVCert for secure messaging
- Public Key Authentication challenge-response
- Secure Lock (binds device to host via private key)
- OTP-stored MKEK
- Secure Boot
- Extended APDU (up to 65535 bytes)
- XKEK (extended key encryption key scheme)
- Multiple key domains
- Rescue interface
- LED customization
- Dynamic VID/PID

---

## 2. Feasibility Assessment

**Short answer: YES — a full Rust rewrite is absolutely feasible.**

The Rust embedded ecosystem has matured dramatically. The key reasons this is now realistic:

| Concern | Status |
|---------|--------|
| No `std` / no alloc embedded Rust | ✅ Mature — Embassy, RustCrypto all support `no_std` |
| USB device stack (HID + CCID) | ✅ `embassy-usb` HID ready; CCID class needs implementation (no existing crate, but straightforward on `embassy-usb` bulk framework) |
| Cryptography parity with mbedTLS | ✅ RustCrypto covers all algorithms; RSA up to 4096; note Marvin attack advisory on `rsa` crate |
| RP2040/RP2350 support | ✅ `embassy-rp` v0.9.0 covers both |
| ESP32-S3 support | ✅ `esp-hal` v1.0.0 + embassy integration |
| ESP32-C5 support | ✅ `esp-hal` covers all ESP32 variants; C5 has full USB OTG on GPIO13/14 |
| ESP32-C6 support | ⚠️ C6 has `USB-Serial-JTAG` peripheral (GPIO12/13) — USB 2.0 FS at physical layer but NOT a programmable USB device controller; cannot implement HID/CCID natively |
| SAMD21 support | ✅ `atsamd-hal` v0.23.3 |
| Flash key-value storage | ✅ `sequential-storage` v7.1.0 — wear-levelled, power-fail-safe |
| CBOR | ✅ `cbor4ii`, `minicbor` (both no_std) |
| CTAP2 types | ✅ `ctap-types` v0.4.0 |
| FIDO2 protocol logic | ✅ `fido-authenticator` v0.2.0 (Trussed, Apache2/MIT) — as reference or base |
| BIP32/SLIP10 | ✅ `bip32` v0.5.3 (no_std) |
| ASN.1 / DER / PKCS | ✅ RustCrypto `der`, `pkcs8`, `x509-cert` |
| Host CLI | ✅ `hidapi`, `pcsc`, `clap` v4, all mature |
| Async runtime | ✅ Embassy executor — zero alloc, cooperative multitasking |

**Notable challenges** (detailed in section 12):
- CCID USB class — needs to be written (≈ 1-2 weeks effort, well-documented spec)
- RSA key generation is slow on bare metal — same as C version; use optimization profile
- `rsa` crate has Marvin-attack advisory — mitigate with constant-time blinding or switch to `openssl` on host
- ESP32-C6 has no native full-speed USB device port (requires external USB hub or using USB-to-serial bridge chip)

---

## 3. Target Platform Matrix

| Board / MCU | Target Triple | HAL Crate | USB for HID/CCID | USB Pins | Secure Boot | OTP/eFuse | Flash |
|-------------|--------------|-----------|---------|----------|-------------|-----------|-------|
| Raspberry Pi Pico (RP2040) | `thumbv6m-none-eabi` | `embassy-rp` | ✅ Native USB FS device | GPIO26 (D−) / GPIO27 (D+) | ❌ | ❌ | 2MB QSPI |
| Raspberry Pi Pico 2 (RP2350) | `thumbv8m.main-none-eabihf` | `embassy-rp` | ✅ Native USB FS device | GPIO26 (D−) / GPIO27 (D+) | ✅ ARM TrustZone | ✅ OTP | 2MB QSPI |
| ESP32-S3 DevKitC-1 | `xtensa-esp32s3-none-elf` | `esp-hal` | ✅ USB OTG DWC2 (USB 1.1 FS) | GPIO19 (D−) / GPIO20 (D+) | ✅ | ✅ eFuse | 4-16MB SPI |
| ESP32-C5 DevKitC-1 | `riscv32imac-unknown-none-elf` | `esp-hal` | ✅ USB OTG (USB 2.0 FS, 12 Mbps) | GPIO13 (D−) / GPIO14 (D+) | ✅ | ✅ eFuse | 4MB SPI |
| ESP32-C6 DevKitC-1 | `riscv32imac-unknown-none-elf` | `esp-hal` | ⚠️ USB-Serial-JTAG ONLY (CDC-ACM) | GPIO12 (D−) / GPIO13 (D+) | ✅ | ✅ eFuse | 4-8MB SPI |
| Atmel SAMD21 (e.g. Arduino Zero) | `thumbv6m-none-eabi` | `atsamd-hal` | ✅ Native USB FS device | USB_DP / USB_DN (dedicated pads) | ❌ | ❌ | 256KB flash |

> **ESP32-C6 Note (CORRECTED):** The C6 has a `USB-Serial-JTAG` peripheral routed to GPIO12 (USB_D−) and GPIO13 (USB_D+). From the host's perspective, this appears as USB 2.0 Full Speed (up to 12 Mbps). However, this peripheral is NOT a general-purpose USB device controller (not an OTG/DWC2 core). The firmware cannot program arbitrary USB device classes through it. Only JTAG and CDC-ACM (serial) are supported via this peripheral. 
>
> To implement USB HID/CCID on C6 you need: (a) an external USB bridge chip such as CH9328 (HID) or a smart card UART bridge, or (b) limit C6 to BLE FIDO / serial-only mode, or (c) use the C6 for non-USB embedded applications (IoT devices with Wi-Fi-based FIDO). **ESP32-C5 (GPIO13/14 USB OTG) is the correct C-series alternative for full USB HID/CCID support.**

> **SAMD21 Note:** 256KB flash is tight for RSA/HSM features. FIDO2 (with smaller key set) is feasible. Recommend 512KB+ variants (SAMD51) for HSM.

---

## 4. Hardware GPIO Reference — Buttons, LEDs & USB Pins

This section documents the exact GPIO assignments for BOOTSEL/user buttons, reset buttons, and LEDs on all supported development boards. This information is sourced directly from official Espressif dev-kit documentation and Raspberry Pi Pico datasheets.

### 4.1 Button & LED GPIO Table

| Board | BOOTSEL / User Button | Reset Button | LED GPIO | LED Type | LED Driver |
|-------|-----------------------|--------------|----------|---------- |-----------|
| **RP2040 Pico** | QSPI_SS_N (SIO HI_IN bit 1) ¹ | RUN pin (pull to GND) ² | GPIO25 | Single-color (white/green) | Digital output |
| **RP2350 Pico 2** | QSPI_SS_N (SIO HI_IN bit 1) ¹ | Dedicated RESET button ✅ | GPIO25 | Single-color | Digital output |
| **ESP32-S3 DevKitC-1 v1.0** | GPIO0 (pull low = boot mode) | EN / RST button | GPIO48 | WS2812 RGB addressable | RMT/SPI |
| **ESP32-S3 DevKitC-1 v1.1** | GPIO0 (pull low = boot mode) | EN / RST button | GPIO38 | WS2812 RGB addressable | RMT/SPI |
| **ESP32-C5 DevKitC-1** | GPIO7 (strapping, pull low) ³ | RST button | GPIO27 | WS2812 RGB addressable | RMT |
| **ESP32-C6 DevKitC-1** | GPIO9 (strapping, pull low) | EN / RST button | GPIO8 | WS2812 RGB addressable | RMT |
| **SAMD21 (Arduino Zero)** | Double-tap RST = bootloader ⁴ | RESET button | GPIO13 | Single-color (amber/red) | Digital output |
| **SAMD21 (Adafruit Feather M0)** | Double-tap RST = bootloader ⁴ | RESET button | GPIO13 | Single-color (red) | Digital output |

**Footnotes:**

¹ **RP2040/RP2350 BOOTSEL**: The BOOTSEL button does not use a standard GPIO. It connects QSPI_SS_N to GND. Reading it while firmware is running requires using SIO QSPI high registers (`sio_hw->gpio_hi_in & (1 << 1)`). In `embassy-rp`, this can be accessed via `QSPI_SS` GPIO handling. Because it shares the QSPI bus, reading it can interfere with flash access on RP2040 — reading in a cache-locked section is recommended. On RP2350 the same mechanism applies.

² **RP2040 Reset**: The standard Pico does NOT have a dedicated RESET button. The `RUN` pin (pin 30) can be briefly pulled to GND to reset the device. The Pico 2 (RP2350) DOES have a physical `RESET` button.

³ **ESP32-C5 Boot Button**: GPIO7 is a strapping pin. DevKit holds it low via the BOOT button. After boot, it becomes a free GPIO. The BOOT button on the DevKit is rated for user-presence detection.

⁴ **SAMD21 Boot**: SAMD21 has no GPIO-accessible BOOTSEL equivalent. Double-tapping the RESET button enters UF2 bootloader mode. For user-presence confirmation a dedicated GPIO button pad should be used (configurable via CLI).

### 4.2 USB Pin Reference

| Board | USB D+ Pin | USB D− Pin | USB Controller Type | Notes |
|-------|-----------|-----------|---------------------|-------|
| RP2040 Pico | GPIO27 / USB_DP | GPIO26 / USB_DM | Native USB FS (on-chip) | 12 Mbps max |
| RP2350 Pico 2 | GPIO27 / USB_DP | GPIO26 / USB_DM | Native USB FS (enhanced) | 12 Mbps, improved USB |
| ESP32-S3 DevKitC-1 | GPIO20 / USB_D+ | GPIO19 / USB_D− | DWC2 USB OTG | USB 1.1 spec (12 Mbps) |
| ESP32-C5 DevKitC-1 | GPIO14 / USB_D+ | GPIO13 / USB_D− | USB OTG Full Speed | USB 2.0 FS (12 Mbps) |
| ESP32-C6 DevKitC-1 | GPIO13 / USB_D+ | GPIO12 / USB_D− | **USB-Serial-JTAG only** | ⚠️ CDC/JTAG only, NO HID/CCID |
| SAMD21 (Arduino Zero) | PA25 / USB_D+ | PA24 / USB_D− | Atmel USB FS | 12 Mbps, SERCOM-based |

### 4.3 Configurability via CLI

The `picokeys-cli config` subcommand must support:

```
picokeys-cli config led gpio <GPIO_NUM>           # Set LED GPIO pin (for non-standard boards)
picokeys-cli config led type [single|rgb]         # LED type: single-color or addressable RGB
picokeys-cli config button gpio <GPIO_NUM>        # Set user/BOOTSEL button GPIO (for SAMD21 or custom boards)
picokeys-cli config button polarity [active-low|active-high]  # Button logic polarity
picokeys-cli config button timeout <SECONDS>      # Press-to-confirm timeout (default: 15s)
picokeys-cli config press-to-confirm [on|off]     # Enable/disable press-to-confirm
```

LED GPIO and button GPIO are stored in flash (first-time configurable), so the same firmware binary works across different hardware variants.

### 4.4 Press-to-Confirm Implementation Notes

The press-to-confirm button (BOOTSEL on Pico/ESP32, user button on SAMD21) should:

1. **RP2040/RP2350**: Poll `sio_hw->gpio_hi_in & (1 << 1)` in a cache-locked loop to safely read QSPI_SS_N without disturbing flash access. This is what the original picokeys C code does via `gpio_set_pulls(PICO_BOOTSEL_VIA_DOUBLE_RESET_GPIO, ...)`.
2. **ESP32-S3/C5/C6**: Read the BOOT/IO0 GPIO directly (active-low, internal pull-up).
3. **SAMD21**: Read the configured user button GPIO (no built-in button — uses external button on configurable GPIO or defaults to simulated-always-confirmed for headless use).

The wait loop:
- LED: shows "Press to confirm" pattern (mostly ON, 100ms OFF per second)
- Sends timeout keepalive APDUs/HID frames to host every 10s to prevent session timeout
- When button pressed: operation proceeds, LED returns to normal
- Timeout: no button = operation denied after `button_timeout` seconds (configurable; pico-hsm default is "wait forever")

---

## 5. Rust Crate Inventory (annotated)

### 5.1 Embedded Runtime & HAL

| Crate | Version | Purpose | no_std | Notes |
|-------|---------|---------|--------|-------|
| `embassy-executor` | 0.7 | Async task executor | ✅ | Zero-alloc, interrupt-driven |
| `embassy-rp` | 0.9.0 | RP2040 + RP2350 HAL | ✅ | USB, flash, RNG, GPIO, timers |
| `embassy-usb` | 0.5.1 | USB device stack | ✅ | HID built-in; CCID via custom class |
| `embassy-usb-driver` | 0.1 | USB driver trait | ✅ | Backend abstraction |
| `embassy-usb-synopsys-otg` | 0.1 | DWC2/OTG USB IP | ✅ | Used by ESP32-S3, ESP32-C5 |
| `embassy-time` | 0.4 | Timekeeping | ✅ | Monotonic timer, delays |
| `embassy-sync` | 0.6 | Channels, mutexes | ✅ | Cross-task comms |
| `embassy-futures` | 0.1 | Future utilities | ✅ | select!, join! etc. |
| `embassy-boot` | 0.4 | Bootloader + DFU | ✅ | OTA firmware updates |
| `esp-hal` | 1.0.0 | ESP32 family HAL (S3/C5/C6) | ✅ | Official Espressif Rust HAL |
| `esp-backtrace` | 0.15 | ESP32 panic handler | ✅ | — |
| `esp-println` | 0.13 | ESP32 debug printing | ✅ | — |
| `atsamd-hal` | 0.23.3 | SAMD21/D51 HAL | ✅ | USB, flash, RNG |
| `cortex-m` | 0.7 | Cortex-M peripherals | ✅ | SysTick, NVIC, etc. |
| `cortex-m-rt` | 0.7 | Cortex-M runtime | ✅ | Stack setup, interrupt table |
| `heapless` | 0.8 | Fixed-capacity collections | ✅ | Vec, String, HashMap w/o alloc |
| `embedded_alloc` | 0.6 | Simple heap allocator for embedded | ✅ | Needed for RSA (large key buffers) |
| `defmt` | 0.3 | Structured embedded logging | ✅ | Efficient log via probe |
| `defmt-rtt` | 0.4 | RTT defmt backend | ✅ | — |
| `panic-probe` | 0.3 | Panic handler (defmt) | ✅ | — |
| `panic-halt` | 0.2 | Minimal panic handler | ✅ | Production use |
| `embedded-hal` | 1.0 | Hardware abstraction traits | ✅ | Universal GPIO/SPI/I2C traits |
| `embedded-storage` | 0.3 | Flash storage abstraction | ✅ | Required by sequential-storage |

### 5.2 LED — RGB & Single-Color

| Crate | Version | Purpose | no_std | Notes |
|-------|---------|---------|--------|-------|
| `smart-leds` | 0.4 | Unified RGB LED trait | ✅ | Works with ws2812 backends |
| `ws2812-pio` | 0.7 | WS2812 via RP2040 PIO | ✅ | Zero CPU overhead for Pico boards |
| `ws2812-spi` | 0.5 | WS2812 via SPI (non-PIO) | ✅ | Fallback for non-PIO platforms |
| `esp-hal` RMT | included | WS2812 via ESP32 RMT peripheral | ✅ | Built-in to esp-hal for ESP32 boards |

> **LED Strategy by Platform:**
> - RP2040/RP2350: use `ws2812-pio` (PIO state machine, no CPU overhead)
> - ESP32-S3/C5/C6: use `esp-hal` RMT driver (hardware PWM, native WS2812 support)
> - SAMD21 / generic: use `ws2812-spi` OR simple single-pin GPIO

### 5.3 USB Transport Layer

| Crate | Version | Purpose | Notes |
|-------|---------|---------|-------|
| `embassy-usb` | 0.5.1 | USB device framework | Composite device support (HID + CCID + CDC) |
| `usbd-hid` | 0.9.0 | USB HID class | HID descriptor macros, report structs |
| `usb-device` | 0.3 | Alternative USB stack | More mature but sync; embassy-usb preferred |
| *(custom)* | — | CCID USB class | Build on embassy-usb bulk endpoints; ~500 LOC |
| *(custom)* | — | CTAP HID framing | Implements U2F HID channel multiplexing |

> **CCID note:** No `embassy-usb-ccid` crate exists (as of early 2026). The CCID spec (USB ICCD) is well-documented and the implementation on top of `embassy-usb` bulk/interrupt endpoints is straightforward. Reference: [USB CCID spec, Rev 1.1](https://www.usb.org/document-library/smart-card-ccid-version-11).

### 5.4 APDU & Smart Card Protocols

| Crate | Version | Purpose | no_std | Notes |
|-------|---------|---------|--------|-------|
| `iso7816` | 0.2.0 | ISO 7816-4 types (APDU, status words) | ✅ | From trussed-dev |
| `apdu-core` | 0.4.0 | APDU command composition | ✅ | Host-side or device-side |
| `pcsc` | 2.9.0 | PC/SC smart card bindings (HOST only) | ❌ | For CLI tool, CCID communication |

### 5.5 FIDO / CTAP Protocol

| Crate | Version | Purpose | no_std | Notes |
|-------|---------|---------|--------|-------|
| `ctap-types` | 0.4.0 | CTAP2 type definitions | ✅ | From trussed-dev; defines CBOR structures |
| `fido-authenticator` | 0.2.0 | FIDO2 authenticator (Trussed app) | ✅ | Apache2/MIT; implements CTAP2.1 handlers; used by SoloKey2, Nitrokey3 |
| `trussed` | 0.1.0 | Embedded crypto service framework | ✅ | Optional: use as crypto service bus |
| `ctap-hid-fido2` | 3.5.8 | CTAP HID client (HOST CLI) | ❌ | For CLI: list/delete credentials, etc. |
| `cosey` | 0.3.0 | COSE key encoding/decoding | ✅ | CTAP2 uses COSE for public key representation |

> **Trussed note:** `fido-authenticator` wraps a complete CTAP 2.1 implementation. It uses `trussed` as a crypto service. See Section 6 for a detailed analysis on whether to adopt or reference this crate.

### 5.6 CBOR Encoding/Decoding

| Crate | Version | Purpose | no_std | Notes |
|-------|---------|---------|--------|-------|
| `cbor4ii` | 1.2.2 | CBOR encode/decode | ✅ | serde support, no alloc mode |
| `minicbor` | 0.24 | Minimal CBOR | ✅ | Type-driven, derive macros |
| `ciborium` | 0.2 | Full CBOR (serde) | ✅ (partial) | Needs alloc for dynamic types |

### 5.7 Cryptography (RustCrypto — all no_std)

#### Elliptic Curves
| Crate | Version | Algorithms | Notes |
|-------|---------|-----------|-------|
| `p256` | 0.13.2 | secp256r1: ECDSA sign/verify, ECDH | Pure Rust, constant-time |
| `p384` | 0.13.2 | secp384r1: ECDSA, ECDH | — |
| `p521` | 0.13.2 | secp521r1: ECDSA, ECDH | — |
| `k256` | 0.13.3 | secp256k1: ECDSA, ECDH | — |
| `ed25519-dalek` | 2.2.0 | Ed25519 signatures, batch verify | 99M+ downloads |
| `x25519-dalek` | 2.0 | X25519 Diffie-Hellman | — |
| `curve25519-dalek` | 4.1 | Curve25519 primitives | — |
| `bls12_381` | 0.8 | BLS pairing curves (future PQC prep) | Optional |

#### RSA
| Crate | Version | Algorithms | Notes |
|-------|---------|-----------|-------|
| `rsa` | 0.9.10 | RSA-PKCS1v1.5, RSA-OAEP, RSA-PSS; 1024-4096 | ⚠️ RUSTSEC-2023-0071 Marvin attack advisory; mitigated by blinding — same risk level as mbedTLS |

#### Symmetric Cryptography
| Crate | Version | Algorithms | Notes |
|-------|---------|-----------|-------|
| `aes` | 0.8 | AES block cipher (128/192/256) | Pure Rust + AES-NI on x86 |
| `aes-gcm` | 0.10.3 | AES-GCM AEAD | — |
| `aes-ccm` | 0.5 | AES-CCM | — |
| `cbc` | 0.1 | CBC mode | — |
| `cfb-mode` | 0.8 | CFB mode | — |
| `ofb` | 0.6 | OFB mode | — |
| `ctr` | 0.9 | CTR mode | — |
| `xts-mode` | 0.5 | XTS mode (disk encryption) | For AES-XTS |
| `chacha20poly1305` | 0.10 | ChaCha20-Poly1305 AEAD | — |
| `cmac` | 0.7 | AES-CMAC | — |
| `ccm` | 0.5 | AES-CCM | — |

#### Digests & MACs
| Crate | Version | Algorithms | Notes |
|-------|---------|-----------|-------|
| `sha1` | 0.10 | SHA-1 | — |
| `sha2` | 0.10 | SHA-224, SHA-256, SHA-384, SHA-512 | — |
| `sha3` | 0.10 | SHA3-256, SHAKE | Future extensibility |
| `hmac` | 0.12.1 | HMAC (any digest) | 326M downloads |
| `hkdf` | 0.12 | HKDF key derivation | — |
| `pbkdf2` | 0.12 | PBKDF2 key derivation | — |

#### Security Primitives (CRITICAL for FIDO/HSM)
| Crate | Version | Algorithms | Notes |
|-------|---------|-----------|-------|
| `zeroize` | 1.8 | Zero sensitive data on drop | ✅ **MANDATORY** — all key material must implement Zeroize |
| `subtle` | 2.6 | Constant-time comparisons | ✅ **MANDATORY** — for PIN/HMAC verification, prevents timing attacks |

#### Key Encoding & X.509
| Crate | Version | Purpose | no_std |
|-------|---------|---------|--------|
| `der` | 0.7 | DER/BER encoding | ✅ |
| `pkcs8` | 0.10 | PKCS#8 private key format | ✅ |
| `pkcs1` | 0.7 | PKCS#1 RSA key format | ✅ |
| `sec1` | 0.7 | SEC1 EC point format | ✅ |
| `x509-cert` | 0.2 | X.509 certificates | ✅ |
| `spki` | 0.7 | SubjectPublicKeyInfo | ✅ |

#### HD Key Derivation
| Crate | Version | Purpose | no_std |
|-------|---------|---------|--------|
| `bip32` | 0.5.3 | BIP32 HD key derivation | ✅ | BIP32 asymmetric HD keys |
| `bip39` | 2.1 | BIP39 mnemonic words | ✅ | 24-word backup phrase — maps to `Backup with 24 words` feature |
| `slip10` | custom | SLIP10 for symmetric keys | Implement over HMAC-SHA512 |

#### Post-Quantum (Future)
| Crate | Version | Purpose | Notes |
|-------|---------|---------|-------|
| `ml-kem` | 0.3 | ML-KEM (Kyber) NIST PQC | pico-keys-sdk added as submodule |

### 5.8 Storage

| Crate | Version | Purpose | no_std | Notes |
|-------|---------|---------|--------|-------|
| `sequential-storage` | 7.1.0 | Wear-levelled key-value + queue flash store | ✅ | Production-ready, power-fail-safe |
| `embedded-storage` | 0.3 | Flash read/write/erase traits | ✅ | Required by sequential-storage |
| `ekv` | git | Alternative KV store (Embassy) | ✅ | If more performance needed |

### 5.9 Random Number Generation

| Crate | Version | Purpose | Notes |
|-------|---------|---------|-------|
| `rand_core` | 0.6 | RNG traits | Use with TRNG from HAL |
| `embassy-rp` TRNG | included | RP2040/RP2350 hardware RNG | Via rosc_read or dedicated TRNG |
| `esp-hal` RNG | included | ESP32 hardware RNG | esp_hal::rng |
| `atsamd-hal` TRNG | 0.21+ | SAMD21 RNG (limited) | SAMD51 has dedicated TRNG |

### 5.10 OTP / OATH

| Crate | Version | Purpose | no_std |
|-------|---------|---------|--------|
| `totp-lite` | 2.0.1 | TOTP (RFC 6238) | ✅ (via hmac) |
| *(custom hotp)* | — | HOTP (RFC 4226) over `hmac` | 10 LOC |

### 5.11 Firmware Update / DFU

| Crate | Version | Purpose | no_std | Notes |
|-------|---------|---------|--------|-------|
| `embassy-boot` | 0.4 | Bootloader + A/B OTA update | ✅ | Supports RP2040, RP2350, STM32 |
| `dfu-core` | 0.3 | USB DFU device class | ✅ | DFU over USB for firmware updates |
| `usbd-dfu` | 0.3 | USB DFU class (usb-device stack) | ✅ | Alternative to embassy-boot DFU |
| `embassy-boot-rp` | 0.4 | RP2040/RP2350 specific boot | ✅ | Flash partition management |
| `embassy-boot-stm32` | 0.4 | (reference only) | ✅ | — |

### 5.12 CLI Host Tool Crates

| Crate | Version | Purpose | Notes |
|-------|---------|---------|-------|
| `clap` | 4.5.60 | Argument parsing | 698M downloads; derive macros |
| `hidapi` | 2.6.5 | USB HID communication (FIDO/CTAP) | Cross-platform libhidapi binding |
| `pcsc` | 2.9.0 | PC/SC smart card (CCID) | Linux/macOS/Windows |
| `ctap-hid-fido2` | 3.5.8 | CTAP2 HID client library | List credentials, manage FIDO |
| `serde` | 1.0 | Serialization framework | JSON/CBOR config export |
| `serde_json` | 1.0 | JSON I/O | Config print, import/export |
| `tokio` | 1.0 | Async runtime (CLI) | For concurrent device ops |
| `anyhow` | 1.0 | Error handling | Ergonomic error propagation |
| `thiserror` | 1.0 | Error type derivation | Device error types |
| `tracing` | 0.1 | Application logging | Structured logs |
| `tracing-subscriber` | 0.3 | Log output | stdout / file |
| `indicatif` | 0.17 | Progress bars | Key generation, firmware flash |
| `dialoguer` | 0.11 | Interactive prompts (PIN entry, confirm) | Secure PIN input |
| `colored` | 2.0 | Terminal colours | Status output |
| `tabled` | 0.16 | ASCII table output | Credential list display |
| `espflash` | 3.x | Flash ESP32 firmware over USB | CLI wraps or invokes espflash |
| `probe-rs` CLI | 0.24 | Flash RP2040/RP2350 via SWD | CLI integration for probe-based flashing |
| `elf2uf2-rs` | 2.0 | Convert ELF to UF2 for Pico | For drag-and-drop Pico flashing |
| `bossac` | extern | Flash SAMD21 | External tool invocation |

---

## 6. Existing Mature Rust FIDO2/CTAP2 Crates — Reuse Analysis

This section analyses the maturity and applicability of existing Rust FIDO2/CTAP2 crates. The goal is to identify which can be directly adopted vs. which should only be referenced.

### 6.1 `fido-authenticator` v0.2.0 (trussed-dev)

| Property | Value |
|----------|-------|
| Repository | `github.com/trussed-dev/fido-authenticator` |
| License | Apache-2.0 OR MIT (dual) |
| no_std | ✅ |
| CTAP version | CTAP 2.1 |
| Used in production | SoloKeys Solo 2, Nitrokey 3 |
| Downloads | ~9,483 total (niche but production-grade) |
| Last release | ~6 months ago |

**What it implements:**
- Full CTAP 2.1 MakeCredential, GetAssertion, GetInfo, ClientPIN
- Discoverable credentials
- HMAC-Secret extension
- PIN protocol v1 and v2
- Credential management

**What it does NOT implement (vs pico-fido):**
- OATH (TOTP/HOTP/YKOATH) — not part of CTAP2 spec
- YubiKey OTP slots — Yubico-proprietary
- Keyboard emulation (HID keyboard class)
- YubiKey management protocol (YKMAN compatibility)
- Secure Boot / OTP-stored MKEK provisioning
- 24-word backup
- LED customization / vendor commands
- Rescue interface

**Architecture:**
`fido-authenticator` requires `trussed` as a crypto service bus. Trussed provides a safe, brokered API for crypto operations (sign, verify, encrypt, etc.) via a message-passing model. This has advantages (security audit surface reduction) but also means:
- You must port or implement a Trussed backend for your hardware HAL
- Trussed adds complexity to the multi-platform adaptation
- The SoloKeys/Nitrokey Trussed backends are hardware-specific

**Recommendation:**
> **Use as reference implementation and source of CTAP type definitions.** Import `ctap-types` (the type definitions crate that `fido-authenticator` uses internally) directly. Write a thin protocol layer on top that calls into our own `pico-rs-sdk` crypto/storage layer. This gives us full control for OATH, OTP, LED, vendor commands etc. while benefiting from a well-tested spec implementation as reference.

### 6.2 `ctap-types` v0.4.0

| Property | Value |
|----------|-------|
| Repository | `github.com/trussed-dev/ctap-types` |
| License | Apache-2.0 OR MIT |
| no_std | ✅ |

**What it provides:**
- All CTAP2 request/response type definitions
- CBOR serialization structures for CTAP2 commands
- Status code enumerations
- Extension types

**Recommendation:** ✅ **USE DIRECTLY.** This is pure type definitions with no logic. Include it as a dependency in `pico-rs-fido` to avoid duplicating the CTAP2 type system.

### 6.3 `cosey` v0.3.0

| Property | Value |
|----------|-------|
| Repository | `github.com/trussed-dev/cosey` |
| License | Apache-2.0 OR MIT |
| no_std | ✅ |

**What it provides:** COSE (CBOR Object Signing and Encryption) key encoding. CTAP2 uses COSE for public key representation in attestation objects.

**Recommendation:** ✅ **USE DIRECTLY.** Required for CTAP2 attestation output.

### 6.4 `iso7816` v0.2.0

| Property | Value |
|----------|-------|
| Repository | `github.com/trussed-dev/iso7816` |
| License | Apache-2.0 OR MIT |
| no_std | ✅ |

**What it provides:** ISO 7816-4 APDU command/response types, status words (SW_0000, SW_6A82, etc.), AID types.

**Recommendation:** ✅ **USE DIRECTLY.** Essential for CCID / smart card (HSM) implementation.

### 6.5 `trussed` v0.1.0

**Recommendation:** ⚠️ **REFERENCE ONLY (do not adopt as architectural base).** Trussed is a complex framework designed for a specific hardware model (SoloKeys/Nitrokey). Adopting it would lock us into their message-passing/service architecture. Instead, use the Trussed crate family for reference and type reuse, but build our own crypto service layer in `pico-rs-sdk`.

### 6.6 `ctap-hid-fido2` v3.5.8 (HOST-side)

| Property | Value |
|----------|-------|
| Repository | `github.com/gebogebogebo/ctap-hid-fido2` |
| License | MIT |
| Platform | Host (CLI, desktop) |

**What it provides:** A client library for communicating with CTAP2 devices over USB HID. Lists credentials, reads device info, sends CTAP commands.

**Recommendation:** ✅ **USE in `picokeys-cli`** for FIDO device interaction. This is the most mature Rust library for host-side CTAP2 management.

### 6.7 Summary Table

| Crate | Use in Project | Role |
|-------|---------------|------|
| `fido-authenticator` | Reference only | Study CTAP 2.1 implementation patterns |
| `ctap-types` | **Direct dependency** | CTAP2 request/response types in `pico-rs-fido` |
| `cosey` | **Direct dependency** | COSE key encoding in CTAP2 attestation |
| `iso7816` | **Direct dependency** | APDU types in `pico-rs-sdk` transport layer |
| `trussed` | Reference only | Study crypto service patterns |
| `ctap-hid-fido2` | **Direct dependency** | `picokeys-cli` FIDO host communication |

---

## 7. Modular Architecture Design

### 7.1 Workspace Overview

```
picokeys-v2/
├── pico-rs-sdk/          # Core SDK (equivalent to pico-keys-sdk)
│   ├── src/              # Platform-agnostic core
│   └── boards/           # Platform-specific adapters
├── pico-rs-fido/         # FIDO2 + OATH application (equivalent to pico-fido)
│   ├── src/              # Application logic
│   └── bin/              # Per-board binary entrypoints
├── pico-rs-hsm/          # HSM application (equivalent to pico-hsm)  [future]
│   ├── src/
│   └── bin/
├── picokeys-cli/         # Host management CLI (ykman equivalent)
│   └── src/
└── Cargo.toml            # Workspace root
```

### 7.2 pico-rs-sdk Crate Structure

The SDK provides traits and implementations that the application crates depend on. No application-specific code here.

```
pico-rs-sdk/
├── Cargo.toml
└── src/
    ├── lib.rs                  # SDK entry point, re-exports
    │
    ├── transport/              # USB transport layer
    │   ├── mod.rs              # Transport trait
    │   ├── hid/
    │   │   ├── mod.rs          # CTAPHID framing (channel mgmt, fragmentation)
    │   │   └── class.rs        # embassy-usb HID class adapter
    │   └── ccid/
    │       ├── mod.rs          # CCID protocol framing (T=0, T=1, extended APDU)
    │       └── class.rs        # Custom embassy-usb CCID class (bulk endpoints)
    │
    ├── apdu/
    │   ├── mod.rs              # APDU command dispatch trait
    │   ├── command.rs          # iso7816 command types
    │   ├── response.rs         # iso7816 response / status words
    │   └── chaining.rs         # Extended APDU chaining
    │
    ├── store/
    │   ├── mod.rs              # FileStore trait
    │   ├── flash.rs            # sequential-storage backed flash store
    │   ├── file.rs             # File ID types and logical file objects
    │   └── otp.rs              # OTP/eFuse read/write abstraction
    │
    ├── crypto/
    │   ├── mod.rs              # CryptoProvider trait (backend-agnostic)
    │   ├── rng.rs              # RNG trait + hardware TRNG adapters
    │   ├── ecc.rs              # ECDSA/ECDH operations
    │   ├── rsa.rs              # RSA sign/decrypt/keygen
    │   ├── aes.rs              # AES modes abstraction
    │   ├── symmetric.rs        # HMAC, CMAC, PBKDF2, HKDF
    │   └── asn1.rs             # DER/ASN.1 encode/decode helpers
    │
    ├── eac/
    │   ├── mod.rs              # Chip Authentication / Terminal Authentication
    │   └── secure_channel.rs   # SCP03/EAC channel encryption
    │
    ├── led/
    │   ├── mod.rs              # LedStatus trait
    │   └── patterns.rs         # Idle/Active/Busy/PressConfirm patterns
    │
    ├── button/
    │   └── mod.rs              # Button press / user presence detection
    │
    ├── rescue/
    │   └── mod.rs              # Rescue interface (minimal CCID stack recovery)
    │
    └── platform/               # Feature-gated HAL adapters
        ├── rp2040.rs           # embassy-rp adapter
        ├── rp2350.rs           # embassy-rp + secure boot / OTP
        ├── esp32s3.rs          # esp-hal + secure boot / eFuse
        ├── esp32c5.rs          # esp-hal RISC-V
        ├── esp32c6.rs          # esp-hal RISC-V (no native USB)
        └── samd21.rs           # atsamd-hal adapter
```

**SDK's critical internal traits:**

```rust
// Transport-agnostic command handler
pub trait Application {
    fn select(&mut self, aid: &[u8]) -> Result<(), Status>;
    fn deselect(&mut self);
    fn call(&mut self, interface: Interface, apdu: &Command) -> Result<Data, Status>;
}

// Flash file abstraction
pub trait FileStore {
    fn read_file(&self, fid: FileId) -> Result<&[u8], StoreError>;
    fn write_file(&mut self, fid: FileId, data: &[u8]) -> Result<(), StoreError>;
    fn delete_file(&mut self, fid: FileId) -> Result<(), StoreError>;
    fn exists(&self, fid: FileId) -> bool;
}

// Crypto backend (allows swapping implementations)
pub trait CryptoBackend {
    fn ecdsa_sign(&mut self, key: &EcPrivKey, msg: &[u8]) -> Result<Signature, CryptoError>;
    fn rng_fill(&mut self, buf: &mut [u8]);
    // ... etc
}
```

### 7.3 pico-rs-fido Crate Structure

```
pico-rs-fido/
├── Cargo.toml
└── src/
    ├── lib.rs                  # Library entrypoint
    │
    ├── fido/
    │   ├── mod.rs              # FIDO application main loop + CTAPHID dispatch
    │   ├── ctap.rs             # CTAP2 command enum + router
    │   ├── make_credential.rs  # CTAP2 MakeCredential handler
    │   ├── get_assertion.rs    # CTAP2 GetAssertion handler
    │   ├── get_info.rs         # CTAP2 GetInfo
    │   ├── client_pin.rs       # PIN protocol v1/v2, user verification
    │   ├── credential_mgmt.rs  # Credential management extension
    │   ├── large_blobs.rs      # Large blobs storage
    │   ├── config.rs           # AuthenticatorConfig
    │   ├── vendor.rs           # Vendor commands (LED, rescue, etc.)
    │   ├── reset.rs            # CTAP2 Reset
    │   └── selection.rs        # Device selection
    │
    ├── u2f/
    │   ├── mod.rs              # U2F / CTAP1 application
    │   ├── register.rs         # U2F register
    │   └── authenticate.rs     # U2F authenticate
    │
    ├── credential/
    │   ├── mod.rs              # Resident credential storage + serialisation
    │   ├── id.rs               # Credential ID format (encrypted)
    │   └── kek.rs              # Key encryption key (MKEK from OTP)
    │
    ├── extensions/
    │   ├── hmac_secret.rs      # HMAC-Secret extension
    │   ├── cred_protect.rs     # CredProtect extension
    │   ├── cred_blob.rs        # credBlob extension
    │   ├── large_blob_key.rs   # largeBlobKey extension
    │   └── min_pin_length.rs   # minPinLength extension
    │
    ├── oath/
    │   ├── mod.rs              # OATH application (YKOATH protocol)
    │   ├── totp.rs             # TOTP (RFC 6238)
    │   ├── hotp.rs             # HOTP (RFC 4226)
    │   └── yubikey_otp.rs      # Yubikey OTP (static/dynamic slots)
    │
    ├── management/
    │   └── mod.rs              # Yubikey management protocol
    │
    └── bin/
        ├── rp2040.rs           # #[embassy_executor::main] entrypoint for RP2040
        ├── rp2350.rs           # RP2350 entrypoint + secure boot init
        ├── esp32s3.rs          # ESP32-S3 entrypoint
        ├── esp32c5.rs          # ESP32-C5 entrypoint  
        ├── esp32c6.rs          # ESP32-C6 entrypoint (serial/BLE only)
        └── samd21.rs           # SAMD21 entrypoint
```

### 7.4 pico-rs-hsm Crate Structure (Future Module)

```
pico-rs-hsm/
├── Cargo.toml
└── src/
    ├── lib.rs
    │
    ├── hsm/
    │   ├── mod.rs              # HSM application main loop + CCID dispatch
    │   ├── apdu_router.rs      # SmartCard-HSM APDU command router
    │   ├── initialize.rs       # Device initialization, PIN setup
    │   ├── key_management.rs   # Key gen, import, export, delete
    │   ├── sign.rs             # Sign operations (RSA, ECDSA, EdDSA)
    │   ├── decrypt.rs          # Decrypt operations (RSA-OAEP, RSA-PKCS)
    │   ├── ecdh.rs             # ECDH key agreement
    │   ├── aes_ops.rs          # AES cipher operations
    │   ├── derive.rs           # KDF operations (HKDF, PBKDF2, BIP32)
    │   ├── dkek.rs             # DKEK shares, n-of-m threshold
    │   ├── secure_msg.rs       # Secure Messaging (EAC SCP)
    │   ├── certificates.rs     # CV cert import/export
    │   ├── attestation.rs      # Key attestation
    │   ├── pin.rs              # PIN management, session PIN
    │   └── rtc.rs              # Real-time clock
    │
    └── bin/ ...                # Same per-board entrypoints
```

### 7.5 Dependency Graph (simplified)

```
picokeys-cli  ─────────────────────────────────────►  hidapi, pcsc, clap, ctap-hid-fido2
     │
     │  (shared protocol types)
     ▼

pico-rs-fido ──────────────────────────────────────►  pico-rs-sdk
     │                                                      │
     │  ctap-types, fido-authenticator (optional)           │  embassy-usb
     │  cbor4ii, totp-lite, hmac, p256, ed25519-dalek       │  sequential-storage
     │  bip32, aes-gcm, chacha20poly1305                    │  RustCrypto crypto primitives
     │  heapless, defmt                                     │  embedded-storage
     ▼                                                      │  HAL crates (embassy-rp / esp-hal / atsamd-hal)
                                                            ▼
pico-rs-hsm ──────────────────────────────────────►  pico-rs-sdk
     │
     │  rsa, p256/384/521/k256, aes-gcm, chacha20poly1305
     │  cmac, hkdf, pbkdf2, bip32, x509-cert, der, pkcs8
     │  iso7816, cbor4ii, heapless
```

The key design pillar: **`pico-rs-fido` and `pico-rs-hsm` depend only on `pico-rs-sdk`** for all HAL interactions. Neither application directly imports HAL crates. This mirrors the pico-keys-sdk architecture exactly.

---

## 8. Folder & Workspace Structure

```
picokeys-v2/
├── Cargo.toml                          # Workspace definition
├── .cargo/
│   └── config.toml                     # Target-specific rustflags, linker settings
├── rust-toolchain.toml                 # Pin Rust nightly/stable version
│
├── pico-rs-sdk/
│   ├── Cargo.toml
│   ├── README.md
│   └── src/ ...
│
├── pico-rs-fido/
│   ├── Cargo.toml
│   ├── README.md
│   ├── memory-rp2040.x                 # Linker script
│   ├── memory-rp2350.x
│   ├── memory-esp32s3.x
│   ├── memory-samd21.x
│   └── src/ ...
│
├── pico-rs-hsm/
│   ├── Cargo.toml
│   ├── README.md
│   └── src/ ...
│
├── picokeys-cli/
│   ├── Cargo.toml
│   ├── README.md
│   └── src/
│       ├── main.rs
│       ├── commands/
│       │   ├── mod.rs
│       │   ├── info.rs
│       │   ├── fido.rs
│       │   ├── oath.rs
│       │   ├── otp.rs
│       │   ├── config.rs
│       │   └── flash.rs
│       ├── transport/
│       │   ├── hid.rs              # hidapi + CTAP HID transport
│       │   └── ccid.rs             # pcsc CCID transport
│       └── device/
│           └── mod.rs              # Device detection, connection handling
│
├── docs/
│   ├── architecture.md
│   ├── crates.md
│   └── flashing.md
│
├── tests/
│   ├── fido2/                      # CTAP2 protocol tests (desktop, emulated)
│   └── hsm/                        # PKCS11 / APDU tests
│
└── scripts/
    ├── flash-rp2040.sh
    ├── flash-esp32s3.sh
    └── flash-samd21.sh
```

**Workspace `Cargo.toml`:**

```toml
[workspace]
members = [
    "pico-rs-sdk",
    "pico-rs-fido",
    "pico-rs-hsm",
    "picokeys-cli",
]
resolver = "2"

[profile.release]
opt-level = "s"        # Size-optimised for embedded
lto = true
codegen-units = 1
debug = false

[profile.release.package.num-bigint-dig]
opt-level = 3          # RSA key gen needs speed
```

---

## 9. CLI Tool Design (picokeys-cli) — Two Roles

`picokeys-cli` has **two distinct roles**:

| Role | Purpose | Key Crates |
|------|---------|------------|
| **Role 1: Firmware Management** | Flash, erase, build, configure and update firmware on the device | `espflash`, `probe-rs`, `elf2uf2-rs`, DFU |
| **Role 2: Device Interaction** | `ykman`-like management of a running device (FIDO, OATH, OTP, HSM) | `ctap-hid-fido2`, `hidapi`, `pcsc` |

The two roles are separate top-level subcommand groups: `firmware` and the existing device management commands. The CLI auto-detects connected devices and selects the correct transport.

### Transport Channels

The CLI communicates with the device over:
- **HID** — FIDO operations, CTAP2/U2F (`ctap-hid-fido2` + `hidapi`)
- **CCID/PC-SC** — HSM operations, PKCS#15 (`pcsc`)
- **USB Serial/UART** — Firmware flash (ESP32 via `espflash`, SAMD21 via `bossac`)
- **SWD Debug Probe** — Firmware flash via `probe-rs` (all platforms with a probe)
- **UF2** — RP2040/RP2350 native bootloader, SAMD21 bootloader

### Top-Level Command Structure

```
picokeys-cli [OPTIONS] <COMMAND>

Options:
  -d, --device <SERIAL>    Select specific device by serial number
  -v, --verbose            Verbose logging
  -h, --help
  -V, --version

--- Role 1: Firmware Management ---
  firmware      Flash, erase, build, configure and update device firmware

--- Role 2: Device Interaction (ykman-like) ---
  info          Show device firmware version, serial, capabilities
  fido          FIDO2 credential and authenticator management
  oath          OATH (TOTP/HOTP) account management
  otp           YubiKey OTP slot management
  hsm           HSM (smart card) key management
  config        Device hardware configuration (LED, GPIO, VID/PID, etc.)
```

---

### Role 1: Firmware Management (`picokeys-cli firmware`)

This role handles all operations that concern the device as hardware — flashing, erasing, building, and updating firmware. It is device-type-aware and picks the correct flash tool automatically.

```
picokeys-cli firmware <SUBCOMMAND>

Subcommands:
  flash        Flash a pre-built firmware binary to the device
  erase        Erase all firmware and user data from the device
  build        Build firmware from source for a target platform
  verify       Verify integrity of flashed firmware
  dfu-update   Perform a DFU-based in-application firmware update
  info         Show firmware version, build hash, target platform
```

#### Flash Subcommand

```bash
# Flash a pre-built UF2 to RP2040 (Pico/Pico 2)
picokeys-cli firmware flash --device rp2040 --firmware firmware.uf2

# Flash ESP32-S3 over USB serial (uses espflash internally)
picokeys-cli firmware flash --device esp32s3 --firmware firmware.bin

# Flash SAMD21 via UF2 bootloader (double-tap reset, then drop file)
picokeys-cli firmware flash --device samd21 --firmware firmware.uf2

# Flash ANY device via SWD debug probe (probe-rs)
picokeys-cli firmware flash --device rp2040 --probe --firmware firmware.elf

# Specify port explicitly
picokeys-cli firmware flash --device esp32s3 --port /dev/ttyUSB0 --firmware firmware.bin
```

#### Erase Subcommand

```bash
# Erase all data (factory reset at hardware level)
picokeys-cli firmware erase --device rp2040
picokeys-cli firmware erase --device esp32s3
picokeys-cli firmware erase --device samd21
```

#### Build Subcommand

```bash
# Build RP2040 FIDO firmware locally and output UF2
picokeys-cli firmware build --target rp2040 --output dist/pico_fido.uf2

# Build ESP32-S3 HSM firmware
picokeys-cli firmware build --target esp32s3 --app hsm --output dist/esp32s3_hsm.bin

# Build with custom features
picokeys-cli firmware build --target rp2350 --features "rp2350,fido,oath,otp" --output dist/
```

#### DFU Update

```bash
# Over-the-air update via USB DFU class (device must have DFU bootloader)
picokeys-cli firmware dfu-update --firmware firmware_dfu.bin
picokeys-cli firmware dfu-update --firmware firmware_dfu.bin --vid 0x2e8a --pid 0x0003
```

#### Flash Tool Dispatch (internal)

| Platform | Default Method | Alt Method |
|----------|---------------|------------|
| RP2040 / RP2350 | UF2 copy via USB drive (`elf2uf2-rs`) | `probe-rs` |
| ESP32-S3 / C5 / C6 | `espflash flash` | `probe-rs` via JTAG |
| SAMD21 | UF2 via bootloader (`uf2conv`) | `bossac` |

---

### Role 2: Device Interaction (ykman-like)

All commands below communicate with a **running** device (firmware already flashed) via HID or CCID.

#### Command Structure (Role 2)

```
picokeys-cli [OPTIONS] <COMMAND>

Options:
  -d, --device <SERIAL>    Select specific device by serial
  -v, --verbose            Verbose logging
  -h, --help
  -V, --version

Commands:
  info          Show device firmware version, serial, capabilities
  fido          FIDO2 management subcommands
  oath          OATH (TOTP/HOTP) subcommands
  otp           Yubikey OTP slot management
  hsm           HSM (smart card) subcommands
  config        Device configuration
  flash         Firmware flashing helpers
```

### FIDO subcommands

```
picokeys-cli fido info                          # Show FIDO authenticator info (AAGUID, etc.)
picokeys-cli fido credentials list              # List discoverable (resident) credentials
picokeys-cli fido credentials delete <id>       # Delete a credential by RP ID
picokeys-cli fido credentials delete-all        # Wipe all credentials
picokeys-cli fido pin set                       # Set FIDO PIN (interactive)
picokeys-cli fido pin change                    # Change PIN (interactive)
picokeys-cli fido pin verify                    # Verify PIN
picokeys-cli fido reset                         # Factory reset (requires button press)
picokeys-cli fido config always-uv [on|off]     # Require UV for all assertions
picokeys-cli fido config enterprise-aaguid <b64> # Set enterprise AAGUID
```

### OATH subcommands

```
picokeys-cli oath list                          # List all OATH credentials
picokeys-cli oath add [OPTIONS] <NAME>          # Add TOTP/HOTP account
  -s, --secret <BASE32>     TOTP/HOTP secret
  -d, --digits [6|7|8]      OTP digits
  -p, --period [15|30|60]   TOTP period (seconds)
  --algorithm [SHA1|SHA256|SHA512]
  --hotp                    HOTP mode (counter-based)
picokeys-cli oath code <NAME>                   # Generate TOTP/HOTP code
picokeys-cli oath code --all                    # Generate codes for all active accounts
picokeys-cli oath delete <NAME>                 # Delete account
picokeys-cli oath rename <OLD> <NEW>            # Rename account
picokeys-cli oath set-password                  # Password-protect OATH applet
```

### OTP subcommands

```
picokeys-cli otp info                           # Show OTP slot status
picokeys-cli otp set-hotp <SLOT> [OPTIONS]      # Configure HOTP slot
picokeys-cli otp set-static <SLOT> <PASSWORD>   # Configure static password
picokeys-cli otp swap                           # Swap slot 1 & 2
picokeys-cli otp delete <SLOT>                  # Delete slot configuration
picokeys-cli otp update <SLOT>                  # Update slot flags
```

### HSM subcommands

```
picokeys-cli hsm info                           # Show HSM status
picokeys-cli hsm init                           # Initialize device (set SO-PIN, PIN)
picokeys-cli hsm keys list                      # List all keys
picokeys-cli hsm keys generate [OPTIONS]        # Generate key pair
  --algorithm [EC|RSA|AES]
  --curve [P-256|P-384|P-521|Ed25519|secp256k1]
  --size [1024|2048|3072|4096]
  --label <LABEL>
picokeys-cli hsm keys delete <id>               # Delete key
picokeys-cli hsm keys export <id> <FILE>        # Export wrapped key (DKEK required)
picokeys-cli hsm keys import <FILE>             # Import wrapped key (DKEK required)
picokeys-cli hsm dkek init                      # Initialize DKEK
picokeys-cli hsm dkek import-share <FILE>       # Import DKEK share  
picokeys-cli hsm sign --key <ID> --alg <ALG>    # Sign data
picokeys-cli hsm verify --key <ID> --alg <ALG>  # Verify signature
picokeys-cli hsm encrypt/decrypt                # AES encrypt/decrypt raw data
```

### Config subcommands

```
picokeys-cli config led set <PATTERN>           # Set LED pattern/colour (idle|active|processing|confirm)
picokeys-cli config led gpio <GPIO_NUM>         # Override LED GPIO pin (non-standard board)
picokeys-cli config led type [single|rgb]       # LED type: single-color or addressable RGB (WS2812)
picokeys-cli config button gpio <GPIO_NUM>      # Override user/BOOTSEL button GPIO (SAMD21 or custom)
picokeys-cli config button polarity [active-low|active-high]  # Button logic polarity
picokeys-cli config button timeout <SECONDS>    # Press-to-confirm window (default: 15s, pico-fido/pico-hsm compat)
picokeys-cli config press-to-confirm [on|off]   # Enable/disable press-to-confirm for all sensitive ops
picokeys-cli config vid-pid <VID:PID>           # Set USB VID:PID (e.g. 1209:4823 for pico-fido default)
picokeys-cli config serial                      # Show device serial
picokeys-cli config lock                        # Write-lock configuration (requires button press)
```

### Example CLI session

```bash
# List OATH accounts and generate codes
$ picokeys-cli oath list
NAME              TYPE  PERIOD  ALGORITHM
GitHub            TOTP  30s     SHA1
Google            TOTP  30s     SHA1
aws:myaccount     TOTP  30s     SHA256

$ picokeys-cli oath code GitHub
GitHub     482 391
$ picokeys-cli oath code --all
GitHub     482 391   (15s remaining)
Google     918 274   (15s remaining)
aws:myaccount  056 812  (29s remaining)

# FIDO credential management
$ picokeys-cli fido credentials list
Enter FIDO PIN: ****
RP ID                         User                  Credential ID (truncated)
example.com                   alice@example.com     3a7f...
github.com                    alice                 9c1b...
mybank.com                    alice                 f420...

$ picokeys-cli fido credentials delete mybank.com
Delete credential for mybank.com? [y/N] y
✓ Credential deleted.
```

---

## 10. Feature Parity Map

### FIDO2 Feature Parity (pico-fido → pico-rs-fido)

| Feature | Source | Rust Implementation | Crate(s) |
|---------|--------|---------------------|---------|
| CTAP 2.1 | cbor.c + all cbor_*.c | `fido/ctap.rs` + handlers | `ctap-types`, custom |
| CTAP 1 / U2F | cmd_register.c, cmd_authenticate.c | `u2f/` | `p256`, custom |
| WebAuthn | cbor_make_credential + get_assertion | handler modules | — |
| HMAC-Secret | (inline) | `extensions/hmac_secret.rs` | `hmac`, `aes-cbc` |
| CredProtect | (inline) | `extensions/cred_protect.rs` | — |
| credBlobs | cbor_make_credential | `extensions/cred_blob.rs` | — |
| largeBlobKey | cbor_large_blobs.c | `fido/large_blobs.rs` | — |
| Discoverable creds | credential.c | `credential/mod.rs` | `sequential-storage` |
| PIN protocol v1/v2 | cbor_client_pin.c | `fido/client_pin.rs` | `p256`, `aes-cbc`, `hmac` |
| Credential Mgmt | cbor_cred_mgmt.c | `fido/credential_mgmt.rs` | — |
| Permissions (MC/GA/CM/ACFG/LBW) | cbor_client_pin.c | `fido/client_pin.rs` | `ctap-types` |
| ECDSA curves | fido.c | `crypto/ecc.rs` | `p256`, `p384`, `p521`, `k256` |
| Ed25519 | fido.c | `crypto/ecc.rs` | `ed25519-dalek` |
| OATH TOTP/HOTP | oath.c | `oath/totp.rs`, `oath/hotp.rs` | `totp-lite`, `hmac` |
| YKOATH protocol | oath.c | `oath/mod.rs` | custom |
| Yubikey OTP slots | otp.c | `oath/yubikey_otp.rs` | `aes-cbc` |
| Challenge-response | otp.c | `oath/yubikey_otp.rs` | `hmac` |
| Keyboard emulation | management.c | via USB HID keyboard class | `embassy-usb` |
| Vendor commands | cbor_vendor.c | `fido/vendor.rs` | — |
| KEK / MKEK | kek.c | `credential/kek.rs` | `aes-gcm` |
| **Backup with 24 words** | kek.c (BIP39 seed) | `credential/backup.rs` | `bip39`, `bip32` |
| **Secure lock** | platform/otp.c | `platform/secure_lock.rs` | `aes-gcm`, HAL OTP |
| Secure Boot | platform init | `platform/rp2350.rs` | `embassy-rp` |
| OTP storage | otp.c (fs) | `store/otp.rs` | HAL-specific |
| Rescue interface | rescue.c | `rescue/mod.rs` | — |
| LED patterns | led/ | `led/patterns.rs` | `embassy-time` |
| User presence | button | `button/mod.rs` | HAL GPIO |
| Enterprise attest | cbor_make_credential | `credential/attestation.rs` | `x509-cert`, `der` |
| Self attestation | cbor_make_credential | inline | `p256` |

### HSM Feature Parity (pico-hsm → pico-rs-hsm)

| Feature | Rust Implementation | Crate(s) |
|---------|---------------------|---------|
| RSA 1024-4096 gen | `hsm/key_management.rs` | `rsa` |
| RSA PKCS1v1.5 sign | `hsm/sign.rs` | `rsa` |
| RSA-PSS sign | `hsm/sign.rs` | `rsa` |
| RSA-OAEP decrypt | `hsm/decrypt.rs` | `rsa` |
| ECDSA all curves | `hsm/sign.rs` | `p256/384/521`, `k256` |
| EdDSA Ed25519 | `hsm/sign.rs` | `ed25519-dalek` |
| ECDH (secp*, X25519) | `hsm/ecdh.rs` | `p256/384`, `x25519-dalek` |
| AES all modes | `hsm/aes_ops.rs` | `aes`, `cbc`, `ctr`, `aes-gcm`, `xts-mode` |
| ChaCha20-Poly1305 | `hsm/aes_ops.rs` | `chacha20poly1305` |
| HMAC | `hsm/` | `hmac` |
| CMAC | `hsm/` | `cmac` |
| HKDF, PBKDF2 | `hsm/derive.rs` | `hkdf`, `pbkdf2` |
| BIP32 HD keys | `hsm/derive.rs` | `bip32` |
| PKCS#15 structure | `hsm/` | custom (iso7816 types) |
| DKEK shares n-of-m | `hsm/dkek.rs` | custom + `aes-gcm` |
| Multiple key domains | `hsm/dkek.rs` | — |
| Key usage counter | `hsm/key_management.rs` | `sequential-storage` |
| PIN auth | `hsm/pin.rs` | `pbkdf2`, `aes-gcm` |
| Secure Messaging | `eac/secure_channel.rs` (SDK) | `aes-cbc`, `cmac` |
| CV certificates | `hsm/certificates.rs` | `der`, `x509-cert` |
| X.509 attestation | `hsm/attestation.rs` | `x509-cert`, `p256` |
| Transport PIN | `hsm/pin.rs` | — |
| Extended APDU | `transport/ccid/` (SDK) | — |
| Press-to-confirm | `button/mod.rs` (SDK) | — |
| Binary data store | `store/` (SDK) | `sequential-storage` |
| RTC | `hsm/rtc.rs` | HAL-specific |
| Secure Boot | `platform/` (SDK) | `embassy-rp`, `esp-hal` |
| OTP MKEK | `store/otp.rs` (SDK) | HAL-specific |

---

## 11. Build & Flash Strategy

### Build System

Use Cargo workspaces with feature flags for each target:

```toml
# pico-rs-fido/Cargo.toml
[features]
default = []
rp2040 = ["pico-rs-sdk/rp2040", "embassy-rp", "dep:rp2040-boot2"]
rp2350 = ["pico-rs-sdk/rp2350", "embassy-rp"]
esp32s3 = ["pico-rs-sdk/esp32s3", "esp-hal/esp32s3"]
esp32c5 = ["pico-rs-sdk/esp32c5", "esp-hal/esp32c5"]
esp32c6 = ["pico-rs-sdk/esp32c6", "esp-hal/esp32c6"]
samd21 = ["pico-rs-sdk/samd21", "atsamd-hal"]
```

### Build Commands

```bash
# RP2040
cargo build --release --bin rp2040 --features rp2040 \
  --target thumbv6m-none-eabi

# RP2350
cargo build --release --bin rp2350 --features rp2350 \
  --target thumbv8m.main-none-eabihf

# ESP32-S3
cargo build --release --bin esp32s3 --features esp32s3 \
  --target xtensa-esp32s3-none-elf

# ESP32-C5
cargo build --release --bin esp32c5 --features esp32c5 \
  --target riscv32imc-unknown-none-elf

# ESP32-C6  
cargo build --release --bin esp32c6 --features esp32c6 \
  --target riscv32imac-unknown-none-elf

# SAMD21
cargo build --release --bin samd21 --features samd21 \
  --target thumbv6m-none-eabi
```

### Flashing

| Platform | Tool | Method |
|----------|------|--------|
| RP2040/RP2350 | `elf2uf2-rs` → UF2 copy | Hold BOOTSEL, copy .uf2 to drive |
| RP2040/RP2350 | `probe-rs` | SWD debug probe (openocd/probe-rs) |
| ESP32-S3/C5/C6 | `espflash` | USB serial / JTAG |
| SAMD21 | `uf2conv` → UF2 | Double-reset bootloader |
| SAMD21 | `openocd` + SWD | Debug probe |

```bash
# Flash RP2040
cargo install elf2uf2-rs
elf2uf2-rs target/thumbv6m-none-eabi/release/rp2040 pico_fido.uf2
# Copy pico_fido.uf2 to RPI-RP2 drive

# Flash ESP32-S3
cargo install espflash
espflash flash --monitor target/xtensa-esp32s3-none-elf/release/esp32s3

# Flash SAMD21 (e.g., Adafruit Circuit Playground Express)
cargo install uf2conv
uf2conv target/thumbv6m-none-eabi/release/samd21 -c -f 0x68ed2b88 -o samd21_fido.uf2
```

---

## 12. Key Technical Challenges & Mitigations

### 12.1 CCID USB Class — No Existing Rust Crate

**Challenge:** `embassy-usb` ships with HID and CDC-ACM. CCID is a bulk-based USB class with its own framing protocol (PC_to_RDR/RDR_to_PC message packets).

**Mitigation:** Implement a custom `UsbCcid` class on top of `embassy-usb`'s raw `Endpoint` API. The CCID spec (USB Device Class Specification for Integrated Circuit(s) Cards, Rev 1.1) is freely available. Estimated: ~600 lines of Rust. This layer:
1. Exposes `async fn send_apdu_response(data: &[u8])`
2. Implements the slot/command/response message envelope
3. Handles extended APDU chaining

### 12.2 RSA Key Generation Speed on Bare Metal

**Challenge:** RSA 2048 key gen → ~124s on RP2040 (from source table). RSA 4096 → ~1000s.

**Mitigation:**
- Ship `[profile.release]` with `opt-level = 3` for `num-bigint-dig` (the RSA bignum crate)
- Set user expectation: key gen is slow, this is normal
- For RP2040: only support up to RSA-2048 as practical maximum
- For RP2350: ARM Cortex-M33 is ~2× faster; RSA-4096 is viable (~500s)
- For ESP32-S3: Xtensa LX7 at 240MHz + hardware bignum accelerator; much faster

### 12.3 ESP32-C6 USB-Serial-JTAG Limitation

**Challenge:** The ESP32-C6 includes a `USB-Serial-JTAG` controller on GPIO12 (D−) / GPIO13 (D+). At the physical layer this is USB 2.0 Full Speed (12 Mbps), and the SoC does connect via a single USB-C port on the DevKitC-1. However, the peripheral is **not a general-purpose USB device controller (OTG/DWC2)** — it is hard-wired to the JTAG debugger and CDC-ACM serial only. Unlike the ESP32-S3, the C6 cannot enumerate as HID or CCID, and there is no software override.

**Mitigation:** Three options:
1. **Serial bridge mode:** Expose a CDC-ACM CTAP-over-serial protocol, write a serial-to-HID bridge in the host CLI. Allows FIDO operation via the CLI on C6 but NOT as a native FIDO authenticator in browsers.
2. **External USB chip:** Add a CH340/FUSB302 or similar USB-to-HID companion for production hardware based on C6 SoC.
3. **Drop C6 for FIDO/HSM:** Treat C6 as development / testing target only. Focus full FIDO/HSM USB support on ESP32-S3 and ESP32-C5.

> **Recommendation:** Support C6 as a "development only" target (serial bridge). Mark in docs that native browser FIDO2 requires ESP32-S3 or ESP32-C5.

### 12.4 SAMD21 Flash Constraints

**Challenge:** SAMD21 has only 256KB flash. RSA + ECDSA + all OATH features may not fit.

**Mitigation:**
- FIDO-only build with LTO → target ~120-180KB
- Drop RSA support from SAMD21 build (feature-gated)
- SAMD21 binaries: FIDO2 + OATH only (no HSM)
- Recommend SAMD51 (512KB) for full feature set

### 12.5 Secure Boot / OTP Abstraction

**Challenge:** OTP/secure boot is hardware-specific (RP2350 uses OTP fuses, ESP32 uses eFuse). Needs clean abstraction.

**Mitigation:**
- `pico-rs-sdk` defines a `SecureStorage` trait with `read_otp(slot)` / `write_otp(slot, value)` methods
- Platform adapters implement it differently:
  - RP2350: `rp2350::otp::read_raw_value()` behind unsafe
  - ESP32: `esp_hal::efuse::read_bit()`
  - RP2040/SAMD21: returns `None` → MKEK stored encrypted in flash instead

### 12.6 RSA Marvin Attack (RUSTSEC-2023-0071)

**Challenge:** `rsa` crate has a timing side-channel advisory (Marvin attack).

**Mitigation:**
- The attack requires a network attacker capable of precise timing measurements — high bar for a USB device
- The `rsa` crate already employs random blinding to randomise execution time
- Track the upstream fix in `rsa` crate issue #390
- For highest security, gate RSA-decrypt operations behind user-presence confirmation (press-to-confirm button)

### 12.7 No `std` Memory Allocator

**Challenge:** `rsa` crate requires heap allocation for large keys (4096-bit keys = large buffers).

**Mitigation:**
- Use `embedded_alloc` (a simple heap allocator for embedded) with a static heap of ~24KB
- This is safe and commonly used in complex embedded firmware
- `fido-authenticator` uses this pattern already

---

## 13. Recommended Development Roadmap

### Phase 1 — Foundation (Weeks 1-4)
- [ ] Set up Cargo workspace, CI pipelines (GitHub Actions, cross-compile for all targets)
- [ ] Implement `pico-rs-sdk`: `store/` module using `sequential-storage`
- [ ] Implement `pico-rs-sdk`: `transport/hid/` CTAPHID framing layer
- [ ] Implement `pico-rs-sdk`: `transport/ccid/` CCID USB class (custom)
- [ ] Implement `pico-rs-sdk`: platform adapters for RP2040 and RP2350 (flash, RNG, LED, GPIO)
- [ ] Implement `pico-rs-sdk`: `crypto/` trait layer wrapping RustCrypto primitives
- [ ] First binary: RP2040 + RP2350 blinky over USB HID (smoke test)

### Phase 2 — FIDO Core (Weeks 5-10)
- [ ] Implement `pico-rs-fido`: CTAP2 core (MakeCredential, GetAssertion, GetInfo)
- [ ] Implement PIN protocol v2 (client_pin.rs)
- [ ] Implement discoverable credentials (encrypt/store/retrieve/delete)
- [ ] Implement HMAC-Secret extension
- [ ] Implement CredProtect, credBlob, largeBlobKey extensions
- [ ] Implement U2F backward compat (cmd_register + cmd_authenticate)
- [ ] Implement CTAP2 Reset
- [ ] Pass CTAP2 conformance tests against RP2040
- [ ] Implement OATH (TOTP/HOTP via YKOATH protocol)
- [ ] Implement Yubikey OTP slots

### Phase 3 — ESP32 & SAMD21 Support (Weeks 11-14)
- [ ] Add `esp-hal` platform adapter to `pico-rs-sdk`
- [ ] Build and test ESP32-S3 binary
- [ ] Build and test ESP32-C5 binary
- [ ] Add `atsamd-hal` platform adapter to `pico-rs-sdk`
- [ ] Build and test SAMD21 binary (FIDO-only feature set)
- [ ] Integration test all platforms with a real browser WebAuthn flow

### Phase 4 — CLI Tool (Weeks 15-18)
- [ ] Scaffold `picokeys-cli` with `clap` v4
- [ ] Implement `info` command (HID + CCID)
- [ ] Implement `fido credentials list/delete` using `ctap-hid-fido2`
- [ ] Implement `fido pin set/change/verify`
- [ ] Implement `oath list/add/code/delete`
- [ ] Implement `otp` slot commands
- [ ] Implement `config` commands (LED, press-to-confirm)
- [ ] Publish CLI as `picokeys-cli` on crates.io

### Phase 5 — HSM Application (Weeks 19-28)
- [ ] Implement `pico-rs-hsm` CCID application skeleton
- [ ] RSA key gen + sign + decrypt
- [ ] ECDSA (all curves)
- [ ] ECDH, AES all modes, ChaCha20-Poly1305
- [ ] DKEK shares + n-of-m threshold
- [ ] Secure Messaging (EAC)
- [ ] Certificate management
- [ ] PKCS#11 interface validation with OpenSC
- [ ] BIP32/SLIP10 HD key derivation
- [ ] HSM CLI commands in `picokeys-cli hsm`

### Phase 6 — Security Hardening & Certification Prep (Ongoing)
- [ ] Constant-time implementations audit
- [ ] Zeroize all sensitive buffers on drop (use `zeroize` crate)
- [ ] Secure Boot + OTP provisioning tooling
- [ ] Fuzz testing (cargo-fuzz)
- [ ] Security audit

---

## Quick Reference: Crate Summary Table

| Domain | Crate | Version | License | no_std |
|--------|-------|---------|---------|--------|
| **HAL – RP2040/2350** | `embassy-rp` | 0.9.0 | MIT/Apache2 | ✅ |
| **HAL – ESP32 all** | `esp-hal` | 1.0.0 | MIT/Apache2 | ✅ |
| **HAL – SAMD21** | `atsamd-hal` | 0.23.3 | MIT/Apache2 | ✅ |
| **USB stack** | `embassy-usb` | 0.5.1 | MIT/Apache2 | ✅ |
| **USB HID class** | `usbd-hid` | 0.9.0 | MIT/Apache2 | ✅ |
| **Async executor** | `embassy-executor` | 0.7 | MIT/Apache2 | ✅ |
| **Flash KV store** | `sequential-storage` | 7.1.0 | MIT/Apache2 | ✅ |
| **CTAP2 types** | `ctap-types` | 0.4.0 | MIT/Apache2 | ✅ |
| **FIDO2 protocol** | `fido-authenticator` | 0.2.0 | MIT/Apache2 | ✅ |
| **ISO 7816 APDU** | `iso7816` | 0.2.0 | MIT/Apache2 | ✅ |
| **CBOR encode** | `cbor4ii` | 1.2.2 | MIT | ✅ |
| **P-256 ECC** | `p256` | 0.13.2 | MIT/Apache2 | ✅ |
| **P-384 ECC** | `p384` | 0.13.2 | MIT/Apache2 | ✅ |
| **P-521 ECC** | `p521` | 0.13.2 | MIT/Apache2 | ✅ |
| **secp256k1** | `k256` | 0.13.3 | MIT/Apache2 | ✅ |
| **Ed25519** | `ed25519-dalek` | 2.2.0 | BSD-3 | ✅ |
| **X25519 DH** | `x25519-dalek` | 2.0 | BSD-3 | ✅ |
| **RSA** | `rsa` | 0.9.10 | MIT/Apache2 | ✅ |
| **AES cipher** | `aes` | 0.8 | MIT/Apache2 | ✅ |
| **AES-GCM** | `aes-gcm` | 0.10.3 | MIT/Apache2 | ✅ |
| **ChaCha20-Poly** | `chacha20poly1305` | 0.10 | MIT/Apache2 | ✅ |
| **HMAC** | `hmac` | 0.12.1 | MIT/Apache2 | ✅ |
| **SHA-2** | `sha2` | 0.10 | MIT/Apache2 | ✅ |
| **CMAC** | `cmac` | 0.7 | MIT/Apache2 | ✅ |
| **HKDF** | `hkdf` | 0.12 | MIT/Apache2 | ✅ |
| **PBKDF2** | `pbkdf2` | 0.12 | MIT/Apache2 | ✅ |
| **BIP32 HD keys** | `bip32` | 0.5.3 | MIT/Apache2 | ✅ |
| **DER/ASN.1** | `der` | 0.7 | MIT/Apache2 | ✅ |
| **PKCS#8 keys** | `pkcs8` | 0.10 | MIT/Apache2 | ✅ |
| **X.509 certs** | `x509-cert` | 0.2 | MIT/Apache2 | ✅ |
| **TOTP** | `totp-lite` | 2.0.1 | MIT | ✅ |
| **No-alloc data** | `heapless` | 0.8 | MIT/Apache2 | ✅ |
| **Secure zeroize** | `zeroize` | 1.8 | MIT/Apache2 | ✅ |
| **Embedded logging** | `defmt` | 0.3 | MIT/Apache2 | ✅ |
| **CLI args** | `clap` | 4.5.60 | MIT/Apache2 | ❌ |
| **USB HID (host)** | `hidapi` | 2.6.5 | MIT | ❌ |
| **PC/SC (host)** | `pcsc` | 2.9.0 | MIT | ❌ |
| **CTAP HID client** | `ctap-hid-fido2` | 3.5.8 | MIT | ❌ |
| **CLI prompts** | `dialoguer` | 0.11 | MIT/Apache2 | ❌ |
| **CLI tables** | `tabled` | 0.16 | MIT/Apache2 | ❌ |
| **Error handling** | `anyhow` | 1.0 | MIT/Apache2 | ❌ |

---

*All findings verified against crates.io and GitHub repositories as of March 2026.*
