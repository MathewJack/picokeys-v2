//! # PicoKeys v2 SDK
//!
//! Core platform-agnostic abstractions for the PicoKeys v2 embedded security key firmware.
//!
//! ## Overview
//!
//! `pico-rs-sdk` provides the hardware abstraction layer (HAL) and shared infrastructure
//! used by [`pico-rs-fido`] and [`pico-rs-hsm`]. It is designed as a `no_std` crate
//! targeting bare-metal embedded systems.
//!
//! ## Modules
//!
//! | Module | Description |
//! |--------|-------------|
//! | [`transport`] | USB HID (CTAPHID) and CCID transport layers |
//! | [`crypto`] | Cryptographic primitives: ECDSA, ECDH, AES-GCM, RSA, hashing |
//! | [`store`] | Wear-levelled flash key-value storage via `sequential-storage` |
//! | [`apdu`] | ISO 7816 APDU command/response parsing with extended length and chaining |
//! | [`led`] | LED state machine with patterns: Idle, Active, Processing, PressToConfirm |
//! | [`button`] | User presence detection via platform-specific GPIO |
//! | [`platform`] | Platform adapters for RP2040, RP2350, ESP32-S3/C5/C6, SAMD21 |
//! | [`eac`] | Extended Access Control: secure channels and chip authentication |
//! | [`rescue`] | Rescue mode for device recovery when unresponsive |
//!
//! ## Supported Platforms
//!
//! | Platform | Target | USB | OTP | Notes |
//! |----------|--------|-----|-----|-------|
//! | RP2040 | `thumbv6m-none-eabi` | Native HID+CCID | No | ROSC RNG (weak) |
//! | RP2350 | `thumbv8m.main-none-eabihf` | Native HID+CCID | Yes | ARM TrustZone, TRNG |
//! | ESP32-S3 | `xtensa-esp32s3-none-elf` | DWC2 OTG | eFuse | Secure Boot |
//! | ESP32-C5 | `riscv32imac-unknown-none-elf` | OTG FS | eFuse | RISC-V |
//! | ESP32-C6 | `riscv32imac-unknown-none-elf` | Serial bridge | eFuse | No native USB |
//! | SAMD21 | `thumbv6m-none-eabi` | Native | No | 256KB flash limit |
//!
//! ## Security
//!
//! All key material types implement [`zeroize::Zeroize`] and [`zeroize::ZeroizeOnDrop`].
//! Secret comparisons use [`subtle::ConstantTimeEq`] to prevent timing attacks.
#![no_std]
#![allow(async_fn_in_trait)]
#![warn(missing_docs)]

#[cfg(feature = "alloc")]
extern crate alloc;

pub mod apdu;
pub mod button;
pub mod crypto;
pub mod eac;
pub mod led;
pub mod platform;
pub mod rescue;
pub mod store;
pub mod transport;
