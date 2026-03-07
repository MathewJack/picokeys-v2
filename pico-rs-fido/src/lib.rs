//! # PicoKeys v2 FIDO2 Application
//!
//! Full CTAP 2.1 / CTAP 1 (U2F) authenticator implementation with OATH support.
//!
//! ## Overview
//!
//! `pico-rs-fido` implements the FIDO2 authenticator specification on top of
//! [`pico-rs-sdk`]. It provides resident key storage, credential management,
//! and all standard CTAP2.1 extensions.
//!
//! ## Features
//!
//! - **CTAP 2.1**: MakeCredential, GetAssertion, GetInfo, ClientPIN, CredentialManagement,
//!   Reset, Selection, AuthenticatorConfig, LargeBlobs
//! - **CTAP 1 (U2F)**: Register, Authenticate (backward compatibility)
//! - **Algorithms**: ES256 (P-256), ES384 (P-384), ES512 (P-521), ES256K (secp256k1), EdDSA (Ed25519)
//! - **Extensions**: hmac-secret, credProtect, credBlob, largeBlobKey, minPinLength
//! - **OATH (YKOATH)**: TOTP, HOTP, YubiKey OTP, challenge-response
//! - **Backup**: BIP39 24-word mnemonic for MKEK recovery
//! - **Vendor**: LED/button configuration, AAGUID, VID/PID, factory reset
//!
//! ## Modules
//!
//! | Module | Description |
//! |--------|-------------|
//! | [`fido`] | CTAP2 command handlers and CBOR router |
//! | [`credential`] | Resident key storage, KEK hierarchy, credential IDs, BIP39 backup |
//! | [`extensions`] | CTAP2.1 extensions (hmac-secret, credProtect, etc.) |
//! | [`oath`] | TOTP/HOTP/YubiKey OTP via YKOATH protocol |
//! | [`u2f`] | CTAP1/U2F register and authenticate handlers |
//! | [`management`] | Device management commands |
#![no_std]
#![allow(async_fn_in_trait)]

pub mod credential;
pub mod extensions;
pub mod fido;
pub mod management;
pub mod oath;
pub mod u2f;
