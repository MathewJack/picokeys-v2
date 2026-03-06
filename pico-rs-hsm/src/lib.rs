//! # PicoKeys v2 HSM Application
//!
//! SmartCard-HSM implementation providing hardware security module functionality.
//!
//! ## Overview
//!
//! `pico-rs-hsm` implements a SmartCard-HSM compatible application on top of
//! [`pico-rs-sdk`]. It provides key generation, signing, decryption, and secure
//! key management via DKEK (Device Key Encryption Key) shares.
//!
//! ## Features
//!
//! - **Key Management**: Generate, import, export, and delete keys (RSA 1024-4096, EC P-256/384/521/k256, Ed25519, X25519, AES 128-512)
//! - **Signing**: ECDSA, EdDSA, RSA-PSS, RSA-PKCS#1 v1.5, raw RSA
//! - **Decryption**: RSA-OAEP, RSA-PKCS#1 v1.5
//! - **ECDH**: Key agreement for P-256, P-384, P-521, X25519
//! - **AES Operations**: ECB, CBC, CFB, OFB, CTR, GCM, CCM, XTS modes
//! - **DKEK**: Device Key Encryption Key with Shamir n-of-m secret sharing
//! - **Key Derivation**: EC private key derivation, AES key derivation
//! - **PIN Management**: SO-PIN and User-PIN with retry counters and session PINs
//! - **Certificates**: CV certificate storage and management
//! - **PKCS#15**: File system emulation for PKCS#15 compatibility
//!
//! ## Module Structure
//!
//! All HSM functionality is in the [`hsm`] module and its submodules:
//! `apdu_router`, `key_management`, `sign`, `decrypt`, `ecdh`, `aes_ops`,
//! `derive`, `dkek`, `pin`, `certificates`, `pkcs15`.
#![no_std]
#![allow(async_fn_in_trait)]

extern crate alloc;

pub mod hsm;
