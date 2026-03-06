//! PicoKeys v2 SDK — Core platform-agnostic abstractions for transport, crypto, storage, LED, and button.
#![no_std]
#![allow(async_fn_in_trait)]

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
