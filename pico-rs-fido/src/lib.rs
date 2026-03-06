//! PicoKeys v2 FIDO2/CTAP2 + OATH application.
#![no_std]
#![allow(async_fn_in_trait)]

pub mod credential;
pub mod extensions;
pub mod fido;
pub mod management;
pub mod oath;
pub mod u2f;
