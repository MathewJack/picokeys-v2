//! EAC / SCP03 secure-channel + Chip Authentication module.

pub mod chip_auth;
pub mod secure_channel;

pub use chip_auth::ChipAuthentication;
pub use secure_channel::{CryptoError, SecureChannel};
