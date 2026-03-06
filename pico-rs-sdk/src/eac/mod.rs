//! EAC / SCP03 secure-channel + Chip Authentication module.

pub mod secure_channel;
pub mod chip_auth;

pub use secure_channel::{SecureChannel, CryptoError};
pub use chip_auth::ChipAuthentication;
