//! CTAP2 `credProtect` extension (FIDO2 §12.4).
//!
//! Allows relying parties to specify a credential protection policy
//! that controls when the authenticator will return the credential
//! during `getAssertion`.

/// Credential protection level.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CredProtectLevel {
    /// UV optional; credential usable with or without UV/allowList.
    UserVerificationOptional = 1,
    /// UV optional, but credential only returned when an allowList is present
    /// (or UV is performed).
    UserVerificationOptionalWithList = 2,
    /// UV required; credential never returned without user verification.
    UserVerificationRequired = 3,
}

impl CredProtectLevel {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::UserVerificationOptional),
            2 => Some(Self::UserVerificationOptionalWithList),
            3 => Some(Self::UserVerificationRequired),
            _ => None,
        }
    }
}

/// Enforce credential protection policy.
///
/// - `level`: protection level stored in the credential.
/// - `has_allow_list`: whether the `getAssertion` request includes an `allowList`.
/// - `uv_performed`: whether user verification (PIN/biometric) was performed.
///
/// Returns `Ok(())` if access is permitted, `Err(())` if the credential
/// must not be returned to the relying party.
pub fn enforce_cred_protect(
    level: CredProtectLevel,
    has_allow_list: bool,
    uv_performed: bool,
) -> Result<(), ()> {
    match level {
        CredProtectLevel::UserVerificationOptional => {
            // Always accessible
            Ok(())
        }
        CredProtectLevel::UserVerificationOptionalWithList => {
            // Accessible if allowList is present OR UV was performed
            if has_allow_list || uv_performed {
                Ok(())
            } else {
                Err(())
            }
        }
        CredProtectLevel::UserVerificationRequired => {
            // Accessible only if UV was performed
            if uv_performed {
                Ok(())
            } else {
                Err(())
            }
        }
    }
}
