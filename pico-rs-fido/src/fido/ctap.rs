//! CTAP2 command bytes and status codes per the FIDO2 specification.

/// CTAP2 command byte values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, defmt::Format)]
#[repr(u8)]
pub enum CtapCommand {
    MakeCredential = 0x01,
    GetAssertion = 0x02,
    GetInfo = 0x04,
    ClientPin = 0x06,
    Reset = 0x07,
    GetNextAssertion = 0x08,
    BioEnrollment = 0x09,
    CredentialManagement = 0x0A,
    Selection = 0x0B,
    LargeBlobs = 0x0C,
    Config = 0x0D,
    VendorFirst = 0x40,
}

impl TryFrom<u8> for CtapCommand {
    type Error = CtapError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(Self::MakeCredential),
            0x02 => Ok(Self::GetAssertion),
            0x04 => Ok(Self::GetInfo),
            0x06 => Ok(Self::ClientPin),
            0x07 => Ok(Self::Reset),
            0x08 => Ok(Self::GetNextAssertion),
            0x09 => Ok(Self::BioEnrollment),
            0x0A => Ok(Self::CredentialManagement),
            0x0B => Ok(Self::Selection),
            0x0C => Ok(Self::LargeBlobs),
            0x0D => Ok(Self::Config),
            0x40..=0xBF => Ok(Self::VendorFirst),
            _ => Err(CtapError::InvalidCommand),
        }
    }
}

/// CTAP2 status codes per the FIDO specification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, defmt::Format)]
#[repr(u8)]
pub enum CtapError {
    Ok = 0x00,
    InvalidCommand = 0x01,
    InvalidParameter = 0x02,
    InvalidLength = 0x03,
    InvalidSeq = 0x04,
    Timeout = 0x05,
    ChannelBusy = 0x06,
    LockRequired = 0x0A,
    InvalidChannel = 0x0B,
    MissingParameter = 0x14,
    LimitExceeded = 0x15,
    UnsupportedExtension = 0x16,
    CredentialExcluded = 0x19,
    Processing = 0x21,
    InvalidCredential = 0x22,
    UserActionPending = 0x23,
    OperationPending = 0x24,
    NoCredentials = 0x2E,
    UserActionTimeout = 0x2F,
    NotAllowed = 0x30,
    PinInvalid = 0x31,
    PinBlocked = 0x32,
    PinAuthInvalid = 0x33,
    PinAuthBlocked = 0x34,
    PinNotSet = 0x35,
    PuatRequired = 0x36,
    PinPolicyViolation = 0x37,
    OperationDenied = 0x39,
    KeyStoreFull = 0x3A,
    UvInvalid = 0x3B,
    UvBlocked = 0x3C,
    UnauthorizedPermission = 0x40,
    Other = 0x7F,
}
