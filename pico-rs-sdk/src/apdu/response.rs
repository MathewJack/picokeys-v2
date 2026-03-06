use core::ops::{Deref, DerefMut};
use heapless::Vec;

/// Maximum reply data capacity in bytes.
pub const MAX_REPLY_LEN: usize = 1024;

/// ISO 7816-4 status word.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Success,
    MoreData(u8),
    WrongLength,
    SecurityNotSatisfied,
    ConditionsNotMet,
    WrongData,
    NotFound,
    WrongP1P2,
    InstructionNotSupported,
    ClassNotSupported,
    UnspecifiedError,
}

impl Status {
    pub fn sw1(self) -> u8 {
        self.to_bytes()[0]
    }

    pub fn sw2(self) -> u8 {
        self.to_bytes()[1]
    }

    pub fn to_bytes(self) -> [u8; 2] {
        match self {
            Status::Success => [0x90, 0x00],
            Status::MoreData(remaining) => [0x61, remaining],
            Status::WrongLength => [0x67, 0x00],
            Status::SecurityNotSatisfied => [0x69, 0x82],
            Status::ConditionsNotMet => [0x69, 0x85],
            Status::WrongData => [0x6A, 0x80],
            Status::NotFound => [0x6A, 0x82],
            Status::WrongP1P2 => [0x6A, 0x86],
            Status::InstructionNotSupported => [0x6D, 0x00],
            Status::ClassNotSupported => [0x6E, 0x00],
            Status::UnspecifiedError => [0x6F, 0x00],
        }
    }

    pub fn is_success(self) -> bool {
        matches!(self, Status::Success)
    }
}

/// APDU response data buffer.
pub struct Reply {
    data: Vec<u8, MAX_REPLY_LEN>,
}

impl Reply {
    pub fn new() -> Self {
        Self { data: Vec::new() }
    }

    pub fn extend_from_slice(&mut self, bytes: &[u8]) -> Result<(), Status> {
        self.data
            .extend_from_slice(bytes)
            .map_err(|_| Status::WrongLength)
    }

    pub fn push(&mut self, byte: u8) -> Result<(), Status> {
        self.data.push(byte).map_err(|_| Status::WrongLength)
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    pub fn clear(&mut self) {
        self.data.clear();
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data
    }
}

impl Default for Reply {
    fn default() -> Self {
        Self::new()
    }
}

impl Deref for Reply {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.data
    }
}

impl DerefMut for Reply {
    fn deref_mut(&mut self) -> &mut [u8] {
        &mut self.data
    }
}
