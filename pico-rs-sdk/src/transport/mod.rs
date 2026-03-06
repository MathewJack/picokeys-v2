//! Transport abstraction layer for PicoKeys v2.
//!
//! Provides async transport traits and implementations for HID (CTAPHID)
//! and CCID (smart card) USB interfaces.

pub mod ccid;
pub mod hid;

/// Transport interface type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, defmt::Format)]
pub enum Interface {
    /// USB HID (CTAPHID) transport — used by FIDO2/U2F.
    Hid,
    /// USB CCID (smart card) transport — used by OpenPGP, PIV, etc.
    Ccid,
}

/// Errors that can occur during transport operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, defmt::Format)]
pub enum TransportError {
    /// Transaction timed out waiting for continuation packets or response.
    Timeout,
    /// Packet received on an unknown or unallocated channel.
    InvalidChannel,
    /// Message payload length exceeds maximum or doesn't match header.
    InvalidLength,
    /// Channel is busy processing another transaction.
    Busy,
    /// Generic transport error (USB endpoint failure, etc.).
    Other,
}

/// Async transport trait for receiving and sending framed messages.
///
/// Implementations handle framing details (HID packet reassembly, CCID chaining)
/// internally and present a clean message-level interface.
pub trait Transport {
    /// Receive a complete message into `buf`, returning the number of bytes written.
    async fn recv(&mut self, buf: &mut [u8]) -> Result<usize, TransportError>;

    /// Send a complete response message, handling fragmentation internally.
    async fn send(&mut self, data: &[u8]) -> Result<(), TransportError>;

    /// Send a keepalive status byte to the host (HID only; CCID may no-op).
    async fn send_keepalive(&mut self, status: u8) -> Result<(), TransportError>;
}
