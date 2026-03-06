//! CTAPHID framing, channel management, and dispatch.
//!
//! Implements the CTAP HID protocol (FIDO v2.1 §8) over 64-byte USB HID reports.
//! Handles packet parsing, reassembly, fragmentation, channel allocation,
//! and an async state machine that routes complete messages to a command handler.

pub mod class;

use heapless::Vec;

use super::TransportError;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Every HID report is exactly 64 bytes, zero-padded.
pub const HID_REPORT_SIZE: usize = 64;

/// Payload bytes in an initialization packet (64 − 4 CID − 1 CMD − 2 BCNT).
pub const INIT_DATA_SIZE: usize = 57;

/// Payload bytes in a continuation packet (64 − 4 CID − 1 SEQ).
pub const CONT_DATA_SIZE: usize = 59;

/// Maximum continuation-packet sequence number (0–127).
pub const MAX_SEQ: u8 = 127;

/// Maximum CTAPHID message payload: 57 + 128×59 = 7609 bytes.
pub const MAX_MSG_SIZE: usize = INIT_DATA_SIZE + (MAX_SEQ as usize + 1) * CONT_DATA_SIZE;

/// Broadcast channel ID — used for CTAPHID_INIT before allocation.
pub const BROADCAST_CID: u32 = 0xFFFF_FFFF;

/// Maximum concurrently allocated channels.
pub const MAX_CHANNELS: usize = 8;

// -- Keepalive status codes --------------------------------------------------

pub const STATUS_PROCESSING: u8 = 1;
pub const STATUS_UPNEEDED: u8 = 2;

// -- CTAP1/HID error codes ---------------------------------------------------

pub const CTAP1_ERR_INVALID_CHANNEL: u8 = 0x0B;
pub const CTAP1_ERR_INVALID_LENGTH: u8 = 0x03;
pub const CTAP1_ERR_INVALID_SEQ: u8 = 0x04;
pub const CTAP1_ERR_MSG_TIMEOUT: u8 = 0x05;
pub const CTAP1_ERR_CHANNEL_BUSY: u8 = 0x06;

// -- Protocol & capability flags ---------------------------------------------

pub const CTAPHID_PROTOCOL_VERSION: u8 = 2;
pub const CAPABILITY_WINK: u8 = 0x01;
pub const CAPABILITY_CBOR: u8 = 0x04;
pub const CAPABILITY_NMSG: u8 = 0x08;

// ---------------------------------------------------------------------------
// CtapHidCommand
// ---------------------------------------------------------------------------

/// CTAPHID command identifiers (§8.1.9).
#[derive(Debug, Clone, Copy, PartialEq, Eq, defmt::Format)]
pub enum CtapHidCommand {
    Ping,
    Msg,
    Lock,
    Init,
    Wink,
    Cbor,
    Cancel,
    Keepalive,
    Error,
    Vendor(u8),
}

impl CtapHidCommand {
    /// Decode a command byte (from the 7-bit CMD field, high bit already stripped).
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x01 => Some(Self::Ping),
            0x03 => Some(Self::Msg),
            0x04 => Some(Self::Lock),
            0x06 => Some(Self::Init),
            0x08 => Some(Self::Wink),
            0x10 => Some(Self::Cbor),
            0x11 => Some(Self::Cancel),
            0x3B => Some(Self::Keepalive),
            0x3F => Some(Self::Error),
            0x40..=0x7F => Some(Self::Vendor(b)),
            _ => None,
        }
    }

    /// Encode back to the 7-bit command byte (caller must OR with 0x80 for init packets).
    pub fn to_byte(self) -> u8 {
        match self {
            Self::Ping => 0x01,
            Self::Msg => 0x03,
            Self::Lock => 0x04,
            Self::Init => 0x06,
            Self::Wink => 0x08,
            Self::Cbor => 0x10,
            Self::Cancel => 0x11,
            Self::Keepalive => 0x3B,
            Self::Error => 0x3F,
            Self::Vendor(b) => b,
        }
    }
}

// ---------------------------------------------------------------------------
// CtapHidPacket — parsed 64-byte report
// ---------------------------------------------------------------------------

/// A parsed CTAPHID packet (initialization or continuation).
#[derive(Debug, Clone)]
pub enum CtapHidPacket {
    /// Initialization packet: starts a new message or single-packet command.
    Init {
        cid: u32,
        cmd: CtapHidCommand,
        bcnt: u16,
        data: [u8; INIT_DATA_SIZE],
    },
    /// Continuation packet: carries additional payload for a multi-packet message.
    Continuation {
        cid: u32,
        seq: u8,
        data: [u8; CONT_DATA_SIZE],
    },
}

impl CtapHidPacket {
    /// Parse a raw 64-byte HID report into a typed packet.
    ///
    /// Returns `None` if the command byte is unrecognised.
    pub fn parse(report: &[u8; HID_REPORT_SIZE]) -> Option<Self> {
        let cid = u32::from_be_bytes([report[0], report[1], report[2], report[3]]);
        let byte4 = report[4];

        if byte4 & 0x80 != 0 {
            // Initialization packet — bit 7 is set.
            let cmd = CtapHidCommand::from_byte(byte4 & 0x7F)?;
            let bcnt = u16::from_be_bytes([report[5], report[6]]);
            let mut data = [0u8; INIT_DATA_SIZE];
            data.copy_from_slice(&report[7..7 + INIT_DATA_SIZE]);
            Some(Self::Init {
                cid,
                cmd,
                bcnt,
                data,
            })
        } else {
            // Continuation packet — bit 7 is clear, byte4 is sequence number.
            let mut data = [0u8; CONT_DATA_SIZE];
            data.copy_from_slice(&report[5..5 + CONT_DATA_SIZE]);
            Some(Self::Continuation {
                cid,
                seq: byte4,
                data,
            })
        }
    }

    /// Channel ID common to both packet types.
    pub fn cid(&self) -> u32 {
        match self {
            Self::Init { cid, .. } | Self::Continuation { cid, .. } => *cid,
        }
    }
}

// ---------------------------------------------------------------------------
// CtapHidInit — INIT response payload (17 bytes)
// ---------------------------------------------------------------------------

/// Data payload of a CTAPHID_INIT response.
pub struct CtapHidInitResponse {
    pub nonce: [u8; 8],
    pub cid: u32,
    pub protocol_version: u8,
    pub major_version: u8,
    pub minor_version: u8,
    pub build_version: u8,
    pub capabilities: u8,
}

impl CtapHidInitResponse {
    pub const SIZE: usize = 17;

    /// Serialize into a 17-byte array.
    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        let cid_bytes = self.cid.to_be_bytes();
        let mut out = [0u8; Self::SIZE];
        out[0..8].copy_from_slice(&self.nonce);
        out[8..12].copy_from_slice(&cid_bytes);
        out[12] = self.protocol_version;
        out[13] = self.major_version;
        out[14] = self.minor_version;
        out[15] = self.build_version;
        out[16] = self.capabilities;
        out
    }
}

// ---------------------------------------------------------------------------
// Channel management
// ---------------------------------------------------------------------------

/// Tracks allocated CTAPHID channels.
pub struct CtapHidChannel {
    cids: [u32; MAX_CHANNELS],
    count: usize,
    next_cid: u32,
}

impl CtapHidChannel {
    pub fn new() -> Self {
        Self {
            cids: [0; MAX_CHANNELS],
            count: 0,
            next_cid: 1,
        }
    }

    /// Allocate a fresh channel, returning its CID.
    ///
    /// When all slots are occupied the oldest slot is recycled.
    pub fn allocate(&mut self) -> u32 {
        let cid = self.next_cid;

        if self.count < MAX_CHANNELS {
            self.cids[self.count] = cid;
            self.count += 1;
        } else {
            // Rotate: shift left and append new CID at end.
            self.cids.rotate_left(1);
            self.cids[MAX_CHANNELS - 1] = cid;
        }

        self.advance_next_cid();
        cid
    }

    /// Check whether `cid` is currently allocated (broadcast always valid).
    pub fn is_valid(&self, cid: u32) -> bool {
        if cid == BROADCAST_CID {
            return true;
        }
        self.cids[..self.count].iter().any(|&c| c == cid)
    }

    fn advance_next_cid(&mut self) {
        self.next_cid = self.next_cid.wrapping_add(1);
        // Skip 0 and the broadcast CID.
        if self.next_cid == 0 || self.next_cid == BROADCAST_CID {
            self.next_cid = 1;
        }
    }
}

// ---------------------------------------------------------------------------
// Traits for I/O and command handling
// ---------------------------------------------------------------------------

/// Async sink for writing 64-byte HID reports back to the host.
pub trait ReportWriter {
    async fn write_report(&mut self, report: &[u8; HID_REPORT_SIZE]) -> Result<(), TransportError>;
}

/// Application-level command handler invoked by the dispatcher.
pub trait CommandHandler {
    /// Handle a CTAPHID_CBOR (FIDO2) message.
    async fn handle_cbor(
        &mut self,
        data: &[u8],
        response: &mut Vec<u8, MAX_MSG_SIZE>,
    ) -> Result<(), TransportError>;

    /// Handle a CTAPHID_MSG (U2F / CTAP1) message.
    async fn handle_msg(
        &mut self,
        data: &[u8],
        response: &mut Vec<u8, MAX_MSG_SIZE>,
    ) -> Result<(), TransportError>;

    /// Visual identification (blink LED, etc.).
    fn wink(&mut self);
}

// ---------------------------------------------------------------------------
// Packet fragmentation (response → 64-byte reports)
// ---------------------------------------------------------------------------

/// Build and send an initialization packet for a response.
fn build_init_report(
    cid: u32,
    cmd: CtapHidCommand,
    bcnt: u16,
    payload: &[u8],
) -> [u8; HID_REPORT_SIZE] {
    let mut pkt = [0u8; HID_REPORT_SIZE];
    pkt[0..4].copy_from_slice(&cid.to_be_bytes());
    pkt[4] = cmd.to_byte() | 0x80;
    pkt[5] = (bcnt >> 8) as u8;
    pkt[6] = (bcnt & 0xFF) as u8;
    let n = core::cmp::min(payload.len(), INIT_DATA_SIZE);
    pkt[7..7 + n].copy_from_slice(&payload[..n]);
    pkt
}

/// Build a continuation packet.
fn build_cont_report(cid: u32, seq: u8, payload: &[u8]) -> [u8; HID_REPORT_SIZE] {
    let mut pkt = [0u8; HID_REPORT_SIZE];
    pkt[0..4].copy_from_slice(&cid.to_be_bytes());
    pkt[4] = seq;
    let n = core::cmp::min(payload.len(), CONT_DATA_SIZE);
    pkt[5..5 + n].copy_from_slice(&payload[..n]);
    pkt
}

/// Fragment `data` into 64-byte HID reports and write them to `writer`.
async fn send_response(
    cid: u32,
    cmd: CtapHidCommand,
    data: &[u8],
    writer: &mut impl ReportWriter,
) -> Result<(), TransportError> {
    let bcnt = data.len() as u16;

    // Init packet
    let init_n = core::cmp::min(data.len(), INIT_DATA_SIZE);
    let pkt = build_init_report(cid, cmd, bcnt, &data[..init_n]);
    writer.write_report(&pkt).await?;

    // Continuation packets
    let mut offset = init_n;
    let mut seq: u8 = 0;
    while offset < data.len() {
        let end = core::cmp::min(offset + CONT_DATA_SIZE, data.len());
        let pkt = build_cont_report(cid, seq, &data[offset..end]);
        writer.write_report(&pkt).await?;
        offset = end;
        seq += 1;
    }

    Ok(())
}

/// Send a single-byte CTAPHID_ERROR response.
async fn send_error(
    cid: u32,
    error_code: u8,
    writer: &mut impl ReportWriter,
) -> Result<(), TransportError> {
    send_response(cid, CtapHidCommand::Error, &[error_code], writer).await
}

/// Send a keepalive packet on `cid` with the given status byte.
async fn send_keepalive(
    cid: u32,
    status: u8,
    writer: &mut impl ReportWriter,
) -> Result<(), TransportError> {
    send_response(cid, CtapHidCommand::Keepalive, &[status], writer).await
}

// ---------------------------------------------------------------------------
// CtapHidDispatcher — async state machine
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DispatcherState {
    /// Waiting for an initialization packet to start a new transaction.
    Idle,
    /// Collecting continuation packets for the current message.
    Assembling,
}

/// Async CTAPHID state machine.
///
/// Receives raw 64-byte HID reports, reassembles multi-packet messages,
/// dispatches complete commands to a [`CommandHandler`], and fragments
/// responses back into 64-byte reports via a [`ReportWriter`].
pub struct CtapHidDispatcher {
    channels: CtapHidChannel,
    state: DispatcherState,
    /// CID of the transaction currently being assembled / processed.
    active_cid: u32,
    /// Command of the active transaction.
    active_cmd: CtapHidCommand,
    /// Total payload length declared in the init packet.
    expected_len: u16,
    /// Next expected continuation-packet sequence number.
    next_seq: u8,
    /// Reassembly buffer for incoming message payload.
    msg_buf: Vec<u8, MAX_MSG_SIZE>,
}

impl CtapHidDispatcher {
    pub fn new() -> Self {
        Self {
            channels: CtapHidChannel::new(),
            state: DispatcherState::Idle,
            active_cid: 0,
            active_cmd: CtapHidCommand::Ping,
            expected_len: 0,
            next_seq: 0,
            msg_buf: Vec::new(),
        }
    }

    /// Reset the assembler back to idle.
    fn reset(&mut self) {
        self.state = DispatcherState::Idle;
        self.active_cid = 0;
        self.expected_len = 0;
        self.next_seq = 0;
        self.msg_buf.clear();
    }

    /// Send a keepalive on the currently active channel.
    pub async fn keepalive(
        &self,
        status: u8,
        writer: &mut impl ReportWriter,
    ) -> Result<(), TransportError> {
        if self.active_cid == 0 {
            return Err(TransportError::InvalidChannel);
        }
        send_keepalive(self.active_cid, status, writer).await
    }

    /// Process one incoming 64-byte HID report.
    ///
    /// The dispatcher parses, reassembles, handles built-in commands (INIT, PING,
    /// CANCEL, WINK, ERROR) internally, and routes CBOR / MSG to `handler`.
    pub async fn process_report(
        &mut self,
        report: &[u8; HID_REPORT_SIZE],
        writer: &mut impl ReportWriter,
        handler: &mut impl CommandHandler,
    ) -> Result<(), TransportError> {
        let packet = match CtapHidPacket::parse(report) {
            Some(p) => p,
            None => {
                defmt::warn!("CTAPHID: unrecognised command byte");
                return Ok(());
            }
        };

        match packet {
            CtapHidPacket::Init {
                cid,
                cmd,
                bcnt,
                data,
            } => {
                self.handle_init_packet(cid, cmd, bcnt, &data, writer, handler)
                    .await
            }
            CtapHidPacket::Continuation { cid, seq, data } => {
                self.handle_cont_packet(cid, seq, &data, writer, handler)
                    .await
            }
        }
    }

    // -- Init-packet handling ------------------------------------------------

    async fn handle_init_packet(
        &mut self,
        cid: u32,
        cmd: CtapHidCommand,
        bcnt: u16,
        data: &[u8; INIT_DATA_SIZE],
        writer: &mut impl ReportWriter,
        handler: &mut impl CommandHandler,
    ) -> Result<(), TransportError> {
        // CTAPHID_INIT on broadcast is always allowed (channel allocation).
        if cmd == CtapHidCommand::Init && cid == BROADCAST_CID {
            return self.handle_init_command(cid, data, writer).await;
        }

        // CTAPHID_INIT on an existing channel re-synchronises it.
        if cmd == CtapHidCommand::Init && self.channels.is_valid(cid) {
            self.reset();
            return self.handle_init_command(cid, data, writer).await;
        }

        // Reject unknown channels.
        if !self.channels.is_valid(cid) {
            defmt::warn!("CTAPHID: invalid channel {=u32:#010X}", cid);
            send_error(cid, CTAP1_ERR_INVALID_CHANNEL, writer).await?;
            return Ok(());
        }

        // CANCEL aborts the current transaction.
        if cmd == CtapHidCommand::Cancel {
            if self.state != DispatcherState::Idle && self.active_cid == cid {
                defmt::debug!("CTAPHID: cancel on CID {=u32:#010X}", cid);
                self.reset();
            }
            return Ok(());
        }

        // If we're mid-assembly on a DIFFERENT channel, the new one gets BUSY.
        if self.state == DispatcherState::Assembling && self.active_cid != cid {
            defmt::warn!("CTAPHID: busy — rejecting CID {=u32:#010X}", cid);
            send_error(cid, CTAP1_ERR_CHANNEL_BUSY, writer).await?;
            return Ok(());
        }

        // If we're mid-assembly on the SAME channel, a new init aborts the old
        // transaction and starts fresh (per spec §8.1.5.1).
        if self.state == DispatcherState::Assembling && self.active_cid == cid {
            defmt::debug!("CTAPHID: aborting in-progress transaction, new init on same CID");
            self.reset();
        }

        // Validate payload length.
        if bcnt as usize > MAX_MSG_SIZE {
            send_error(cid, CTAP1_ERR_INVALID_LENGTH, writer).await?;
            return Ok(());
        }

        // Begin assembling.
        self.active_cid = cid;
        self.active_cmd = cmd;
        self.expected_len = bcnt;
        self.next_seq = 0;
        self.msg_buf.clear();

        let copy_len = core::cmp::min(bcnt as usize, INIT_DATA_SIZE);
        // Safety: MAX_MSG_SIZE >= INIT_DATA_SIZE, extend won't fail.
        let _ = self.msg_buf.extend_from_slice(&data[..copy_len]);

        if self.msg_buf.len() >= self.expected_len as usize {
            // Entire message fit in the init packet — dispatch immediately.
            self.state = DispatcherState::Idle;
            self.dispatch(writer, handler).await
        } else {
            self.state = DispatcherState::Assembling;
            Ok(())
        }
    }

    // -- Continuation-packet handling ----------------------------------------

    async fn handle_cont_packet(
        &mut self,
        cid: u32,
        seq: u8,
        data: &[u8; CONT_DATA_SIZE],
        writer: &mut impl ReportWriter,
        handler: &mut impl CommandHandler,
    ) -> Result<(), TransportError> {
        if self.state != DispatcherState::Assembling {
            // Unexpected continuation — ignore or error.
            defmt::warn!("CTAPHID: unexpected continuation in idle state");
            return Ok(());
        }

        if cid != self.active_cid {
            defmt::warn!("CTAPHID: continuation on wrong CID {=u32:#010X}", cid);
            send_error(cid, CTAP1_ERR_CHANNEL_BUSY, writer).await?;
            return Ok(());
        }

        if seq != self.next_seq {
            defmt::warn!("CTAPHID: bad seq {=u8}, expected {=u8}", seq, self.next_seq);
            send_error(cid, CTAP1_ERR_INVALID_SEQ, writer).await?;
            self.reset();
            return Ok(());
        }

        let remaining = self.expected_len as usize - self.msg_buf.len();
        let copy_len = core::cmp::min(remaining, CONT_DATA_SIZE);
        let _ = self.msg_buf.extend_from_slice(&data[..copy_len]);

        self.next_seq = seq.wrapping_add(1);

        if self.msg_buf.len() >= self.expected_len as usize {
            self.state = DispatcherState::Idle;
            self.dispatch(writer, handler).await
        } else {
            if self.next_seq > MAX_SEQ {
                defmt::warn!("CTAPHID: exceeded max continuation packets");
                send_error(cid, CTAP1_ERR_INVALID_LENGTH, writer).await?;
                self.reset();
            }
            Ok(())
        }
    }

    // -- Command dispatch ----------------------------------------------------

    async fn dispatch(
        &mut self,
        writer: &mut impl ReportWriter,
        handler: &mut impl CommandHandler,
    ) -> Result<(), TransportError> {
        let cid = self.active_cid;
        let cmd = self.active_cmd;

        defmt::debug!(
            "CTAPHID: dispatch cmd={=u8:#04X} len={=usize} on CID {=u32:#010X}",
            cmd.to_byte(),
            self.msg_buf.len(),
            cid,
        );

        match cmd {
            CtapHidCommand::Ping => {
                // Echo the payload back.
                let mut echo = Vec::<u8, MAX_MSG_SIZE>::new();
                let _ = echo.extend_from_slice(&self.msg_buf);
                self.msg_buf.clear();
                send_response(cid, CtapHidCommand::Ping, &echo, writer).await
            }

            CtapHidCommand::Wink => {
                handler.wink();
                self.msg_buf.clear();
                send_response(cid, CtapHidCommand::Wink, &[], writer).await
            }

            CtapHidCommand::Lock => {
                // Minimal implementation: lock not supported, respond with empty OK.
                self.msg_buf.clear();
                send_response(cid, CtapHidCommand::Lock, &[], writer).await
            }

            CtapHidCommand::Cbor => {
                let mut resp = Vec::<u8, MAX_MSG_SIZE>::new();
                let result = handler.handle_cbor(&self.msg_buf, &mut resp).await;
                self.msg_buf.clear();
                match result {
                    Ok(()) => send_response(cid, CtapHidCommand::Cbor, &resp, writer).await,
                    Err(e) => {
                        defmt::warn!("CTAPHID: CBOR handler error");
                        send_error(cid, CTAP1_ERR_INVALID_LENGTH, writer).await?;
                        Err(e)
                    }
                }
            }

            CtapHidCommand::Msg => {
                let mut resp = Vec::<u8, MAX_MSG_SIZE>::new();
                let result = handler.handle_msg(&self.msg_buf, &mut resp).await;
                self.msg_buf.clear();
                match result {
                    Ok(()) => send_response(cid, CtapHidCommand::Msg, &resp, writer).await,
                    Err(e) => {
                        defmt::warn!("CTAPHID: MSG handler error");
                        send_error(cid, CTAP1_ERR_INVALID_LENGTH, writer).await?;
                        Err(e)
                    }
                }
            }

            CtapHidCommand::Cancel => {
                // Handled earlier; should not reach dispatch. Ignore.
                self.msg_buf.clear();
                Ok(())
            }

            CtapHidCommand::Init => {
                // INIT should have been handled before dispatch. Fallback:
                self.msg_buf.clear();
                send_error(cid, CTAP1_ERR_INVALID_CHANNEL, writer).await
            }

            CtapHidCommand::Keepalive | CtapHidCommand::Error => {
                // These are device→host only; receiving them is invalid. Ignore.
                defmt::warn!("CTAPHID: received device-only command from host");
                self.msg_buf.clear();
                Ok(())
            }

            CtapHidCommand::Vendor(_) => {
                // Unsupported vendor command — reply with error.
                self.msg_buf.clear();
                send_error(cid, CTAP1_ERR_INVALID_CHANNEL, writer).await
            }
        }
    }

    // -- INIT command --------------------------------------------------------

    async fn handle_init_command(
        &mut self,
        cid: u32,
        data: &[u8; INIT_DATA_SIZE],
        writer: &mut impl ReportWriter,
    ) -> Result<(), TransportError> {
        // Nonce is the first 8 bytes of the INIT request payload.
        let mut nonce = [0u8; 8];
        nonce.copy_from_slice(&data[..8]);

        let new_cid = if cid == BROADCAST_CID {
            self.channels.allocate()
        } else {
            cid
        };

        defmt::debug!(
            "CTAPHID_INIT: nonce echoed, allocated CID {=u32:#010X}",
            new_cid,
        );

        let resp = CtapHidInitResponse {
            nonce,
            cid: new_cid,
            protocol_version: CTAPHID_PROTOCOL_VERSION,
            major_version: 0,
            minor_version: 1,
            build_version: 0,
            capabilities: CAPABILITY_WINK | CAPABILITY_CBOR | CAPABILITY_NMSG,
        };

        // INIT response is always sent on the CID that was used in the request.
        send_response(cid, CtapHidCommand::Init, &resp.to_bytes(), writer).await
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_roundtrip() {
        for b in 0x00..=0x7Fu8 {
            if let Some(cmd) = CtapHidCommand::from_byte(b) {
                assert_eq!(cmd.to_byte(), b);
            }
        }
    }

    #[test]
    fn parse_init_packet() {
        let mut report = [0u8; 64];
        // CID = 0x01020304
        report[0..4].copy_from_slice(&[0x01, 0x02, 0x03, 0x04]);
        // CMD = CBOR (0x10) | 0x80
        report[4] = 0x90;
        // BCNT = 5
        report[5] = 0x00;
        report[6] = 0x05;
        // DATA
        report[7..12].copy_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE]);

        let pkt = CtapHidPacket::parse(&report).unwrap();
        match pkt {
            CtapHidPacket::Init {
                cid,
                cmd,
                bcnt,
                data,
            } => {
                assert_eq!(cid, 0x01020304);
                assert_eq!(cmd, CtapHidCommand::Cbor);
                assert_eq!(bcnt, 5);
                assert_eq!(&data[..5], &[0xAA, 0xBB, 0xCC, 0xDD, 0xEE]);
            }
            _ => panic!("expected init packet"),
        }
    }

    #[test]
    fn parse_continuation_packet() {
        let mut report = [0u8; 64];
        report[0..4].copy_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF]);
        report[4] = 0x03; // SEQ = 3
        report[5] = 0x42;

        let pkt = CtapHidPacket::parse(&report).unwrap();
        match pkt {
            CtapHidPacket::Continuation { cid, seq, data } => {
                assert_eq!(cid, BROADCAST_CID);
                assert_eq!(seq, 3);
                assert_eq!(data[0], 0x42);
            }
            _ => panic!("expected continuation packet"),
        }
    }

    #[test]
    fn channel_allocation() {
        let mut ch = CtapHidChannel::new();
        let c1 = ch.allocate();
        let c2 = ch.allocate();
        assert_ne!(c1, c2);
        assert!(ch.is_valid(c1));
        assert!(ch.is_valid(c2));
        assert!(ch.is_valid(BROADCAST_CID));
        assert!(!ch.is_valid(0xDEAD));
    }

    #[test]
    fn channel_recycle() {
        let mut ch = CtapHidChannel::new();
        let mut first = 0;
        for i in 0..MAX_CHANNELS + 2 {
            let cid = ch.allocate();
            if i == 0 {
                first = cid;
            }
        }
        // After recycling, the oldest CID should have been evicted.
        assert!(!ch.is_valid(first));
    }

    #[test]
    fn init_response_serialization() {
        let resp = CtapHidInitResponse {
            nonce: [1, 2, 3, 4, 5, 6, 7, 8],
            cid: 0xAABBCCDD,
            protocol_version: 2,
            major_version: 1,
            minor_version: 0,
            build_version: 3,
            capabilities: CAPABILITY_WINK | CAPABILITY_CBOR,
        };
        let bytes = resp.to_bytes();
        assert_eq!(bytes.len(), 17);
        assert_eq!(&bytes[0..8], &[1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(&bytes[8..12], &[0xAA, 0xBB, 0xCC, 0xDD]);
        assert_eq!(bytes[12], 2);
        assert_eq!(bytes[16], CAPABILITY_WINK | CAPABILITY_CBOR);
    }

    #[test]
    fn fragmentation_single_packet() {
        let pkt = build_init_report(0x01020304, CtapHidCommand::Cbor, 3, &[0xAA, 0xBB, 0xCC]);
        assert_eq!(pkt.len(), 64);
        assert_eq!(&pkt[0..4], &[0x01, 0x02, 0x03, 0x04]);
        assert_eq!(pkt[4], 0x10 | 0x80);
        assert_eq!(pkt[5], 0x00);
        assert_eq!(pkt[6], 0x03);
        assert_eq!(&pkt[7..10], &[0xAA, 0xBB, 0xCC]);
        // Remaining bytes zero-padded.
        assert!(pkt[10..].iter().all(|&b| b == 0));
    }
}
