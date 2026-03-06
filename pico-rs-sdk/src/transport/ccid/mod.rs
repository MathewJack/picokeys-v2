pub mod class;

use heapless::Vec;

use crate::apdu::{
    chaining::{self, ChainingState, CHUNK_SIZE},
    Application, Command, Reply, Status,
};

// ---------------------------------------------------------------------------
// CCID Message Types (USB CCID Rev 1.1)
// ---------------------------------------------------------------------------

/// PC_to_RDR command message types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CcidMessageType {
    IccPowerOn = 0x62,
    IccPowerOff = 0x63,
    GetSlotStatus = 0x65,
    XfrBlock = 0x6F,
    Abort = 0x72,
}

impl CcidMessageType {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x62 => Some(Self::IccPowerOn),
            0x63 => Some(Self::IccPowerOff),
            0x65 => Some(Self::GetSlotStatus),
            0x6F => Some(Self::XfrBlock),
            0x72 => Some(Self::Abort),
            _ => None,
        }
    }
}

/// RDR_to_PC response message types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CcidResponseType {
    DataBlock = 0x80,
    SlotStatus = 0x81,
    Parameters = 0x82,
}

// ---------------------------------------------------------------------------
// CCID Header (10 bytes)
// ---------------------------------------------------------------------------

/// CCID message header — 10 bytes, little-endian wire format.
#[derive(Debug, Clone)]
pub struct CcidHeader {
    pub message_type: u8,
    pub length: u32,
    pub slot: u8,
    pub seq: u8,
    pub specific: [u8; 3],
}

/// Errors from CCID message parsing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CcidError {
    HeaderTooShort,
    PayloadTooShort,
    PayloadTooLong,
    UnknownMessageType,
    InvalidSlot,
}

pub const CCID_HEADER_LEN: usize = 10;
const MAX_CCID_PAYLOAD: usize = 1024;

impl CcidHeader {
    /// Parse a CCID header from a 10-byte slice (little-endian wire format).
    pub fn from_bytes(buf: &[u8]) -> Result<Self, CcidError> {
        if buf.len() < CCID_HEADER_LEN {
            return Err(CcidError::HeaderTooShort);
        }
        let length = u32::from_le_bytes([buf[1], buf[2], buf[3], buf[4]]);
        Ok(CcidHeader {
            message_type: buf[0],
            length,
            slot: buf[5],
            seq: buf[6],
            specific: [buf[7], buf[8], buf[9]],
        })
    }

    /// Serialize the header into a 10-byte array (little-endian).
    pub fn to_bytes(&self) -> [u8; CCID_HEADER_LEN] {
        let len_le = self.length.to_le_bytes();
        [
            self.message_type,
            len_le[0],
            len_le[1],
            len_le[2],
            len_le[3],
            self.slot,
            self.seq,
            self.specific[0],
            self.specific[1],
            self.specific[2],
        ]
    }
}

// ---------------------------------------------------------------------------
// CCID Message (header + payload)
// ---------------------------------------------------------------------------

/// A parsed CCID message with header and optional data payload.
pub struct CcidMessage {
    pub header: CcidHeader,
    pub data: Vec<u8, MAX_CCID_PAYLOAD>,
}

impl CcidMessage {
    /// Parse a complete CCID message from raw bytes.
    pub fn from_bytes(buf: &[u8]) -> Result<Self, CcidError> {
        let header = CcidHeader::from_bytes(buf)?;
        let payload_len = header.length as usize;
        let total = CCID_HEADER_LEN + payload_len;

        if payload_len > MAX_CCID_PAYLOAD {
            return Err(CcidError::PayloadTooLong);
        }
        if buf.len() < total {
            return Err(CcidError::PayloadTooShort);
        }

        let mut data = Vec::new();
        data.extend_from_slice(&buf[CCID_HEADER_LEN..total])
            .map_err(|_| CcidError::PayloadTooLong)?;

        Ok(CcidMessage { header, data })
    }

    /// Serialize into the provided buffer, returning the number of bytes written.
    pub fn to_bytes(&self, buf: &mut [u8]) -> Result<usize, CcidError> {
        let total = CCID_HEADER_LEN + self.data.len();
        if buf.len() < total {
            return Err(CcidError::PayloadTooLong);
        }
        buf[..CCID_HEADER_LEN].copy_from_slice(&self.header.to_bytes());
        buf[CCID_HEADER_LEN..total].copy_from_slice(&self.data);
        Ok(total)
    }
}

// ---------------------------------------------------------------------------
// CCID Slot State
// ---------------------------------------------------------------------------

/// Standard T=1 ATR for a smart card.
pub const ATR: &[u8] = &[0x3B, 0x80, 0x80, 0x01, 0x01];

/// ICC status values for the bmICCStatus field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum IccStatus {
    Active = 0,
    Inactive = 1,
    NotPresent = 2,
}

/// CCID command status (bits 7-6 of bStatus).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CommandStatus {
    Ok = 0x00,
    Failed = 0x40,
    TimeExtension = 0x80,
}

/// Error codes for the bError field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SlotError {
    None = 0x00,
    BadSlot = 0x05,
    CmdNotSupported = 0x40,
    IccMute = 0xFE,
    CmdAborted = 0xFF,
}

/// Tracks the state of a single CCID card slot.
pub struct CcidSlot {
    pub card_present: bool,
    pub card_powered: bool,
}

impl CcidSlot {
    pub fn new() -> Self {
        Self {
            card_present: true,
            card_powered: false,
        }
    }

    pub fn icc_status(&self) -> u8 {
        if !self.card_present {
            IccStatus::NotPresent as u8
        } else if self.card_powered {
            IccStatus::Active as u8
        } else {
            IccStatus::Inactive as u8
        }
    }

    fn status_byte(&self, cmd: CommandStatus) -> u8 {
        self.icc_status() | (cmd as u8)
    }
}

impl Default for CcidSlot {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// CCID Dispatcher
// ---------------------------------------------------------------------------

/// Processes incoming CCID messages, dispatches APDU data to an Application, builds responses.
pub struct CcidDispatcher {
    slot: CcidSlot,
    chaining: ChainingState,
}

impl CcidDispatcher {
    pub fn new() -> Self {
        Self {
            slot: CcidSlot::new(),
            chaining: ChainingState::new(),
        }
    }

    /// Process an incoming CCID message and produce a response message.
    /// Returns the response serialized into `out_buf`, yielding the number of bytes written.
    pub fn process<A: Application>(
        &mut self,
        msg: &CcidMessage,
        app: &mut A,
        out_buf: &mut [u8],
    ) -> Result<usize, CcidError> {
        if msg.header.slot != 0 {
            return self.build_slot_status(
                msg.header.seq,
                CommandStatus::Failed,
                SlotError::BadSlot,
                IccStatus::NotPresent as u8,
                out_buf,
            );
        }

        let msg_type = CcidMessageType::from_u8(msg.header.message_type)
            .ok_or(CcidError::UnknownMessageType)?;

        match msg_type {
            CcidMessageType::IccPowerOn => self.handle_power_on(msg.header.seq, app, out_buf),
            CcidMessageType::IccPowerOff => self.handle_power_off(msg.header.seq, out_buf),
            CcidMessageType::GetSlotStatus => self.handle_slot_status(msg.header.seq, out_buf),
            CcidMessageType::XfrBlock => self.handle_xfr_block(msg, app, out_buf),
            CcidMessageType::Abort => self.handle_abort(msg.header.seq, out_buf),
        }
    }

    fn handle_power_on<A: Application>(
        &mut self,
        seq: u8,
        app: &mut A,
        out_buf: &mut [u8],
    ) -> Result<usize, CcidError> {
        self.slot.card_powered = true;
        self.chaining.reset();
        let _ = app.select();
        self.build_data_block(seq, ATR, CommandStatus::Ok, SlotError::None, out_buf)
    }

    fn handle_power_off(&mut self, seq: u8, out_buf: &mut [u8]) -> Result<usize, CcidError> {
        self.slot.card_powered = false;
        self.chaining.reset();
        self.build_slot_status(
            seq,
            CommandStatus::Ok,
            SlotError::None,
            self.slot.icc_status(),
            out_buf,
        )
    }

    fn handle_slot_status(&self, seq: u8, out_buf: &mut [u8]) -> Result<usize, CcidError> {
        self.build_slot_status(
            seq,
            CommandStatus::Ok,
            SlotError::None,
            self.slot.icc_status(),
            out_buf,
        )
    }

    fn handle_xfr_block<A: Application>(
        &mut self,
        msg: &CcidMessage,
        app: &mut A,
        out_buf: &mut [u8],
    ) -> Result<usize, CcidError> {
        if !self.slot.card_powered {
            return self.build_slot_status(
                msg.header.seq,
                CommandStatus::Failed,
                SlotError::IccMute,
                self.slot.icc_status(),
                out_buf,
            );
        }

        // Parse the APDU command from the XfrBlock data
        let apdu_data = &msg.data;

        let cmd = match Command::from_bytes(apdu_data) {
            Ok(c) => c,
            Err(_) => {
                // Return an error data block with SW 6700 (wrong length)
                return self.build_data_block(
                    msg.header.seq,
                    &[0x67, 0x00],
                    CommandStatus::Ok,
                    SlotError::None,
                    out_buf,
                );
            }
        };

        // Handle GET RESPONSE for chained responses
        if chaining::is_get_response(&cmd) {
            if !self.chaining.is_active() {
                return self.build_data_block(
                    msg.header.seq,
                    &[0x69, 0x85], // Conditions not met
                    CommandStatus::Ok,
                    SlotError::None,
                    out_buf,
                );
            }
            let max = cmd.expected_len().unwrap_or(CHUNK_SIZE as u32) as usize;
            let (chunk, status) = self.chaining.next_chunk(max);
            return self.build_data_block_with_sw(msg.header.seq, chunk, status, out_buf);
        }

        // Normal APDU dispatch
        let mut reply = Reply::new();
        let status = match app.call(&cmd, &mut reply) {
            Ok(()) => Status::Success,
            Err(s) => s,
        };

        // If reply is small enough, send directly
        let reply_data = reply.as_slice();
        if reply_data.len() <= CHUNK_SIZE {
            self.chaining.reset();
            return self.build_data_block_with_sw(msg.header.seq, reply_data, status, out_buf);
        }

        // Large response — start chaining
        self.chaining.start(reply_data);
        let max = cmd.expected_len().unwrap_or(CHUNK_SIZE as u32) as usize;
        let (chunk, chain_status) = self.chaining.next_chunk(max);
        self.build_data_block_with_sw(msg.header.seq, chunk, chain_status, out_buf)
    }

    fn handle_abort(&mut self, seq: u8, out_buf: &mut [u8]) -> Result<usize, CcidError> {
        self.chaining.reset();
        self.build_slot_status(
            seq,
            CommandStatus::Ok,
            SlotError::CmdAborted,
            self.slot.icc_status(),
            out_buf,
        )
    }

    // -----------------------------------------------------------------------
    // Response builders
    // -----------------------------------------------------------------------

    fn build_data_block(
        &self,
        seq: u8,
        data: &[u8],
        cmd_status: CommandStatus,
        error: SlotError,
        out_buf: &mut [u8],
    ) -> Result<usize, CcidError> {
        let header = CcidHeader {
            message_type: CcidResponseType::DataBlock as u8,
            length: data.len() as u32,
            slot: 0,
            seq,
            specific: [
                self.slot.status_byte(cmd_status),
                error as u8,
                0x00, // chain parameter
            ],
        };
        let total = CCID_HEADER_LEN + data.len();
        if out_buf.len() < total {
            return Err(CcidError::PayloadTooLong);
        }
        out_buf[..CCID_HEADER_LEN].copy_from_slice(&header.to_bytes());
        out_buf[CCID_HEADER_LEN..total].copy_from_slice(data);
        Ok(total)
    }

    fn build_data_block_with_sw(
        &self,
        seq: u8,
        data: &[u8],
        status: Status,
        out_buf: &mut [u8],
    ) -> Result<usize, CcidError> {
        let sw = status.to_bytes();
        let payload_len = data.len() + 2;
        let header = CcidHeader {
            message_type: CcidResponseType::DataBlock as u8,
            length: payload_len as u32,
            slot: 0,
            seq,
            specific: [
                self.slot.status_byte(CommandStatus::Ok),
                SlotError::None as u8,
                0x00,
            ],
        };
        let total = CCID_HEADER_LEN + payload_len;
        if out_buf.len() < total {
            return Err(CcidError::PayloadTooLong);
        }
        out_buf[..CCID_HEADER_LEN].copy_from_slice(&header.to_bytes());
        out_buf[CCID_HEADER_LEN..CCID_HEADER_LEN + data.len()].copy_from_slice(data);
        out_buf[CCID_HEADER_LEN + data.len()..total].copy_from_slice(&sw);
        Ok(total)
    }

    fn build_slot_status(
        &self,
        seq: u8,
        cmd_status: CommandStatus,
        error: SlotError,
        icc_status: u8,
        out_buf: &mut [u8],
    ) -> Result<usize, CcidError> {
        let header = CcidHeader {
            message_type: CcidResponseType::SlotStatus as u8,
            length: 0,
            slot: 0,
            seq,
            specific: [
                icc_status | (cmd_status as u8),
                error as u8,
                0x00, // clock status
            ],
        };
        if out_buf.len() < CCID_HEADER_LEN {
            return Err(CcidError::PayloadTooLong);
        }
        out_buf[..CCID_HEADER_LEN].copy_from_slice(&header.to_bytes());
        Ok(CCID_HEADER_LEN)
    }
}

impl Default for CcidDispatcher {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Slot Change Notification (for interrupt endpoint)
// ---------------------------------------------------------------------------

/// Build a 2-byte RDR_to_PC_NotifySlotChange message.
/// Bit 0 of byte 1: slot 0 changed, bit 1: slot 0 present.
pub fn slot_change_notification(card_present: bool) -> [u8; 2] {
    let mut msg = [0x50, 0x00]; // bMessageType = 0x50
    if card_present {
        msg[1] = 0x03; // slot 0 changed + slot 0 card present
    } else {
        msg[1] = 0x02; // slot 0 changed + slot 0 card not present
    }
    msg
}
