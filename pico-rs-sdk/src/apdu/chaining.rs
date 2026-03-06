use heapless::Vec;

use super::command::Command;
use super::response::Status;

pub const GET_RESPONSE_INS: u8 = 0xC0;
pub const CHUNK_SIZE: usize = 256;

/// Maximum chaining buffer size (supports extended APDU responses).
const MAX_CHAIN_BUF: usize = 4096;

/// Manages response chaining for large APDU responses via GET RESPONSE.
pub struct ChainingState {
    buffer: Vec<u8, MAX_CHAIN_BUF>,
    offset: usize,
}

impl ChainingState {
    pub fn new() -> Self {
        Self {
            buffer: Vec::new(),
            offset: 0,
        }
    }

    /// Returns true if there is remaining data to send.
    pub fn is_active(&self) -> bool {
        self.offset < self.buffer.len()
    }

    /// Bytes remaining to be read.
    pub fn remaining(&self) -> usize {
        self.buffer.len().saturating_sub(self.offset)
    }

    /// Load a full response into the chaining buffer, resetting offset.
    /// Data exceeding buffer capacity is silently truncated.
    pub fn start(&mut self, data: &[u8]) {
        self.buffer.clear();
        self.offset = 0;
        let take = data.len().min(MAX_CHAIN_BUF);
        // Won't fail because we capped at capacity.
        let _ = self.buffer.extend_from_slice(&data[..take]);
    }

    /// Return the next chunk (up to `max_len` bytes) and the corresponding status word.
    pub fn next_chunk(&mut self, max_len: usize) -> (&[u8], Status) {
        let remaining = self.remaining();
        let chunk_len = remaining.min(max_len);
        let chunk = &self.buffer[self.offset..self.offset + chunk_len];
        self.offset += chunk_len;

        let after = self.remaining();
        let status = if after == 0 {
            Status::Success
        } else if after > 255 {
            Status::MoreData(0x00)
        } else {
            Status::MoreData(after as u8)
        };

        (chunk, status)
    }

    /// Clear the chaining buffer and reset offset.
    pub fn reset(&mut self) {
        self.buffer.clear();
        self.offset = 0;
    }
}

impl Default for ChainingState {
    fn default() -> Self {
        Self::new()
    }
}

/// Returns true if the command is a GET RESPONSE (INS = 0xC0).
pub fn is_get_response(cmd: &Command) -> bool {
    cmd.ins() == GET_RESPONSE_INS
}
