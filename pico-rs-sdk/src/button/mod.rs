//! Button / user-presence detection module.
//!
//! Platform adapters implement [`ButtonReader`]; higher-level code uses
//! [`PresenceDetector`] to run the press-to-confirm flow.

/// Result of a user-presence check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, defmt::Format)]
pub enum UserPresence {
    /// The user pressed the button within the timeout window.
    Confirmed,
    /// The user did not press the button and the timeout expired.
    Denied,
    /// The timeout elapsed without any interaction.
    Timeout,
}

/// Errors that can occur during button / presence operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, defmt::Format)]
pub enum ButtonError {
    /// The timeout period expired.
    Timeout,
    /// The operation was cancelled by the host.
    Cancelled,
    /// No button hardware is available on this platform.
    NotAvailable,
}

/// Platform-specific button reader.
pub trait ButtonReader {
    /// Returns `true` when the physical button is currently pressed.
    fn is_pressed(&mut self) -> bool;
}

/// Polling-based user-presence detector.
///
/// Call [`wait_for_press`](Self::wait_for_press) repeatedly from a tick loop;
/// it will return [`UserPresence::Confirmed`] once the button is pressed, or
/// [`ButtonError::Timeout`] when the deadline has passed.
pub struct PresenceDetector<B: ButtonReader> {
    reader: B,
    timeout_ms: u32,
    keepalive_interval_ms: u32,
    /// Start timestamp of the current wait (set on first call).
    start_ms: Option<u64>,
    /// Timestamp of the last keep-alive event.
    last_keepalive_ms: u64,
}

impl<B: ButtonReader> PresenceDetector<B> {
    /// Create a new detector with the given reader and timeout (milliseconds).
    ///
    /// The keep-alive interval defaults to 10 000 ms (per CTAPHID spec).
    pub fn new(reader: B, timeout_ms: u32) -> Self {
        Self {
            reader,
            timeout_ms,
            keepalive_interval_ms: 10_000,
            start_ms: None,
            last_keepalive_ms: 0,
        }
    }

    /// Convenience constructor with the default 15 000 ms timeout.
    pub fn with_default_timeout(reader: B) -> Self {
        Self::new(reader, 15_000)
    }

    /// Poll for a button press.
    ///
    /// * Returns `Ok(Confirmed)` when the button is pressed.
    /// * Returns `Err(Timeout)` when `timeout_ms` has elapsed since the
    ///   first call without a press.
    ///
    /// The caller should also check [`needs_keepalive`](Self::needs_keepalive)
    /// after each call to know when to send a CTAPHID keep-alive packet.
    pub fn wait_for_press(&mut self, now_ms: u64) -> Result<UserPresence, ButtonError> {
        let start = match self.start_ms {
            Some(s) => s,
            None => {
                self.start_ms = Some(now_ms);
                self.last_keepalive_ms = now_ms;
                now_ms
            }
        };

        if self.reader.is_pressed() {
            self.reset();
            return Ok(UserPresence::Confirmed);
        }

        let elapsed = now_ms.saturating_sub(start);
        if elapsed >= self.timeout_ms as u64 {
            self.reset();
            return Err(ButtonError::Timeout);
        }

        Ok(UserPresence::Denied)
    }

    /// Returns `true` when the caller should send a CTAPHID keep-alive.
    pub fn needs_keepalive(&mut self, now_ms: u64) -> bool {
        let since = now_ms.saturating_sub(self.last_keepalive_ms);
        if since >= self.keepalive_interval_ms as u64 {
            self.last_keepalive_ms = now_ms;
            true
        } else {
            false
        }
    }

    /// Reset internal state so the detector can be reused for a new wait.
    pub fn reset(&mut self) {
        self.start_ms = None;
        self.last_keepalive_ms = 0;
    }

    /// Returns a mutable reference to the underlying reader.
    pub fn reader_mut(&mut self) -> &mut B {
        &mut self.reader
    }
}

// ---------------------------------------------------------------------------
// Built-in stub readers
// ---------------------------------------------------------------------------

/// Always reports the button as pressed (headless / SAMD21 fallback).
pub struct AlwaysConfirm;

impl ButtonReader for AlwaysConfirm {
    fn is_pressed(&mut self) -> bool {
        true
    }
}

/// Never reports a press (for testing timeout paths).
pub struct NeverConfirm;

impl ButtonReader for NeverConfirm {
    fn is_pressed(&mut self) -> bool {
        false
    }
}
