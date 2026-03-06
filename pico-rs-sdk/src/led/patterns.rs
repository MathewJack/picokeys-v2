//! LED blink-pattern timing constants and helper logic.

use super::LedState;

// Idle: ON 500 ms every second (slow blink)
pub const IDLE_ON_MS: u32 = 500;
pub const IDLE_OFF_MS: u32 = 500;

// Active: 4 Hz blink
pub const ACTIVE_ON_MS: u32 = 125;
pub const ACTIVE_OFF_MS: u32 = 125;

// Processing: 20 Hz blink
pub const PROCESSING_ON_MS: u32 = 25;
pub const PROCESSING_OFF_MS: u32 = 25;

// Press-to-confirm: mostly ON, brief OFF
pub const PRESS_CONFIRM_ON_MS: u32 = 900;
pub const PRESS_CONFIRM_OFF_MS: u32 = 100;

/// Returns `(on_ms, off_ms)` for the given LED state.
pub fn get_timing(state: &LedState) -> (u32, u32) {
    match state {
        LedState::Off => (0, 0),
        LedState::Idle => (IDLE_ON_MS, IDLE_OFF_MS),
        LedState::Active => (ACTIVE_ON_MS, ACTIVE_OFF_MS),
        LedState::Processing => (PROCESSING_ON_MS, PROCESSING_OFF_MS),
        LedState::PressToConfirm => (PRESS_CONFIRM_ON_MS, PRESS_CONFIRM_OFF_MS),
        LedState::Custom { on_ms, off_ms } => (*on_ms, *off_ms),
    }
}

/// Returns `true` when the LED should flip ON↔OFF based on elapsed time.
pub fn should_toggle(state: &LedState, elapsed_ms: u64, is_on: bool) -> bool {
    let (on_ms, off_ms) = get_timing(state);
    if on_ms == 0 && off_ms == 0 {
        return false;
    }
    let threshold = if is_on { on_ms } else { off_ms } as u64;
    elapsed_ms >= threshold
}
