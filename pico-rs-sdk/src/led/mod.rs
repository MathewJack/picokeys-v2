//! LED controller — state machine driving single-color or RGB LEDs
//! through the standard PicoKeys blink patterns.

pub mod patterns;

/// Visual state the LED should represent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, defmt::Format)]
pub enum LedState {
    /// LED permanently off.
    Off,
    /// Idle heartbeat: 500 ms ON / 500 ms OFF.
    Idle,
    /// Active (authenticating): 125 ms ON / 125 ms OFF (4 Hz).
    Active,
    /// Processing CTAP/APDU: 25 ms ON / 25 ms OFF (20 Hz).
    Processing,
    /// Waiting for user button press: 900 ms ON / 100 ms OFF.
    PressToConfirm,
    /// Arbitrary custom timing.
    Custom { on_ms: u32, off_ms: u32 },
}

/// Simple RGB colour value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, defmt::Format)]
pub struct LedColor {
    pub r: u8,
    pub g: u8,
    pub b: u8,
}

impl LedColor {
    pub const fn new(r: u8, g: u8, b: u8) -> Self {
        Self { r, g, b }
    }

    pub const WHITE: Self = Self {
        r: 255,
        g: 255,
        b: 255,
    };
    pub const OFF: Self = Self { r: 0, g: 0, b: 0 };
}

/// Platform-specific LED driver.
pub trait LedDriver {
    /// Turn the LED on (using the current colour).
    fn set_on(&mut self);
    /// Turn the LED off.
    fn set_off(&mut self);
    /// Set the LED colour (ignored on single-colour drivers).
    fn set_color(&mut self, color: LedColor);
}

/// High-level LED controller that drives an [`LedDriver`] according to the
/// current [`LedState`] pattern.
///
/// Call [`update`](Self::update) from a periodic tick (≤ 10 ms recommended).
pub struct LedController<L: LedDriver> {
    driver: L,
    state: LedState,
    last_toggle: u64,
    is_on: bool,
}

impl<L: LedDriver> LedController<L> {
    /// Create a new controller. The LED starts in [`LedState::Off`].
    pub fn new(driver: L) -> Self {
        Self {
            driver,
            state: LedState::Off,
            last_toggle: 0,
            is_on: false,
        }
    }

    /// Change the current LED state. Resets the timing phase so the new
    /// pattern starts immediately.
    pub fn set_state(&mut self, state: LedState, now_ms: u64) {
        if self.state == state {
            return;
        }
        self.state = state;
        self.last_toggle = now_ms;

        match state {
            LedState::Off => {
                self.is_on = false;
                self.driver.set_off();
            }
            _ => {
                // Start each new pattern with LED ON.
                self.is_on = true;
                self.driver.set_on();
            }
        }
    }

    /// Poll-update — call at least every 10 ms.
    pub fn update(&mut self, now_ms: u64) {
        if self.state == LedState::Off {
            return;
        }

        let elapsed = now_ms.saturating_sub(self.last_toggle);
        if patterns::should_toggle(&self.state, elapsed, self.is_on) {
            self.is_on = !self.is_on;
            self.last_toggle = now_ms;
            if self.is_on {
                self.driver.set_on();
            } else {
                self.driver.set_off();
            }
        }
    }

    /// Returns a reference to the underlying driver.
    pub fn driver(&self) -> &L {
        &self.driver
    }

    /// Returns a mutable reference to the underlying driver.
    pub fn driver_mut(&mut self) -> &mut L {
        &mut self.driver
    }

    /// Returns the current LED state.
    pub fn state(&self) -> LedState {
        self.state
    }
}
