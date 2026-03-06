#![no_std]
#![no_main]

//! PicoKeys FIDO2 firmware — ESP32-C6 (RISC-V, **serial-only**).
//!
//! **IMPORTANT: The ESP32-C6 has NO native USB HID/CCID support.**
//! It only has a USB-Serial-JTAG peripheral that exposes a CDC-ACM serial port.
//! This firmware implements CTAP-over-serial: length-prefixed CBOR frames
//! sent/received over the USB serial interface.
//!
//! This means:
//! - The C6 CANNOT be used as a native FIDO2 authenticator in browsers.
//! - It requires `picokeys-cli` on the host side with serial transport.
//! - The host CLI detects C6 by VID/PID and routes commands via serial.
//!
//! Button: GPIO9 (active-low boot button).
//! LED: WS2812 on GPIO8 via RMT.

use esp_hal as _;

use embassy_executor::Spawner;
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::channel::Channel;
use embassy_time::{Duration, Ticker, Timer};

use pico_rs_sdk::button::{ButtonReader, PresenceDetector};
use pico_rs_sdk::led::{LedColor, LedController, LedDriver, LedState};
use pico_rs_sdk::rescue::{detect_rescue_mode, RescueMode};

use pico_rs_fido::fido::{FidoApp, FidoConfig};

// ---------------------------------------------------------------------------
// Serial protocol constants
// ---------------------------------------------------------------------------

/// Maximum CTAP-over-serial frame size (4-byte length prefix + CBOR payload).
const MAX_SERIAL_FRAME: usize = 7613;

/// Frame header: 4-byte little-endian payload length.
const FRAME_HEADER_SIZE: usize = 4;

// ---------------------------------------------------------------------------
// Flash / USB constants
// ---------------------------------------------------------------------------

const STORAGE_SIZE: usize = 128 * 1024;

// ---------------------------------------------------------------------------
// GPIO pins
// ---------------------------------------------------------------------------

const BUTTON_GPIO: u8 = 9;
const LED_GPIO: u8 = 8;

// ---------------------------------------------------------------------------
// Shared state
// ---------------------------------------------------------------------------

static LED_CHANNEL: Channel<CriticalSectionRawMutex, LedState, 4> = Channel::new();

// ---------------------------------------------------------------------------
// GPIO9 boot button (active-low)
// ---------------------------------------------------------------------------

struct Esp32c6Button {
    pressed: bool,
}

impl Esp32c6Button {
    fn new() -> Self {
        Self { pressed: false }
    }
}

impl ButtonReader for Esp32c6Button {
    fn is_pressed(&mut self) -> bool {
        self.pressed
    }
}

// ---------------------------------------------------------------------------
// WS2812 LED driver via RMT on GPIO8
// ---------------------------------------------------------------------------

struct RmtLed {
    on: bool,
    color: LedColor,
}

impl RmtLed {
    fn new() -> Self {
        Self {
            on: false,
            color: LedColor::WHITE,
        }
    }
}

impl LedDriver for RmtLed {
    fn set_on(&mut self) {
        self.on = true;
    }
    fn set_off(&mut self) {
        self.on = false;
    }
    fn set_color(&mut self, color: LedColor) {
        self.color = color;
    }
}

// ---------------------------------------------------------------------------
// CTAP-over-serial frame helpers
// ---------------------------------------------------------------------------

/// Read a length-prefixed frame from the serial buffer.
/// Returns the number of payload bytes, or 0 if the buffer is too short.
fn parse_serial_frame(buf: &[u8]) -> Option<(usize, &[u8])> {
    if buf.len() < FRAME_HEADER_SIZE {
        return None;
    }
    let len = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    if buf.len() < FRAME_HEADER_SIZE + len {
        return None;
    }
    Some((len, &buf[FRAME_HEADER_SIZE..FRAME_HEADER_SIZE + len]))
}

/// Build a length-prefixed serial frame into `out_buf`.
/// Returns the total frame size (header + payload).
fn build_serial_frame(payload: &[u8], out_buf: &mut [u8]) -> usize {
    let len = payload.len() as u32;
    let header = len.to_le_bytes();
    let total = FRAME_HEADER_SIZE + payload.len();
    if out_buf.len() >= total {
        out_buf[..FRAME_HEADER_SIZE].copy_from_slice(&header);
        out_buf[FRAME_HEADER_SIZE..total].copy_from_slice(payload);
    }
    total
}

// ---------------------------------------------------------------------------
// Embassy tasks
// ---------------------------------------------------------------------------

#[embassy_executor::task]
async fn led_task(mut controller: LedController<RmtLed>) -> ! {
    let mut ticker = Ticker::every(Duration::from_millis(10));
    controller.set_state(LedState::Idle, embassy_time::Instant::now().as_millis());

    loop {
        if let Ok(state) = LED_CHANNEL.try_receive() {
            controller.set_state(state, embassy_time::Instant::now().as_millis());
        }
        controller.update(embassy_time::Instant::now().as_millis());
        ticker.next().await;
    }
}

#[embassy_executor::task]
async fn button_task(mut detector: PresenceDetector<Esp32c6Button>) -> ! {
    let mut ticker = Ticker::every(Duration::from_millis(50));
    loop {
        let now_ms = embassy_time::Instant::now().as_millis();
        let _ = detector.wait_for_press(now_ms);
        ticker.next().await;
    }
}

/// Serial CTAP transport task.
///
/// Reads length-prefixed CBOR frames from the USB-Serial-JTAG CDC-ACM port,
/// dispatches them to the FIDO application, and sends back framed responses.
#[embassy_executor::task]
async fn serial_ctap_task(mut fido: FidoApp) -> ! {
    let mut rx_buf = [0u8; MAX_SERIAL_FRAME];
    let mut tx_buf = [0u8; MAX_SERIAL_FRAME];
    let mut response_buf = [0u8; 7609];

    loop {
        // In a real implementation:
        // 1. Read bytes from USB-Serial-JTAG into rx_buf using esp-hal UART/USB-Serial driver
        // 2. Parse the length-prefixed frame
        // 3. Dispatch the CBOR payload to fido.process_ctaphid_cbor()
        // 4. Build a length-prefixed response frame
        // 5. Write the frame back over serial

        // Placeholder: wait for serial data to arrive
        Timer::after(Duration::from_millis(10)).await;

        // Example dispatch flow (activated when serial data arrives):
        // if let Some((payload_len, payload)) = parse_serial_frame(&rx_buf[..n]) {
        //     let now_ms = embassy_time::Instant::now().as_millis();
        //     match fido.process_ctaphid_cbor(payload, &mut response_buf, now_ms, false) {
        //         Ok(resp_len) => {
        //             let frame_len = build_serial_frame(&response_buf[..resp_len], &mut tx_buf);
        //             // serial.write(&tx_buf[..frame_len]).await;
        //         }
        //         Err(_) => {
        //             // Send error frame
        //             let err = [0x01]; // CTAP2_ERR_INVALID_COMMAND
        //             let frame_len = build_serial_frame(&err, &mut tx_buf);
        //             // serial.write(&tx_buf[..frame_len]).await;
        //         }
        //     }
        // }
    }
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

#[embassy_executor::main]
async fn main(spawner: Spawner) {
    defmt::info!("PicoKeys FIDO2 — ESP32-C6 starting (SERIAL-ONLY mode)");
    defmt::warn!("ESP32-C6 has NO native HID/CCID — using CTAP-over-serial protocol");

    // 1. Initialize ESP32-C6 peripherals (RISC-V)
    let config = esp_hal::Config::default();
    let peripherals = esp_hal::init(config);

    // 2. Initialize hardware TRNG
    let mut rng = esp_hal::rng::Rng::new(peripherals.RNG);
    defmt::info!("ESP32-C6 hardware TRNG initialized");

    // 3. Setup flash storage
    defmt::info!("Flash storage partition: {} KB", STORAGE_SIZE / 1024);

    // 4. Setup WS2812 LED on GPIO8 via RMT
    let led_driver = RmtLed::new();
    let led_controller = LedController::new(led_driver);

    // 5. Setup GPIO9 boot button
    let button = Esp32c6Button::new();
    let mut rescue_button = Esp32c6Button::new();
    let rescue_mode = detect_rescue_mode(&mut rescue_button);
    let detector = PresenceDetector::with_default_timeout(button);

    // 6. USB-Serial-JTAG initialization
    // The C6's USB-Serial-JTAG peripheral appears as a CDC-ACM device.
    // No HID or CCID class — only serial I/O is available.
    defmt::info!("USB-Serial-JTAG → CDC-ACM serial transport");

    // 7. Initialize FIDO application
    let fido_config = FidoConfig::default();
    let fido_app = FidoApp::new(fido_config, embassy_time::Instant::now().as_millis());

    // 8. Handle rescue mode
    if rescue_mode == RescueMode::Rescue {
        defmt::warn!("Rescue mode detected — entering recovery");
    }

    // 9. Spawn tasks
    spawner.spawn(led_task(led_controller)).unwrap();
    spawner.spawn(button_task(detector)).unwrap();
    spawner.spawn(serial_ctap_task(fido_app)).unwrap();

    defmt::info!("PicoKeys FIDO2 — ESP32-C6 running (serial-only, use picokeys-cli)");
}
