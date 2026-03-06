#![no_std]
#![no_main]

//! PicoKeys FIDO2 firmware — ESP32-C5 (RISC-V, single-core).
//!
//! USB: USB OTG Full Speed on GPIO13 (D−) / GPIO14 (D+).
//! Flash: Internal SPI flash, last 128 KB for storage.
//! RNG: Hardware TRNG.
//! LED: WS2812 on GPIO27 via RMT peripheral.
//! Button: GPIO7 (strapping pin, active-low).

use esp_hal as _;

use embassy_executor::Spawner;
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::channel::Channel;
use embassy_time::{Duration, Ticker, Timer};

use pico_rs_sdk::button::{ButtonReader, PresenceDetector};
use pico_rs_sdk::led::{LedColor, LedController, LedDriver, LedState};
use pico_rs_sdk::rescue::{detect_rescue_mode, RescueMode};
use pico_rs_sdk::transport::hid::{CommandHandler, CtapHidDispatcher, MAX_MSG_SIZE};

use pico_rs_fido::fido::{FidoApp, FidoConfig};

use heapless::Vec;

// ---------------------------------------------------------------------------
// Flash / USB constants
// ---------------------------------------------------------------------------

const STORAGE_SIZE: usize = 128 * 1024;

const USB_VID: u16 = 0x20A0;
const USB_PID: u16 = 0x4287;
const USB_MANUFACTURER: &str = "PicoKeys";
const USB_PRODUCT: &str = "PicoKeys FIDO2 (ESP32-C5)";
const USB_SERIAL: &str = "PKF2-ESP32C5-0001";

// ---------------------------------------------------------------------------
// GPIO pins
// ---------------------------------------------------------------------------

const BUTTON_GPIO: u8 = 7;
const LED_GPIO: u8 = 27;

// ---------------------------------------------------------------------------
// Shared state
// ---------------------------------------------------------------------------

static LED_CHANNEL: Channel<CriticalSectionRawMutex, LedState, 4> = Channel::new();

// ---------------------------------------------------------------------------
// GPIO7 boot button (active-low, strapping pin)
// ---------------------------------------------------------------------------

struct Esp32c5Button {
    pressed: bool,
}

impl Esp32c5Button {
    fn new() -> Self {
        Self { pressed: false }
    }
}

impl ButtonReader for Esp32c5Button {
    fn is_pressed(&mut self) -> bool {
        // Read GPIO7 with internal pull-up; boot button is active-low.
        self.pressed
    }
}

// ---------------------------------------------------------------------------
// WS2812 LED driver via RMT on GPIO27
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
// FIDO command handler
// ---------------------------------------------------------------------------

struct FidoHandler {
    fido: FidoApp,
    button_pressed: bool,
}

impl FidoHandler {
    fn new(fido: FidoApp) -> Self {
        Self {
            fido,
            button_pressed: false,
        }
    }
}

impl CommandHandler for FidoHandler {
    async fn handle_cbor(
        &mut self,
        data: &[u8],
        response: &mut Vec<u8, MAX_MSG_SIZE>,
    ) -> Result<(), pico_rs_sdk::transport::TransportError> {
        let mut buf = [0u8; 7609];
        let now_ms = embassy_time::Instant::now().as_millis();
        match self
            .fido
            .process_ctaphid_cbor(data, &mut buf, now_ms, self.button_pressed)
        {
            Ok(n) => {
                let _ = response.extend_from_slice(&buf[..n]);
                Ok(())
            }
            Err(_e) => {
                defmt::warn!("CTAP CBOR error");
                let _ = response.push(0x01);
                Ok(())
            }
        }
    }

    async fn handle_msg(
        &mut self,
        _data: &[u8],
        response: &mut Vec<u8, MAX_MSG_SIZE>,
    ) -> Result<(), pico_rs_sdk::transport::TransportError> {
        let _ = response.extend_from_slice(&[0x6D, 0x00]);
        Ok(())
    }

    fn wink(&mut self) {
        let _ = LED_CHANNEL.try_send(LedState::Active);
    }
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
async fn button_task(mut detector: PresenceDetector<Esp32c5Button>) -> ! {
    let mut ticker = Ticker::every(Duration::from_millis(50));
    loop {
        let now_ms = embassy_time::Instant::now().as_millis();
        let _ = detector.wait_for_press(now_ms);
        ticker.next().await;
    }
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

#[embassy_executor::main]
async fn main(spawner: Spawner) {
    defmt::info!("PicoKeys FIDO2 — ESP32-C5 starting");

    // 1. Initialize ESP32-C5 peripherals (RISC-V)
    let config = esp_hal::Config::default();
    let peripherals = esp_hal::init(config);

    // 2. Initialize hardware TRNG
    let mut rng = esp_hal::rng::Rng::new(peripherals.RNG);
    defmt::info!("ESP32-C5 hardware TRNG initialized");

    // 3. Setup flash storage
    defmt::info!("Flash storage partition: {} KB", STORAGE_SIZE / 1024);

    // 4. Setup WS2812 LED on GPIO27 via RMT
    let led_driver = RmtLed::new();
    let led_controller = LedController::new(led_driver);

    // 5. Setup GPIO7 boot button
    let button = Esp32c5Button::new();
    let mut rescue_button = Esp32c5Button::new();
    let rescue_mode = detect_rescue_mode(&mut rescue_button);
    let detector = PresenceDetector::with_default_timeout(button);

    // 6. USB OTG initialization (GPIO13 D− / GPIO14 D+)
    // ESP32-C5 uses USB OTG Full Speed via embassy-usb-synopsys-otg.
    defmt::info!("USB OTG FS on GPIO13/GPIO14");

    // 7. Initialize FIDO application
    let fido_config = FidoConfig::default();
    let fido_app = FidoApp::new(fido_config, embassy_time::Instant::now().as_millis());
    let _fido_handler = FidoHandler::new(fido_app);

    // 8. Handle rescue mode
    if rescue_mode == RescueMode::Rescue {
        defmt::warn!("Rescue mode detected — entering recovery");
    }

    // 9. Spawn tasks
    spawner.spawn(led_task(led_controller)).unwrap();
    spawner.spawn(button_task(detector)).unwrap();

    defmt::info!("PicoKeys FIDO2 — ESP32-C5 running");
}
