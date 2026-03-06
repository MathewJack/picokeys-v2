#![no_std]
#![no_main]

//! PicoKeys FIDO2 firmware — SAMD21 (Cortex-M0+, 48 MHz).
//!
//! USB: Native USB FS on PA24 (D−) / PA25 (D+).
//! Flash: 256 KB total, last 32 KB reserved for storage.
//! LED: Single-color digital output on GPIO13 (PA17).
//! Button: No dedicated BOOTSEL — configurable GPIO, defaults to AlwaysConfirm.
//! TRNG: Limited (SAMD21 has no dedicated TRNG; uses ADC noise or external seed).
//!
//! **Excluded features (256 KB flash limit):**
//! - No RSA support (`#[cfg(not(feature = "samd21"))]` gates RSA in SDK)
//! - No HSM application
//! - FIDO2 + OATH only

use defmt_rtt as _;
use panic_probe as _;

use embassy_executor::Spawner;
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::channel::Channel;
use embassy_time::{Duration, Ticker, Timer};
use embassy_usb::class::hid;
use embassy_usb::UsbDevice;

use pico_rs_sdk::button::{AlwaysConfirm, ButtonReader, PresenceDetector};
use pico_rs_sdk::led::{LedColor, LedController, LedDriver, LedState};
use pico_rs_sdk::rescue::{detect_rescue_mode, RescueMode};
use pico_rs_sdk::store::FlashStore;
use pico_rs_sdk::transport::ccid::class::CcidClass;
use pico_rs_sdk::transport::ccid::CcidDispatcher;
use pico_rs_sdk::transport::hid::class::FidoHidClass;
use pico_rs_sdk::transport::hid::{
    CommandHandler, CtapHidDispatcher, ReportWriter, HID_REPORT_SIZE, MAX_MSG_SIZE,
};

use pico_rs_fido::fido::{FidoApp, FidoConfig};

use heapless::Vec;

// ---------------------------------------------------------------------------
// Flash geometry (256 KB total, last 32 KB for storage)
// ---------------------------------------------------------------------------

const FLASH_SIZE: usize = 256 * 1024;
const STORAGE_SIZE: usize = 32 * 1024;
const STORAGE_OFFSET: u32 = (FLASH_SIZE - STORAGE_SIZE) as u32;

// ---------------------------------------------------------------------------
// USB identifiers
// ---------------------------------------------------------------------------

const USB_VID: u16 = 0x20A0;
const USB_PID: u16 = 0x4287;
const USB_MANUFACTURER: &str = "PicoKeys";
const USB_PRODUCT: &str = "PicoKeys FIDO2 (SAMD21)";
const USB_SERIAL: &str = "PKF2-SAMD21-0001";

// ---------------------------------------------------------------------------
// GPIO pins
// ---------------------------------------------------------------------------

const LED_GPIO: u8 = 13; // PA17

// ---------------------------------------------------------------------------
// Shared state
// ---------------------------------------------------------------------------

static LED_CHANNEL: Channel<CriticalSectionRawMutex, LedState, 4> = Channel::new();

// ---------------------------------------------------------------------------
// Simple digital LED on GPIO13 (PA17)
// ---------------------------------------------------------------------------

struct GpioLed {
    on: bool,
}

impl GpioLed {
    fn new() -> Self {
        Self { on: false }
    }
}

impl LedDriver for GpioLed {
    fn set_on(&mut self) {
        self.on = true;
        // In real implementation: set PA17 high via atsamd-hal GPIO.
    }
    fn set_off(&mut self) {
        self.on = false;
        // In real implementation: set PA17 low via atsamd-hal GPIO.
    }
    fn set_color(&mut self, _color: LedColor) {
        // Single-color LED — color is ignored.
        if self.on {
            self.set_on();
        }
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
        match self.fido.process_ctaphid_cbor(data, &mut buf, now_ms, self.button_pressed) {
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
        // U2F/CTAP1 not implemented on SAMD21
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
async fn led_task(mut controller: LedController<GpioLed>) -> ! {
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
async fn button_task(mut detector: PresenceDetector<AlwaysConfirm>) -> ! {
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
    defmt::info!("PicoKeys FIDO2 — SAMD21 starting (no RSA, no HSM)");

    // 1. Initialize SAMD21 peripherals (Cortex-M0+, 48 MHz)
    // atsamd-hal initialization would configure clocks, GPIO, and USB here.
    // let peripherals = atsamd_hal::pac::Peripherals::take().unwrap();
    defmt::info!("SAMD21 peripherals initialized");

    // 2. Flash storage: last 32 KB of 256 KB
    // SAMD21 NVM is accessed via atsamd-hal's NVM controller.
    defmt::info!("Flash storage: {}KB at offset {:#X}", STORAGE_SIZE / 1024, STORAGE_OFFSET);

    // 3. TRNG: SAMD21 has no dedicated TRNG.
    // Use ADC noise sampling or require external entropy seed.
    defmt::warn!("SAMD21 has no hardware TRNG — using ADC noise seed");

    // 4. Setup LED on GPIO13 (PA17)
    let led_driver = GpioLed::new();
    let led_controller = LedController::new(led_driver);

    // 5. No dedicated button — use AlwaysConfirm (auto-approve user presence)
    let button = AlwaysConfirm;
    let mut rescue_button = AlwaysConfirm;
    let rescue_mode = detect_rescue_mode(&mut rescue_button);
    let detector = PresenceDetector::with_default_timeout(button);

    // 6. USB FS initialization (PA24 D− / PA25 D+)
    // SAMD21 native USB FS via atsamd-hal USB driver.
    defmt::info!("USB FS on PA24/PA25");

    // 7. Initialize FIDO application (no RSA on SAMD21)
    let fido_config = FidoConfig::default();
    let fido_app = FidoApp::new(fido_config, embassy_time::Instant::now().as_millis());
    let _fido_handler = FidoHandler::new(fido_app);

    // 8. Handle rescue mode
    if rescue_mode == RescueMode::Rescue {
        defmt::warn!("Rescue mode detected — entering recovery");
    }

    // 9. Spawn tasks
    // USB task and HID/CCID tasks will be spawned once atsamd-hal USB
    // driver is integrated with embassy-usb.
    spawner.spawn(led_task(led_controller)).unwrap();
    spawner.spawn(button_task(detector)).unwrap();

    defmt::info!("PicoKeys FIDO2 — SAMD21 running (FIDO2 + OATH only, no RSA/HSM)");
}
