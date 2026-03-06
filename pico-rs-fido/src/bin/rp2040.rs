#![no_std]
#![no_main]

//! PicoKeys FIDO2 firmware — RP2040 (Raspberry Pi Pico / Pico W).
//!
//! USB composite device: HID (CTAPHID/FIDO2) + CCID (OATH).
//! Flash storage in last 128 KB of 2 MB QSPI.
//! LED on GPIO25 (or WS2812 via PIO on supported boards).
//! BOOTSEL button for user presence.

use defmt_rtt as _;
use panic_probe as _;

use embassy_executor::Spawner;
use embassy_rp::bind_interrupts;
use embassy_rp::flash::{Async as FlashAsync, Flash, ERASE_SIZE};
use embassy_rp::gpio::{Input, Level, Output, Pull};
use embassy_rp::peripherals::USB;
use embassy_rp::usb::Driver;
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::channel::Channel;
use embassy_time::{Duration, Ticker, Timer};
use embassy_usb::class::hid;
use embassy_usb::UsbDevice;

use pico_rs_sdk::button::{AlwaysConfirm, ButtonReader, PresenceDetector};
use pico_rs_sdk::led::{LedColor, LedController, LedDriver, LedState};
use pico_rs_sdk::rescue::{detect_rescue_mode, RescueHandler, RescueMode};
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
// Interrupts
// ---------------------------------------------------------------------------

bind_interrupts!(struct Irqs {
    USBCTRL_IRQ => embassy_rp::usb::InterruptHandler<USB>;
});

// ---------------------------------------------------------------------------
// Flash geometry
// ---------------------------------------------------------------------------

/// Total QSPI flash size (2 MB).
const FLASH_SIZE: usize = 2 * 1024 * 1024;
/// Storage partition: last 128 KB of flash.
const STORAGE_SIZE: usize = 128 * 1024;
/// Storage offset from flash base.
const STORAGE_OFFSET: u32 = (FLASH_SIZE - STORAGE_SIZE) as u32;

// ---------------------------------------------------------------------------
// USB identifiers
// ---------------------------------------------------------------------------

const USB_VID: u16 = 0x20A0;
const USB_PID: u16 = 0x4287;
const USB_MANUFACTURER: &str = "PicoKeys";
const USB_PRODUCT: &str = "PicoKeys FIDO2 (RP2040)";
const USB_SERIAL: &str = "PKF2-RP2040-0001";

// ---------------------------------------------------------------------------
// Shared state channels
// ---------------------------------------------------------------------------

/// Signal from the FIDO task to the LED task to update the LED state.
static LED_CHANNEL: Channel<CriticalSectionRawMutex, LedState, 4> = Channel::new();

// ---------------------------------------------------------------------------
// Simple GPIO LED driver
// ---------------------------------------------------------------------------

struct GpioLed<'d> {
    pin: Output<'d>,
}

impl<'d> GpioLed<'d> {
    fn new(pin: Output<'d>) -> Self {
        Self { pin }
    }
}

impl LedDriver for GpioLed<'_> {
    fn set_on(&mut self) {
        self.pin.set_high();
    }
    fn set_off(&mut self) {
        self.pin.set_low();
    }
    fn set_color(&mut self, _color: LedColor) {
        // Single-color LED — ignore color, just turn on.
        self.pin.set_high();
    }
}

// ---------------------------------------------------------------------------
// BOOTSEL button reader (active-low on GPIO25 detection via ROM)
// ---------------------------------------------------------------------------

struct BootselButton;

impl ButtonReader for BootselButton {
    fn is_pressed(&mut self) -> bool {
        // The RP2040 BOOTSEL button is read via the ROM API.
        // In a real implementation this calls rom_data::get_bootsel_button().
        // For now we always return false (user must use external button or
        // AlwaysConfirm fallback).
        false
    }
}

// ---------------------------------------------------------------------------
// FIDO command handler adapter
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
                // Return CTAP2 error status
                let _ = response.push(0x01); // CTAP2_ERR_INVALID_COMMAND
                Ok(())
            }
        }
    }

    async fn handle_msg(
        &mut self,
        _data: &[u8],
        response: &mut Vec<u8, MAX_MSG_SIZE>,
    ) -> Result<(), pico_rs_sdk::transport::TransportError> {
        // U2F/CTAP1 not yet implemented — return SW_INS_NOT_SUPPORTED
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
async fn usb_task(mut device: UsbDevice<'static, Driver<'static, USB>>) -> ! {
    device.run().await
}

#[embassy_executor::task]
async fn hid_task(
    mut hid_class: FidoHidClass<'static, Driver<'static, USB>>,
    mut handler: FidoHandler,
) -> ! {
    let mut dispatcher = CtapHidDispatcher::new();

    loop {
        match hid_class.read_report().await {
            Ok(report) => {
                let _ = dispatcher
                    .process_report(&report, &mut hid_class, &mut handler)
                    .await;
            }
            Err(_) => {
                Timer::after(Duration::from_millis(1)).await;
            }
        }
    }
}

#[embassy_executor::task]
async fn ccid_task(mut ccid_class: CcidClass<'static, Driver<'static, USB>>) -> ! {
    let mut dispatcher = CcidDispatcher::new();
    let mut rx_buf = [0u8; 1034]; // CCID header (10) + max payload (1024)
    let mut tx_buf = [0u8; 1034];

    // OATH application placeholder — uses the Application trait
    // For now, CCID responds with basic slot status until OATH is implemented.

    loop {
        ccid_class.wait_connected().await;
        let _ = ccid_class.notify_slot_change(true).await;

        loop {
            match ccid_class.read_message(&mut rx_buf).await {
                Ok(msg) => {
                    // Placeholder: no Application wired yet; build minimal response
                    let _ = msg;
                    // When OATH is implemented, dispatch through:
                    // dispatcher.process(&msg, &mut oath_app, &mut tx_buf)
                    let _ = &mut dispatcher;
                    let _ = &mut tx_buf;
                }
                Err(_) => break,
            }
        }
    }
}

#[embassy_executor::task]
async fn led_task(mut controller: LedController<GpioLed<'static>>) -> ! {
    let mut ticker = Ticker::every(Duration::from_millis(10));
    controller.set_state(LedState::Idle, embassy_time::Instant::now().as_millis());

    loop {
        // Check for state updates from other tasks.
        if let Ok(state) = LED_CHANNEL.try_receive() {
            controller.set_state(state, embassy_time::Instant::now().as_millis());
        }
        controller.update(embassy_time::Instant::now().as_millis());
        ticker.next().await;
    }
}

#[embassy_executor::task]
async fn button_task(mut detector: PresenceDetector<BootselButton>) -> ! {
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
    defmt::info!("PicoKeys FIDO2 — RP2040 starting");

    // 1. Initialize RP2040 peripherals
    let p = embassy_rp::init(Default::default());

    // 2. Setup flash storage (last 128 KB of 2 MB QSPI)
    let flash = Flash::<_, FlashAsync, FLASH_SIZE>::new(p.FLASH, p.DMA_CH0);
    let _store = FlashStore::new(flash, STORAGE_OFFSET..STORAGE_OFFSET + STORAGE_SIZE as u32);

    // 3. Setup LED on GPIO25
    let led_pin = Output::new(p.PIN_25, Level::Low);
    let led_driver = GpioLed::new(led_pin);
    let led_controller = LedController::new(led_driver);

    // 4. Setup BOOTSEL button / presence detector
    let button = BootselButton;
    let rescue_mode = detect_rescue_mode(&mut AlwaysConfirm);
    let detector = PresenceDetector::with_default_timeout(button);

    // 5. Create USB driver
    let driver = Driver::new(p.USB, Irqs);

    // 6. Build USB composite device (HID + CCID)
    let mut usb_config = embassy_usb::Config::new(USB_VID, USB_PID);
    usb_config.manufacturer = Some(USB_MANUFACTURER);
    usb_config.product = Some(USB_PRODUCT);
    usb_config.serial_number = Some(USB_SERIAL);
    usb_config.max_power = 100;
    usb_config.max_packet_size_0 = 64;

    static CONFIG_DESCRIPTOR: static_cell::StaticCell<[u8; 256]> = static_cell::StaticCell::new();
    static BOS_DESCRIPTOR: static_cell::StaticCell<[u8; 256]> = static_cell::StaticCell::new();
    static MSOS_DESCRIPTOR: static_cell::StaticCell<[u8; 256]> = static_cell::StaticCell::new();
    static CONTROL_BUF: static_cell::StaticCell<[u8; 64]> = static_cell::StaticCell::new();

    let mut builder = embassy_usb::Builder::new(
        driver,
        usb_config,
        CONFIG_DESCRIPTOR.init([0; 256]),
        BOS_DESCRIPTOR.init([0; 256]),
        MSOS_DESCRIPTOR.init([0; 256]),
        CONTROL_BUF.init([0; 64]),
    );

    // HID class (FIDO2)
    static HID_STATE: static_cell::StaticCell<hid::State<'static>> = static_cell::StaticCell::new();
    let hid_state = HID_STATE.init(hid::State::new());
    let hid_class = FidoHidClass::new(&mut builder, hid_state);

    // CCID class (OATH / smart card)
    let ccid_class = CcidClass::new(&mut builder);

    // Build the USB device
    let usb_device = builder.build();

    // 7. Initialize FIDO application
    let fido_config = FidoConfig::default();
    let fido_app = FidoApp::new(fido_config, embassy_time::Instant::now().as_millis());
    let fido_handler = FidoHandler::new(fido_app);

    // 8. Handle rescue mode
    if rescue_mode == RescueMode::Rescue {
        defmt::warn!("Rescue mode detected — entering recovery");
        // In rescue mode, only the CCID rescue handler runs.
        // Full rescue mode loop would be implemented here.
    }

    // 9. Spawn tasks
    defmt::info!("Spawning tasks");
    spawner.spawn(usb_task(usb_device)).unwrap();
    spawner.spawn(hid_task(hid_class, fido_handler)).unwrap();
    spawner.spawn(ccid_task(ccid_class)).unwrap();
    spawner.spawn(led_task(led_controller)).unwrap();
    spawner.spawn(button_task(detector)).unwrap();

    defmt::info!("PicoKeys FIDO2 — RP2040 running");
}
