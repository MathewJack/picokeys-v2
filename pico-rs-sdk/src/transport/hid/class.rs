//! FIDO HID USB class adapter.
//!
//! Wraps `embassy-usb`'s HID class with the FIDO Alliance report descriptor
//! (usage page `0xF1D0`, usage `0x01`, 64-byte reports) and exposes a simple
//! `read_report` / `write_report` interface used by [`super::CtapHidDispatcher`].

use embassy_usb::class::hid::{self, HidReader, HidReaderWriter, HidWriter};
use embassy_usb::Builder;
use embassy_usb_driver::Driver;

use super::{ReportWriter, HID_REPORT_SIZE};
use crate::transport::TransportError;

// ---------------------------------------------------------------------------
// FIDO HID Report Descriptor
// ---------------------------------------------------------------------------

/// HID report descriptor for a FIDO U2F / CTAP2 authenticator.
///
/// Usage Page: FIDO Alliance (0xF1D0)
/// Usage:      U2F Authenticator Device (0x01)
/// Reports:    64-byte Input and Output (no Report ID)
pub const FIDO_REPORT_DESCRIPTOR: &[u8] = &[
    0x06, 0xD0, 0xF1, // Usage Page (FIDO Alliance 0xF1D0)
    0x09, 0x01, // Usage (U2F Authenticator Device)
    0xA1, 0x01, // Collection (Application)
    //   --- Input Report (device → host) ---
    0x09, 0x20, //   Usage (Input Report Data)
    0x15, 0x00, //   Logical Minimum (0)
    0x26, 0xFF, 0x00, //   Logical Maximum (255)
    0x75, 0x08, //   Report Size (8 bits)
    0x95, 0x40, //   Report Count (64)
    0x81, 0x02, //   Input (Data, Variable, Absolute)
    //   --- Output Report (host → device) ---
    0x09, 0x21, //   Usage (Output Report Data)
    0x15, 0x00, //   Logical Minimum (0)
    0x26, 0xFF, 0x00, //   Logical Maximum (255)
    0x75, 0x08, //   Report Size (8 bits)
    0x95, 0x40, //   Report Count (64)
    0x91, 0x02, //   Output (Data, Variable, Absolute)
    0xC0, // End Collection
];

// ---------------------------------------------------------------------------
// FidoHidClass
// ---------------------------------------------------------------------------

/// Wrapper around `embassy-usb` HID reader/writer configured for FIDO 64-byte reports.
pub struct FidoHidClass<'d, D: Driver<'d>> {
    reader: HidReader<'d, D, HID_REPORT_SIZE>,
    writer: HidWriter<'d, D, HID_REPORT_SIZE>,
}

impl<'d, D: Driver<'d>> FidoHidClass<'d, D> {
    /// Create a new FIDO HID class and register it on the USB builder.
    ///
    /// `state` must live at least as long as the USB device.
    pub fn new(builder: &mut Builder<'d, D>, state: &'d mut hid::State<'d>) -> Self {
        let config = hid::Config {
            report_descriptor: FIDO_REPORT_DESCRIPTOR,
            request_handler: None,
            poll_ms: 5,
            max_packet_size: HID_REPORT_SIZE as u16,
        };

        let hid =
            HidReaderWriter::<_, HID_REPORT_SIZE, HID_REPORT_SIZE>::new(builder, state, config);
        let (reader, writer) = hid.split();
        Self { reader, writer }
    }

    /// Read one 64-byte HID report from the host (blocking-async).
    pub async fn read_report(&mut self) -> Result<[u8; HID_REPORT_SIZE], TransportError> {
        let mut buf = [0u8; HID_REPORT_SIZE];
        self.reader
            .read(&mut buf)
            .await
            .map_err(|_| TransportError::Other)?;
        Ok(buf)
    }

    /// Write one 64-byte HID report to the host (blocking-async).
    pub async fn write_report(
        &mut self,
        data: &[u8; HID_REPORT_SIZE],
    ) -> Result<(), TransportError> {
        self.writer
            .write(data)
            .await
            .map_err(|_| TransportError::Other)?;
        Ok(())
    }
}

/// [`ReportWriter`] implementation so `FidoHidClass` can be passed directly
/// to [`super::CtapHidDispatcher::process_report`].
impl<'d, D: Driver<'d>> ReportWriter for FidoHidClass<'d, D> {
    async fn write_report(&mut self, report: &[u8; HID_REPORT_SIZE]) -> Result<(), TransportError> {
        FidoHidClass::write_report(self, report).await
    }
}
