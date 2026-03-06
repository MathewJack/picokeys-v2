use embassy_usb::driver::{Driver, Endpoint, EndpointError, EndpointIn, EndpointOut};
use embassy_usb::Builder;

use super::{CcidError, CcidMessage, CCID_HEADER_LEN};

// ---------------------------------------------------------------------------
// USB CCID Descriptor Constants
// ---------------------------------------------------------------------------

/// bInterfaceClass for Smart Card Devices (CCID).
const CCID_INTERFACE_CLASS: u8 = 0x0B;
/// bInterfaceSubClass.
const CCID_INTERFACE_SUBCLASS: u8 = 0x00;
/// bInterfaceProtocol.
const CCID_INTERFACE_PROTOCOL: u8 = 0x00;

/// CCID class-specific descriptor type (0x21 per USB CCID Rev 1.1).
const CCID_DESCRIPTOR_TYPE: u8 = 0x21;

/// Bulk endpoint max packet size (full speed).
const BULK_MAX_PACKET_SIZE: u16 = 64;
/// Interrupt endpoint max packet size.
const INTERRUPT_MAX_PACKET_SIZE: u16 = 8;
/// Interrupt endpoint polling interval in ms.
const INTERRUPT_INTERVAL_MS: u8 = 32;

/// Build the 54-byte CCID functional descriptor (USB CCID Rev 1.1 §5.1).
fn ccid_functional_descriptor() -> [u8; 52] {
    // The descriptor body (after bLength and bDescriptorType which are added by
    // the embassy-usb `descriptor()` call which prepends length+type).
    // Actually, embassy-usb's `descriptor(type, body)` writes: [bLength, bDescriptorType, body...]
    // where bLength = body.len() + 2. So we provide the 52 content bytes and get 54 total.
    let mut d = [0u8; 52];
    let mut i = 0;

    // bcdCCID: CCID specification version 1.10
    d[i] = 0x10;
    d[i + 1] = 0x01;
    i += 2;

    // bMaxSlotIndex: 0 (one slot)
    d[i] = 0x00;
    i += 1;

    // bVoltageSupport: 5V (bit 0)
    d[i] = 0x01;
    i += 1;

    // dwProtocols: T=1 (bit 1) — little-endian u32
    d[i] = 0x02;
    d[i + 1] = 0x00;
    d[i + 2] = 0x00;
    d[i + 3] = 0x00;
    i += 4;

    // dwDefaultClock: 3580 kHz — little-endian u32
    let clock: u32 = 3580;
    let b = clock.to_le_bytes();
    d[i..i + 4].copy_from_slice(&b);
    i += 4;

    // dwMaximumClock: 3580 kHz
    d[i..i + 4].copy_from_slice(&b);
    i += 4;

    // bNumClockSupported: 0 (not used for T=1)
    d[i] = 0x00;
    i += 1;

    // dwDataRate: 9600 bps — little-endian u32
    let rate: u32 = 9600;
    let b = rate.to_le_bytes();
    d[i..i + 4].copy_from_slice(&b);
    i += 4;

    // dwMaxDataRate: 9600 bps
    d[i..i + 4].copy_from_slice(&b);
    i += 4;

    // bNumDataRatesSupported: 0
    d[i] = 0x00;
    i += 1;

    // dwMaxIFSD: 254 — little-endian u32
    let ifsd: u32 = 254;
    let b = ifsd.to_le_bytes();
    d[i..i + 4].copy_from_slice(&b);
    i += 4;

    // dwSynchProtocols: 0 — little-endian u32
    d[i] = 0x00;
    d[i + 1] = 0x00;
    d[i + 2] = 0x00;
    d[i + 3] = 0x00;
    i += 4;

    // dwMechanical: 0 — little-endian u32
    d[i] = 0x00;
    d[i + 1] = 0x00;
    d[i + 2] = 0x00;
    d[i + 3] = 0x00;
    i += 4;

    // dwFeatures: little-endian u32
    // 0x00010030 = short APDU level exchange (0x20000) + automatic params based on ATR (0x10) + automatic ICC voltage (0x08) + ...
    // Standard features for a simple smart-card reader:
    // Bit  4 (0x10): Automatic parameter config based on ATR
    // Bit  5 (0x20): Automatic activation on insert
    // Bit 16 (0x10000): TPDU level exchange
    // We use short APDU level exchange = 0x00020000 + auto params = 0x10 + auto voltage = 0x08
    // Actually for APDU-level: 0x00040000 (short APDU) or 0x00040010 with auto params
    let features: u32 = 0x0004_0010;
    let b = features.to_le_bytes();
    d[i..i + 4].copy_from_slice(&b);
    i += 4;

    // dwMaxCCIDMessageLength: 1034 (header 10 + max payload 1024) — little-endian u32
    let max_msg: u32 = 1034;
    let b = max_msg.to_le_bytes();
    d[i..i + 4].copy_from_slice(&b);
    i += 4;

    // bClassGetResponse: 0xFF (echo class byte from command)
    d[i] = 0xFF;
    i += 1;

    // bClassEnvelope: 0xFF (echo class byte from command)
    d[i] = 0xFF;
    i += 1;

    // wLcdLayout: 0x0000 (no LCD)
    d[i] = 0x00;
    d[i + 1] = 0x00;
    i += 2;

    // bPINSupport: 0x00 (no PIN pad)
    d[i] = 0x00;
    i += 1;

    // bMaxCCIDBusySlots: 1
    d[i] = 0x01;
    let _ = i + 1;

    d
}

// ---------------------------------------------------------------------------
// CCID USB Class
// ---------------------------------------------------------------------------

/// Custom embassy-usb CCID class with 2 bulk + 1 interrupt endpoint.
pub struct CcidClass<'d, D: Driver<'d>> {
    ep_bulk_out: D::EndpointOut,
    ep_bulk_in: D::EndpointIn,
    ep_interrupt_in: D::EndpointIn,
}

impl<'d, D: Driver<'d>> CcidClass<'d, D> {
    /// Create a new CCID class, registering descriptors and endpoints with the USB builder.
    pub fn new(builder: &mut Builder<'d, D>) -> Self {
        let mut func = builder.function(
            CCID_INTERFACE_CLASS,
            CCID_INTERFACE_SUBCLASS,
            CCID_INTERFACE_PROTOCOL,
        );

        let mut iface = func.interface();
        let mut alt = iface.alt_setting(
            CCID_INTERFACE_CLASS,
            CCID_INTERFACE_SUBCLASS,
            CCID_INTERFACE_PROTOCOL,
            None,
        );

        // Write the CCID functional descriptor
        alt.descriptor(CCID_DESCRIPTOR_TYPE, &ccid_functional_descriptor());

        // Allocate endpoints
        let ep_bulk_out = alt.endpoint_bulk_out(BULK_MAX_PACKET_SIZE);
        let ep_bulk_in = alt.endpoint_bulk_in(BULK_MAX_PACKET_SIZE);
        let ep_interrupt_in =
            alt.endpoint_interrupt_in(INTERRUPT_MAX_PACKET_SIZE, INTERRUPT_INTERVAL_MS);

        Self {
            ep_bulk_out,
            ep_bulk_in,
            ep_interrupt_in,
        }
    }

    /// Read a complete CCID message from the bulk OUT endpoint.
    ///
    /// CCID messages may span multiple USB packets (64 bytes each). This method
    /// reads the header first to determine total length, then reads remaining packets.
    pub async fn read_message(&mut self, buf: &mut [u8]) -> Result<CcidMessage, CcidClassError> {
        let mut total_read = 0usize;

        // Read at least the 10-byte header
        while total_read < CCID_HEADER_LEN {
            let remaining_buf = &mut buf[total_read..];
            if remaining_buf.is_empty() {
                return Err(CcidClassError::BufferTooSmall);
            }
            let n = self
                .ep_bulk_out
                .read(remaining_buf)
                .await
                .map_err(CcidClassError::Endpoint)?;
            if n == 0 {
                return Err(CcidClassError::ZeroLengthRead);
            }
            total_read += n;
        }

        // Parse header to learn total message size
        let header =
            super::CcidHeader::from_bytes(&buf[..CCID_HEADER_LEN]).map_err(CcidClassError::Ccid)?;
        let expected_total = CCID_HEADER_LEN + header.length as usize;

        if expected_total > buf.len() {
            return Err(CcidClassError::BufferTooSmall);
        }

        // Read remaining payload
        while total_read < expected_total {
            let remaining_buf = &mut buf[total_read..];
            let n = self
                .ep_bulk_out
                .read(remaining_buf)
                .await
                .map_err(CcidClassError::Endpoint)?;
            if n == 0 {
                return Err(CcidClassError::ZeroLengthRead);
            }
            total_read += n;
        }

        CcidMessage::from_bytes(&buf[..expected_total]).map_err(CcidClassError::Ccid)
    }

    /// Write a CCID response to the bulk IN endpoint.
    ///
    /// Large responses are split into max-packet-sized USB packets.
    pub async fn write_message(&mut self, data: &[u8]) -> Result<(), CcidClassError> {
        let max_packet = BULK_MAX_PACKET_SIZE as usize;
        let mut offset = 0;

        while offset < data.len() {
            let end = (offset + max_packet).min(data.len());
            self.ep_bulk_in
                .write(&data[offset..end])
                .await
                .map_err(CcidClassError::Endpoint)?;
            offset = end;
        }

        // Send zero-length packet if message was exact multiple of max packet size
        if data.len() % max_packet == 0 && !data.is_empty() {
            self.ep_bulk_in
                .write(&[])
                .await
                .map_err(CcidClassError::Endpoint)?;
        }

        Ok(())
    }

    /// Send a slot change notification over the interrupt IN endpoint.
    pub async fn notify_slot_change(&mut self, card_present: bool) -> Result<(), CcidClassError> {
        let msg = super::slot_change_notification(card_present);
        self.ep_interrupt_in
            .write(&msg)
            .await
            .map_err(CcidClassError::Endpoint)?;
        Ok(())
    }

    /// Wait for the bulk OUT endpoint to be enabled (USB configured).
    pub async fn wait_connected(&mut self) {
        self.ep_bulk_out.wait_enabled().await;
    }
}

/// Errors from the CCID USB class.
#[derive(Debug)]
pub enum CcidClassError {
    Endpoint(EndpointError),
    Ccid(CcidError),
    BufferTooSmall,
    ZeroLengthRead,
}
