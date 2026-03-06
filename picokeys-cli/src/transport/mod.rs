pub mod ccid;
pub mod hid;

use anyhow::Result;

/// Known PicoKeys USB Vendor/Product ID pairs.
pub const KNOWN_DEVICES: &[KnownDevice] = &[
    KnownDevice {
        vid: 0x20A0,
        pid: 0x4230,
        name: "Nitrokey FIDO2",
        has_fido: true,
        has_ccid: false,
    },
    KnownDevice {
        vid: 0x20A0,
        pid: 0x4231,
        name: "Nitrokey 3",
        has_fido: true,
        has_ccid: true,
    },
    KnownDevice {
        vid: 0x1209,
        pid: 0x4823,
        name: "PicoKeys FIDO2",
        has_fido: true,
        has_ccid: true,
    },
    KnownDevice {
        vid: 0x1209,
        pid: 0x4824,
        name: "PicoKeys HSM",
        has_fido: false,
        has_ccid: true,
    },
    KnownDevice {
        vid: 0x1050,
        pid: 0x0407,
        name: "YubiKey 5 (FIDO+CCID)",
        has_fido: true,
        has_ccid: true,
    },
];

pub struct KnownDevice {
    pub vid: u16,
    pub pid: u16,
    pub name: &'static str,
    pub has_fido: bool,
    pub has_ccid: bool,
}

/// Trait for host-to-device communication transports.
pub trait DeviceTransport {
    /// Send a raw command payload and receive the response.
    fn exchange(&mut self, command: &[u8]) -> Result<Vec<u8>>;

    /// Close the transport connection.
    fn close(&mut self) -> Result<()>;
}
