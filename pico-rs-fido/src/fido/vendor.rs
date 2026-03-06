//! Vendor-specific commands (CTAP2 0x40–0xBF range).
//!
//! PicoKeys-specific extensions for device management.  Commands that modify
//! configuration require a valid PIN token; read-only commands do not.
//!
//! The device configuration ([`DeviceConfig`]) is serialised to a fixed-size
//! 33-byte binary blob for flash storage.

use super::ctap::CtapError;

// ── Vendor sub-command identifiers ──────────────────────────────────────────

/// Vendor sub-command identifiers (carried in the first payload byte after
/// the CTAP command byte).
#[derive(Debug, Clone, Copy, PartialEq, Eq, defmt::Format)]
#[repr(u8)]
pub enum VendorCommand {
    /// Set the RGB LED colour (3-byte payload: R, G, B).
    SetLedColor = 0x01,
    /// Set the LED blink pattern (1-byte pattern ID).
    SetLedPattern = 0x02,
    /// Return firmware version string.
    GetVersion = 0x03,
    /// Trigger rescue / DFU mode on next reboot.
    TriggerRescue = 0x04,
    /// Write a custom 16-byte AAGUID to flash.
    SetAaguid = 0x05,
    /// Override USB VID/PID stored in config (4-byte payload: VID\_LE, PID\_LE).
    SetVidPid = 0x06,
    /// Read the full device configuration.
    GetConfig = 0x07,
    /// Factory reset: wipe all credentials and config.
    FactoryReset = 0x08,
    /// Set button configuration (gpio, polarity, timeout, press-to-confirm).
    SetButtonConfig = 0x09,
}

impl TryFrom<u8> for VendorCommand {
    type Error = CtapError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(Self::SetLedColor),
            0x02 => Ok(Self::SetLedPattern),
            0x03 => Ok(Self::GetVersion),
            0x04 => Ok(Self::TriggerRescue),
            0x05 => Ok(Self::SetAaguid),
            0x06 => Ok(Self::SetVidPid),
            0x07 => Ok(Self::GetConfig),
            0x08 => Ok(Self::FactoryReset),
            0x09 => Ok(Self::SetButtonConfig),
            _ => Err(CtapError::InvalidCommand),
        }
    }
}

impl VendorCommand {
    /// Whether this command requires PIN token authentication.
    pub fn requires_auth(self) -> bool {
        !matches!(self, Self::GetVersion | Self::GetConfig)
    }
}

// ── LED / Button types ──────────────────────────────────────────────────────

/// LED driver type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, defmt::Format)]
#[repr(u8)]
pub enum LedType {
    SingleColor = 0x00,
    Ws2812Rgb = 0x01,
}

impl TryFrom<u8> for LedType {
    type Error = ();
    fn try_from(v: u8) -> Result<Self, ()> {
        match v {
            0x00 => Ok(Self::SingleColor),
            0x01 => Ok(Self::Ws2812Rgb),
            _ => Err(()),
        }
    }
}

/// Button active-state polarity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, defmt::Format)]
#[repr(u8)]
pub enum ButtonPolarity {
    ActiveLow = 0x00,
    ActiveHigh = 0x01,
}

impl TryFrom<u8> for ButtonPolarity {
    type Error = ();
    fn try_from(v: u8) -> Result<Self, ()> {
        match v {
            0x00 => Ok(Self::ActiveLow),
            0x01 => Ok(Self::ActiveHigh),
            _ => Err(()),
        }
    }
}

// ── Device configuration ────────────────────────────────────────────────────

/// Hardware-level device configuration stored in flash.
///
/// Serialised as a fixed-size [`CONFIG_SERIALIZED_LEN`]-byte binary blob
/// (2-byte magic + 1-byte format version + 30 bytes of fields).
#[derive(Debug, Clone, defmt::Format)]
pub struct DeviceConfig {
    pub led_gpio: u8,
    pub led_type: LedType,
    pub led_color_r: u8,
    pub led_color_g: u8,
    pub led_color_b: u8,
    pub led_pattern: u8,
    pub button_gpio: u8,
    pub button_polarity: ButtonPolarity,
    pub button_timeout_secs: u8,
    pub press_to_confirm: bool,
    pub usb_vid: u16,
    pub usb_pid: u16,
    pub aaguid: [u8; 16],
}

impl Default for DeviceConfig {
    fn default() -> Self {
        Self {
            led_gpio: 25,
            led_type: LedType::SingleColor,
            led_color_r: 0,
            led_color_g: 0,
            led_color_b: 0xFF,
            led_pattern: 0,
            button_gpio: 0,
            button_polarity: ButtonPolarity::ActiveLow,
            button_timeout_secs: 15,
            press_to_confirm: true,
            usb_vid: 0x1209,
            usb_pid: 0x4823,
            aaguid: [0u8; 16],
        }
    }
}

// ── Binary serialisation ────────────────────────────────────────────────────

/// Magic bytes identifying a serialised [`DeviceConfig`] blob.
const CONFIG_MAGIC: [u8; 2] = [0x50, 0x4B]; // "PK"

/// Current binary format version.
const CONFIG_VERSION: u8 = 0x01;

/// Total serialised size in bytes.
///
/// Layout (offsets):
/// ```text
///  0..2   magic ("PK")
///  2      format version
///  3      led_gpio
///  4      led_type
///  5      led_color_r
///  6      led_color_g
///  7      led_color_b
///  8      led_pattern
///  9      button_gpio
/// 10      button_polarity
/// 11      button_timeout_secs
/// 12      press_to_confirm
/// 13..15  usb_vid  (LE)
/// 15..17  usb_pid  (LE)
/// 17..33  aaguid   (16 bytes)
/// ```
pub const CONFIG_SERIALIZED_LEN: usize = 33;

/// Encode `config` into a fixed-size binary blob.
///
/// Returns `CONFIG_SERIALIZED_LEN` on success, or `0` if `buf` is too small.
pub fn serialize_config(config: &DeviceConfig, buf: &mut [u8]) -> usize {
    if buf.len() < CONFIG_SERIALIZED_LEN {
        return 0;
    }
    buf[0] = CONFIG_MAGIC[0];
    buf[1] = CONFIG_MAGIC[1];
    buf[2] = CONFIG_VERSION;
    buf[3] = config.led_gpio;
    buf[4] = config.led_type as u8;
    buf[5] = config.led_color_r;
    buf[6] = config.led_color_g;
    buf[7] = config.led_color_b;
    buf[8] = config.led_pattern;
    buf[9] = config.button_gpio;
    buf[10] = config.button_polarity as u8;
    buf[11] = config.button_timeout_secs;
    buf[12] = u8::from(config.press_to_confirm);
    let [vid_lo, vid_hi] = config.usb_vid.to_le_bytes();
    buf[13] = vid_lo;
    buf[14] = vid_hi;
    let [pid_lo, pid_hi] = config.usb_pid.to_le_bytes();
    buf[15] = pid_lo;
    buf[16] = pid_hi;
    buf[17..33].copy_from_slice(&config.aaguid);
    CONFIG_SERIALIZED_LEN
}

/// Decode a [`DeviceConfig`] from a binary blob produced by
/// [`serialize_config`].
pub fn deserialize_config(data: &[u8]) -> Result<DeviceConfig, ()> {
    if data.len() < CONFIG_SERIALIZED_LEN {
        return Err(());
    }
    if data[0] != CONFIG_MAGIC[0] || data[1] != CONFIG_MAGIC[1] {
        return Err(());
    }
    if data[2] != CONFIG_VERSION {
        return Err(());
    }
    let led_type = LedType::try_from(data[4])?;
    let button_polarity = ButtonPolarity::try_from(data[10])?;
    let mut aaguid = [0u8; 16];
    aaguid.copy_from_slice(&data[17..33]);

    Ok(DeviceConfig {
        led_gpio: data[3],
        led_type,
        led_color_r: data[5],
        led_color_g: data[6],
        led_color_b: data[7],
        led_pattern: data[8],
        button_gpio: data[9],
        button_polarity,
        button_timeout_secs: data[11],
        press_to_confirm: data[12] != 0,
        usb_vid: u16::from_le_bytes([data[13], data[14]]),
        usb_pid: u16::from_le_bytes([data[15], data[16]]),
        aaguid,
    })
}

// ── Side-effect flags ───────────────────────────────────────────────────────

/// Actions the caller must perform after a vendor command completes.
pub struct VendorSideEffects {
    /// Wipe all credentials, reset PIN, restore default config.
    pub factory_reset: bool,
    /// Set a persistent flag so the next boot enters rescue mode.
    pub rescue_trigger: bool,
    /// The AAGUID was changed — sync it to `FidoConfig`.
    pub aaguid_updated: bool,
}

impl VendorSideEffects {
    const fn none() -> Self {
        Self {
            factory_reset: false,
            rescue_trigger: false,
            aaguid_updated: false,
        }
    }
}

// ── Command handler ─────────────────────────────────────────────────────────

/// Firmware version returned by `GetVersion`.
const FIRMWARE_VERSION: &[u8] = b"PicoKeys-v2 0.1.0";

/// Process a vendor command.
///
/// `data` is the command-specific payload — PIN authentication has already
/// been verified and stripped by the caller.
///
/// Returns `(bytes_written_to_response, side_effects)`.
pub fn handle_vendor(
    cmd: VendorCommand,
    data: &[u8],
    config: &mut DeviceConfig,
    response: &mut [u8],
) -> Result<(usize, VendorSideEffects), CtapError> {
    match cmd {
        VendorCommand::SetLedColor => {
            if data.len() < 3 {
                return Err(CtapError::InvalidLength);
            }
            config.led_color_r = data[0];
            config.led_color_g = data[1];
            config.led_color_b = data[2];
            Ok((0, VendorSideEffects::none()))
        }

        VendorCommand::SetLedPattern => {
            if data.is_empty() {
                return Err(CtapError::InvalidLength);
            }
            config.led_pattern = data[0];
            Ok((0, VendorSideEffects::none()))
        }

        VendorCommand::GetVersion => {
            let len = FIRMWARE_VERSION.len();
            if response.len() < len {
                return Err(CtapError::InvalidLength);
            }
            response[..len].copy_from_slice(FIRMWARE_VERSION);
            Ok((len, VendorSideEffects::none()))
        }

        VendorCommand::TriggerRescue => Ok((
            0,
            VendorSideEffects {
                rescue_trigger: true,
                ..VendorSideEffects::none()
            },
        )),

        VendorCommand::SetAaguid => {
            if data.len() < 16 {
                return Err(CtapError::InvalidLength);
            }
            config.aaguid.copy_from_slice(&data[..16]);
            if response.len() < 16 {
                return Err(CtapError::InvalidLength);
            }
            response[..16].copy_from_slice(&config.aaguid);
            Ok((
                16,
                VendorSideEffects {
                    aaguid_updated: true,
                    ..VendorSideEffects::none()
                },
            ))
        }

        VendorCommand::SetVidPid => {
            if data.len() < 4 {
                return Err(CtapError::InvalidLength);
            }
            config.usb_vid = u16::from_le_bytes([data[0], data[1]]);
            config.usb_pid = u16::from_le_bytes([data[2], data[3]]);
            Ok((0, VendorSideEffects::none()))
        }

        VendorCommand::GetConfig => {
            let n = serialize_config(config, response);
            if n == 0 {
                return Err(CtapError::InvalidLength);
            }
            Ok((n, VendorSideEffects::none()))
        }

        VendorCommand::FactoryReset => {
            *config = DeviceConfig::default();
            Ok((
                0,
                VendorSideEffects {
                    factory_reset: true,
                    ..VendorSideEffects::none()
                },
            ))
        }

        VendorCommand::SetButtonConfig => {
            // Format: [button_gpio, polarity, timeout_secs, press_to_confirm]
            if data.len() < 4 {
                return Err(CtapError::InvalidLength);
            }
            config.button_gpio = data[0];
            config.button_polarity = ButtonPolarity::try_from(data[1])
                .map_err(|_| CtapError::InvalidParameter)?;
            if data[2] == 0 || data[2] > 60 {
                return Err(CtapError::InvalidParameter);
            }
            config.button_timeout_secs = data[2];
            config.press_to_confirm = data[3] != 0;
            Ok((0, VendorSideEffects::none()))
        }
    }
}
