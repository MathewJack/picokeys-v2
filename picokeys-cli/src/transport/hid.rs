use anyhow::{bail, Context, Result};
use rand::Rng;

/// FIDO CTAPHID usage page (FIDO Alliance).
const FIDO_USAGE_PAGE: u16 = 0xF1D0;

/// HID report size (excluding report ID byte).
const HID_REPORT_SIZE: usize = 64;

/// Broadcast channel ID used for CTAPHID_INIT.
const BROADCAST_CID: [u8; 4] = [0xFF, 0xFF, 0xFF, 0xFF];

// CTAPHID command bytes (high bit set = initialization packet).
const CTAPHID_INIT: u8 = 0x06;
const CTAPHID_CBOR: u8 = 0x10;
const CTAPHID_MSG: u8 = 0x03;
const CTAPHID_PING: u8 = 0x01;
#[allow(dead_code)]
const CTAPHID_CANCEL: u8 = 0x11;
const CTAPHID_ERROR: u8 = 0x3F;
const CTAPHID_KEEPALIVE: u8 = 0x3B;
#[allow(dead_code)]
const CTAPHID_WINK: u8 = 0x08;

/// Data capacity in an initialization packet: 64 - 4(CID) - 1(CMD) - 2(LEN) = 57.
const INIT_DATA_SIZE: usize = 57;
/// Data capacity in a continuation packet: 64 - 4(CID) - 1(SEQ) = 59.
const CONT_DATA_SIZE: usize = 59;

/// Default response timeout (ms).
const DEFAULT_TIMEOUT_MS: i32 = 30_000;

/// HID transport implementing full CTAPHID host-side framing.
pub struct HidTransport {
    device: hidapi::HidDevice,
    channel_id: [u8; 4],
}

impl HidTransport {
    /// Open a HID device by vendor/product ID, optionally filtering by serial.
    /// Performs CTAPHID_INIT channel allocation automatically.
    pub fn open(vid: u16, pid: u16, serial: Option<&str>) -> Result<Self> {
        let api = hidapi::HidApi::new().context("failed to initialize hidapi")?;

        let device_info = api
            .device_list()
            .filter(|d| d.vendor_id() == vid && d.product_id() == pid)
            .filter(|d| d.usage_page() == FIDO_USAGE_PAGE)
            .filter(|d| {
                if let Some(s) = serial {
                    d.serial_number().is_some_and(|sn| sn == s)
                } else {
                    true
                }
            })
            .next()
            .context("no matching FIDO HID device found")?;

        let path = device_info.path().to_owned();
        let device = api.open_path(&path).context("failed to open HID device")?;

        let mut transport = Self {
            device,
            channel_id: BROADCAST_CID,
        };

        transport.allocate_channel()?;
        Ok(transport)
    }

    /// Allocate a CTAPHID channel via CTAPHID_INIT on the broadcast CID.
    fn allocate_channel(&mut self) -> Result<()> {
        let nonce: [u8; 8] = rand::thread_rng().gen();

        self.channel_id = BROADCAST_CID;
        let response = self.send_command(CTAPHID_INIT, &nonce)?;

        if response.len() < 17 {
            bail!("CTAPHID_INIT response too short ({} bytes)", response.len());
        }

        // Verify nonce echo.
        if response[..8] != nonce {
            bail!("CTAPHID_INIT nonce mismatch");
        }

        // Bytes 8..12 are the allocated channel ID.
        let mut cid = [0u8; 4];
        cid.copy_from_slice(&response[8..12]);

        if cid == BROADCAST_CID {
            bail!("device returned broadcast CID — channel allocation failed");
        }

        self.channel_id = cid;
        tracing::debug!(
            "CTAPHID channel allocated: {:02X}{:02X}{:02X}{:02X}",
            cid[0],
            cid[1],
            cid[2],
            cid[3]
        );

        Ok(())
    }

    /// Send a CTAPHID command with proper init + continuation framing and receive the response.
    pub fn send_command(&self, cmd: u8, data: &[u8]) -> Result<Vec<u8>> {
        self.send_framed(cmd, data)?;
        self.recv_response(cmd)
    }

    /// Send a CTAP CBOR command (CTAPHID_CBOR).
    pub fn send_cbor(&self, cbor_cmd: u8, cbor_data: &[u8]) -> Result<Vec<u8>> {
        let mut payload = Vec::with_capacity(1 + cbor_data.len());
        payload.push(cbor_cmd);
        payload.extend_from_slice(cbor_data);
        self.send_command(CTAPHID_CBOR, &payload)
    }

    /// Send a CTAP MSG command (CTAPHID_MSG) for U2F / raw messages.
    pub fn send_msg(&self, data: &[u8]) -> Result<Vec<u8>> {
        self.send_command(CTAPHID_MSG, data)
    }

    /// Send a CTAPHID PING.
    pub fn ping(&self, data: &[u8]) -> Result<Vec<u8>> {
        self.send_command(CTAPHID_PING, data)
    }

    /// Assemble and send CTAPHID packets (init + continuation).
    fn send_framed(&self, cmd: u8, data: &[u8]) -> Result<()> {
        let total_len = data.len();
        let mut offset = 0;

        // --- Initialization packet ---
        let mut pkt = [0u8; HID_REPORT_SIZE];
        pkt[0..4].copy_from_slice(&self.channel_id);
        pkt[4] = cmd | 0x80; // command byte with init bit
        pkt[5] = ((total_len >> 8) & 0xFF) as u8;
        pkt[6] = (total_len & 0xFF) as u8;

        let chunk = total_len.min(INIT_DATA_SIZE);
        pkt[7..7 + chunk].copy_from_slice(&data[..chunk]);
        offset += chunk;

        self.write_report(&pkt)?;

        // --- Continuation packets ---
        let mut seq: u8 = 0;
        while offset < total_len {
            let mut pkt = [0u8; HID_REPORT_SIZE];
            pkt[0..4].copy_from_slice(&self.channel_id);
            pkt[4] = seq;

            let chunk = (total_len - offset).min(CONT_DATA_SIZE);
            pkt[5..5 + chunk].copy_from_slice(&data[offset..offset + chunk]);
            offset += chunk;

            self.write_report(&pkt)?;
            seq = seq.wrapping_add(1);
            if seq > 127 {
                bail!("CTAPHID payload too large — exceeded max continuation sequence");
            }
        }

        Ok(())
    }

    /// Receive and reassemble a full CTAPHID response, handling keepalives.
    fn recv_response(&self, expected_cmd: u8) -> Result<Vec<u8>> {
        // Read initialization packet.
        let pkt = loop {
            let pkt = self.read_report(DEFAULT_TIMEOUT_MS)?;
            if pkt.len() < 7 {
                bail!("HID response packet too short");
            }

            // Verify CID matches (or broadcast for INIT responses).
            let resp_cid = &pkt[0..4];
            if resp_cid != &self.channel_id && self.channel_id != BROADCAST_CID {
                tracing::warn!("ignoring packet for different CID");
                continue;
            }

            let resp_cmd = pkt[4] & 0x7F;

            // Handle keepalive: just loop and keep reading.
            if resp_cmd == CTAPHID_KEEPALIVE {
                let status = if pkt.len() > 7 { pkt[7] } else { 0 };
                match status {
                    1 => tracing::info!("device is processing..."),
                    2 => tracing::info!("user presence required — please touch the device"),
                    _ => tracing::debug!("keepalive status: {status}"),
                }
                continue;
            }

            // Handle error response.
            if resp_cmd == CTAPHID_ERROR {
                let code = if pkt.len() > 7 { pkt[7] } else { 0 };
                bail!("CTAPHID error: 0x{code:02X} ({})", ctaphid_error_name(code));
            }

            if resp_cmd != expected_cmd {
                bail!(
                    "unexpected CTAPHID response command: 0x{resp_cmd:02X} (expected 0x{expected_cmd:02X})"
                );
            }

            break pkt;
        };

        let total_len = ((pkt[5] as usize) << 8) | (pkt[6] as usize);
        let mut data = Vec::with_capacity(total_len);

        let chunk = total_len.min(INIT_DATA_SIZE);
        if pkt.len() < 7 + chunk {
            bail!(
                "init packet too short: need {} bytes, got {}",
                7 + chunk,
                pkt.len()
            );
        }
        data.extend_from_slice(&pkt[7..7 + chunk]);

        // Read continuation packets.
        let mut expected_seq: u8 = 0;
        while data.len() < total_len {
            let pkt = self.read_report(DEFAULT_TIMEOUT_MS)?;
            if pkt.len() < 5 {
                bail!("continuation packet too short");
            }

            let resp_cid = &pkt[0..4];
            if resp_cid != &self.channel_id {
                tracing::warn!("ignoring continuation packet for different CID");
                continue;
            }

            let seq = pkt[4];
            if seq != expected_seq {
                bail!("CTAPHID sequence mismatch: got {seq}, expected {expected_seq}");
            }

            let remaining = total_len - data.len();
            let chunk = remaining.min(CONT_DATA_SIZE);
            if pkt.len() < 5 + chunk {
                bail!(
                    "continuation packet too short: need {} bytes, got {}",
                    5 + chunk,
                    pkt.len()
                );
            }
            data.extend_from_slice(&pkt[5..5 + chunk]);

            expected_seq = expected_seq.wrapping_add(1);
        }

        data.truncate(total_len);
        Ok(data)
    }

    /// Write a single 64-byte HID report (prepend report-ID 0x00).
    fn write_report(&self, data: &[u8; HID_REPORT_SIZE]) -> Result<()> {
        let mut report = [0u8; HID_REPORT_SIZE + 1];
        report[0] = 0x00; // report ID
        report[1..].copy_from_slice(data);
        self.device
            .write(&report)
            .context("HID write failed — device may be disconnected")?;
        Ok(())
    }

    /// Read a single 64-byte HID report with timeout.
    fn read_report(&self, timeout_ms: i32) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; HID_REPORT_SIZE];
        let n = self
            .device
            .read_timeout(&mut buf, timeout_ms)
            .context("HID read failed — device may be disconnected")?;
        if n == 0 {
            bail!("HID read timed out after {timeout_ms}ms — no response from device");
        }
        buf.truncate(n);
        Ok(buf)
    }
}

impl super::DeviceTransport for HidTransport {
    fn exchange(&mut self, command: &[u8]) -> Result<Vec<u8>> {
        if command.is_empty() {
            bail!("empty command payload");
        }
        // First byte is the CTAPHID command, rest is data.
        let cmd = command[0];
        let data = &command[1..];
        self.send_command(cmd, data)
    }

    fn close(&mut self) -> Result<()> {
        // hidapi closes on drop
        Ok(())
    }
}

/// Human-readable CTAPHID error names.
fn ctaphid_error_name(code: u8) -> &'static str {
    match code {
        0x01 => "INVALID_CMD",
        0x02 => "INVALID_PAR",
        0x03 => "INVALID_LEN",
        0x04 => "INVALID_SEQ",
        0x05 => "MSG_TIMEOUT",
        0x06 => "CHANNEL_BUSY",
        0x0A => "LOCK_REQUIRED",
        0x0B => "INVALID_CHANNEL",
        _ => "UNKNOWN",
    }
}
