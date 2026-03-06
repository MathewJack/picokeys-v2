use anyhow::{bail, Context, Result};
use pcsc::{Card, Context as PcscContext, Protocols, Scope, ShareMode};

/// Known ATR prefixes for PicoKeys / compatible devices.
const PICOKEYS_ATR_PREFIX: &[u8] = &[0x3B];

/// SW success.
const SW_OK: u16 = 0x9000;
/// SW prefix indicating more data available (61xx).
const SW_MORE_PREFIX: u8 = 0x61;

/// CCID (PC/SC) transport for smartcard APDU communication.
/// Used for OATH (YKOATH) and HSM (SmartCard-HSM) protocols.
pub struct CcidTransport {
    card: Card,
    reader_name: String,
}

impl CcidTransport {
    /// Open a CCID connection to a smartcard reader.
    /// If `reader_name` is `None`, picks the first available reader with a card present.
    pub fn open(reader_name: Option<&str>) -> Result<Self> {
        let ctx = PcscContext::establish(Scope::System)
            .context("failed to establish PC/SC context — is pcscd running?")?;

        let readers_buf_len = ctx
            .list_readers_len()
            .context("failed to query PC/SC readers length")?;
        let mut readers_buf = vec![0u8; readers_buf_len];
        let readers: Vec<_> = ctx
            .list_readers(&mut readers_buf)
            .context("failed to list PC/SC readers")?
            .collect();

        if readers.is_empty() {
            bail!("no PC/SC smartcard readers found");
        }

        let target_reader = if let Some(name) = reader_name {
            readers
                .into_iter()
                .find(|r| r.to_string_lossy().contains(name))
                .context(format!("no reader matching '{name}' found"))?
        } else {
            // Try each reader until we find one with a card present.
            let mut found = None;
            for reader in &readers {
                match ctx.connect(reader, ShareMode::Shared, Protocols::ANY) {
                    Ok(card) => {
                        found = Some((reader.to_owned(), card));
                        break;
                    }
                    Err(_) => continue,
                }
            }
            if let Some((reader_cstr, card)) = found {
                let reader_name = reader_cstr.to_string_lossy().into_owned();
                tracing::debug!("connected to reader: {reader_name}");
                return Ok(Self {
                    card,
                    reader_name,
                });
            }
            bail!("no smartcard reader with a card present found");
        };

        let card = ctx
            .connect(target_reader, ShareMode::Shared, Protocols::ANY)
            .context("failed to connect to card")?;

        let name = target_reader.to_string_lossy().into_owned();
        tracing::debug!("connected to reader: {name}");

        Ok(Self {
            card,
            reader_name: name,
        })
    }

    /// Get the reader name this transport is connected to.
    pub fn reader_name(&self) -> &str {
        &self.reader_name
    }

    /// Get the card ATR (Answer to Reset).
    pub fn get_atr(&self) -> Result<Vec<u8>> {
        let mut atr_buf = [0u8; 64];
        let mut reader_buf = [0u8; 256];
        let status = self
            .card
            .status2(&mut reader_buf, &mut atr_buf)
            .context("failed to get card status")?;
        let atr_len = status.atr().len();
        Ok(status.atr().to_vec())
    }

    /// Transmit an APDU (CLA, INS, P1, P2, data) and return (response_data, status_word).
    /// Handles GET RESPONSE chaining for SW 61xx automatically.
    pub fn transmit_apdu(
        &self,
        cla: u8,
        ins: u8,
        p1: u8,
        p2: u8,
        data: &[u8],
    ) -> Result<(Vec<u8>, u16)> {
        let apdu = build_apdu(cla, ins, p1, p2, data);
        let (mut resp_data, mut sw) = self.transmit_raw(&apdu)?;

        // Handle GET RESPONSE chaining (SW 61xx = more data available).
        while (sw >> 8) as u8 == SW_MORE_PREFIX {
            let remaining = (sw & 0xFF) as u8;
            let get_response = build_apdu(0x00, 0xC0, 0x00, 0x00, &[]);
            let (more_data, next_sw) = self.transmit_raw(&get_response)?;
            resp_data.extend_from_slice(&more_data);
            sw = next_sw;
        }

        Ok((resp_data, sw))
    }

    /// Select an application by AID. Returns the response data.
    pub fn select_aid(&self, aid: &[u8]) -> Result<Vec<u8>> {
        let (data, sw) = self.transmit_apdu(0x00, 0xA4, 0x04, 0x00, aid)?;
        if sw != SW_OK {
            bail!(
                "SELECT AID failed: SW={:04X} (AID={})",
                sw,
                hex::encode(aid)
            );
        }
        Ok(data)
    }

    /// Transmit raw APDU bytes and return (response_data, status_word).
    pub fn transmit_raw(&self, apdu: &[u8]) -> Result<(Vec<u8>, u16)> {
        let mut recv_buf = vec![0u8; 4096];
        let resp = self
            .card
            .transmit(apdu, &mut recv_buf)
            .context("PC/SC transmit failed — card may be disconnected")?;

        if resp.len() < 2 {
            bail!("APDU response too short ({} bytes)", resp.len());
        }

        let sw = ((resp[resp.len() - 2] as u16) << 8) | (resp[resp.len() - 1] as u16);
        let data = resp[..resp.len() - 2].to_vec();

        tracing::trace!(
            "APDU response: {} bytes, SW={:04X}",
            data.len(),
            sw
        );

        Ok((data, sw))
    }
}

impl super::DeviceTransport for CcidTransport {
    fn exchange(&mut self, command: &[u8]) -> Result<Vec<u8>> {
        let (data, sw) = self.transmit_raw(command)?;
        // Return SW appended for the caller to interpret.
        let mut result = data;
        result.push((sw >> 8) as u8);
        result.push((sw & 0xFF) as u8);
        Ok(result)
    }

    fn close(&mut self) -> Result<()> {
        // pcsc::Card disconnects on drop
        Ok(())
    }
}

/// Build a standard ISO 7816-4 APDU command.
fn build_apdu(cla: u8, ins: u8, p1: u8, p2: u8, data: &[u8]) -> Vec<u8> {
    let mut apdu = Vec::with_capacity(5 + data.len());
    apdu.push(cla);
    apdu.push(ins);
    apdu.push(p1);
    apdu.push(p2);

    if data.is_empty() {
        // Case 1: no data, no Le — just the 4-byte header.
        // Some devices expect Lc=0 for certain commands; omit it for standard SELECT etc.
    } else if data.len() <= 255 {
        apdu.push(data.len() as u8);
        apdu.extend_from_slice(data);
    } else {
        // Extended length APDU.
        apdu.push(0x00);
        apdu.push((data.len() >> 8) as u8);
        apdu.push((data.len() & 0xFF) as u8);
        apdu.extend_from_slice(data);
    }

    apdu
}
