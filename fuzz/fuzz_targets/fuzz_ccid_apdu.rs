#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Fuzz CCID message parser
    if data.len() < 10 { return; } // CCID header is 10 bytes
    let msg_type = data[0];
    let length = u32::from_le_bytes([data[1], data[2], data[3], data[4]]);
    let slot = data[5];
    let seq = data[6];
    let _ = (length, slot, seq); // suppress unused warnings
    match msg_type {
        0x62 => { /* PC_to_RDR_IccPowerOn */ },
        0x63 => { /* PC_to_RDR_IccPowerOff */ },
        0x65 => { /* PC_to_RDR_GetSlotStatus */ },
        0x6F => {
            // PC_to_RDR_XfrBlock — contains APDU
            if data.len() > 10 {
                let apdu = &data[10..];
                let _ = parse_apdu(apdu);
            }
        },
        _ => {},
    }
});

fn parse_apdu(data: &[u8]) -> Result<(u8, u8, u8, u8), ()> {
    if data.len() < 4 { return Err(()); }
    Ok((data[0], data[1], data[2], data[3])) // CLA, INS, P1, P2
}
