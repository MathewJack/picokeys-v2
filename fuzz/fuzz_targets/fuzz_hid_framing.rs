#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Fuzz CTAPHID packet reassembly
    if data.len() < 7 { return; } // Minimum init packet header
    let cid = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
    let cmd_or_seq = data[4];
    if cmd_or_seq & 0x80 != 0 {
        // Initialization packet
        let cmd = cmd_or_seq & 0x7F;
        if data.len() >= 7 {
            let bcnt = u16::from_be_bytes([data[5], data[6]]);
            let payload = &data[7..core::cmp::min(data.len(), 64)];
            let _ = validate_init_packet(cid, cmd, bcnt, payload);
        }
    } else {
        // Continuation packet
        let seq = cmd_or_seq;
        let payload = &data[5..core::cmp::min(data.len(), 64)];
        let _ = validate_cont_packet(cid, seq, payload);
    }
});

fn validate_init_packet(cid: u32, _cmd: u8, bcnt: u16, _payload: &[u8]) -> Result<(), ()> {
    if cid == 0 { return Err(()); }
    if bcnt as usize > 7609 { return Err(()); } // Max CTAPHID message
    Ok(())
}

fn validate_cont_packet(cid: u32, seq: u8, _payload: &[u8]) -> Result<(), ()> {
    if cid == 0 { return Err(()); }
    if seq > 127 { return Err(()); }
    Ok(())
}
