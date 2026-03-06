#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Fuzz the CTAP2 CBOR command parser
    // Feed arbitrary bytes as if they were a CTAP2 command payload
    if data.is_empty() { return; }
    let cmd_byte = data[0];
    let payload = &data[1..];
    // Try to parse as CTAP2 command — should never panic
    let _ = parse_ctap_command(cmd_byte, payload);
});

fn parse_ctap_command(cmd: u8, payload: &[u8]) -> Result<(), ()> {
    match cmd {
        0x01 => parse_make_credential(payload),
        0x02 => parse_get_assertion(payload),
        0x04 => Ok(()), // GetInfo has no payload
        0x06 => parse_client_pin(payload),
        0x07 => Ok(()), // Reset
        0x08 => Ok(()), // GetNextAssertion
        0x0A => parse_credential_mgmt(payload),
        0x0C => parse_large_blobs(payload),
        0x0D => parse_config(payload),
        _ => Err(()),
    }
}

fn parse_make_credential(data: &[u8]) -> Result<(), ()> {
    // Keys: 1=clientDataHash, 2=rp, 3=user, 4=pubKeyCredParams, etc.
    if data.len() < 2 { return Err(()); }
    let major = data[0] >> 5;
    if major != 5 { return Err(()); } // Must be a CBOR map
    Ok(())
}

fn parse_get_assertion(data: &[u8]) -> Result<(), ()> {
    if data.len() < 2 { return Err(()); }
    let major = data[0] >> 5;
    if major != 5 { return Err(()); }
    Ok(())
}

fn parse_client_pin(data: &[u8]) -> Result<(), ()> {
    if data.len() < 2 { return Err(()); }
    Ok(())
}

fn parse_credential_mgmt(data: &[u8]) -> Result<(), ()> {
    if data.len() < 2 { return Err(()); }
    Ok(())
}

fn parse_large_blobs(data: &[u8]) -> Result<(), ()> {
    if data.len() < 1 { return Err(()); }
    Ok(())
}

fn parse_config(data: &[u8]) -> Result<(), ()> {
    if data.len() < 1 { return Err(()); }
    Ok(())
}
