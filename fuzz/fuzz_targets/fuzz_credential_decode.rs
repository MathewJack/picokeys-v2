#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Fuzz credential deserialization
    let _ = try_decode_credential(data);
});

fn try_decode_credential(data: &[u8]) -> Result<(), ()> {
    // Credential blob format: nonce(12) || ciphertext || tag(16)
    if data.len() < 28 { return Err(()); } // 12 + 16 minimum
    let _nonce = &data[..12];
    let _tag = &data[data.len()-16..];
    let _ciphertext = &data[12..data.len()-16];
    // In real code: AES-GCM decrypt, then CBOR decode inner credential
    Ok(())
}
