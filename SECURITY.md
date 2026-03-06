# PicoKeys v2 Security Policy

## Supported Versions

| Version | Supported |
| ------- | --------- |
| 0.1.x   | ✅        |

## Security Model

### Key Material Protection
- All private keys, PINs, and sensitive data use `zeroize` crate with `ZeroizeOnDrop`
- Temporary crypto buffers are explicitly zeroized after use
- `SecretBox<T>` pattern for long-lived secrets

### Constant-Time Operations
- All PIN and HMAC comparisons use `subtle::ConstantTimeEq`
- No branch-on-secret patterns in crypto paths
- `subtle::Choice` for conditional assignments on secret data

### Credential Encryption
- AES-256-GCM with random 12-byte nonces for credential encryption
- Nonces are never reused (random generation + nonce counter tracking)
- MKEK (Master Key Encryption Key) stored in OTP fuses (RP2350, ESP32) or AES-wrapped in flash (RP2040, SAMD21)

### DKEK (Device Key Encryption Key) for HSM
- n-of-m Shamir Secret Sharing threshold scheme
- Each share is 32 bytes + 1 byte index
- GF(256) polynomial evaluation for share generation
- Key wrapping: AES-256-GCM with random nonces

### PIN Storage
- PBKDF2-HMAC-SHA256 with 256,000 iterations (CTAP2 spec uses SHA-256 left-16)
- Random 16-byte salt per device
- Retry counter: 8 attempts, locked at 0, reset on successful auth

### Known Advisories

#### RUSTSEC-2023-0071 — RSA Marvin Attack
- **Affected crate:** `rsa` v0.9.x
- **Impact:** Timing side-channel in RSA decryption
- **Mitigation:** 
  - RSA decrypt gated behind press-to-confirm (user presence required)
  - Random blinding enabled (default in `rsa` crate)
  - Tracking upstream issue: https://github.com/RustCrypto/RSA/issues/390
- **Pin:** `rsa = "0.9.10"` until advisory fully resolved

### Platform-Specific Security

| Platform | OTP/Fuses | Secure Boot | TRNG |
|----------|-----------|-------------|------|
| RP2040 | ❌ (MKEK in flash) | ❌ | ROSC (weak) |
| RP2350 | ✅ OTP fuses | ✅ ARM TrustZone | ✅ Dedicated TRNG |
| ESP32-S3 | ✅ eFuse block 3 | ✅ Secure Boot V2 | ✅ Hardware |
| ESP32-C5 | ✅ eFuse | ✅ Secure Boot V2 | ✅ Hardware |
| ESP32-C6 | ✅ eFuse | ✅ Secure Boot V2 | ✅ Hardware |
| SAMD21 | ❌ | ❌ | ❌ (weak entropy) |

## Reporting a Vulnerability

Please report security vulnerabilities via GitHub Security Advisories.

## Secure Boot Provisioning

### RP2350 OTP Fuse Burn
```bash
picokeys-cli firmware provision-otp --mkek <32-BYTE-HEX>
```
⚠️ This is ONE-TIME and IRREVERSIBLE.

### ESP32 eFuse Burn
```bash
esptool.py burn_efuse BLOCK3 <MKEK_HEX>
espefuse.py burn_key secure_boot_v2 secure_boot_key.bin
```
