# PicoKeys CLI Usage

## Installation

```bash
# From source
cargo install --path picokeys-cli

# Or build without installing
cargo build -p picokeys-cli --release
# Binary at: target/release/picokeys-cli
```

## Global Options

```
picokeys-cli [OPTIONS] <COMMAND>

Options:
  -d, --device <SERIAL>   Select device by serial number (auto-detect if omitted)
  -v, --verbose            Enable debug logging
  -h, --help               Print help
  -V, --version            Print version
```

When multiple PicoKeys devices are connected, use `-d` to select by serial number.
With a single device, it is auto-detected via USB HID and PC/SC scanning.

## Commands

### `info` — Device Information

Display firmware version, serial number, and capabilities.

```bash
$ picokeys-cli info
PicoKeys FIDO2 (RP2040)
  Serial:     PKF2-RP2040-0001
  Firmware:   0.1.0
  VID/PID:    20A0:4287
  Transport:  HID + CCID
  FIDO2:      ✓ (CTAP 2.1)
  OATH:       ✓ (TOTP, HOTP)
  HSM:        ✓ (SmartCard-HSM)
  PIN set:    No
  Credentials: 0 / 128
```

### `fido` — FIDO2 / WebAuthn Management

#### Show FIDO2 authenticator info

```bash
$ picokeys-cli fido info
CTAP2 Authenticator Info:
  AAGUID:       01020304-0506-0708-090a-0b0c0d0e0f10
  Versions:     FIDO_2_0, FIDO_2_1, U2F_V2
  Extensions:   credBlob, credProtect, hmac-secret, largeBlobKey, minPinLength
  Options:
    rk: true, up: true, uv: true, plat: false
    alwaysUv: false, credMgmt: true, authnrCfg: true
  Max credential count: 128
  PIN protocols:  1, 2
  Transports:     usb
```

#### List discoverable credentials

```bash
$ picokeys-cli fido credentials list
# Credentials (2):
  [0] example.com
      User: alice@example.com (Alice)
      Created: 2025-01-15
      Discoverable: yes

  [1] github.com
      User: bob (Bob)
      Created: 2025-02-01
      Discoverable: yes
```

#### Delete a credential

```bash
$ picokeys-cli fido credentials delete --id <CREDENTIAL_ID_HEX>
Credential deleted.
```

#### Delete all credentials

```bash
$ picokeys-cli fido credentials delete-all
⚠️  This will delete ALL 2 discoverable credentials. Continue? [y/N] y
All credentials deleted.
```

#### Set PIN (first time)

```bash
$ picokeys-cli fido pin set
Enter new PIN: ********
Confirm PIN:   ********
✅ PIN set successfully.
```

#### Change PIN

```bash
$ picokeys-cli fido pin change
Enter current PIN: ********
Enter new PIN:     ********
Confirm new PIN:   ********
✅ PIN changed successfully.
```

#### Verify PIN

```bash
$ picokeys-cli fido pin verify
Enter PIN: ********
✅ PIN verified. Retries remaining: 8
```

#### Factory reset

```bash
$ picokeys-cli fido reset
⚠️  WARNING: This will destroy ALL credentials and reset the PIN.
   The device must have been powered on for less than 10 seconds.
   Press the button on the device within 30 seconds to confirm.

Type "RESET" to proceed: RESET
✅ Device reset complete.
```

#### FIDO2 configuration

```bash
# Toggle alwaysUV
$ picokeys-cli fido config always-uv --enable

# Toggle enterprise attestation
$ picokeys-cli fido config enterprise-attestation --enable
```

#### MKEK backup (BIP39 mnemonic)

```bash
$ picokeys-cli fido backup export
Enter PIN: ********
⚠️  Write down these 24 words. They can restore all credentials.
1. abandon  2. ability  3. able  ...  24. zoo

$ picokeys-cli fido backup import
Enter 24-word mnemonic: abandon ability able ...
Enter PIN: ********
✅ MKEK restored. Credentials decryptable again.
```

### `oath` — OATH TOTP/HOTP Management

#### Add a TOTP credential

```bash
$ picokeys-cli oath add --name "GitHub" --secret JBSWY3DPEHPK3PXP --type totp --algorithm sha1 --digits 6 --period 30
✅ Credential "GitHub" added.
```

#### Add an HOTP credential

```bash
$ picokeys-cli oath add --name "AWS" --secret BASE32SECRET --type hotp --digits 6
✅ Credential "AWS" added.
```

#### List credentials

```bash
$ picokeys-cli oath list
# OATH Credentials (2):
  [0] GitHub (TOTP, SHA1, 6 digits, 30s)
  [1] AWS    (HOTP, SHA1, 6 digits)
```

#### Calculate a code

```bash
$ picokeys-cli oath calculate --name "GitHub"
GitHub: 123456 (valid for 18s)

$ picokeys-cli oath calculate --all
GitHub: 123456 (valid for 18s)
AWS:    789012
```

#### Delete a credential

```bash
$ picokeys-cli oath delete --name "GitHub"
Credential "GitHub" deleted.
```

### `otp` — YubiKey-Compatible OTP Slots

```bash
# Configure slot 1
$ picokeys-cli otp configure --slot 1 --secret <HEX_KEY> --public-id <HEX>

# Read slot info
$ picokeys-cli otp info --slot 1

# Delete slot
$ picokeys-cli otp delete --slot 1
```

### `hsm` — SmartCard-HSM Management

#### Initialize HSM

```bash
$ picokeys-cli hsm init --so-pin 3537363231383830 --pin 648219
✅ HSM initialized.
```

#### Generate a key pair

```bash
$ picokeys-cli hsm generate --key-id 1 --type ec-p256 --label "signing-key"
Key generated:
  ID:     1
  Type:   EC P-256
  Label:  signing-key
  Public: 04abcdef...
```

Supported key types: `ec-p256`, `ec-p384`, `ec-p521`, `ec-k256`, `ed25519`, `x25519`,
`rsa-2048`, `rsa-3072`, `rsa-4096`, `aes-128`, `aes-192`, `aes-256`.

#### Sign data

```bash
$ echo -n "hello" | picokeys-cli hsm sign --key-id 1 --algorithm ecdsa
Enter PIN: ********
Signature (hex): 3045022100...
```

#### Decrypt data

```bash
$ picokeys-cli hsm decrypt --key-id 2 --algorithm rsa-oaep --input ciphertext.bin --output plaintext.bin
Enter PIN: ********
✅ Decrypted 256 bytes.
```

#### List keys

```bash
$ picokeys-cli hsm list
# HSM Keys (2):
  [1] signing-key     EC P-256    (sign, verify)
  [2] encryption-key  RSA-2048    (decrypt, unwrap)
```

#### DKEK management (Shamir secret sharing)

```bash
# Import DKEK share
$ picokeys-cli hsm dkek import --share share1.bin
Enter PIN: ********
✅ DKEK share 1 of 3 imported.

# Export wrapped key
$ picokeys-cli hsm wrap --key-id 1 --output wrapped-key.bin
```

### `config` — Device Configuration

```bash
# Set LED brightness
$ picokeys-cli config led --brightness 50

# Set custom blink pattern
$ picokeys-cli config led --idle-on 1000 --idle-off 1000

# Read current configuration
$ picokeys-cli config show
```

### `firmware` — Firmware Management

```bash
# Show firmware version
$ picokeys-cli firmware version

# Provision OTP (RP2350 only)
$ picokeys-cli firmware provision-otp --mkek <64_HEX_CHARS>
⚠️  This permanently burns the MKEK into hardware OTP fuses.
Type "BURN" to proceed: BURN
✅ MKEK provisioned to OTP.
```

## Device Auto-Detection

The CLI scans for PicoKeys devices on:

1. **USB HID** — CTAPHID interface (VID `0x20A0`, PID `0x4287`)
2. **PC/SC** — Smart card readers with ATR matching PicoKeys

```bash
$ picokeys-cli info
Found 2 devices:
  [1] PicoKeys FIDO2 (RP2040) — PKF2-RP2040-0001 (HID + CCID)
  [2] PicoKeys FIDO2 (RP2350) — PKF2-RP2350-0001 (HID + CCID)

Use -d <serial> to select a device.
```

## Transport Selection

Most commands auto-select the correct transport:

| Command | Transport |
|---------|-----------|
| `fido` | USB HID (CTAPHID) |
| `oath` | USB CCID (YKOATH AID) |
| `hsm` | USB CCID (HSM AID) |
| `otp` | USB CCID |
| `info` | Both (merges information) |

## Environment Variables

| Variable | Description |
|----------|-------------|
| `PICOKEYS_DEVICE` | Default device serial (same as `-d`) |
| `PICOKEYS_LOG` | Log level: `error`, `warn`, `info`, `debug`, `trace` |
| `RUST_LOG` | Alternative log level (via `tracing-subscriber`) |
