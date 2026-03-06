# PicoKeys v2 Hardware Reference

## Supported Platforms

| Platform | MCU | Architecture | Clock | Flash | RAM | USB |
|----------|-----|-------------|-------|-------|-----|-----|
| RP2040 | RP2040 | Cortex-M0+ (dual) | 133 MHz | 2 MB QSPI | 264 KB | USB 1.1 Device |
| RP2350 | RP2350 | Cortex-M33 (dual) | 150 MHz | 4 MB QSPI | 520 KB | USB 1.1 Device |
| ESP32-S3 | ESP32-S3 | Xtensa LX7 (dual) | 240 MHz | 8 MB SPI | 512 KB | USB OTG 1.1 |
| ESP32-C5 | ESP32-C5 | RISC-V (single) | 160 MHz | 4 MB SPI | 400 KB | USB Serial/JTAG |
| ESP32-C6 | ESP32-C6 | RISC-V (single) | 160 MHz | 4 MB SPI | 512 KB | USB Serial/JTAG |
| SAMD21 | ATSAMD21 | Cortex-M0+ (single) | 48 MHz | 256 KB | 32 KB | USB 2.0 FS |

## USB Descriptors

### Default VID/PID

| Field | Value |
|-------|-------|
| Vendor ID (VID) | `0x20A0` |
| Product ID (PID) | `0x4287` |
| Manufacturer | `PicoKeys` |

### Per-Platform Product Strings

| Platform | USB Product String | Serial Format |
|----------|-------------------|---------------|
| RP2040 | `PicoKeys FIDO2 (RP2040)` | `PKF2-RP2040-XXXX` |
| RP2350 | `PicoKeys FIDO2 (RP2350)` | `PKF2-RP2350-XXXX` |
| ESP32-S3 | `PicoKeys FIDO2 (ESP32-S3)` | `PKF2-ESP32S3-XXXX` |
| ESP32-C5 | `PicoKeys FIDO2 (ESP32-C5)` | `PKF2-ESP32C5-XXXX` |
| ESP32-C6 | `PicoKeys FIDO2 (ESP32-C6)` | `PKF2-ESP32C6-XXXX` |
| SAMD21 | `PicoKeys FIDO2 (SAMD21)` | `PKF2-SAMD21-XXXX` |

### Composite USB Device

Each device exposes a composite USB device with two interfaces:

1. **USB HID** — CTAPHID for FIDO2/WebAuthn (64-byte reports)
2. **USB CCID** — Smart card interface for OATH, Management, and HSM applets

## GPIO Pin Assignments

### RP2040 (Raspberry Pi Pico)

| Function | GPIO | Notes |
|----------|------|-------|
| LED | GPIO25 | On-board green LED (active high) |
| Button | BOOTSEL | Read via QSPI_SS_N (atomic to avoid flash corruption) |
| USB D+ | GPIO (internal) | USB 1.1 PHY |
| USB D− | GPIO (internal) | USB 1.1 PHY |
| Flash CS | GPIO (QSPI) | W25Q16JV 2 MB |

### RP2350 (Raspberry Pi Pico 2)

| Function | GPIO | Notes |
|----------|------|-------|
| LED | GPIO25 | On-board green LED (active high) |
| Button | BOOTSEL | Read via QSPI_SS_N (bit 17 in GPIO_HI_IN) |
| USB D+ | GPIO (internal) | USB 1.1 PHY |
| USB D− | GPIO (internal) | USB 1.1 PHY |
| TRNG | Internal | ARM CryptoCell-312 at `0x400D_0000` |
| OTP | Internal | ARM TrustZone hardware fuses |

### ESP32-S3

| Function | GPIO | Notes |
|----------|------|-------|
| LED (v1.0) | GPIO48 | WS2812 RGB NeoPixel |
| LED (v1.1) | GPIO38 | WS2812 RGB NeoPixel |
| Button | GPIO0 | Boot button (active-low, internal pull-up) |
| USB D− | GPIO19 | USB OTG |
| USB D+ | GPIO20 | USB OTG |
| OTP | eFuse block 3 | 256-bit MKEK slot |

### ESP32-C5

| Function | GPIO | Notes |
|----------|------|-------|
| LED | Platform-specific | Configurable GPIO |
| Button | Platform-specific | Configurable GPIO (active-low) |
| USB | USB Serial/JTAG | Built-in peripheral |
| OTP | eFuse | 256-bit MKEK slot |

### ESP32-C6

| Function | GPIO | Notes |
|----------|------|-------|
| LED | Platform-specific | Configurable GPIO |
| Button | Platform-specific | Configurable GPIO (active-low) |
| USB | USB Serial/JTAG | Serial bridge mode only |
| OTP | eFuse | 256-bit MKEK slot |

### SAMD21

| Function | GPIO | Notes |
|----------|------|-------|
| LED | Configurable | No standard on-board LED; varies by board |
| Button | Configurable | GPIO or `AlwaysConfirm` stub |
| USB D− | PA24 | USB 2.0 Full Speed |
| USB D+ | PA25 | USB 2.0 Full Speed |

## Flash Layout

### RP2040 (2 MB)

```
0x0000_0000 ┌────────────────────┐
            │  Boot2 (256 B)     │
0x0000_0100 ├────────────────────┤
            │  Application       │
            │  (~1920 KB)        │
0x001E_0000 ├────────────────────┤
            │  KV Storage        │
            │  (128 KB)          │
            │  sequential-storage│
            │  4 KB erase sector │
0x0020_0000 └────────────────────┘
```

### RP2350 (4 MB)

```
0x0000_0000 ┌────────────────────┐
            │  Secure Boot       │
            │  + Application     │
            │  (~3968 KB)        │
0x003E_0000 ├────────────────────┤
            │  KV Storage        │
            │  (128 KB)          │
0x0040_0000 └────────────────────┘
```

### ESP32-S3 (8 MB)

```
0x0000_0000 ┌────────────────────┐
            │  Bootloader        │
0x0001_0000 ├────────────────────┤
            │  Application       │
            │  (~7936 KB)        │
0x007E_0000 ├────────────────────┤
            │  KV Storage        │
            │  (128 KB)          │
0x0080_0000 └────────────────────┘
```

### SAMD21 (256 KB)

```
0x0000_0000 ┌────────────────────┐
            │  Application       │
            │  (~224 KB)         │
0x0003_8000 ├────────────────────┤
            │  KV Storage        │
            │  (32 KB)           │
0x0004_0000 └────────────────────┘
```

### Storage Parameters

| Platform | Total Flash | Storage Size | Sector Size | Max Files | Max File Size |
|----------|-------------|-------------|-------------|-----------|---------------|
| RP2040 | 2 MB | 128 KB | 4 KB | ~128 | 1024 B |
| RP2350 | 4 MB | 128 KB | 4 KB | ~128 | 1024 B |
| ESP32-S3 | 8 MB | 128 KB | 4 KB | ~128 | 1024 B |
| ESP32-C5/C6 | 4 MB | 128 KB | 4 KB | ~128 | 1024 B |
| SAMD21 | 256 KB | 32 KB | varies | ~32 | 1024 B |

## LED Wiring

### Single-Color LED (RP2040, RP2350)

Standard GPIO output driving an on-board LED:

```
GPIO25 ──[330Ω]──► LED ──► GND
```

The on-board LED on Raspberry Pi Pico/Pico 2 is wired this way. Active high.

### WS2812 RGB NeoPixel (ESP32-S3)

Addressable RGB LED driven via the RMT peripheral:

```
GPIO48 (or GPIO38) ──► DIN of WS2812 ──► 5V, GND
```

- Data voltage: 3.3V (works reliably with most WS2812 at short distances)
- Add a 300–500Ω series resistor on the data line for signal integrity
- Add a 100µF bypass capacitor near the LED's VCC/GND

### Configurable LED (SAMD21, ESP32-C5/C6)

No standard LED pin. Configure in firmware or use an external LED:

```
GPIOx ──[330Ω]──► LED ──► GND
```

## Button Wiring

### BOOTSEL Button (RP2040, RP2350)

The BOOTSEL button is read by temporarily making the QSPI flash chip-select (CS) pin
an input. This requires atomic access to avoid flash corruption during reads.

No external wiring needed — built into the Pico/Pico 2 board.

### GPIO Boot Button (ESP32-S3)

```
GPIO0 ──┬──► 10KΩ pull-up to 3.3V
        └──► Momentary switch to GND
```

Active-low with internal pull-up enabled in firmware.

### Configurable Button (SAMD21, ESP32-C5/C6)

Wire a momentary switch between the chosen GPIO and GND. Enable internal pull-up
in firmware, or add an external 10KΩ pull-up to 3.3V.

If no physical button is available, the firmware falls back to `AlwaysConfirm`
(auto-approves user presence).

## Known Board Variants

### RP2040

| Board | LED | Button | Flash | Notes |
|-------|-----|--------|-------|-------|
| Raspberry Pi Pico | GPIO25 | BOOTSEL | 2 MB W25Q16JV | Reference board |
| Raspberry Pi Pico W | WL_GPIO0 (via CYW43) | BOOTSEL | 2 MB | WiFi; LED on wireless chip |
| Adafruit Feather RP2040 | GPIO13 | BOOTSEL + GPIO7 | 8 MB | NeoPixel on GPIO16 |
| Pimoroni Tiny 2040 | GPIO18/19/20 (RGB) | BOOTSEL | 8 MB | Three-color LED |

### RP2350

| Board | LED | Button | Flash | Notes |
|-------|-----|--------|-------|-------|
| Raspberry Pi Pico 2 | GPIO25 | BOOTSEL | 4 MB | Reference board |

### ESP32-S3

| Board | LED GPIO | Button | Flash | Notes |
|-------|----------|--------|-------|-------|
| ESP32-S3-DevKitC-1 (v1.0) | GPIO48 | GPIO0 | 8 MB | USB OTG on GPIO19/20 |
| ESP32-S3-DevKitC-1 (v1.1) | GPIO38 | GPIO0 | 8 MB | LED moved to GPIO38 |

### SAMD21

| Board | LED | Button | Flash | Notes |
|-------|-----|--------|-------|-------|
| Adafruit Trinket M0 | GPIO13 | — | 256 KB | Very constrained |
| Adafruit ItsyBitsy M0 | GPIO13 | — | 256 KB | DotStar on APA102 |
| Seeeduino XIAO | GPIO13 | — | 256 KB | Compact form factor |

## Power Consumption

Typical USB-powered operation:

| State | Current Draw |
|-------|-------------|
| Idle (LED blinking) | ~15–25 mA |
| Processing (crypto) | ~30–80 mA |
| RSA-4096 generation | ~80–120 mA |
| WS2812 LED active | +5–20 mA per LED |

All platforms operate at 3.3V logic levels and are USB-bus powered (5V, 500 mA max).
