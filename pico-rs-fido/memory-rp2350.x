/* PicoKeys FIDO2 — RP2350 Memory Layout
 *
 * 2 MB QSPI Flash (XIP at 0x10000000):
 *   FLASH:   1920 KB — firmware code + read-only data
 *   STORAGE: 128 KB  — wear-levelled key-value store (sequential-storage)
 *
 * Note: RP2350 does NOT require a separate BOOT2 region (secure boot ROM
 * handles the second-stage boot internally with signed boot blocks).
 *
 * 520 KB SRAM (at 0x20000000):
 *   10 banks totalling 520 KB (vs 264 KB on RP2040).
 *
 * RP2350 also has:
 *   - Dedicated TRNG peripheral
 *   - 8 KB OTP fuse storage (for MKEK and secure boot keys)
 */

MEMORY {
    FLASH   : ORIGIN = 0x10000000, LENGTH = 2048K - 128K
    STORAGE : ORIGIN = 0x101E0000, LENGTH = 128K
    RAM     : ORIGIN = 0x20000000, LENGTH = 520K
}

SECTIONS {
    /* Storage region — not loaded, symbols only for runtime access. */
    .storage (NOLOAD) : {
        _storage_start = .;
        . += LENGTH(STORAGE);
        _storage_end = .;
    } > STORAGE
}
