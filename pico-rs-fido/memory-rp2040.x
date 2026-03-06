/* PicoKeys FIDO2 — RP2040 Memory Layout
 *
 * 2 MB QSPI Flash (XIP at 0x10000000):
 *   BOOT2:   256 bytes  — second-stage bootloader
 *   FLASH:   1920 KB    — firmware code + read-only data
 *   STORAGE: 128 KB     — wear-levelled key-value store (sequential-storage)
 *
 * 264 KB SRAM (at 0x20000000):
 *   6 banks: 4×16 KB striped + 2×4 KB = 256 KB main + 4 KB scratch X + 4 KB scratch Y
 */

MEMORY {
    BOOT2   : ORIGIN = 0x10000000, LENGTH = 0x100
    FLASH   : ORIGIN = 0x10000100, LENGTH = 2048K - 256 - 128K
    STORAGE : ORIGIN = 0x101E0000, LENGTH = 128K
    RAM     : ORIGIN = 0x20000000, LENGTH = 264K
}

SECTIONS {
    /* Boot2 second-stage bootloader (required for XIP on RP2040). */
    .boot2 ORIGIN(BOOT2) : {
        KEEP(*(.boot2))
    } > BOOT2

    /* Storage region — not loaded, symbols only for runtime access. */
    .storage (NOLOAD) : {
        _storage_start = .;
        . += LENGTH(STORAGE);
        _storage_end = .;
    } > STORAGE
}
