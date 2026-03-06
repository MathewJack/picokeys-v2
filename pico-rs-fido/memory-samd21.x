/* PicoKeys FIDO2 — SAMD21 Memory Layout
 *
 * 256 KB Internal Flash (at 0x00000000):
 *   FLASH:   224 KB — firmware code + read-only data
 *   STORAGE: 32 KB  — wear-levelled key-value store (sequential-storage)
 *
 * The storage partition is intentionally small (32 KB vs 128 KB on RP2040)
 * because the SAMD21's total flash is only 256 KB and firmware code must fit
 * in the remaining space.
 *
 * 32 KB SRAM (at 0x20000000):
 *   Single contiguous SRAM block.
 *
 * SAMD21 limitations:
 *   - No RSA support (code too large for 256 KB flash)
 *   - No HSM application
 *   - No dedicated TRNG (uses ADC noise or external seed)
 *   - No OTP fuses (MKEK stored encrypted in flash)
 */

MEMORY {
    FLASH   : ORIGIN = 0x00000000, LENGTH = 256K - 32K
    STORAGE : ORIGIN = 0x00038000, LENGTH = 32K
    RAM     : ORIGIN = 0x20000000, LENGTH = 32K
}

SECTIONS {
    /* Storage region — not loaded, symbols only for runtime access. */
    .storage (NOLOAD) : {
        _storage_start = .;
        . += LENGTH(STORAGE);
        _storage_end = .;
    } > STORAGE
}
