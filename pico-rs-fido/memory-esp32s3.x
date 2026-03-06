/* PicoKeys FIDO2 — ESP32-S3 Memory Layout
 *
 * ESP32-S3 memory mapping is handled by esp-hal's linker script (linkall.x).
 * This file provides only the storage partition definition for reference
 * and for use by the build script if needed.
 *
 * Flash: 4 MB or 8 MB (board-dependent), mapped via SPI cache.
 * Storage partition: last 128 KB of flash.
 *   - 4 MB boards: 0x003E0000..0x00400000
 *   - 8 MB boards: 0x007E0000..0x00800000
 *
 * Internal SRAM: 512 KB (SRAM0 + SRAM1 + SRAM2).
 * RTC SRAM: 8 KB (retained in deep sleep).
 *
 * The esp-hal linker script handles the IRAM/DRAM split, instruction cache,
 * and ROM function tables automatically. We only define storage symbols here
 * for runtime use by FlashStore.
 *
 * To select flash size, set the ESP_FLASH_SIZE environment variable or use
 * a board-specific sdkconfig.
 */

/* Default: assume 4 MB flash. Override via build config for 8 MB boards. */
_flash_size = 4M;
_storage_size = 128K;
_storage_start = _flash_size - _storage_size;
_storage_end = _flash_size;
