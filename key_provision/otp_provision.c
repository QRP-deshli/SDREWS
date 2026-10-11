// OTP PROVISIONING TOOL           //
// RP2350 / W6100-EVB-Pico2        //
// University Work Project         //
// Technical University of Kosice  //
// Nikita Kuropatkin               //

/*
 * Stage 1  BURN         write MASTER_KEY + TLS key + IP hash key into the next free OTP slot,
 *                       verify by read-back, write the commit marker, lock the page.
 * Stage 2  DISABLE-SWD  set DEBUG_DISABLE + SECURE_DEBUG_DISABLE in CRIT1.
 *
 * Everything written to OTP is permanent. Each stage needs a typed confirmation.
 * Stage 2 is only offered when stage 1 is complete and verified.
 */

#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include "pico/stdlib.h"
#include "pico/bootrom.h"
#include "hardware/regs/otp_data.h"
#include "otp_layout.h"
#include "otp_secrets.h"

#define CONFIRM_BURN        "BURN"
#define CONFIRM_SWD         "DISABLE-SWD"
#define LINE_BUF_SIZE       16U
#define USB_POLL_MS         100U
#define NO_SLOT             (-1)
#define CRIT1_COPY_COUNT    3U
#define CRIT1_DEBUG_OFF     (OTP_DATA_CRIT1_DEBUG_DISABLE_BITS | OTP_DATA_CRIT1_SECURE_DEBUG_DISABLE_BITS)
#define OTP_RAW_MASK        0x00FFFFFFU
#define OTP_RAW_BYTES       4U

typedef enum {
    SLOT_EMPTY,
    SLOT_COMMITTED,
    SLOT_USED   // Partly burned or unreadable: never reused
} slot_state_t;

/* ---------------------------------------------------------------- OTP I/O */

static bool otp_read_ecc(uint32_t row, uint8_t *buf, uint32_t rows)
{
    otp_cmd_t cmd = { .flags = row | OTP_CMD_ECC_BITS };

    return rom_func_otp_access(buf, rows * OTP_BYTES_PER_ROW, cmd) == BOOTROM_OK;
}

static bool otp_write_ecc(uint32_t row, const uint8_t *buf, uint32_t rows)
{
    otp_cmd_t cmd = { .flags = row | OTP_CMD_ECC_BITS | OTP_CMD_WRITE_BITS };

    return rom_func_otp_access((uint8_t *)buf, rows * OTP_BYTES_PER_ROW, cmd) == BOOTROM_OK;
}

static bool otp_read_raw(uint32_t row, uint32_t *val)
{
    otp_cmd_t cmd = { .flags = row };

    if (rom_func_otp_access((uint8_t *)val, OTP_RAW_BYTES, cmd) != BOOTROM_OK) {
        return false;
    }
    *val &= OTP_RAW_MASK;
    return true;
}

static bool otp_write_raw(uint32_t row, uint32_t val)
{
    otp_cmd_t cmd = { .flags = row | OTP_CMD_WRITE_BITS };

    return rom_func_otp_access((uint8_t *)&val, OTP_RAW_BYTES, cmd) == BOOTROM_OK;
}

/* Writes ECC rows and verifies them by reading back */
static bool burn_rows(uint32_t row, const uint8_t *data, uint32_t rows)
{
    uint8_t check[OTP_SLOT_ROWS * OTP_BYTES_PER_ROW];

    if (!otp_write_ecc(row, data, rows)) {
        return false;
    }
    if (!otp_read_ecc(row, check, rows)) {
        return false;
    }
    return memcmp(check, data, rows * OTP_BYTES_PER_ROW) == 0;
}

/* ------------------------------------------------------------------ slots */

static slot_state_t slot_state(uint32_t slot)
{
    uint16_t rows[OTP_SLOT_ROWS];
    uint32_t i;

    if (!otp_read_ecc(OTP_SLOT_ROW(slot), (uint8_t *)rows, OTP_SLOT_ROWS)) {
        return SLOT_USED;
    }
    if (rows[OTP_SLOT_COMMIT_OFFSET] == OTP_COMMIT_MAGIC) {
        return SLOT_COMMITTED;
    }
    for (i = 0; i < OTP_SLOT_ROWS; i++) {
        if (rows[i] != 0U) {
            return SLOT_USED;
        }
    }
    return SLOT_EMPTY;
}

static bool slot_matches_secrets(uint32_t slot)
{
    uint8_t master[OTP_MASTER_KEY_BYTES];
    uint8_t tls[OTP_TLS_KEY_BYTES];
    uint8_t iphash[OTP_IPHASH_KEY_BYTES];

    if (!otp_read_ecc(OTP_SLOT_ROW(slot) + OTP_SLOT_MASTER_OFFSET, master, OTP_MASTER_ROWS)) {
        return false;
    }
    if (!otp_read_ecc(OTP_SLOT_ROW(slot) + OTP_SLOT_TLS_OFFSET, tls, OTP_TLS_ROWS)) {
        return false;
    }
    if (!otp_read_ecc(OTP_SLOT_ROW(slot) + OTP_SLOT_IPHASH_OFFSET, iphash, OTP_IPHASH_ROWS)) {
        return false;
    }
    return memcmp(master, OTP_SECRET_MASTER_KEY, sizeof(master)) == 0 &&
           memcmp(tls, OTP_SECRET_TLS_KEY, sizeof(tls)) == 0 &&
           memcmp(iphash, OTP_SECRET_IPHASH_KEY, sizeof(iphash)) == 0;
}

/* Newest committed slot, or NO_SLOT */
static int newest_committed(void)
{
    int slot;

    for (slot = (int)OTP_SLOT_COUNT - 1; slot >= 0; slot--) {
        if (slot_state((uint32_t)slot) == SLOT_COMMITTED) {
            return slot;
        }
    }
    return NO_SLOT;
}

/* First slot after every slot that is already in use, or NO_SLOT */
static int next_free_slot(void)
{
    int slot;
    int last_used = NO_SLOT;

    for (slot = 0; slot < (int)OTP_SLOT_COUNT; slot++) {
        if (slot_state((uint32_t)slot) != SLOT_EMPTY) {
            last_used = slot;
        }
    }
    if (last_used + 1 >= (int)OTP_SLOT_COUNT) {
        return NO_SLOT;
    }
    return last_used + 1;
}

static bool slot_is_locked(uint32_t slot)
{
    uint32_t val;

    if (!otp_read_raw(OTP_PAGE_LOCK1_ROW(OTP_SLOT_PAGE(slot)), &val)) {
        return false;
    }
    return val == OTP_LOCK_ROW_VALUE;
}

/* --------------------------------------------------------------- stage 1 */

static bool burn_slot(uint32_t slot)
{
    uint32_t base = OTP_SLOT_ROW(slot);
    uint16_t magic = OTP_COMMIT_MAGIC;

    printf("Writing MASTER_KEY...\n");
    if (!burn_rows(base + OTP_SLOT_MASTER_OFFSET, OTP_SECRET_MASTER_KEY, OTP_MASTER_ROWS)) {
        return false;
    }
    printf("Writing TLS key...\n");
    if (!burn_rows(base + OTP_SLOT_TLS_OFFSET, OTP_SECRET_TLS_KEY, OTP_TLS_ROWS)) {
        return false;
    }
    printf("Writing IP hash key...\n");
    if (!burn_rows(base + OTP_SLOT_IPHASH_OFFSET, OTP_SECRET_IPHASH_KEY, OTP_IPHASH_ROWS)) {
        return false;
    }
    printf("Writing commit marker...\n");
    return burn_rows(base + OTP_SLOT_COMMIT_OFFSET, (const uint8_t *)&magic, 1U);
}

static bool lock_slot(uint32_t slot)
{
    uint32_t row = OTP_PAGE_LOCK1_ROW(OTP_SLOT_PAGE(slot));
    uint32_t val;

    if (!otp_write_raw(row, OTP_LOCK_ROW_VALUE)) {
        return false;
    }
    return otp_read_raw(row, &val) && val == OTP_LOCK_ROW_VALUE;
}

/* --------------------------------------------------------------- stage 2 */

static bool swd_is_disabled(void)
{
    uint32_t val;

    return otp_read_raw(OTP_DATA_CRIT1_ROW, &val) && (val & CRIT1_DEBUG_OFF) == CRIT1_DEBUG_OFF;
}

static bool disable_swd(void)
{
    uint32_t i;
    uint32_t val;

    // CRIT1 is stored in 3 redundant rows (majority vote): write all of them
    for (i = 0; i < CRIT1_COPY_COUNT; i++) {
        if (!otp_read_raw(OTP_DATA_CRIT1_ROW + i, &val)) {
            return false;
        }
        if (!otp_write_raw(OTP_DATA_CRIT1_ROW + i, val | CRIT1_DEBUG_OFF)) {
            return false;
        }
        if (!otp_read_raw(OTP_DATA_CRIT1_ROW + i, &val) || (val & CRIT1_DEBUG_OFF) != CRIT1_DEBUG_OFF) {
            return false;
        }
    }
    return true;
}

/* ------------------------------------------------------------------- UI */

static void read_line(char *buf, size_t size)
{
    size_t len = 0;
    int c;

    for (;;) {
        c = getchar();
        if (c == '\r' || c == '\n') {
            if (len > 0U) {
                break;
            }
            continue;
        }
        if (len + 1U < size) {
            buf[len] = (char)c;
            len++;
        }
    }
    buf[len] = '\0';
}

static bool confirm(const char *word)
{
    char line[LINE_BUF_SIZE];

    printf("Type %s and press Enter to continue, anything else aborts: ", word);
    read_line(line, sizeof(line));
    printf("\n");
    return strcmp(line, word) == 0;
}

static void halt(const char *msg)
{
    printf("\nSTOP: %s\n", msg);
    for (;;) {
        sleep_ms(USB_POLL_MS);
    }
}

/* Returns the verified, locked slot index; halts on any problem */
static uint32_t stage_burn(void)
{
    int slot = newest_committed();
    int free_slot;

    if (slot != NO_SLOT && slot_matches_secrets((uint32_t)slot)) {
        printf("Slot %d already holds exactly these keys, nothing to burn.\n", slot);
    } else {
        free_slot = next_free_slot();
        if (free_slot == NO_SLOT) {
            halt("no free OTP slot left");
        }
        slot = free_slot;
        printf("Keys will be written to slot %d (OTP rows 0x%03X..). This cannot be undone.\n",
               slot, (unsigned)OTP_SLOT_ROW((uint32_t)slot));
        if (!confirm(CONFIRM_BURN)) {
            halt("aborted, nothing written");
        }
        if (!burn_slot((uint32_t)slot)) {
            halt("OTP write or verify failed, this slot is now unusable (the next run uses the next slot)");
        }
        if (!slot_matches_secrets((uint32_t)slot)) {
            halt("verify after commit failed");
        }
    }
    if (!slot_is_locked((uint32_t)slot)) {
        printf("Locking page...\n");
        if (!lock_slot((uint32_t)slot)) {
            halt("page lock failed");
        }
    }
    printf("Stage 1 OK: slot %d committed, verified, locked.\n", slot);
    return (uint32_t)slot;
}

static void stage_swd(void)
{
    if (swd_is_disabled()) {
        printf("SWD debugging is already disabled.\n");
        return;
    }
    printf("\nSWD/debug access will be disabled permanently (takes effect after power cycle).\n"
           "After this the board can only be reprogrammed through BOOTSEL.\n");
    if (!confirm(CONFIRM_SWD)) {
        printf("SWD left enabled.\n");
        return;
    }
    if (!disable_swd()) {
        halt("CRIT1 write or verify failed");
    }
    printf("Stage 2 OK: debug disabled. Power-cycle the board.\n");
}

int main(void)
{
    stdio_init_all();
    while (!stdio_usb_connected()) {
        sleep_ms(USB_POLL_MS);
    }
    printf("\n=== RP2350 OTP key provisioning ===\n");

    stage_burn();
    stage_swd();

    printf("\nDone. Flash the server firmware now; it overwrites this tool and its embedded keys.\n");
    for (;;) {
        sleep_ms(USB_POLL_MS);
    }
}
