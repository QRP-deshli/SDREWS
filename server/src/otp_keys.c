// SERVER                         //
// OTP key access                 //
// University Work Project        //
// Technical University of Kosice //
// Nikita Kuropatkin              //

#include <string.h>
#include "pico/bootrom.h"
#include "mbedtls/platform_util.h"
#include "otp/otp_keys.h"

#if !PICO_RP2350
#error "OTP key storage requires RP2350"
#endif

_Static_assert(KEY_SIZE == OTP_MASTER_KEY_BYTES, "KEY_SIZE must match the OTP layout");

// The bootrom refuses OTP transfers into a misaligned buffer (BOOTROM_ERROR_BAD_ALIGNMENT)
#define OTP_BUF_ALIGN   4U
#define OTP_ALIGNED     __attribute__((aligned(OTP_BUF_ALIGN)))

uint8_t MASTER_KEY[KEY_SIZE] OTP_ALIGNED;
uint8_t IP_HASH_KEY[OTP_IPHASH_KEY_BYTES] OTP_ALIGNED;

// Fixed ASN.1 around the scalar: SEQ{ INT 1, OCTET STRING(32), [0] OID prime256v1 }.
// The public key is optional in SEC1 and is recomputed by mbedTLS when parsing.
static const uint8_t SEC1_PREFIX[SEC1_PREFIX_BYTES] = {
    0x30, 0x31, 0x02, 0x01, 0x01, 0x04, 0x20
};
static const uint8_t SEC1_SUFFIX[SEC1_SUFFIX_BYTES] = {
    0xA0, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07
};

static uint32_t active_slot = OTP_SLOT_COUNT;

static bool otp_read_rows(uint32_t row, uint8_t *dst, uint32_t rows)
{
    otp_cmd_t cmd = { .flags = row | OTP_CMD_ECC_BITS };

    return rom_func_otp_access(dst, rows * OTP_BYTES_PER_ROW, cmd) == BOOTROM_OK;
}

static bool slot_committed(uint32_t slot)
{
    uint16_t magic = 0;

    if (!otp_read_rows(OTP_SLOT_ROW(slot) + OTP_SLOT_COMMIT_OFFSET, (uint8_t *)&magic, 1U)) {
        return false;
    }
    return magic == OTP_COMMIT_MAGIC;
}

static bool load_slot(uint32_t slot)
{
    uint32_t base = OTP_SLOT_ROW(slot);

    if (!otp_read_rows(base + OTP_SLOT_MASTER_OFFSET, MASTER_KEY, OTP_MASTER_ROWS)) {
        return false;
    }
    return otp_read_rows(base + OTP_SLOT_IPHASH_OFFSET, IP_HASH_KEY, OTP_IPHASH_ROWS);
}

bool otp_keys_load(void)
{
    uint32_t slot = OTP_SLOT_COUNT;

    while (slot > 0U) {
        slot--;
        if (slot_committed(slot)) {
            if (!load_slot(slot)) {
                return false;
            }
            active_slot = slot;
            return true;
        }
    }
    return false;
}

bool otp_tls_key_der(uint8_t der[OTP_TLS_DER_BYTES])
{
    // der + SEC1_PREFIX_BYTES is odd, so read into an aligned buffer first
    uint8_t scalar[OTP_TLS_KEY_BYTES] OTP_ALIGNED;
    bool ok;

    if (active_slot >= OTP_SLOT_COUNT) {
        return false;
    }
    ok = otp_read_rows(OTP_SLOT_ROW(active_slot) + OTP_SLOT_TLS_OFFSET, scalar, OTP_TLS_ROWS);
    if (ok) {
        memcpy(der, SEC1_PREFIX, SEC1_PREFIX_BYTES);
        memcpy(der + SEC1_PREFIX_BYTES, scalar, OTP_TLS_KEY_BYTES);
        memcpy(der + SEC1_PREFIX_BYTES + OTP_TLS_KEY_BYTES, SEC1_SUFFIX, SEC1_SUFFIX_BYTES);
    }
    mbedtls_platform_zeroize(scalar, sizeof(scalar));
    return ok;
}
