// ============================================================================
// OTP key storage layout (RP2350)
// Shared by the server firmware and the otp_provision burner tool.
// Technical University of Kosice | Nikita Kuropatkin
// ============================================================================

/*
 * Secrets live in the RP2350 general-purpose OTP user area, stored with ECC
 * (16 data bits per 24-bit row). One "slot" is one OTP page:
 *
 *   rows 0..7    MASTER_KEY   (16 B, Chaskey auth key)
 *   rows 8..23   TLS private key scalar (32 B, ECDSA P-256)
 *   rows 24..39  IP_HASH_KEY  (32 B, HMAC key for the IP tables)
 *   row  40      commit marker, written last, so a half-burned slot is ignored
 *
 * OTP bits can never be cleared. Several slots allow the keys to be replaced
 * later: the firmware always uses the highest committed slot.
 */

#ifndef OTP_LAYOUT_H
#define OTP_LAYOUT_H

#include <stdint.h>
#include "hardware/regs/otp_data.h"

#define OTP_ROWS_PER_PAGE       64U
#define OTP_FIRST_SLOT_PAGE     40U   // Rows 0xA00..; inside the user-data area
#define OTP_SLOT_COUNT          4U
#define OTP_BYTES_PER_ROW       2U    // ECC mode: 16 data bits per row

#define OTP_MASTER_KEY_BYTES    16U
#define OTP_TLS_KEY_BYTES       32U
#define OTP_IPHASH_KEY_BYTES    32U
#define OTP_MASTER_ROWS         (OTP_MASTER_KEY_BYTES / OTP_BYTES_PER_ROW)
#define OTP_TLS_ROWS            (OTP_TLS_KEY_BYTES / OTP_BYTES_PER_ROW)
#define OTP_IPHASH_ROWS         (OTP_IPHASH_KEY_BYTES / OTP_BYTES_PER_ROW)

// Row offsets inside a slot
#define OTP_SLOT_MASTER_OFFSET  0U
#define OTP_SLOT_TLS_OFFSET     (OTP_SLOT_MASTER_OFFSET + OTP_MASTER_ROWS)
#define OTP_SLOT_IPHASH_OFFSET  (OTP_SLOT_TLS_OFFSET + OTP_TLS_ROWS)
#define OTP_SLOT_COMMIT_OFFSET  (OTP_SLOT_IPHASH_OFFSET + OTP_IPHASH_ROWS)
#define OTP_SLOT_ROWS           (OTP_SLOT_COMMIT_OFFSET + 1U)

#define OTP_COMMIT_MAGIC        0x4B59U   // "KY"

#define OTP_SLOT_PAGE(slot)     (OTP_FIRST_SLOT_PAGE + (slot))
#define OTP_SLOT_ROW(slot)      (OTP_SLOT_PAGE(slot) * OTP_ROWS_PER_PAGE)

/*
 * Page lock (LOCK1 row of the page) applied after burning:
 *   Secure   = read-only      firmware can read, nobody can write
 *   Non-sec  = inaccessible
 *   Bootloader = inaccessible USB bootloader (picotool) refuses to read it
 * Lock rows use 3-way majority voting, so the byte is repeated 3 times.
 */
#define OTP_LOCK_COPY_SHIFT     8U
#define OTP_LOCK_COPIES         3U
#define OTP_PAGE_LOCK1_ROW(page) (OTP_DATA_PAGE0_LOCK1_ROW + 2U * (page))
#define OTP_LOCK_BYTE \
    ((OTP_DATA_PAGE0_LOCK1_LOCK_BL_VALUE_INACCESSIBLE << OTP_DATA_PAGE0_LOCK1_LOCK_BL_LSB) | \
     (OTP_DATA_PAGE0_LOCK1_LOCK_NS_VALUE_INACCESSIBLE << OTP_DATA_PAGE0_LOCK1_LOCK_NS_LSB) | \
     (OTP_DATA_PAGE0_LOCK1_LOCK_S_VALUE_READ_ONLY     << OTP_DATA_PAGE0_LOCK1_LOCK_S_LSB))
#define OTP_LOCK_ROW_VALUE \
    (OTP_LOCK_BYTE | (OTP_LOCK_BYTE << OTP_LOCK_COPY_SHIFT) | \
     (OTP_LOCK_BYTE << (2U * OTP_LOCK_COPY_SHIFT)))

_Static_assert(OTP_SLOT_ROWS <= OTP_ROWS_PER_PAGE, "slot must fit in one OTP page");

#endif // OTP_LAYOUT_H
