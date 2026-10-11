// SERVER — MACRAW + dual TLS     //
// Ver. 0.1                       //
// University Work Project        //
// Technical University of Kosice //
// 15.08.2026                     //
// Nikita Kuropatkin              //
//
// See ip_hash.h for the design rationale.

#include "ip_hash.h"
#include "parameters.h"          /* IP_HASH_LEN */
#include "otp/otp_keys.h"        /* IP_HASH_KEY, loaded from OTP */
#include "mbedtls/md.h"
#include <string.h>

/*
 * ip_hash_compute(ip, out)
 * HMAC-SHA256(IP_HASH_KEY, ip) truncated to IP_HASH_LEN (4) bytes.
 *
 * Truncating a keyed HMAC output is safe (unlike truncating a bare
 * hash of low-entropy input): the security only degrades to "as hard
 * as guessing IP_HASH_LEN*8 = 32 bits of a keyed PRF output", which
 * is already far more than this table (MAX_BLACKLIST_ENTRY = 64
 * entries) will ever need for collision safety -- a 32-bit space
 * needs on the order of tens of thousands of entries before a
 * birthday collision becomes likely, and a false-positive collision
 * here just means two IPs share a strike counter, not an
 * authentication bypass (SPA verification never goes through this
 * hash at all).
 *
 * mbedtls_md_hmac() is a one-shot convenience wrapper -- no context
 * to init/free, safe to call from add_strike()/is_blocked() on every
 * lookup without worrying about state.
 */
void ip_hash_compute(const uint8_t ip[4], uint8_t out[4])
{
    uint8_t full[32]; /* SHA-256 output size */

    const mbedtls_md_info_t *info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);

    /* info is only NULL if MBEDTLS_MD_C/MBEDTLS_SHA256_C aren't
     * compiled in -- both are already required by ssl_config.h for
     * TLS, so this should never trip in this build. */
    mbedtls_md_hmac(info, IP_HASH_KEY, sizeof(IP_HASH_KEY), ip, 4, full);

    memcpy(out, full, IP_HASH_LEN);
}

int ip_hash_equal(const uint8_t stored_hash[4], const uint8_t ip[4])
{
    uint8_t computed[4];
    ip_hash_compute(ip, computed);
    return memcmp(stored_hash, computed, IP_HASH_LEN) == 0;
}

/* ============================================================
 * OPTIONAL: hardware acceleration
 * ============================================================
 * This file never touches the SHA-256 hardware directly -- it goes
 * through mbedtls, which can be pointed at the RP2350's accelerator
 * with zero changes here:
 *
 *   1. Add to ssl_config.h:      #define MBEDTLS_SHA256_ALT
 *   2. In CMakeLists.txt, link:  pico_sha256   (alongside pico_mbedtls)
 *
 * With both in place, mbedtls_sha256()/mbedtls_md_hmac() -- INCLUDING
 * the SHA-256 calls TLS itself already makes for the handshake
 * transcript hash and HKDF -- transparently route through the
 * hardware block instead of the software implementation. Given this
 * module only ever hashes a handful of 4-byte IPs per incident, the
 * software path is already fast enough that this is a nice-to-have,
 * not a requirement -- worth doing mainly if you also want the TLS
 * handshake itself to get faster, not for this module's sake alone.
 * ============================================================ */
