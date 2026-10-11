// Client                         //
// Argon2id wrapper               //
// University Work Project        //
// Technical University of Kosice //
// Nikita Kuropatkin              //
//
// Thin wrapper around the official Argon2 reference implementation
// (third_party/argon2, P-H-C/phc-winner-argon2, CC0 / Apache-2.0),
// built single-threaded (-DARGON2_NO_THREADS) so it needs no pthreads
// on Linux or Windows.

#include <stddef.h>
#include <stdint.h>
#include "argon2.h"
#include "argon2id.h"

int a2id_derive(uint32_t t_cost, uint32_t m_cost, uint32_t lanes,
                      const void *pwd,    size_t pwdlen,
                      const void *salt,   size_t saltlen,
                      const void *secret, size_t secretlen,
                      const void *ad,     size_t adlen,
                      void *out, size_t outlen)
{
    argon2_context ctx;
    int rc;

    if (out == NULL || salt == NULL || outlen < 4 || outlen > 1024 ||
        pwdlen > 0xFFFFFFFFu / 2 || saltlen > 0xFFFFFFFFu / 2 ||
        secretlen > 0xFFFFFFFFu / 2 || adlen > 0xFFFFFFFFu / 2 ||
        m_cost > (1U << 22)) {          /* 4 GiB cap, protects against hostile files */
        return ARGON2ID_BAD_PARAMS;
    }

    ctx.out       = (uint8_t *)out;
    ctx.outlen    = (uint32_t)outlen;
    ctx.pwd       = (uint8_t *)pwd;
    ctx.pwdlen    = (uint32_t)pwdlen;
    ctx.salt      = (uint8_t *)salt;
    ctx.saltlen   = (uint32_t)saltlen;
    ctx.secret    = (uint8_t *)secret;
    ctx.secretlen = (uint32_t)secretlen;
    ctx.ad        = (uint8_t *)ad;
    ctx.adlen     = (uint32_t)adlen;
    ctx.t_cost    = t_cost;
    ctx.m_cost    = m_cost;
    ctx.lanes     = lanes;
    ctx.threads   = lanes;
    ctx.version   = ARGON2_VERSION_13;
    ctx.allocate_cbk = NULL;
    ctx.free_cbk     = NULL;
    ctx.flags     = ARGON2_DEFAULT_FLAGS;

    rc = argon2_ctx(&ctx, Argon2_id);
    if (rc == ARGON2_OK) {
        return ARGON2ID_OK;
    }
    if (rc == ARGON2_MEMORY_ALLOCATION_ERROR) {
        return ARGON2ID_NO_MEMORY;
    }
    return ARGON2ID_BAD_PARAMS;
}
