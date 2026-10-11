// Client                         //
// Argon2id (RFC 9106, v1.3)      //
// University Work Project        //
// Technical University of Kosice //
// Nikita Kuropatkin              //

#ifndef ARGON2ID_H
#define ARGON2ID_H

#include <stddef.h>
#include <stdint.h>

#define ARGON2ID_OK           0
#define ARGON2ID_BAD_PARAMS  -1
#define ARGON2ID_NO_MEMORY   -2

/*
 * Computes Argon2id (version 0x13) into out[outlen].
 *   t_cost   : number of passes (>= 1)
 *   m_cost   : memory in KiB (>= 8 * lanes)
 *   lanes    : degree of parallelism (1..16). Lanes are filled one after the
 *              other (no threads), which gives the same result as the
 *              reference implementation.
 *   secret / ad may be NULL with length 0.
 *   outlen   : 4 .. 1024 bytes
 * Allocates m_cost KiB of heap for the duration of the call and wipes it.
 */
int a2id_derive(uint32_t t_cost, uint32_t m_cost, uint32_t lanes,
                      const void *pwd,    size_t pwdlen,
                      const void *salt,   size_t saltlen,
                      const void *secret, size_t secretlen,
                      const void *ad,     size_t adlen,
                      void *out, size_t outlen);

#endif /* ARGON2ID_H */
