// SERVER — MACRAW + dual TLS     //
// Ver. 0.1                       //
// University Work Project        //
// Technical University of Kosice //
// 15.08.2026                     //
// Nikita Kuropatkin              //
//
// ============================================================================
// SERVER: keyed IP-at-rest hashing.
//
// Purpose: blacklist.c (and, if applied there too, the ip_tracker_t
// table) used to store source IPv4 addresses in RAM as plaintext
// bytes. This derives a keyed HMAC-SHA256 (truncated to
// IP_HASH_LEN bytes) instead, so nothing that sits in RAM for an
// extended time reveals a real client IP directly.
//
// NOT part of the SPA protocol. spa.c / spa_token.c still work with
// raw IPs the moment they arrive off the wire (spa_verify(),
// spa_ip_quick_hash()) -- that's a transient stack value, not a
// long-lived table entry, and touching it would change the wire
// protocol. This module only changes what gets STORED afterwards.
//
// Backed by mbedtls_md_hmac() (mbedtls/md.h), which is already
// linked into this build for TLS (MBEDTLS_SHA256_C + MBEDTLS_MD_C
// are already enabled in ssl_config.h) -- no new crypto dependency.
// Runs in software by default; if MBEDTLS_SHA256_ALT is enabled and
// the pico_sha256 hardware library is linked, mbedtls transparently
// routes this (and every other SHA-256 call, including the ones TLS
// already makes) through the RP2350's SHA-256 accelerator instead --
// see the comment at the bottom of ip_hash.c.
// ============================================================================

#ifndef IP_HASH_H
#define IP_HASH_H

#include <stdint.h>

/*
 * ip_hash_compute(ip, out)
 * Derives a 4-byte keyed hash of a raw IPv4 address into `out`.
 * Deterministic and keyed with IP_HASH_KEY (loaded from OTP, see otp_keys.c) --
 * same input always produces the same output, so it's safe to use
 * for table lookups/equality checks, just never for recovering the
 * original IP.
 */
void ip_hash_compute(const uint8_t ip[4], uint8_t out[4]);

/*
 * ip_hash_equal(hash, ip)
 * Convenience: computes ip_hash_compute(ip) and compares it against
 * an already-stored hash. Returns true on match.
 */
int ip_hash_equal(const uint8_t stored_hash[4], const uint8_t ip[4]);

#endif /* IP_HASH_H */
