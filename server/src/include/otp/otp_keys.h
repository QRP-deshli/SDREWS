// ============================================================================
// SERVER: OTP key access
// Technical University of Kosice | Nikita Kuropatkin
// ============================================================================

#ifndef OTP_KEYS_H
#define OTP_KEYS_H

#include <stdbool.h>
#include <stdint.h>
#include "parameters.h"
#include "otp_layout.h"

// SEC1 ECPrivateKey (RFC 5915) = prefix + 32 B scalar + suffix
#define SEC1_PREFIX_BYTES   7U
#define SEC1_SUFFIX_BYTES   12U
#define OTP_TLS_DER_BYTES   (SEC1_PREFIX_BYTES + OTP_TLS_KEY_BYTES + SEC1_SUFFIX_BYTES)

// Keys loaded from OTP into RAM by otp_keys_load()
extern uint8_t MASTER_KEY[KEY_SIZE];          // Chaskey auth / session key derivation
extern uint8_t IP_HASH_KEY[OTP_IPHASH_KEY_BYTES];   // HMAC key for the IP tables

/*
 * Selects the newest committed OTP slot and loads MASTER_KEY and IP_HASH_KEY
 * from it. Returns false if no slot is provisioned or OTP cannot be read.
 */
bool otp_keys_load(void);

/*
 * Builds the TLS private key as DER for mbedtls_pk_parse_key().
 * The caller must wipe the buffer after parsing.
 * Returns false if otp_keys_load() has not succeeded or OTP cannot be read.
 */
bool otp_tls_key_der(uint8_t der[OTP_TLS_DER_BYTES]);

#endif // OTP_KEYS_H
