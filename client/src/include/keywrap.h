// Client                         //
// Master key protected by a PIN  //
// University Work Project        //
// Technical University of Kosice //
// Nikita Kuropatkin              //

#ifndef KEYWRAP_H
#define KEYWRAP_H

#include <stddef.h>
#include <stdint.h>
#include "key_file.h"          /* MASTER_KEY_SIZE */

/*
 * Encrypted key file ("master_key.enc"), plain text, one field per line:
 *
 *   SLEHS-KEYFILE-V1
 *   m=65536            Argon2id memory in KiB
 *   t=3                Argon2id passes
 *   p=1                Argon2id lanes
 *   salt=<32 hex>      random, per file (public, not secret)
 *   key=<32 hex>       master key XOR pad
 *   tag=<64 hex>       BLAKE2b-256 MAC over the header, salt and key
 *
 * Argon2id(PIN, salt, ad="SLEHS-MASTER-KEY-V1") produces 48 bytes:
 *   bytes  0..15 = one-time pad for the key
 *   bytes 16..47 = MAC key for the tag
 * The salt is random for every file, so the pad is never reused. The tag
 * lets us tell "wrong PIN / damaged file" apart from a valid key.
 */

#define KEYWRAP_MAGIC        "SLEHS-KEYFILE-V1"
#define KEYWRAP_DEFAULT_M    65536U    /* 64 MiB */
#define KEYWRAP_DEFAULT_T    3U
#define KEYWRAP_DEFAULT_P    1U
#define KEYWRAP_MIN_PIN_LEN  6U
#define KEYWRAP_PIN_MAX      128U

typedef struct {
    uint32_t m;
    uint32_t t;
    uint32_t p;
    uint8_t  salt[16];
    uint8_t  key[MASTER_KEY_SIZE];
    uint8_t  tag[32];
} keywrap_t;

/* Encrypts master[16] under pin. Returns OK or an error.h code. */
int keywrap_encrypt(keywrap_t *kw, const uint8_t master[MASTER_KEY_SIZE],
                    const char *pin, uint32_t m, uint32_t t, uint32_t p);

/* Returns OK, WRONG_PIN (bad PIN or tampered file), or another error.h code. */
int keywrap_decrypt(const keywrap_t *kw, const char *pin, uint8_t master[MASTER_KEY_SIZE]);

int keywrap_save(const char *path, const keywrap_t *kw);

/* Returns OK, ERROR_OPENING_FILE or WRONG_TXT_FORMAT. */
int keywrap_load(const char *path, keywrap_t *kw);

/* 1 if the file starts with the KEYWRAP_MAGIC line, else 0. */
int keywrap_is_wrapped_file(const char *path);

#endif /* KEYWRAP_H */
