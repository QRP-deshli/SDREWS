// Client                         //
// Master key protected by a PIN  //
// University Work Project        //
// Technical University of Kosice //
// Nikita Kuropatkin              //

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "keywrap.h"
#include "argon2id.h"
#include "blake2/blake2.h"      /* BLAKE2b from the official Argon2 sources */
#include "platform.h"
#include "error.h"

#define KW_AD            "SLEHS-MASTER-KEY-V1"
#define KW_FILE_MAX      1024U
/* Sanity limits so a tampered file cannot make us allocate gigabytes or spin. */
#define KW_M_MIN         8U
#define KW_M_MAX         (1U << 19)    /* 512 MiB */
#define KW_T_MAX         32U
#define KW_P_MAX         16U

static void put32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}

static int params_ok(uint32_t m, uint32_t t, uint32_t p)
{
    return p >= 1U && p <= KW_P_MAX && t >= 1U && t <= KW_T_MAX &&
           m >= KW_M_MIN * p && m <= KW_M_MAX;
}

/* tag = BLAKE2b-256(mac_key, magic || m || t || p || salt || key) */
static void compute_tag(uint8_t tag[32], const uint8_t mac_key[32], const keywrap_t *kw)
{
    blake2b_state c;
    uint8_t tmp[4];

    blake2b_init_key(&c, 32, mac_key, 32);
    blake2b_update(&c, KEYWRAP_MAGIC, strlen(KEYWRAP_MAGIC));
    put32(tmp, kw->m); blake2b_update(&c, tmp, 4);
    put32(tmp, kw->t); blake2b_update(&c, tmp, 4);
    put32(tmp, kw->p); blake2b_update(&c, tmp, 4);
    blake2b_update(&c, kw->salt, sizeof(kw->salt));
    blake2b_update(&c, kw->key, sizeof(kw->key));
    blake2b_final(&c, tag, 32);
}

static int derive(uint8_t okm[48], const keywrap_t *kw, const char *pin)
{
    int r = a2id_derive(kw->t, kw->m, kw->p,
                              pin, strlen(pin),
                              kw->salt, sizeof(kw->salt),
                              NULL, 0,
                              KW_AD, strlen(KW_AD),
                              okm, 48);
    if (r == ARGON2ID_NO_MEMORY) {
        return ALLOCATION_ERROR;
    }
    return (r == ARGON2ID_OK) ? OK : UNSUPPORTED_SIZE;
}

int keywrap_encrypt(keywrap_t *kw, const uint8_t master[MASTER_KEY_SIZE],
                    const char *pin, uint32_t m, uint32_t t, uint32_t p)
{
    uint8_t okm[48];
    unsigned i;
    int err;

    if (!params_ok(m, t, p) || strlen(pin) < KEYWRAP_MIN_PIN_LEN || strlen(pin) >= KEYWRAP_PIN_MAX) {
        return WRONG_PIN_FORMAT;
    }
    memset(kw, 0, sizeof(*kw));
    kw->m = m; kw->t = t; kw->p = p;
    if (plat_random(kw->salt, sizeof(kw->salt)) != 0) {
        return ERROR_GENERATING_RANDOM;
    }
    err = derive(okm, kw, pin);
    if (err != OK) {
        return err;
    }
    for (i = 0; i < MASTER_KEY_SIZE; i++) {
        kw->key[i] = master[i] ^ okm[i];
    }
    compute_tag(kw->tag, okm + 16, kw);
    plat_wipe(okm, sizeof(okm));
    return OK;
}

int keywrap_decrypt(const keywrap_t *kw, const char *pin, uint8_t master[MASTER_KEY_SIZE])
{
    uint8_t okm[48];
    uint8_t tag[32];
    uint8_t diff = 0;
    unsigned i;
    int err;

    if (!params_ok(kw->m, kw->t, kw->p)) {
        return WRONG_TXT_FORMAT;
    }
    err = derive(okm, kw, pin);
    if (err != OK) {
        return err;
    }
    compute_tag(tag, okm + 16, kw);
    for (i = 0; i < sizeof(tag); i++) {
        diff |= (uint8_t)(tag[i] ^ kw->tag[i]);
    }
    if (diff != 0) {
        plat_wipe(okm, sizeof(okm));
        return WRONG_PIN;
    }
    for (i = 0; i < MASTER_KEY_SIZE; i++) {
        master[i] = kw->key[i] ^ okm[i];
    }
    plat_wipe(okm, sizeof(okm));
    return OK;
}

static void hex_out(FILE *f, const char *name, const uint8_t *d, size_t n)
{
    size_t i;
    fprintf(f, "%s=", name);
    for (i = 0; i < n; i++) {
        fprintf(f, "%02x", d[i]);
    }
    fputc('\n', f);
}

int keywrap_save(const char *path, const keywrap_t *kw)
{
    FILE *f = fopen(path, "wb");
    if (f == NULL) {
        return ERROR_OPENING_FILE;
    }
    fprintf(f, "%s\n", KEYWRAP_MAGIC);
    fprintf(f, "m=%u\nt=%u\np=%u\n", (unsigned)kw->m, (unsigned)kw->t, (unsigned)kw->p);
    hex_out(f, "salt", kw->salt, sizeof(kw->salt));
    hex_out(f, "key",  kw->key,  sizeof(kw->key));
    hex_out(f, "tag",  kw->tag,  sizeof(kw->tag));
    if (fclose(f) != 0) {
        return ERROR_OPENING_FILE;
    }
    return OK;
}

static int hex_in(const char *s, uint8_t *out, size_t n)
{
    size_t i;
    for (i = 0; i < n; i++) {
        char b[3];
        if (!isxdigit((unsigned char)s[2*i]) || !isxdigit((unsigned char)s[2*i + 1])) {
            return 0;
        }
        b[0] = s[2*i]; b[1] = s[2*i + 1]; b[2] = '\0';
        out[i] = (uint8_t)strtoul(b, NULL, 16);
    }
    return s[2*n] == '\0' || s[2*n] == '\r' || s[2*n] == '\n';
}

int keywrap_load(const char *path, keywrap_t *kw)
{
    char text[KW_FILE_MAX + 1U];
    char *line, *save = NULL;
    FILE *f = fopen(path, "rb");
    size_t len;
    unsigned have = 0;           /* bitmask of fields seen */
    int first = 1;

    if (f == NULL) {
        fprintf(stderr, "cannot open key file %s\n", path);
        return ERROR_OPENING_FILE;
    }
    len = fread(text, 1U, KW_FILE_MAX, f);
    fclose(f);
    text[len] = '\0';
    memset(kw, 0, sizeof(*kw));

    for (line = text; line != NULL; line = save) {
        char *nl = strpbrk(line, "\r\n");
        if (nl != NULL) {
            char *next = nl;
            while (*next == '\r' || *next == '\n') next++;
            *nl = '\0';
            save = (*next != '\0') ? next : NULL;
        } else {
            save = NULL;
        }
        if (line[0] == '\0') {
            continue;
        }
        if (first) {
            if (strcmp(line, KEYWRAP_MAGIC) != 0) {
                return WRONG_TXT_FORMAT;
            }
            first = 0;
            continue;
        }
        if (strncmp(line, "m=", 2) == 0)         { kw->m = (uint32_t)strtoul(line + 2, NULL, 10); have |= 1U; }
        else if (strncmp(line, "t=", 2) == 0)    { kw->t = (uint32_t)strtoul(line + 2, NULL, 10); have |= 2U; }
        else if (strncmp(line, "p=", 2) == 0)    { kw->p = (uint32_t)strtoul(line + 2, NULL, 10); have |= 4U; }
        else if (strncmp(line, "salt=", 5) == 0) { if (!hex_in(line + 5, kw->salt, sizeof(kw->salt))) return WRONG_TXT_FORMAT; have |= 8U; }
        else if (strncmp(line, "key=", 4) == 0)  { if (!hex_in(line + 4, kw->key, sizeof(kw->key))) return WRONG_TXT_FORMAT; have |= 16U; }
        else if (strncmp(line, "tag=", 4) == 0)  { if (!hex_in(line + 4, kw->tag, sizeof(kw->tag))) return WRONG_TXT_FORMAT; have |= 32U; }
        else return WRONG_TXT_FORMAT;
    }
    if (first || have != 63U || !params_ok(kw->m, kw->t, kw->p)) {
        return WRONG_TXT_FORMAT;
    }
    return OK;
}

int keywrap_is_wrapped_file(const char *path)
{
    char head[sizeof(KEYWRAP_MAGIC)];
    FILE *f = fopen(path, "rb");
    size_t n;

    if (f == NULL) {
        return 0;
    }
    n = fread(head, 1U, sizeof(head) - 1U, f);
    fclose(f);
    head[n] = '\0';
    return strcmp(head, KEYWRAP_MAGIC) == 0;
}
