// OTP SECRETS GENERATOR           //
// Host tool, plain C99            //
// University Work Project         //
// Technical University of Kosice  //
// Nikita Kuropatkin               //

/*
 * Reads the keys from header files (or plain PEM files) and writes
 * otp_secrets.h for the otp_provision burner.
 *
 *   gen_otp_secrets <key_file> <master_file> <iphash_file> <out_file> [cert_file]
 *
 *   key_file    file with the "-----BEGIN ... PRIVATE KEY-----" block, either a PEM
 *               file or a header holding it as C strings. ECDSA P-256, SEC1 or PKCS#8.
 *   master_file header with the "MASTER_KEY[...] = { 0xNN, ... };" array (16 bytes)
 *   iphash_file header with the "IP_HASH_KEY[...] = { 0xNN, ... };" array (32 bytes)
 *   out_file    generated header (contains secrets, delete after burning)
 *   cert_file   optional, certificate PEM or header; checked against the key
 *
 * Build (key/cert match check needs OpenSSL 3 development files):
 *   gcc -std=c99 -O2 -Wall -Wextra -o gen_otp_secrets gen_otp_secrets.c -DWITH_OPENSSL -lcrypto
 *   gcc -std=c99 -O2 -Wall -Wextra -o gen_otp_secrets gen_otp_secrets.c      (no match check)
 *   cl gen_otp_secrets.c                                                     (MSVC, no match check)
 */

#ifdef _MSC_VER
#define _CRT_SECURE_NO_WARNINGS
#endif

#include <ctype.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef WITH_OPENSSL
#include <openssl/evp.h>
#include <openssl/x509.h>
#if OPENSSL_VERSION_NUMBER < 0x30000000L
#error "WITH_OPENSSL needs OpenSSL 3"
#endif
#endif

#define MASTER_NAME         "MASTER_KEY"
#define IPHASH_NAME         "IP_HASH_KEY"
#define KEY_LABEL           "PRIVATE KEY-----"
#define CERT_LABEL          "CERTIFICATE-----"
#define END_MARK            "-----END"
#define ENCRYPTED_WORD      "ENCRYPTED"
#define MASTER_BYTES        16U
#define TLS_BYTES           32U
#define IPHASH_BYTES        32U
#define DER_MAX             2048U
#define BYTES_PER_LINE      8U
#define B64_BITS            6U
#define BYTE_BITS           8U
#define HEX_PREFIX_CHARS    2U
#define HEX_BYTE_CHARS      4U
#define HEX_BASE            16
#define NOT_B64             (-1)
#define ARGS_REQUIRED       5
#define ARGS_WITH_CERT      6

static const char B64_TABLE[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

// ASN.1 for "INTEGER 1, OCTET STRING (32 bytes)": the scalar follows right after
static const uint8_t SCALAR_TAG[] = { 0x02, 0x01, 0x01, 0x04, 0x20 };

// OID 1.2.840.10045.3.1.7 (prime256v1)
static const uint8_t P256_OID[] = { 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07 };

// Keys that used to be in the source code: never accept them again
static const uint8_t LEGACY_MASTER[MASTER_BYTES] = {
    0xAA, 0xBB, 0xCC, 0xDD, 0x11, 0x22, 0x33, 0x44,
    0x55, 0x66, 0x77, 0x88, 0x99, 0x00, 0xAA, 0xBB
};
static const uint8_t LEGACY_IPHASH[IPHASH_BYTES] = {
    0x8F, 0x2A, 0x5C, 0x91, 0x0D, 0x77, 0xE4, 0x3B,
    0x6A, 0x1F, 0xC8, 0x54, 0x9E, 0x02, 0xB6, 0x3D,
    0x71, 0xA9, 0x0C, 0x4E, 0xD5, 0x88, 0x33, 0xF0,
    0x2C, 0x6B, 0x99, 0x15, 0x7A, 0xE2, 0x40, 0xBD
};

static char *read_file(const char *path)
{
    FILE *f = fopen(path, "rb");
    char *buf;
    long size;

    if (f == NULL) {
        fprintf(stderr, "cannot open %s\n", path);
        return NULL;
    }
    fseek(f, 0, SEEK_END);
    size = ftell(f);
    fseek(f, 0, SEEK_SET);
    buf = malloc((size_t)size + 1U);
    if (buf == NULL || fread(buf, 1U, (size_t)size, f) != (size_t)size) {
        fprintf(stderr, "cannot read %s\n", path);
        free(buf);
        fclose(f);
        return NULL;
    }
    buf[size] = '\0';
    fclose(f);
    return buf;
}

static int b64_val(char c)
{
    const char *p;

    if (c == '\0') {
        return NOT_B64;
    }
    p = strchr(B64_TABLE, c);
    if (p == NULL) {
        return NOT_B64;
    }
    return (int)(p - B64_TABLE);
}

/*
 * Decodes the first PEM block with the given label. Quotes, whitespace and
 * C escapes like \n (when the PEM sits in a header as strings) are skipped.
 */
static bool pem_decode(const char *text, const char *label, uint8_t *der, size_t *len)
{
    const char *p = strstr(text, label);
    const char *end;
    uint32_t acc = 0;
    unsigned bits = 0;
    size_t n = 0;
    int v;

    if (p == NULL) {
        fprintf(stderr, "no block with label \"%s\" found\n", label);
        return false;
    }
    p += strlen(label);
    end = strstr(p, END_MARK);
    if (end == NULL) {
        fprintf(stderr, "block \"%s\" has no end marker\n", label);
        return false;
    }
    while (p < end && *p != '=') {
        if (*p == '\\') {
            p++;
            if (p < end) {
                p++;
            }
            continue;
        }
        v = b64_val(*p);
        p++;
        if (v == NOT_B64) {
            continue;
        }
        acc = (acc << B64_BITS) | (uint32_t)v;
        bits += B64_BITS;
        if (bits >= BYTE_BITS) {
            bits -= BYTE_BITS;
            if (n >= DER_MAX) {
                fprintf(stderr, "block \"%s\" is too large\n", label);
                return false;
            }
            der[n] = (uint8_t)(acc >> bits);
            n++;
            acc &= (1U << bits) - 1U;
        }
    }
    *len = n;
    return true;
}

static const uint8_t *find_bytes(const uint8_t *buf, size_t len, const uint8_t *pat, size_t pat_len)
{
    size_t i;

    if (len < pat_len) {
        return NULL;
    }
    for (i = 0; i + pat_len <= len; i++) {
        if (memcmp(buf + i, pat, pat_len) == 0) {
            return buf + i;
        }
    }
    return NULL;
}

static bool is_all_zero(const uint8_t *d, size_t n)
{
    size_t i;

    for (i = 0; i < n; i++) {
        if (d[i] != 0U) {
            return false;
        }
    }
    return true;
}

static bool extract_scalar(const uint8_t *der, size_t len, uint8_t scalar[TLS_BYTES])
{
    const uint8_t *p = find_bytes(der, len, SCALAR_TAG, sizeof(SCALAR_TAG));

    if (find_bytes(der, len, P256_OID, sizeof(P256_OID)) == NULL) {
        fprintf(stderr, "key is not ECDSA P-256 (prime256v1)\n");
        return false;
    }
    if (p == NULL || (size_t)(der + len - p) < sizeof(SCALAR_TAG) + TLS_BYTES) {
        fprintf(stderr, "no 32-byte private scalar found in key\n");
        return false;
    }
    memcpy(scalar, p + sizeof(SCALAR_TAG), TLS_BYTES);
    if (is_all_zero(scalar, TLS_BYTES)) {
        fprintf(stderr, "private scalar is all zero\n");
        return false;
    }
    return true;
}

static bool parse_array(const char *text, const char *name, uint8_t *out, size_t count)
{
    const char *p = text;
    const char *q = NULL;
    char digits[HEX_PREFIX_CHARS + 1U];
    size_t n = 0;

    // First occurrence of the name that is followed by '{' before any ';'
    while (q == NULL) {
        p = strstr(p, name);
        if (p == NULL) {
            fprintf(stderr, "array %s not found\n", name);
            return false;
        }
        p += strlen(name);
        q = p;
        while (*q != '\0' && *q != '{' && *q != ';') {
            q++;
        }
        if (*q != '{') {
            q = NULL;
        }
    }
    q++;
    while (*q != '\0' && *q != '}') {
        if (q[0] != '0' || (q[1] != 'x' && q[1] != 'X')) {
            q++;
            continue;
        }
        if (!isxdigit((unsigned char)q[2]) || !isxdigit((unsigned char)q[3]) ||
            isxdigit((unsigned char)q[HEX_BYTE_CHARS])) {
            fprintf(stderr, "%s: every byte must be written as 0xNN\n", name);
            return false;
        }
        if (n >= count) {
            fprintf(stderr, "%s has more than %u bytes\n", name, (unsigned)count);
            return false;
        }
        digits[0] = q[2];
        digits[1] = q[3];
        digits[2] = '\0';
        out[n] = (uint8_t)strtoul(digits, NULL, HEX_BASE);
        n++;
        q += HEX_BYTE_CHARS;
    }
    if (*q != '}' || n != count) {
        fprintf(stderr, "%s must have exactly %u bytes\n", name, (unsigned)count);
        return false;
    }
    return true;
}

static bool check_secret(const char *name, const uint8_t *key, size_t count, const uint8_t *legacy)
{
    if (is_all_zero(key, count)) {
        fprintf(stderr, "%s is all zero\n", name);
        return false;
    }
    if (memcmp(key, legacy, count) == 0) {
        fprintf(stderr, "%s is the old key from the source code, create a new one\n", name);
        return false;
    }
    return true;
}

#ifdef WITH_OPENSSL
static bool pair_matches(const uint8_t *key_der, size_t key_len, const uint8_t *crt_der, size_t crt_len)
{
    const uint8_t *kp = key_der;
    const uint8_t *cp = crt_der;
    EVP_PKEY *priv = d2i_AutoPrivateKey(NULL, &kp, (long)key_len);
    X509 *crt = d2i_X509(NULL, &cp, (long)crt_len);
    bool same = false;

    if (priv != NULL && crt != NULL) {
        same = EVP_PKEY_eq(X509_get0_pubkey(crt), priv) == 1;
    }
    EVP_PKEY_free(priv);
    X509_free(crt);
    return same;
}
#endif

static void write_array(FILE *f, const char *name, const uint8_t *d, size_t n)
{
    size_t i;

    fprintf(f, "static const uint8_t %s[%u] = {\n", name, (unsigned)n);
    for (i = 0; i < n; i++) {
        if (i % BYTES_PER_LINE == 0U) {
            fprintf(f, "    ");
        }
        fprintf(f, "0x%02X", d[i]);
        if (i + 1U < n) {
            fprintf(f, ",");
        }
        if ((i + 1U) % BYTES_PER_LINE == 0U || i + 1U == n) {
            fprintf(f, "\n");
        } else {
            fprintf(f, " ");
        }
    }
    fprintf(f, "};\n\n");
}

static bool write_header(const char *path, const uint8_t *master, const uint8_t *tls, const uint8_t *iphash)
{
    FILE *f = fopen(path, "wb");

    if (f == NULL) {
        fprintf(stderr, "cannot write %s\n", path);
        return false;
    }
    fprintf(f, "// GENERATED by gen_otp_secrets. Contains secrets: never commit, delete after burning.\n"
               "#ifndef OTP_SECRETS_H\n#define OTP_SECRETS_H\n\n#include <stdint.h>\n\n");
    write_array(f, "OTP_SECRET_MASTER_KEY", master, MASTER_BYTES);
    write_array(f, "OTP_SECRET_TLS_KEY", tls, TLS_BYTES);
    write_array(f, "OTP_SECRET_IPHASH_KEY", iphash, IPHASH_BYTES);
    fprintf(f, "#endif\n");
    return fclose(f) == 0;
}

int main(int argc, char **argv)
{
    uint8_t key_der[DER_MAX];
    uint8_t crt_der[DER_MAX];
    uint8_t master[MASTER_BYTES];
    uint8_t tls[TLS_BYTES];
    uint8_t iphash[IPHASH_BYTES];
    size_t key_len = 0;
    size_t crt_len = 0;
    char *key_text;
    char *master_text;
    char *iphash_text;
    char *crt_text;
    bool ok;

    if (argc != ARGS_REQUIRED && argc != ARGS_WITH_CERT) {
        fprintf(stderr, "usage: %s <key_file> <master_file> <iphash_file> <out_file> [cert_file]\n", argv[0]);
        return EXIT_FAILURE;
    }
    key_text = read_file(argv[1]);
    master_text = read_file(argv[2]);
    iphash_text = read_file(argv[3]);
    if (key_text == NULL || master_text == NULL || iphash_text == NULL) {
        return EXIT_FAILURE;
    }
    if (strstr(key_text, ENCRYPTED_WORD) != NULL) {
        fprintf(stderr, "encrypted private keys are not supported\n");
        return EXIT_FAILURE;
    }
    ok = pem_decode(key_text, KEY_LABEL, key_der, &key_len) &&
         extract_scalar(key_der, key_len, tls) &&
         parse_array(master_text, MASTER_NAME, master, MASTER_BYTES) &&
         check_secret(MASTER_NAME, master, MASTER_BYTES, LEGACY_MASTER) &&
         parse_array(iphash_text, IPHASH_NAME, iphash, IPHASH_BYTES) &&
         check_secret(IPHASH_NAME, iphash, IPHASH_BYTES, LEGACY_IPHASH);
    if (!ok) {
        return EXIT_FAILURE;
    }

    if (argc == ARGS_WITH_CERT) {
        crt_text = read_file(argv[5]);
        if (crt_text == NULL || !pem_decode(crt_text, CERT_LABEL, crt_der, &crt_len)) {
            return EXIT_FAILURE;
        }
#ifdef WITH_OPENSSL
        if (!pair_matches(key_der, key_len, crt_der, crt_len)) {
            fprintf(stderr, "private key does NOT belong to the certificate\n");
            return EXIT_FAILURE;
        }
        printf("key matches certificate\n");
#else
        printf("WARNING: built without OpenSSL, key/certificate match NOT checked\n");
#endif
    } else {
        printf("WARNING: no certificate given, key/certificate match NOT checked\n");
    }

    if (!write_header(argv[4], master, tls, iphash)) {
        return EXIT_FAILURE;
    }
    printf("wrote %s\n", argv[4]);
    return EXIT_SUCCESS;
}
