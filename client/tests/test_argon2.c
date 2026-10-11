/* Self-test: BLAKE2b and Argon2id against known answers.
 * Argon2id vector: RFC 9106 section 5.3. */
#include <stdio.h>
#include <string.h>
#include "argon2id.h"
#include "blake2/blake2.h"

static int hexcmp(const uint8_t *got, const char *hex, size_t n)
{
    size_t i;
    for (i = 0; i < n; i++) {
        char b[3];
        snprintf(b, sizeof(b), "%02x", got[i]);
        if (hex[2*i] != b[0] || hex[2*i+1] != b[1]) return 1;
    }
    return 0;
}

int main(void)
{
    uint8_t out[64], pwd[32], salt[16], secret[8], ad[12];
    int fail = 0;

    /* BLAKE2b-512("abc") from RFC 7693 appendix A */
    blake2b(out, 64, "abc", 3, NULL, 0);
    if (hexcmp(out, "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1"
                    "7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923", 64)) {
        printf("BLAKE2b: FAIL\n"); fail = 1;
    } else printf("BLAKE2b: ok\n");

    memset(pwd, 0x01, sizeof(pwd));
    memset(salt, 0x02, sizeof(salt));
    memset(secret, 0x03, sizeof(secret));
    memset(ad, 0x04, sizeof(ad));
    if (a2id_derive(3, 32, 4, pwd, 32, salt, 16, secret, 8, ad, 12, out, 32) != 0 ||
        hexcmp(out, "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659", 32)) {
        printf("Argon2id RFC 9106 vector: FAIL\n"); fail = 1;
    } else printf("Argon2id RFC 9106 vector: ok\n");

    return fail;
}
