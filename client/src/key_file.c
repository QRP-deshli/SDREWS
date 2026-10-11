// Client                         //
// Master key loading             //
// University Work Project        //
// Technical University of Kosice //
// Nikita Kuropatkin              //

#include <ctype.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "key_file.h"
#include "error.h"

#define KEY_FILE_MAX        4096U
#define HEX_DIGITS          2U
#define HEX_BYTE_CHARS      4U     // "0xNN"
#define HEX_BASE            16

static bool is_all_zero(const uint8_t *data, size_t count)
{
    size_t i;

    for (i = 0; i < count; i++) {
        if (data[i] != 0U) {
            return false;
        }
    }
    return true;
}

// Finds the first `name` that is followed by '{' before any ';' and returns the position after '{'
static const char *find_array_body(const char *text, const char *name)
{
    const char *p = text;
    const char *q;

    for (;;) {
        p = strstr(p, name);
        if (p == NULL) {
            return NULL;
        }
        p += strlen(name);
        q = p;
        while (*q != '\0' && *q != '{' && *q != ';') {
            q++;
        }
        if (*q == '{') {
            return q + 1;
        }
    }
}

static bool parse_array(const char *text, const char *name, uint8_t *out, size_t count)
{
    const char *q = find_array_body(text, name);
    char digits[HEX_DIGITS + 1U];
    size_t n = 0;

    if (q == NULL) {
        fprintf(stderr, "array %s not found in key file\n", name);
        return false;
    }
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
            break;
        }
        digits[0] = q[2];
        digits[1] = q[3];
        digits[2] = '\0';
        out[n] = (uint8_t)strtoul(digits, NULL, HEX_BASE);
        n++;
        q += HEX_BYTE_CHARS;
    }
    if (n != count || *q != '}') {
        fprintf(stderr, "%s must have exactly %u bytes\n", name, (unsigned)count);
        return false;
    }
    if (is_all_zero(out, count)) {
        fprintf(stderr, "%s is all zero\n", name);
        return false;
    }
    return true;
}

int key_file_load(const char *path, const char *name, uint8_t *out, size_t count)
{
    char text[KEY_FILE_MAX + 1U];
    FILE *f = fopen(path, "rb");
    size_t len;

    if (f == NULL) {
        fprintf(stderr, "cannot open key file %s\n", path);
        return ERROR_OPENING_FILE;
    }
    len = fread(text, 1U, KEY_FILE_MAX, f);
    fclose(f);
    text[len] = '\0';
    if (!parse_array(text, name, out, count)) {
        return WRONG_TXT_FORMAT;
    }
    return OK;
}
