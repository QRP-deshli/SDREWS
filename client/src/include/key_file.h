// Client                         //
// Master key loading             //
// University Work Project        //
// Technical University of Kosice //
// Nikita Kuropatkin              //

#ifndef KEY_FILE_H
#define KEY_FILE_H

#include <stddef.h>
#include <stdint.h>

#define MASTER_KEY_SIZE     16U
#define MASTER_KEY_NAME     "MASTER_KEY"
#define KEY_FILE_DEFAULT    "master_key.enc"     // PIN-protected key file made by keywrap
#define KEY_FILE_LEGACY     "master_key.h"       // Old plain-text file made by keygen.sh / keygen.bat (fallback, warns)
#define KEY_FILE_ENV        "MASTER_KEY_FILE"    // Environment variable that overrides the path

/*
 * Reads the byte array called `name` from a header file such as
 *     const uint8_t MASTER_KEY[] = { 0x11, 0x22, ... };
 * into `out`. The array must have exactly `count` bytes, written as 0xNN.
 * Returns OK, ERROR_OPENING_FILE or WRONG_TXT_FORMAT (error.h).
 */
int key_file_load(const char *path, const char *name, uint8_t *out, size_t count);

#endif // KEY_FILE_H
