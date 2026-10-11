// Client                         //
// keywrap: protect master_key.h  //
// University Work Project        //
// Technical University of Kosice //
// Nikita Kuropatkin              //
//
// Turns the plain-text master_key.h into master_key.enc, protected by a PIN
// (Argon2id). Run it once per key, then delete master_key.h.

#include <stdio.h>
#include <string.h>
#include "error.h"
#include "key_file.h"
#include "keywrap.h"
#include "platform.h"

int main(int argc, char *argv[])
{
    const char *in_path  = (argc > 1) ? argv[1] : KEY_FILE_LEGACY;
    const char *out_path = (argc > 2) ? argv[2] : KEY_FILE_DEFAULT;
    uint8_t master[MASTER_KEY_SIZE];
    uint8_t check[MASTER_KEY_SIZE];
    char pin1[KEYWRAP_PIN_MAX], pin2[KEYWRAP_PIN_MAX];
    keywrap_t kw;
    FILE *probe;
    int err;

    if (argc > 3 || (argc > 1 && (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0))) {
        printf("Usage: %s [plain_key_file=%s] [output=%s]\n", argv[0], KEY_FILE_LEGACY, KEY_FILE_DEFAULT);
        return 0;
    }

    probe = fopen(out_path, "rb");
    if (probe != NULL) {
        fclose(probe);
        fprintf(stderr, "%s already exists - move or delete it first (it would be overwritten).\n", out_path);
        return ERROR_OPENING_FILE;
    }

    err = key_file_load(in_path, MASTER_KEY_NAME, master, MASTER_KEY_SIZE);
    if (err != OK) {
        fprintf(stderr, "Cannot read the plain key from %s\n", in_path);
        return err;
    }

    if (plat_read_secret("New PIN / passphrase: ", pin1, sizeof(pin1)) < 0 ||
        plat_read_secret("Repeat it:             ", pin2, sizeof(pin2)) < 0) {
        fprintf(stderr, "No input.\n");
        return ERROR_GETTING_INPUT;
    }
    if (strcmp(pin1, pin2) != 0) {
        fprintf(stderr, "The two entries differ.\n");
        return WRONG_PIN;
    }
    if (strlen(pin1) < KEYWRAP_MIN_PIN_LEN) {
        fprintf(stderr, "Use at least %u characters.\n", KEYWRAP_MIN_PIN_LEN);
        return WRONG_PIN_FORMAT;
    }

    printf("Deriving key (Argon2id, %u MiB, %u passes)...\n",
           KEYWRAP_DEFAULT_M / 1024U, KEYWRAP_DEFAULT_T);
    err = keywrap_encrypt(&kw, master, pin1, KEYWRAP_DEFAULT_M, KEYWRAP_DEFAULT_T, KEYWRAP_DEFAULT_P);
    if (err != OK) {
        fprintf(stderr, "Encryption failed (code %d)\n", err);
        return err;
    }
    err = keywrap_save(out_path, &kw);
    if (err != OK) {
        fprintf(stderr, "Cannot write %s\n", out_path);
        return err;
    }

    /* Read it back and prove the PIN opens it before telling the user to delete the plain file. */
    err = keywrap_load(out_path, &kw);
    if (err == OK) err = keywrap_decrypt(&kw, pin1, check);
    if (err != OK || memcmp(check, master, MASTER_KEY_SIZE) != 0) {
        fprintf(stderr, "Self-check FAILED - keep %s and do not delete it.\n", in_path);
        return (err != OK) ? err : ERROR_PROTOCOL;
    }

    printf("Wrote %s (self-check passed).\n", out_path);
    printf("Now delete the plain-text %s (and any copies / backups of it).\n", in_path);
    plat_wipe(master, sizeof(master));
    plat_wipe(check, sizeof(check));
    plat_wipe(pin1, sizeof(pin1));
    plat_wipe(pin2, sizeof(pin2));
    return OK;
}
