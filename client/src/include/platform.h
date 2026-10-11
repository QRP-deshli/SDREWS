// Client                         //
// Small Windows/Linux helpers    //
// University Work Project        //
// Technical University of Kosice //
// Nikita Kuropatkin              //

#ifndef PLATFORM_H
#define PLATFORM_H

#include <stddef.h>
#include <stdint.h>

/* Sleep for the given number of milliseconds. */
void plat_sleep_ms(unsigned ms);

/* Fill buf with n cryptographically secure random bytes. Returns 0 on success. */
int  plat_random(void *buf, size_t n);

/* Overwrite memory in a way the compiler will not optimise away. */
void plat_wipe(void *p, size_t n);

/*
 * Prompts on the terminal and reads one line WITHOUT echo (falls back to a
 * plain line read if stdin is not a terminal). The result is NUL-terminated
 * and stored in buf. Returns its length, or -1 on error / end of input.
 */
int  plat_read_secret(const char *prompt, char *buf, size_t size);

#endif /* PLATFORM_H */
