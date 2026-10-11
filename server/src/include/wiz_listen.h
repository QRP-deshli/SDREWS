// Server                         //
// Race-free LISTEN for the W6100 //
// University Work Project        //
// Technical University of Kosice //
// Nikita Kuropatkin              //

#ifndef WIZ_LISTEN_H
#define WIZ_LISTEN_H

#include <stdint.h>
#include "pico/stdlib.h"
#include "socket.h"

/*
 * Drop-in replacement for the ioLibrary listen().
 *
 * listen() sends the LISTEN command, waits for the command register to clear
 * and then reads Sn_SR ONCE. If the chip has not yet moved INIT -> LISTEN at
 * that instant (it needs a few microseconds), listen() closes the socket and
 * returns SOCKERR_SOCKCLOSED (-4). The caller then has to re-open it, so the
 * port keeps flickering between "listening" and "closed" - and a browser or
 * client that connects in a "closed" moment is refused. With the faster main
 * loop this happened constantly.
 *
 * Here we wait (max ~2 ms) until the chip leaves INIT. LISTEN, or a state that
 * can only follow it (SYNRECV / ESTABLISHED, when a client connected within
 * those microseconds), counts as success.
 */
static inline int8_t wiz_listen_robust(uint8_t sk)
{
    if (getSn_SR(sk) != SOCK_INIT) {
        return SOCKERR_SOCKINIT;
    }
    setSn_CR(sk, Sn_CR_LISTEN);
    while (getSn_CR(sk)) {
        /* command accepted when the register clears */
    }
    for (uint32_t i = 0; i < 200; i++) {
        uint8_t sr = getSn_SR(sk);
        if (sr != SOCK_INIT) {
            return (sr == SOCK_CLOSED) ? SOCKERR_SOCKCLOSED : SOCK_OK;
        }
        sleep_us(10);
    }
    close(sk);
    return SOCKERR_SOCKCLOSED;
}

#endif /* WIZ_LISTEN_H */
