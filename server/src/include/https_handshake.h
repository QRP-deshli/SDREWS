// SERVER                         //
// Netdata functions              //
// Ver. 0.6                       //
// University Work Project        //
// Technical University of Kosice //
// 22.3.2026                      //
// Nikita Kuropatkin              //

#ifndef HTTPS_HANDSHAKE_H
#define HTTPS_HANDSHAKE_H

#include <stdint.h>

// 1. One-time Initialization: sets up mbedTLS config/cert/key and one TLS
//    session context per socket (0..MAX_SOCKETS-1).
void https_init_system(void);

// 2. The polling logic — call once per poll tick for EACH socket sk in
//    0..MAX_SOCKETS-1 while current_port_mode == PORT_MODE_HTTPS.
//    (Previously this took no argument and only ever drove one fixed
//    socket; TLS now runs on the same 4 sockets the custom protocol uses.)
void https_poll_task(uint8_t sk);

// 3. Hard-resets every HTTPS session and closes sockets 0..MAX_SOCKETS-1.
//    Call this whenever the port mode is switched (entering HTTPS mode, or
//    reverting back to the custom protocol after the dead timer expires)
//    instead of touching mbedTLS internals directly from the main loop.
void https_force_reset_all(void);

#endif
