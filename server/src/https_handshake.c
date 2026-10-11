// SERVER                         //
// Netdata functions              //
// Ver. 0.6                       //
// University Work Project        //
// Technical University of Kosice //
// 22.3.2026                      //
// Nikita Kuropatkin              //
//
// CHANGE LOG (Ver 0.6):
// - TLS now runs on SOCKETS 0-3 (same physical sockets the custom anti-DoS
//   protocol uses) instead of being pinned to a single dedicated socket.
//   This lets up to 4 concurrent TLS sessions run in parallel from the
//   whitelisted client, removing the old single-socket bottleneck.
// - Every piece of per-connection TLS state (ssl context, handshake flag,
//   handshake timer, idle timer, response buffers) is now an array indexed
//   by socket number instead of a lone global.
// - The HTTP response send path used to block in a spin loop until the
//   whole page was flushed. With 4 sockets running through the same poll
//   loop that would let one slow/stalled client starve the other three, so
//   it is now a small per-session state machine: build the response once,
//   then hand a chunk of it to mbedtls_ssl_write() per poll tick and return
//   immediately on MBEDTLS_ERR_SSL_WANT_READ/WRITE instead of spinning.
// - Listener lock: once a whitelisted client is ESTABLISHED on one socket, the
//   other sockets are closed and stay closed (no SYN-ACK to anyone else) until
//   no client is connected any more, then all of them listen again.

// mbedTLS
#include "mbedtls/ssl.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/pk.h"

#include "certs.h"
#include "mbedtls/platform_util.h"
#include "error.h"
#include "otp/otp_keys.h"
#include "page.h"
#include "pico/rand.h"
#include "port_common.h"
#include "socket.h"
#include "wizchip_spi.h"
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include "parameters.h"
#include <stdio.h>
#include "debug.h"
#include "wiz_listen.h"
#include "sntp.h"
#include "sntp_time.h"
#include "https_handshake.h"

// External global variables
extern port_mode_t current_port_mode;
uint8_t https_client_ip[4] = {0};
extern stats_tracker_t hourly_stats;
extern volatile datetime g_current_time;
extern volatile uint32_t g_uptime_sec;

// Sensor measurements values, defined in sensor_data.c
extern volatile float g_sensor_temp;
extern volatile int   g_sensor_co2;
extern volatile float g_sensor_pm1;
extern volatile float g_sensor_pm2p5;

// Shared "any HTTPS traffic happened" timestamp, used by the main loop's
// global 30s dead-timer (see slehs.c) to decide when to revert the whole
// port back to the custom protocol. Each session ALSO keeps its own
// last_activity below for its individual 35s idle-close timeout.
extern absolute_time_t https_last_activity;

// mbedTLS shared config/credentials — one ssl_config + one cert/key pair is
// safely reused across multiple mbedtls_ssl_context instances as long as it
// is not mutated after setup, so these stay singular.
mbedtls_ssl_config conf;
mbedtls_ctr_drbg_context ctr_drbg;
mbedtls_x509_crt srvcert;
mbedtls_pk_context pkey;

// Idle timeout — must be longer than Keep-Alive timeout sent to browser
// AND shorter than the global dead timer in slehs.c (SEC(180)/3min), so a
// single stale connection gets recycled before the whole port reverts to
// stealth mode.
//
// page.h polls every 10s in the foreground; Chrome's background-tab timer
// throttling stretches that to roughly once/minute when hidden (confirmed
// empirically — see the earlier ~60s idle-close cadence in testing). 90s
// comfortably covers that with margin. This no longer needs to be
// generous enough to also cover "tab actually closed" — page.h now sends
// a pagehide -> navigator.sendBeacon('/close') signal on real teardown
// (handled below, search "POST /close"), so a genuine close is detected
// in well under a second regardless of this timeout.
#define HTTPS_IDLE_TIMEOUT_US  90000000ULL   // 90 s

// Max time a single TLS handshake may take before the socket is dropped.
// Was 15 s. A software handshake on the Pico takes well under a second, so
// 5 s still leaves ample margin and frees a stalled socket 3x sooner.
#define HTTPS_HANDSHAKE_TIMEOUT_US  5000000ULL   // 5 s

// Number of parallel TLS sessions == number of sockets we now serve HTTPS on
#define HTTPS_SESSIONS  MAX_SOCKETS

/* ============================================================
 * PER-SOCKET TLS SESSION STATE
 * ============================================================
 * One of these per socket (0..MAX_SOCKETS-1). Replaces what used to be a
 * handful of file-scope globals/statics that only supported one connection.
 * ============================================================ */
typedef struct {
    mbedtls_ssl_context ssl;
    int             sock_id;        // == array index; address of this is the mbedTLS BIO ctx
    bool            handshake_done;
    uint64_t        hs_start_us;
    absolute_time_t last_activity;  // per-connection idle timer (35s)

    // Deferred / non-blocking response write state
    bool     tx_pending;
    uint16_t tx_len;
    uint16_t tx_written;
    char     tx_buf[ETHERNET_BUF_MAX_SIZE * 2 + 128];

    // Scratch buffers for the in-progress request/response (per-session so
    // concurrent sockets never share/clobber each other's buffers)
    unsigned char rx_buf[2048];       // GET requests are tiny; 2KB is generous
    char          html_body[ETHERNET_BUF_MAX_SIZE * 2];
} https_sess_t;

static https_sess_t https_sess[HTTPS_SESSIONS];

// true while socket i holds an ESTABLISHED connection from the whitelisted
// client. While any entry is true the other sockets are not allowed to listen.
static bool https_owner[HTTPS_SESSIONS];

// Helper: returns true for any error code that means "peer closed cleanly"
// (or is effectively equivalent to that for our purposes).
// -0x7780 = CONN_EOF, -0x7708 = PEER_CLOSE_NOTIFY
// Also catches -0x7900 (FATAL_ALERT) which Chrome sends on self-signed cert
// rejection — we don't want that to close the socket permanently either.
//
// -0x6C00 (MBEDTLS_ERR_SSL_INTERNAL_ERROR) is included too: in this codebase
// it is ONLY ever produced by our own tls_recv()/tls_send() callbacks below,
// as their fallback when recv()/send() return <=0 while the WIZnet socket
// hasn't yet reported SOCK_CLOSE_WAIT/SOCK_CLOSED (a brief timing gap while
// an abrupt peer disconnect — e.g. Chrome killing a speculative extra
// connection — is still propagating through the socket state machine). It
// is NOT a genuine mbedTLS internal-invariant failure here, so treating it
// as fatal was forcing an unnecessary close(sk) + full TCP re-handshake
// (CLOSED -> LISTEN -> new SYN) instead of the cheaper TLS-only soft reset
// that the other three codes already get. That re-handshake window is
// exactly the kind of churn you don't want an attacker able to induce, so
// this is now handled the same as a clean peer close.
static inline bool tls_is_soft_close(int ret) {
    return (ret == MBEDTLS_ERR_SSL_CONN_EOF           ||  // -0x7280
            ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY  ||  // -0x7880
            ret == MBEDTLS_ERR_SSL_FATAL_ALERT_MESSAGE|| 
            ret == MBEDTLS_ERR_SSL_INTERNAL_ERROR     ||  // -0x6C00, see above
            ret == 0);
}


psa_status_t mbedtls_psa_external_get_random(mbedtls_psa_external_random_context_t *ctx,
                                              uint8_t *output, size_t output_size,
                                              size_t *output_length) {
    (void)ctx;
    size_t i = 0;
    while (i < output_size) {
        uint64_t r = get_rand_64();
        size_t chunk = (output_size - i) < 8 ? (output_size - i) : 8;
        memcpy(output + i, &r, chunk);
        i += chunk;
    }
    *output_length = output_size;
    return PSA_SUCCESS;
}

/*
 * Function: tls_recv
 * Description: mbedTLS RX callback — bridges mbedTLS with the WIZnet socket layer.
 *              ctx is the address of that session's sock_id (int), NOT a fixed socket.
 */
static int tls_recv(void *ctx, unsigned char *buf, size_t len) {
    int sock = *(int *)ctx;

    uint16_t rx_len = getSn_RX_RSR(sock);
    if (rx_len == 0) {
        uint8_t sr = getSn_SR(sock);
        if (sr == SOCK_CLOSE_WAIT || sr == SOCK_CLOSED) {
            return MBEDTLS_ERR_SSL_CONN_EOF;
        }
        return MBEDTLS_ERR_SSL_WANT_READ;
    }

    if (len > rx_len) {
        len = rx_len;
    }

    int32_t recvd = recv(sock, (uint8_t *)buf, (uint16_t)len);
    if (recvd > 0) {
        return recvd;
    }

    return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
}

/*
 * Function: tls_send
 * Description: mbedTLS TX callback — bridges mbedTLS with the WIZnet socket layer.
 */
static int tls_send(void *ctx, const unsigned char *buf, size_t len) {
    int sock = *(int *)ctx;

    uint16_t tx_free = getSn_TX_FSR(sock);
    if (tx_free == 0) {
        uint8_t sr = getSn_SR(sock);
        if (sr == SOCK_CLOSE_WAIT || sr == SOCK_CLOSED) {
            return MBEDTLS_ERR_SSL_CONN_EOF;
        }
        return MBEDTLS_ERR_SSL_WANT_WRITE;
    }

    if (len > tx_free) {
        len = tx_free;
    }

    int32_t sent = send(sock, (uint8_t *)buf, (uint16_t)len);
    if (sent > 0) {
        return sent;
    }

    return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
}

/*
 * Function: pico_entropy
 * Description: Hardware entropy source for mbedTLS using the Pico's built-in RNG.
 */
static int pico_entropy(void *data, unsigned char *output, size_t len)
{
    (void)data;
    size_t i = 0;
    while (i < len) {
        uint64_t r = get_rand_64();
        size_t chunk;
        if ((len - i) < 8) {
            chunk = len - i;
        } else {
            chunk = 8;
        }
        memcpy(output + i, &r, chunk);
        i += chunk;
    }
    return 0;
}

/*
 * Function: tls_soft_reset
 * Description: Resets one socket's mbedTLS session state without touching
 *              the TCP socket. Call this whenever Chrome closes the TLS
 *              layer but TCP stays up.
 */
static void tls_soft_reset(uint8_t sk) {
    https_sess_t *s = &https_sess[sk];
    mbedtls_ssl_session_reset(&s->ssl);
    // Re-register BIO — session_reset() clears it in mbedTLS 2.x
    mbedtls_ssl_set_bio(&s->ssl, &s->sock_id, tls_send, tls_recv, NULL);
    s->handshake_done = false;
    s->hs_start_us     = 0;
    s->tx_pending       = false;
}

/*
 * Function: tls_soft_reset_if_dirty
 * Description: Same as tls_soft_reset(), but skipped when no TLS activity has
 *              happened on this socket since its last reset. mbedtls_ssl_
 *              session_reset() frees and re-allocates the handshake
 *              structures, which is wasteful to do for every junk SYN a
 *              non-whitelisted host throws at us during a flood (the TLS
 *              layer of that socket was never touched in the first place).
 */
static void tls_soft_reset_if_dirty(uint8_t sk) {
    https_sess_t *s = &https_sess[sk];
    if (s->handshake_done || s->hs_start_us != 0 || s->tx_pending) {
        tls_soft_reset(sk);
    }
}

/*
 * Function: https_has_owner
 * Description: true if a whitelisted client is currently connected.
 */
static bool https_has_owner(void) {
    for (int i = 0; i < HTTPS_SESSIONS; i++) {
        if (https_owner[i]) {
            return true;
        }
    }
    return false;
}

/*
 * Function: https_close_listeners
 * Description: Closes every socket that is only waiting for a client
 *              (INIT / LISTEN / SYNRECV). Sockets that already hold a
 *              connection are left alone. Called once a client got connected.
 */
static void https_close_listeners(void) {
    for (uint8_t i = 0; i < HTTPS_SESSIONS; i++) {
        if (https_owner[i]) {
            continue;
        }
        uint8_t sr = getSn_SR(i);
        if (sr == SOCK_INIT || sr == SOCK_LISTEN || sr == SOCK_SYNRECV) {
            close(i);
            tls_soft_reset_if_dirty(i);
        }
    }
}

/*
 * Function: https_force_reset_all
 * Description: Hard-resets every HTTPS session and closes every socket
 *              0..MAX_SOCKETS-1. Called by the main loop whenever the port
 *              mode is switched (either freshly entering HTTPS mode, or
 *              reverting back to the custom protocol after the dead timer).
 */
void https_force_reset_all(void) {
    for (int i = 0; i < HTTPS_SESSIONS; i++) {
        close(i);
        tls_soft_reset((uint8_t)i);
        https_owner[i] = false;
    }
}

/*
 * Function: https_init_system
 * Description: One-time initialisation of mbedTLS structures, certificates,
 *              keys, and all HTTPS_SESSIONS per-socket TLS session contexts.
 */
void https_init_system() {
    uint8_t key_der[OTP_TLS_DER_BYTES];
    int key_ret;

    mbedtls_ssl_config_init(&conf);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_x509_crt_init(&srvcert);
    mbedtls_pk_init(&pkey);

    mbedtls_ctr_drbg_seed(&ctr_drbg, pico_entropy, NULL,
                           (const unsigned char *)"wiznet-srv", 10);
    mbedtls_x509_crt_parse(&srvcert,
                            (const unsigned char *)srv_crt_pem,
                            sizeof(srv_crt_pem));

    // Private key comes from OTP, only lives in RAM during parsing
    if (!otp_tls_key_der(key_der)) {
        exit_with_error(ERROR_OTP_KEYS, "TLS key read from OTP failed");
    }
    key_ret = mbedtls_pk_parse_key(&pkey, key_der, sizeof(key_der),
                                   NULL, 0, pico_entropy, &ctr_drbg);
    mbedtls_platform_zeroize(key_der, sizeof(key_der));
    if (key_ret != 0) {
        exit_with_error(ERROR_OTP_KEYS, "TLS key parse failed");
    }

    mbedtls_ssl_config_defaults(&conf,
                                 MBEDTLS_SSL_IS_SERVER,
                                 MBEDTLS_SSL_TRANSPORT_STREAM,
                                 MBEDTLS_SSL_PRESET_DEFAULT);

    // --- Key exchange: X25519 only -----------------------------------
    static const uint16_t groups[] = {
        MBEDTLS_SSL_IANA_TLS_GROUP_X25519,
        0   // zero-terminated
    };
    mbedtls_ssl_conf_groups(&conf, groups);

    static const int ciphersuites[] = {
    MBEDTLS_TLS1_3_CHACHA20_POLY1305_SHA256,   // 0x1303 — the correct TLS 1.3 ID
    0
    };
    mbedtls_ssl_conf_ciphersuites(&conf, ciphersuites);

    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
    mbedtls_ssl_conf_own_cert(&conf, &srvcert, &pkey);

    // One mbedtls_ssl_context PER SOCKET — each carries its own TLS state
    // (keys, sequence numbers, handshake progress) but all share `conf`.
    for (int i = 0; i < HTTPS_SESSIONS; i++) {
        https_sess_t *s = &https_sess[i];
        memset(s, 0, sizeof(*s));
        mbedtls_ssl_init(&s->ssl);
        mbedtls_ssl_setup(&s->ssl, &conf);
        s->sock_id = i;
        mbedtls_ssl_set_bio(&s->ssl, &s->sock_id, tls_send, tls_recv, NULL);
        s->handshake_done = false;
        s->last_activity  = get_absolute_time();
    }
}

/*
 * Function: https_try_flush
 * Description: Sends up to one mbedtls_ssl_write()'s worth of the pending
 *              response for socket sk. Non-blocking: returns immediately on
 *              MBEDTLS_ERR_SSL_WANT_READ/WRITE instead of spinning, so a slow
 *              client on one socket never delays the other three.
 * Returns: true if the caller should keep going this tick (nothing pending,
 *          or the whole response just finished sending); false if it should
 *          return out of https_poll_task for this tick (write still pending
 *          or a fatal/soft-close error occurred, which this function already
 *          handles by tearing the session down).
 */
static bool https_try_flush(uint8_t sk) {
    https_sess_t *s = &https_sess[sk];
    if (!s->tx_pending) {
        return true;
    }

    int ret = mbedtls_ssl_write(&s->ssl,
                                 (const unsigned char *)(s->tx_buf + s->tx_written),
                                 s->tx_len - s->tx_written);

    if (ret > 0) {
        s->tx_written += (uint16_t)ret;
        if (s->tx_written >= s->tx_len) {
            s->tx_pending = false;      // done — free to read the next request
        }
        return false; // yield this tick either way; resume next poll if not done
    }

    if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
        return false; // socket TX buffer full for now — try again next tick
    }

    // Fatal or soft-close mid-response: tear this session down.
    if (tls_is_soft_close(ret)) {
        async_print("Socket %d: HTTPS write soft-close: -0x%04X\n", sk, -ret);
    } else {
        char err_buf[80];
        mbedtls_strerror(ret, err_buf, sizeof(err_buf));
        async_print("Socket %d: HTTPS write fatal: -0x%04X %s\n", sk, -ret, err_buf);
    }
    close(sk);
    tls_soft_reset(sk);
    return false;
}

/*
 * Function: https_poll_task
 * Description: Non-blocking polling loop for one HTTPS socket's state
 *              transitions. Call this once per poll tick for EACH socket in
 *              0..MAX_SOCKETS-1 (see slehs.c main loop) while
 *              current_port_mode == PORT_MODE_HTTPS.
 *
 *   CLOSED      → open socket, listen
 *   CLOSE_WAIT  → send TLS close_notify, disconnect (→ CLOSED next poll)
 *   ESTABLISHED + pending write   → flush a chunk (non-blocking)
 *   ESTABLISHED + no handshake    → TLS handshake
 *   ESTABLISHED + handshake OK    → read request, build response
 *
 * Chrome behaviour: it sends close_notify (or just TCP FIN) between every
 * auto-refresh even on keep-alive connections. We handle this by doing a
 * TLS soft-reset (session_reset + re-register BIO) WITHOUT closing the TCP
 * socket, so the re-handshake starts immediately on the next poll tick and
 * the port is never left unguarded.
 */
void https_poll_task(uint8_t sk) {
    if (current_port_mode != PORT_MODE_HTTPS) {
        return;
    }

    https_sess_t *s = &https_sess[sk];
    int ret;
    uint8_t dip[4];

    uint8_t sr = getSn_SR(sk);

    if (sr != SOCK_ESTABLISHED) {
        https_owner[sk] = false;
    }

    // ── CLOSED: open socket and start listening ───────────────────────────────
    if (sr == SOCK_CLOSED) {
        s->handshake_done = false;
        if (https_has_owner()) {
            return;   // a client is connected: stay closed, answer no SYN
        }
        int8_t so = socket(sk, Sn_MR_TCP, HTTPS_PORT, 0);
        int8_t lr = wiz_listen_robust(sk);
        if (so != (int8_t)sk || lr != SOCK_OK) {
            // Rare diagnostic that stays on with DEBUG_LOG 0: a socket that cannot listen = "connection refused"
            static uint32_t last_report_ms = 0;
            uint32_t now_ms = to_ms_since_boot(get_absolute_time());
            if (now_ms - last_report_ms > 1000) {
                last_report_ms = now_ms;
                printf("[https] socket %d open/listen failed (socket=%d listen=%d)\n", sk, (int)so, (int)lr);
            }
        }
        return;   // (no sleep here: under a SYN flood sockets are re-opened constantly)
    }

    if (sr == SOCK_SYNRECV) {
            getSn_DIPR(sk, dip); 

            // STRICT WHITELIST FILTER: If the IP doesn't match the allowed client, kill it instantly
            if (memcmp(dip, https_client_ip, 4) != 0) {
                close(sk);
                async_print("SECURITY: Unauthorized IP %d.%d.%d.%d dropped instantly in HTTPS SYNRECV (sock %d)\n",
                            dip[0], dip[1], dip[2], dip[3], sk);
                
                // (no disconnect(): the socket is already closed, and
                // disconnect() is a blocking call)
                tls_soft_reset_if_dirty(sk);
                return;
            }
            return;
        }

    // ── CLOSE_WAIT: browser sent TCP FIN (tab closed, navigated away, etc.) ──
    if (sr == SOCK_CLOSE_WAIT) {
        mbedtls_ssl_close_notify(&s->ssl);   // best-effort; ignore return value
        disconnect(sk);
        tls_soft_reset(sk);
        // Socket → CLOSED on next poll, which reopens and listens immediately
        return;
    }

    // ── Any transient state (LISTEN, SYN_RECV, TIME_WAIT…): just wait ────────
    if (sr != SOCK_ESTABLISHED) {
        return;
    }

    // ── ESTABLISHED ───────────────────────────────────────────────────────────

    // --- IP whitelist: drop anyone who isn't the authorised client ------------
    getSn_DIPR(sk, dip);
    if (memcmp(dip, https_client_ip, 4) != 0) {
        async_print("Socket %d: HTTPS rejected non-whitelisted client\n", sk);
        // close(), not disconnect(): disconnect() blocks the whole poll loop
        // (up to the chip's retransmit timeout) waiting for the peer's FIN/ACK,
        // which a hostile peer will never send.
        close(sk);
        tls_soft_reset_if_dirty(sk);
        return;
    }

    if (!https_owner[sk]) {
        https_owner[sk] = true;
        https_close_listeners();
    }

    // --- Idle timeout: release stale sessions so the slot never locks up ------
    if (s->handshake_done) {
        if (absolute_time_diff_us(s->last_activity, get_absolute_time())
                > HTTPS_IDLE_TIMEOUT_US) {
            async_print("Socket %d: HTTPS idle timeout — closing session\n", sk);
            mbedtls_ssl_close_notify(&s->ssl);
            disconnect(sk);
            tls_soft_reset(sk);
            return;
        }
    }

    // --- Finish any response still being flushed before doing anything else ---
    if (!https_try_flush(sk)) {
        return;
    }

    // --- TLS Handshake — runs once per TCP connection (or after soft-reset) ---
    if (!s->handshake_done) {

        // Guard: if TCP is already tearing down don't even try
        uint8_t cur_sr = getSn_SR(sk);
        if (cur_sr == SOCK_CLOSE_WAIT || cur_sr == SOCK_CLOSED) {
            tls_soft_reset(sk);
            return;
        }

        if (s->hs_start_us == 0) {
            s->hs_start_us = to_us_since_boot(get_absolute_time());
        }

        while ((ret = mbedtls_ssl_handshake(&s->ssl)) != 0) {

            uint64_t elapsed_us = to_us_since_boot(get_absolute_time()) - s->hs_start_us;

            // Timeout guard — revert to stealth if handshake takes too long
            if (elapsed_us > HTTPS_HANDSHAKE_TIMEOUT_US) {
                async_print("Socket %d: HTTPS handshake timeout\n", sk);
                close(sk);
                tls_soft_reset(sk);
                return;
            }

            if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
                // Not enough data yet — yield and come back next poll tick
                // (do NOT tight_loop here; that starves the other sockets)
                return;
            }

            // Anything else is either a soft peer-close or a real fatal error
            if (tls_is_soft_close(ret)) {
                // Chrome closed before we finished — soft-reset and wait for
                // the CLOSE_WAIT branch to cycle the TCP socket
                async_print("Socket %d: HTTPS handshake soft-close: -0x%04X\n", sk, -ret);
                tls_soft_reset(sk);
                return;
            }

            // Genuine fatal handshake error — log it and hard-close
            char err_buf[80];
            mbedtls_strerror(ret, err_buf, sizeof(err_buf));
            async_print("Socket %d: HTTPS handshake fatal: -0x%04X %s\n", sk, -ret, err_buf);
            close(sk);
            tls_soft_reset(sk);
            return;
        }

        s->handshake_done = true;
        s->hs_start_us    = 0;
        s->last_activity  = get_absolute_time();
        https_last_activity = get_absolute_time();
        async_print("Socket %d: HTTPS handshake OK — persistent session established\n", sk);
    }

    // --- Non-blocking read: bail out if no HTTP request has arrived yet -------
    ret = mbedtls_ssl_read(&s->ssl, s->rx_buf, sizeof(s->rx_buf) - 1);

    if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
        return;  // Nothing ready — come back on next poll tick
    }

    if (tls_is_soft_close(ret)) {
        // Chrome closed the TLS layer (close_notify or clean EOF).
        // Reply with our own close_notify, soft-reset TLS, keep TCP alive.
        // The next poll tick immediately re-enters the handshake block.
        async_print("Socket %d: HTTPS read soft-close: -0x%04X\n", sk, -ret);
        mbedtls_ssl_close_notify(&s->ssl);
        tls_soft_reset(sk);
        return;
    }

    if (ret < 0) {
        // Genuine fatal read error — hard-close everything
        char err_buf[80];
        mbedtls_strerror(ret, err_buf, sizeof(err_buf));
        async_print("Socket %d: HTTPS read fatal: -0x%04X %s\n", sk, -ret, err_buf);
        close(sk);
        tls_soft_reset(sk);
        return;
    }

    // --- Explicit "I'm leaving" signal (see the pagehide/sendBeacon JS in
    // page.h) — handle this BEFORE building the normal page response.
    // Previously this only tore down THIS ONE socket's session and left
    // current_port_mode untouched, relying on the passive global dead-timer
    // to eventually revert the whole port. That's fragile: if ANYTHING else
    // touches one of the other 3 sockets in the meantime (Chrome's own
    // connection-pool preconnects, a stray reconnect attempt, etc.), the
    // dead-timer keeps getting pushed out and the port can stay in HTTPS
    // mode indefinitely even though we were explicitly told the user left.
    // A confirmed close signal is unambiguous, so act on it immediately
    // instead of waiting on inferred inactivity: revert the ENTIRE port
    // back to the custom protocol right now, not just this one socket.
    s->rx_buf[ret < (int)sizeof(s->rx_buf) - 1 ? ret : (int)sizeof(s->rx_buf) - 1] = '\0';
    if (ret >= 11 && memcmp(s->rx_buf, "POST /close", 11) == 0) {
        async_print("Socket %d: client signaled tab close — reverting to Stealth Mode immediately\n", sk);
        static const char close_resp[] =
            "HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n";
        // Best-effort single write — sendBeacon() doesn't wait on/read the
        // response body anyway, so no need for the tx_pending state machine.
        mbedtls_ssl_write(&s->ssl, (const unsigned char *)close_resp, sizeof(close_resp) - 1);
        mbedtls_ssl_close_notify(&s->ssl);
        disconnect(sk);
        current_port_mode = PORT_MODE_CUSTOM;
        https_force_reset_all();   // closes + resets ALL 4 sockets, not just this one
        return;
    }

    // --- Request received: format uptime string -------------------------------
    uint32_t ud = g_uptime_sec / 86400;
    uint32_t uh = (g_uptime_sec % 86400) / 3600;
    uint32_t um = (g_uptime_sec % 3600) / 60;
    uint32_t us = g_uptime_sec % 60;

    char uptime_str[32];
    if (ud > 0)
        snprintf(uptime_str, sizeof(uptime_str), "%ud %02u:%02u:%02u", ud, uh, um, us);
    else
        snprintf(uptime_str, sizeof(uptime_str), "%02u:%02u:%02u", uh, um, us);

    // --- Format device IP string ----------------------------------------------
    uint8_t my_ip[4];
    getSIPR(my_ip);
    char ip_str[16];
    snprintf(ip_str, sizeof(ip_str), "%d.%d.%d.%d",
             my_ip[0], my_ip[1], my_ip[2], my_ip[3]);

    uint8_t max_socks_last_hour = hourly_stats.peak_sockets_last;

    // --- Build HTML body so Content-Length can be calculated exactly ----------
    snprintf(s->html_body, sizeof(s->html_body), html_page_template,
             g_current_time.yy, g_current_time.mo, g_current_time.dd,
             g_current_time.hh, g_current_time.mm, g_current_time.ss,
             uptime_str, max_socks_last_hour,
             g_sensor_temp, g_sensor_co2, g_sensor_pm1, g_sensor_pm2p5,
             ip_str);

    int body_len = strlen(s->html_body);

    // --- Prepend HTTP headers with exact Content-Length -----------------------
    int header_len = snprintf(s->tx_buf, sizeof(s->tx_buf),
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: %d\r\n"
        "Connection: keep-alive\r\n"
        "Keep-Alive: timeout=30, max=100\r\n\r\n",
        body_len);

    memcpy(s->tx_buf + header_len, s->html_body, body_len);

    // --- Hand off to the non-blocking flush state machine ----------------------
    s->tx_len     = (uint16_t)(header_len + body_len);
    s->tx_written = 0;
    s->tx_pending = true;
    https_try_flush(sk);   // best-effort: send what we can this tick

    // Session stays open — browser reuses the TLS connection on next refresh
    s->last_activity     = get_absolute_time();
    https_last_activity   = get_absolute_time();
}