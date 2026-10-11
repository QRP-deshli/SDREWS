// Client
// Tester for server (batch + modes + "web" auto-retry)
// University Work Project
// Technical University of Kosice
// Nikita Kuropatkin
//
// Usage: client_connect <IP> <basic|stats|web> [batch_runs]
//   web   : keeps retrying (new connection every time) until the server accepts
//           the "web" command, then tells you to open the browser.
// The master key is read from master_key.enc (PIN-protected, see keywrap).

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <time.h>
#include <stdarg.h>
#include <setjmp.h>
#include <stdbool.h>

#ifdef _WIN32
#include <winsock2.h>
#include <windows.h>
#else
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/select.h>
#include <errno.h>
#endif

#include "network.h"
#include "addition.h"
#include "parameters.h"
#include "error.h"
#include "chaskey.h"
#include "key_file.h"
#include "keywrap.h"
#include "platform.h"

#pragma pack(push,1)                   // Force 1-byte alignment (no padding) for network frame
typedef struct {
    uint16_t magic;      // Protocol magic (send/receive) - must match exactly
    uint8_t version;     // Protocol version - must be PROTOCOL_VER
    uint8_t cmd;         // Command type (CMD_INIT, CMD_AUTH, CMD_DATA, CMD_ACK...)
    uint32_t counter;    // Monotonic counter (anti-replay protection)
    uint16_t len;        // Payload length (0 = control frame, no data)
    uint64_t tag;        // 64-bit truncated Chaskey MAC (authenticity + integrity)
    uint8_t data[MAX_PAYLOAD]; // Variable-length payload
} frame_t;
#pragma pack(pop)                      // Restore default alignment

#define MAX_HISTORY_HOURS 337

/* ============================================================
 * BATCH + LOG + ERROR-RECOVERY GLOBALS
 * ------------------------------------------------------------
 * recover_mode : true  -> handle_error() records the message and longjmp()s
 *                         back to try_session() (batch runs, "web" retries)
 *                false -> handle_error() prints and exits
 * g_verbose    : false -> log_printf() stays quiet on the console (used for
 *                         the many failed "web" attempts)
 * g_sock       : socket of the session in progress, so a failed attempt can
 *                always close it (no descriptor leak across retries)
 * ============================================================ */
static bool batch_mode = false;
static int batch_runs = 1;
static jmp_buf jmp_buf_error;
static bool recover_mode = false;
static bool g_verbose = true;
static int g_sock = -1;
static char last_err[160] = "";
static const char *SUCCESS_LOG = "client_success.log";
static const char *ERROR_LOG = "client_errors.log";
static FILE *success_file = NULL;
static FILE *error_file = NULL;

/* ============================================================
 * CRYPTO CONSTANTS & HELPERS (unchanged)
 * ============================================================ */
#define ROTATION_INTERVAL 1024         

static uint8_t MASTER_KEY[MASTER_KEY_SIZE]; // 128-bit master key, loaded from the key file in main()

static const uint8_t SESSION_INFO[] = "CHASKEY-SESSION-KEY"; 
static const uint8_t ROTATION_INFO[] = "CHASKEY-ROTATION-KEY";
static const uint8_t ROTATION_CONST[] = {0x01,0x02,0x03,0x04};

typedef struct {                       // Persistent session state
    uint32_t rx_counter;               // Last received counter (anti-replay)
    uint32_t tx_counter;               // Last sent counter
    uint8_t session_key[16];           // Current derived 128-bit session key
} session_t;
static session_t sess;                 // Global session (reset per run)

static void chaskey_mac_wrapper(
    const uint8_t key_bytes[16],
    const uint8_t *msg, size_t msg_len,
    uint8_t out[16])
{
    uint32_t k[4];
    uint32_t k1[4];
    uint32_t k2[4];
    memcpy(k, key_bytes, 16);
    chaskey_subkeys(k1, k2, k);
    chaskey_mac(out, 16, msg, msg_len, k, k1, k2);
}

void derive_session_key(
    const uint8_t *ikm, size_t ikm_len,
    const uint8_t salt[16],
    const uint8_t *info, size_t info_len,
    uint8_t *okm, size_t okm_len)
{
    uint8_t prk[16];
    uint8_t t[16] = {0};
    uint8_t counter = 1;
    size_t produced = 0;
    chaskey_mac_wrapper(salt, ikm, ikm_len, prk);
    while (produced < okm_len) {
        uint8_t buf[16 + info_len + 1];
        size_t pos = 0;
        memcpy(buf + pos, t, 16); pos += 16;
        if (info_len) {
            memcpy(buf + pos, info, info_len);
            pos += info_len;
        }
        buf[pos++] = counter;
        chaskey_mac_wrapper(prk, buf, pos, t);
        size_t n = (okm_len - produced > 16) ? 16 : (okm_len - produced);
        memcpy(okm + produced, t, n);
        produced += n;
        counter++;
    }
}

static void rotate_session_key(uint8_t new_key[16],
                               const uint8_t current_key[16],
                               uint32_t counter)
{
    if ((counter % ROTATION_INTERVAL) != 0) {
        memcpy(new_key, current_key, 16);
        return;
    }
    uint8_t salt[16];
    uint32_t block_index = counter / ROTATION_INTERVAL;
    memcpy(salt, current_key, 8);
    memcpy(salt + 8, &block_index, 4);
    salt[12] = ROTATION_CONST[0];
    salt[13] = ROTATION_CONST[1];
    salt[14] = ROTATION_CONST[2];
    salt[15] = ROTATION_CONST[3];
    derive_session_key(current_key, 16, salt, ROTATION_INFO, sizeof(ROTATION_INFO)-1, new_key, 16);
}

static void build_salt_from_nonces(uint32_t n1, uint32_t n2, uint8_t salt[16])
{
    memcpy(salt + 0, &n1, 4);
    memcpy(salt + 4, &n2, 4);
    memcpy(salt + 8, &n1, 4);
    memcpy(salt + 12, &n2, 4);
}

static uint64_t frame_chaskey(frame_t *f, const uint8_t *key)
{
    uint8_t tag128[16];
    uint64_t tag64;
    uint64_t saved;
    size_t mac_len;
    uint32_t k[4];
    uint32_t k1[4];
    uint32_t k2[4];
    saved = f->tag;
    f->tag = 0;
    if (f->len != 0) {
        mac_len = offsetof(frame_t, data) + f->len;
    } else {
        mac_len = offsetof(frame_t, data);
    }
    memcpy(k, key, 16);
    chaskey_subkeys(k1, k2, k);
    chaskey_mac(tag128, 16, (const uint8_t *)f, mac_len, k, k1, k2);
    f->tag = saved;
    memcpy(&tag64, tag128, sizeof(tag64));
    return tag64;
}


static void get_timestamp(char *buf, size_t len) {
    time_t now = time(NULL);
    struct tm *ltm = localtime(&now);
    if (ltm) {
        strftime(buf, len, "%Y-%m-%d %H:%M:%S", ltm);
    } else {
        strncpy(buf, "0000-00-00 00:00:00", len);
    }
}

void log_printf(const char *format, ...) {
    char time_str[64];
    get_timestamp(time_str, sizeof(time_str));
    va_list args;
    if (g_verbose) {
        va_start(args, format);
        vprintf(format, args);
        va_end(args);
    }
    if (batch_mode && success_file) {
        fprintf(success_file, "[%s] ", time_str);
        va_list args2;
        va_start(args2, format);
        vfprintf(success_file, format, args2);
        va_end(args2);
        fflush(success_file);
    }
}

void error_log_printf(const char *format, ...) {
    char time_str[64];
    get_timestamp(time_str, sizeof(time_str));
    va_list args;
    fprintf(stderr, "[%s] ", time_str);
    va_start(args, format);
    vfprintf(stderr, format, args);
    va_end(args);
    if (batch_mode && error_file) {
        fprintf(error_file, "[%s] ", time_str);
        va_list args2;
        va_start(args2, format);
        vfprintf(error_file, format, args2);
        va_end(args2);
        fflush(error_file);
    }
}

static void drop_socket(void) {
    if (g_sock != -1) {
        sockct_cls(g_sock);
        g_sock = -1;
    }
}

void handle_error(int err_code, const char *msg) {
    snprintf(last_err, sizeof(last_err), "%s", msg);
    if (recover_mode) {
        if (batch_mode) {
            error_log_printf("ERROR %d: %s\n", err_code, msg);
        }
        longjmp(jmp_buf_error, 1);
    } else {
        exit_with_error(err_code, msg);
    }
}

/* ============================================================
 * CONNECT WITH TIMEOUT (CLIENT_CONNECT_TIMEOUT_MS)
 * ============================================================ */
static int connect_with_timeout(int sock, const struct sockaddr *addr, socklen_t addrlen, int timeout_ms) {
#ifdef _WIN32
    u_long nonblock = 1;
    if (ioctlsocket(sock, FIONBIO, &nonblock) == SOCKET_ERROR) return -1;
#else
    int flags = fcntl(sock, F_GETFL, 0);
    if (flags == -1) return -1;
    if (fcntl(sock, F_SETFL, flags | O_NONBLOCK) == -1) return -1;
#endif
    int ret = connect(sock, addr, addrlen);
    if (ret != 0) {
#ifdef _WIN32
        if (WSAGetLastError() != WSAEWOULDBLOCK) return -1;
#else
        if (errno != EINPROGRESS) return -1;
#endif
        fd_set writefds, exceptfds;
        FD_ZERO(&writefds);
        FD_ZERO(&exceptfds);
        FD_SET(sock, &writefds);
        FD_SET(sock, &exceptfds);   // Windows reports a refused connect here
        struct timeval tv;
        tv.tv_sec  = timeout_ms / 1000;
        tv.tv_usec = (timeout_ms % 1000) * 1000;
        ret = select(sock + 1, NULL, &writefds, &exceptfds, &tv);
        if (ret <= 0 || !FD_ISSET(sock, &writefds)) return -1;
        int error = 0;
        socklen_t len = sizeof(error);
        if (getsockopt(sock, SOL_SOCKET, SO_ERROR, (char *)&error, &len) < 0 || error != 0) return -1;
    }
#ifdef _WIN32
    nonblock = 0; ioctlsocket(sock, FIONBIO, &nonblock);
#else
    fcntl(sock, F_SETFL, flags);
#endif
    return 0;
}

static int sockct_opn(char *ip) {
    int sockfd;
    struct sockaddr_in servaddr;
    sockfd = (int)socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        handle_error(ERROR_SOCKET_CREATION, "Socket creation failed");
    }
    g_sock = sockfd;
    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = inet_addr(ip);
    servaddr.sin_port = htons(PORT);
    if (connect_with_timeout(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr), CLIENT_CONNECT_TIMEOUT_MS) == RETURN_ERROR) {
        handle_error(ERROR_SOCKET_CREATION, "Connection with the server failed (refused or timed out)");
    }
    log_printf("Connected to the server..\n");
    int one = 1;
    setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, (const char *)&one, sizeof(one));  // INIT must leave immediately
#ifdef _WIN32
    DWORD timeout = CLIENT_IO_TIMEOUT_MS;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));
    setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout, sizeof(timeout));
#else
    struct timeval tv;
    tv.tv_sec  = CLIENT_IO_TIMEOUT_MS / 1000;
    tv.tv_usec = (CLIENT_IO_TIMEOUT_MS % 1000) * 1000;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
    setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv, sizeof(tv));
#endif
    return sockfd;
}

/* Send / receive wrappers: any failure is an error for the caller's recovery logic. */
static void net_fail(int code, const char *what) {
    char msg[sizeof(last_err)];
    snprintf(msg, sizeof(msg), "%s (%s)", what, net_err_reason);
    handle_error(code, msg);
}

static void tx_all(int sockfd, const void *buf, uint32_t n) {
    if (write_win_lin(sockfd, (const uint8_t *)buf, n) != 0) {
        net_fail(ERROR_SENDING_DATA, "Send to server failed");
    }
}

static void rx_header(int sockfd, frame_t *f, const char *what) {
    if (read_win_lin(sockfd, (uint8_t *)f, FRAME_HEADER_SIZE) != 0) {
        net_fail(ERROR_RECEIVING_DATA, what);
    }
}

static void verify_rx(int sockfd, frame_t *rx) {
    if (rx->magic != PROTOCOL_MAGIC_RECEIVE || rx->version != PROTOCOL_VER)
        handle_error(ERROR_PROTOCOL, "Protocol violation");

    if (rx->counter <= sess.rx_counter) {
        handle_error(ERROR_PROTOCOL, "RX counter replay detected");
    }
    
    if (rx->counter > sess.rx_counter + 1) {
        sess.rx_counter = rx->counter - 1; 
    }

    if (rx->cmd == CMD_DATA) {
        if (rx->len > MAX_PAYLOAD)
            handle_error(ERROR_PROTOCOL, "Payload size violation");
        if (read_win_lin(sockfd, rx->data, rx->len) != 0) {
            net_fail(ERROR_RECEIVING_DATA, "Failed to read payload");
        }
    }

    rotate_session_key(sess.session_key, sess.session_key, rx->counter);
    uint64_t expected = frame_chaskey(rx, sess.session_key);
    if (expected != rx->tag) handle_error(ERROR_PROTOCOL, "MAC verification failed");

    sess.rx_counter = rx->counter;
}

static void send_ctrl(int sockfd, uint8_t cmd) {
    frame_t tx = {0};
    tx.magic = PROTOCOL_MAGIC_SEND;
    tx.version = PROTOCOL_VER;
    tx.cmd = cmd;
    tx.counter = ++sess.tx_counter;
    tx.len = 0;
    rotate_session_key(sess.session_key, sess.session_key, tx.counter);
    tx.tag = frame_chaskey(&tx, sess.session_key);
    tx_all(sockfd, &tx, FRAME_HEADER_SIZE);
}

/* Builds and sends one CMD_DATA frame carrying `msg`. */
static void send_data_msg(int sockfd, const char *msg) {
    frame_t tx;
    memset(&tx, 0, sizeof(tx));
    tx.magic = PROTOCOL_MAGIC_SEND;
    tx.version = PROTOCOL_VER;
    tx.cmd = CMD_DATA;
    tx.counter = ++sess.tx_counter;
    tx.len = (uint16_t)strlen(msg);
    memcpy(tx.data, msg, tx.len);
    rotate_session_key(sess.session_key, sess.session_key, tx.counter);
    tx.tag = frame_chaskey(&tx, sess.session_key);
    tx_all(sockfd, &tx, FRAME_HEADER_SIZE + tx.len);
}

/* ============================================================
 * ONE FULL SESSION: INIT -> AUTH -> mode-specific exchange -> close
 * Any failure ends in handle_error().
 * ============================================================ */
static void run_session(char *ip, const char *mode) {
    uint32_t client_nonce;
    frame_t tx, rx;

    sess.rx_counter = 0;           
    sess.tx_counter = 0;
    if (plat_random(&client_nonce, sizeof(client_nonce)) != 0) {
        handle_error(ERROR_GENERATING_RANDOM, "Random generator failed");
    }

    // === CMD_INIT ===
    frame_t tx_init = {0};         
    tx_init.magic = PROTOCOL_MAGIC_SEND;
    tx_init.version = PROTOCOL_VER;
    tx_init.cmd = CMD_INIT;
    tx_init.counter = ++sess.tx_counter;
    tx_init.len = 4;
    memcpy(tx_init.data, &client_nonce, 4); 

    int sockfd = sockct_opn(ip);   
    tx_all(sockfd, &tx_init, FRAME_HEADER_SIZE + 4);
    log_printf("Sent CMD_INIT with Client nonce: 0x%08X\n", client_nonce);

    // === receive server nonce ===
    frame_t rx_init;
    rx_header(sockfd, &rx_init, "Failed to read INIT header");

    if (rx_init.magic != PROTOCOL_MAGIC_RECEIVE || rx_init.version != PROTOCOL_VER ||
        rx_init.cmd != CMD_INIT || rx_init.len != 4)
        handle_error(ERROR_PROTOCOL, "Bad INIT reply from server");

    if (read_win_lin(sockfd, rx_init.data, 4) != 0)
        net_fail(ERROR_RECEIVING_DATA, "Failed to read server nonce");

    uint32_t server_nonce;
    memcpy(&server_nonce, rx_init.data, 4);
    sess.rx_counter = rx_init.counter; 
    log_printf("Received server nonce: 0x%08X\n", server_nonce);

    // === Derive key ===
    uint8_t salt[16];
    build_salt_from_nonces(server_nonce, client_nonce, salt);
    derive_session_key(MASTER_KEY, MASTER_KEY_SIZE, salt, SESSION_INFO, sizeof(SESSION_INFO)-1,
                       sess.session_key, 16);

    // === CMD_AUTH ===
    memset(&tx, 0, sizeof(tx));
    tx.magic = PROTOCOL_MAGIC_SEND;
    tx.version = PROTOCOL_VER;
    tx.cmd = CMD_AUTH;
    tx.counter = ++sess.tx_counter;
    tx.len = 12;   
    uint8_t auth_buf[8];
    memcpy(auth_buf, &server_nonce, 4);
    memcpy(auth_buf + 4, &client_nonce, 4);
    uint8_t auth_tag[16];
    chaskey_mac_wrapper(MASTER_KEY, auth_buf, 8, auth_tag);
    uint64_t nonce_hmac;
    memcpy(&nonce_hmac, auth_tag, 8);
    memcpy(&tx.data[0], &nonce_hmac, 8);
    memcpy(&tx.data[8], &client_nonce, 4);
    tx.tag = frame_chaskey(&tx, sess.session_key);

    tx_all(sockfd, &tx, FRAME_HEADER_SIZE + tx.len);
    log_printf("Sent AUTH with Client Nonce: 0x%08X\n", client_nonce);
    rx_header(sockfd, &rx, "Failed to read AUTH ACK header");
    verify_rx(sockfd, &rx);
    if (rx.cmd != CMD_ACK) handle_error(ERROR_PROTOCOL, "AUTH ACK invalid");
    log_printf("AUTH ACK received. Secure Session Established.\n");

    // ==========================================
    // DYNAMIC MODE BRANCHING (web | stats | basic)
    // ==========================================
    if (strcmp(mode, "web") == 0) {

        log_printf("Sending 'web' signal to trigger HTTPS mode...\n");
        send_data_msg(sockfd, "web");

        rx_header(sockfd, &rx, "Failed to read transition ACK header");
        verify_rx(sockfd, &rx); 
        
        if (rx.cmd == CMD_DATA) {
            log_printf("SERVER CONFIRMATION: %.*s\n", rx.len, rx.data);
        } else if (rx.cmd != CMD_ACK) {
            handle_error(ERROR_PROTOCOL, "Unexpected response from server");
        }

        log_printf("Transition signal accepted. The server is now switching to HTTPS.\n");
        log_printf("Closing custom protocol connection...\n");

    } else if (strcmp(mode, "stats") == 0) {

        send_data_msg(sockfd, "info");
        rx_header(sockfd, &rx, "Failed to read DATA ACK header");
        verify_rx(sockfd, &rx);
        if (rx.cmd != CMD_ACK) handle_error(ERROR_PROTOCOL, "DATA ACK invalid");
        log_printf("Initial DATA ACK received. Waiting for stats stream...\n");

        static char history_buffer[MAX_HISTORY_HOURS][MAX_PAYLOAD]; 
        int total_received = 0;

        log_printf("Receiving history... please wait.\n");

        while (1) {
            rx_header(sockfd, &rx, "Failed to read stream frame");
            verify_rx(sockfd, &rx);

            if (rx.cmd == CMD_ACK) continue; 

            if (rx.cmd != CMD_DATA) handle_error(ERROR_PROTOCOL, "Expected server DATA");
            
            if (rx.len == 3 && strncmp((char*)rx.data, "EOF", 3) == 0) {
                send_ctrl(sockfd, CMD_ACK);
                break; 
            }

            if (total_received < MAX_HISTORY_HOURS) {
                memset(history_buffer[total_received], 0, MAX_PAYLOAD);
                memcpy(history_buffer[total_received], rx.data, rx.len);
                total_received++;
            }
            send_ctrl(sockfd, CMD_ACK); 
        }

        log_printf("--- Historical Stats (Oldest to Newest) ---\n");
        for (int i = 0; i < total_received; i++) {
            log_printf("[%d] %s\n", i + 1, history_buffer[i]);
        }
        log_printf("-------------------------------------------\n");

        send_ctrl(sockfd, CMD_CLOSE);

    } else {
        
        // --- BASIC MODE ---
        send_data_msg(sockfd, "stats");
        rx_header(sockfd, &rx, "Failed to read DATA ACK header");
        verify_rx(sockfd, &rx);
        if (rx.cmd != CMD_ACK) handle_error(ERROR_PROTOCOL, "DATA ACK invalid");
        log_printf("Initial DATA ACK received\n");

        rx_header(sockfd, &rx, "Failed to read server hi message");
        verify_rx(sockfd, &rx);
        if (rx.cmd != CMD_DATA) handle_error(ERROR_PROTOCOL, "Expected server DATA");
        log_printf("Server says: %.*s\n", rx.len, rx.data);
        send_ctrl(sockfd, CMD_ACK);
        
        send_ctrl(sockfd, CMD_CLOSE);
    }

    // === GRACEFUL SHUTDOWN ===
#ifdef _WIN32
    shutdown(sockfd, SD_SEND);      
#else
    shutdown(sockfd, SHUT_WR);
#endif

    uint8_t trash_buf[16];
#ifdef _WIN32
    u_long nonblock = 1;
    ioctlsocket(sockfd, FIONBIO, &nonblock);           
    while (recv(sockfd, (char*)trash_buf, sizeof(trash_buf), 0) > 0);
#else
    int flags = fcntl(sockfd, F_GETFL, 0);
    fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);
    while (read(sockfd, trash_buf, sizeof(trash_buf)) > 0);
#endif
    drop_socket();
    plat_sleep_ms(2);
}

/* Runs one session; returns 0 on success, -1 if it failed (only possible in recover_mode). */
static int try_session(char *ip, const char *mode) {
    if (setjmp(jmp_buf_error) != 0) {
        drop_socket();
        return -1;
    }
    run_session(ip, mode);
    return 0;
}

/* ============================================================
 * MASTER KEY LOADING (PIN-protected file, legacy plain file as fallback)
 * ============================================================ */
#define PIN_TRIES 3

static bool file_exists(const char *path) {
    FILE *f = fopen(path, "rb");
    if (f) { fclose(f); return true; }
    return false;
}

static void load_master_key(void) {
    const char *key_path = getenv(KEY_FILE_ENV);
    int err;

    if (key_path == NULL) {
        key_path = KEY_FILE_DEFAULT;
        if (!file_exists(key_path) && file_exists(KEY_FILE_LEGACY)) {
            key_path = KEY_FILE_LEGACY;
        }
    }

    if (keywrap_is_wrapped_file(key_path)) {
        keywrap_t kw;
        char pin[KEYWRAP_PIN_MAX];
        int tries;

        err = keywrap_load(key_path, &kw);
        if (err != OK) {
            exit_with_error(err, "Key file is damaged");
        }
        for (tries = 1; tries <= PIN_TRIES; tries++) {
            if (plat_read_secret("PIN: ", pin, sizeof(pin)) < 0) {
                exit_with_error(ERROR_GETTING_INPUT, "No PIN entered");
            }
            err = keywrap_decrypt(&kw, pin, MASTER_KEY);
            plat_wipe(pin, sizeof(pin));
            if (err == OK) {
                return;
            }
            if (err != WRONG_PIN) {
                exit_with_error(err, "Cannot unlock the key file");
            }
            fprintf(stderr, "Wrong PIN (%d/%d)\n", tries, PIN_TRIES);
        }
        exit_with_error(WRONG_PIN, "Too many wrong PINs");
    }

    fprintf(stderr, "WARNING: %s holds the key in plain text. Run keywrap to protect it with a PIN.\n", key_path);
    err = key_file_load(key_path, MASTER_KEY_NAME, MASTER_KEY, MASTER_KEY_SIZE);
    if (err != OK) {
        exit_with_error(err, "Cannot load master key file");
    }
}

/* ============================================================
 * "web" MODE: keep trying until the server accepts the switch to HTTPS
 * ============================================================ */
static int web_loop(char *ip) {
    unsigned attempt = 0;

    recover_mode = true;
    g_verbose = false;
    printf("Asking %s to open the HTTPS window. Retrying until it accepts (Ctrl+C to stop)...\n", ip);

    for (;;) {
        attempt++;
        if (try_session(ip, "web") == 0) {
            break;
        }
        printf("\r  attempt %u failed: %-70.70s", attempt, last_err);
        fflush(stdout);
#if WEB_MAX_ATTEMPTS > 0
        if (attempt >= WEB_MAX_ATTEMPTS) {
            printf("\nGiving up after %u attempts.\n", attempt);
            return -1;
        }
#endif
        plat_sleep_ms(WEB_RETRY_DELAY_MIN_MS + (unsigned)(rand() % (WEB_RETRY_DELAY_JITTER_MS + 1)));
    }

    g_verbose = true;
    printf("\r%100s\r", "");
    log_printf("Server accepted the 'web' command (attempt %u).\n", attempt);
    log_printf("\n[!!!] ACTION REQUIRED [!!!]\n");
    log_printf("Open your browser and go to: https://%s\n", ip);
    log_printf("Note: You have 60 seconds to connect before it reverts to stealth mode.\n");
    return 0;
}

/* ============================================================
 * MAIN
 * ============================================================ */
int main(int argc, char *argv[]) {
    srand((unsigned)time(NULL));
#ifndef _WIN32
    signal(SIGPIPE, SIG_IGN);      // a reset by the server must not kill the client
#endif
    
    if (argc < 3 || argv[1][0] == '\0') { 
        printf("Usage: %s <IP> <basic|stats|web> [batch_runs]\n", argv[0]);
        printf("  web : keep retrying until the server opens the HTTPS window\n");
        printf("Master key is read from %s (PIN asked at start; create it with keywrap).\n", KEY_FILE_DEFAULT);
        printf("Set %s to use another file.\n", KEY_FILE_ENV);
        return 0;
    }
    
    char ip[IPSZ];
    if (strlen(argv[1]) >= IPSZ) {
        exit_with_error(ERROR_IP_INPUT, "Invalid IP length");
    }
    strcpy(ip, argv[1]);
    ip_check(ip); 

    char mode[16];
    strncpy(mode, argv[2], sizeof(mode) - 1);
    mode[sizeof(mode) - 1] = '\0';

    load_master_key();
    init_sock();

    if (strcmp(mode, "web") == 0) {
        int rc = web_loop(ip);
#ifdef _WIN32
        WSACleanup();
#endif
        return rc == 0 ? 0 : ERROR_CLIENT_CONNECTION;
    }

    /* BATCH SETUP */
    batch_mode = false;
    batch_runs = 1;
    if (argc >= 4) {                   
        batch_runs = atoi(argv[3]);
        if (batch_runs < 1) batch_runs = 1;
        batch_mode = true;
        success_file = fopen(SUCCESS_LOG, "a");
        error_file = fopen(ERROR_LOG, "a");
        if (!success_file || !error_file) {
            fprintf(stderr, "Cannot open log files! Falling back to console only.\n");
            batch_mode = false;
            if (success_file) fclose(success_file);
            if (error_file) fclose(error_file);
            success_file = error_file = NULL;
        }
    }
    recover_mode = batch_mode;

    for (int run = 1; run <= batch_runs; run++) { 
        if (batch_mode) {
            char time_str[64];
            get_timestamp(time_str, sizeof(time_str));
            log_printf("\n=== TEST RUN %d/%d started at %s (Mode: %s) ===\n", run, batch_runs, time_str, mode);
        }
        if (try_session(ip, mode) != 0) {
            error_log_printf("Test run %d completed with ERROR.\n\n", run);
            continue;
        }
        log_printf("Test run %d completed SUCCESSFULLY.\n\n", run);
    }
#ifdef _WIN32
    WSACleanup();
#endif
    if (success_file) fclose(success_file); 
    if (error_file) fclose(error_file);
    return 0;                          
}
