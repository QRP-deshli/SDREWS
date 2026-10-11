// ============================================================================
// SERVER: Netdata functions
// Ver. 0.4
// University Work Project | Technical University of Kosice
// 22.3.2026
// Nikita Kuropatkin
// ============================================================================

/* * This header file contains macros for the operation of the 
 * client_server_hidden program. Read the comments next to each macro 
 * for an explanation of its purpose.
 */

#ifndef PARAMETERS_H
#define PARAMETERS_H

#include <stdint.h>
#include <stddef.h>

/* ============================================================
 * DEPLOYMENT MODE SWITCH
 * Controls whether diagnostic post-auth commands ("stats", "info")
 * are active. Set to PROD before flashing to any public network
 * to minimise the firmware's attack surface.
 * ============================================================ */
#define TESTING 0   // Diagnostic commands enabled  — for evaluation/research only
#define PROD    1   // Diagnostic commands disabled — minimal attack surface

#define DEPLOYMENT_OPTION TESTING

/* ============================================================
 * RUNTIME LOGGING SWITCH
 * 1 = async_print() events are formatted and sent to the console
 *     (development / debugging).
 * 0 = every async_print() call is compiled out to nothing: no
 *     vsnprintf(), no inter-core queue traffic, no USB/UART work,
 *     and the core 1 print task is not started. Use 0 for flood
 *     tests and for production, so no CPU time is spent on logs.
 * (One-time boot messages that use plain printf() are unaffected.)
 * ============================================================ */
#define DEBUG_LOG   0

// ============================================================================
// AT-REST IP HASHING (blacklist.c, ip_tracker_t) — see ip_hash.h for the
// design rationale. Defined early since ip_tracker_t below needs IP_HASH_LEN.
// ============================================================================
// Keyed HMAC-SHA256(IP_HASH_KEY, ip) truncated to IP_HASH_LEN bytes, used to
// avoid storing client IPv4 addresses as plaintext in RAM tables that live
// for any length of time (the blacklist, and the SYN/congestion tracker).
// The HMAC key itself is NOT defined here. It is read from OTP at boot
// (IP_HASH_KEY, see otp_keys.c), so it is not part of the firmware image.
#define IP_HASH_LEN  4          // Truncated output length in bytes (see ip_hash.c for the collision-safety reasoning)

// ============================================================================
// SNTP TIME RETRIEVAL CONFIGURATION
// ============================================================================
#define SNTP_RECV_TIMEOUT    10000    // Timeout for receiving SNTP data
#define TIMEZONE             26       // SLOVAKIA timezone offset

typedef enum {
    PORT_MODE_CUSTOM = 0,
    PORT_MODE_HTTPS
} port_mode_t;

#define PORT_SERVER          443      // Custom protocol port
#define HTTPS_PORT           PORT_SERVER // HTTPS port

// ============================================================================
// SOCKET MEMORY MAP (W6100: 8 hardware sockets, 32KB internal memory shared
// as a 16KB TX pool + 16KB RX pool across all sockets)
// ============================================================================
// Sockets 0-3 : the custom anti-DoS protocol AND the HTTPS/TLS server. The
//               two are mutually exclusive in time (current_port_mode),
//               never concurrent, so they can safely share the same 4
//               physical sockets instead of TLS being pinned to its own
//               single dedicated socket.
// Socket 4    : shared by DHCP and SNTP. Neither runs concurrently with the
//               other (both are only ever driven from the single-threaded
//               main loop), so one small socket covers both.
// Sockets 5-7 : unused (0KB) — free headroom in the buffer pool.
//
// Per-socket buffer sizes are set once via wizchip_init()/ctlwizchip() in
// slehs.c using SOCK_BUF_TX_KB / SOCK_BUF_RX_KB below. Valid sizes are ONLY
// 1, 2, 4, 8, or 16 (KB) — the WIZnet driver silently rounds anything else
// down to the nearest power of two, so keep this array to those values, and
// keep the per-direction sum <= 16.
// Current allocation: 4x2KB (sockets 0-3) + 1x1KB (socket 4) = 9KB of 16KB
// used, leaving 7KB spare if you want to give sockets 0-3 more room later.
// ============================================================================
#define SOCKET_SHARED_SVC       4          // Shared socket: DHCP + SNTP


// ============================================================================
// TRACKER & CONGESTION STRUCTURES
// ============================================================================
/* Size of tracker list (individual adaptive SYN timer logic). Can be modified. */
#define TRACKER_SIZE         32 

/* * Struct for tracker list, contains a keyed IP hash, fail amount, 
 * last timestamp and handshake time. Do not modify!
 * `hash` stores ip_hash_compute(ip) (see ip_hash.h) instead of the raw
 * IPv4 address, for the same at-rest reason as blacklist_entry_t.
 */
typedef struct {
    uint8_t  hash[IP_HASH_LEN]; // Keyed hash of the remote IP address (was: raw ip[4])
    uint16_t fails;           // Persistent fail count (strikes)
    uint64_t last_seen_us;    // Timestamp for LRU eviction
    uint64_t handshake_time;  // Time in which handshake was made 
} ip_tracker_t;


// ============================================================================
// ENVIRONMENT CONFIGURATION (LOCATION)
// ============================================================================
/* * Switching this macro between OFFICE and LAB changes the device identity:
 * - OFFICE: Disables debug output on UART1 to stay 'hidden' and uses Office MAC.
 * - LAB:    Enables full debug logging on UART1 and uses Lab-specific MAC.
 */
#define OFFICE               0
#define LAB                  1
#define OFFICE2              2

#define LOCATION             LAB      // Set to LAB for development, OFFICE for production


// ============================================================================
// PERSISTENT COUNTERS / TELEMETRY CONFIGURATION
// ============================================================================
#define RESTART_COUNTER_MAGIC   0x52535452UL                             // "RSTR"
#define RESTART_COUNTER_VER     1
#define PERSISTENT_DATA_OFFSET  (PICO_FLASH_SIZE_BYTES - BLACKLIST_SIZE - 4096) // 4 KB before blacklist


// ============================================================================
// MEMORY & PACKET MANAGEMENT
// ============================================================================
/* Calculates the size of the frame_t structure excluding the payload data. */
#define FRAME_HEADER_SIZE    offsetof(frame_t, data)
#define MAX_HISTORY_HOURS    336


// ============================================================================
// TIME CONVERSION MACROS (Microseconds / Milliseconds)
// ============================================================================
#define US(x)                ((int64_t)(x))                     // Microseconds
#define MS(x)                ((int64_t)(x) * 1000LL)            // Milliseconds -> Microseconds
#define SEC(x)               ((int64_t)(x) * 1000000LL)         // Seconds -> Microseconds
#define MIN_MS(x)            ((int64_t)(x) * 60LL * 1000000LL)  // Minutes -> Microseconds
#define HOUR_MS(x)           ((x) * 3600000UL)                  // Hours -> Milliseconds
#define SEC_MS(x)            ((uint32_t)(x) * 1000UL)           // Seconds -> Milliseconds


// ============================================================================
// NETWORK CONGESTION & SECURITY PARAMETERS
// ============================================================================
/* --- CONGESTION THRESHOLDS ---
 * Number of failed attempts before we escalate the timeout.
 */
#define MID_CONG             10       // Significant packet loss detected
#define HIGH_CONG            5        // Critical congestion or slow-scanning
#define SYN_FLOOD            3        // Final threshold before absolute ban

/* --- TIMEOUT SCALING ---
 * How long we wait (in microseconds) for the client's ACK.
 */
#define TIMEOUT_BASE         MS(260)  // Standard wait time for the client's ACK (100 ms was too tight for real-world RTT / Wi-Fi jitter)
#define TIMEOUT_CONG         MS(500)  // ACK wait time under mid congestion
#define TIMEOUT_HARD         SEC(1)   // ACK wait time under extreme congestion
#define TIMEOUT_MAX          SEC(1.1)   // Maximum patience for lagged users
#define ULTIMATE_BAN         SEC(1.1)   // Hard cut-off to prevent socket hanging

#define INIT_PERIOD          MS(50)  // Timeout for client to send the init frame


// ============================================================================
// PERSISTENT DEBUG & FORENSICS (RAM-BASED)
// ============================================================================
/* * These variables are designed to survive a soft-reset (Watchdog).
 * They allow for post-mortem analysis of the system state immediately following a crash.
 */
extern volatile uint8_t  last_critical_state;   // The Enum value at time of failure
extern volatile uint8_t  last_socket;           // Index of the active socket (0-MAX_SOCKETS)
extern volatile uint16_t state_change_counter;  // Total transitions (helps detect "spin" loops)
extern volatile uint16_t state_magic;           // Signature to verify if data is valid post-reboot

#define STATE_MAGIC_EXPECTED 0x5A5A 

/* --- SET_CRITICAL_STATE ---
 * An atomic-style macro to update the system "breadcrumb."
 */
#define SET_CRITICAL_STATE(st, sk)  do {                \
    last_critical_state   = (st);                       \
    last_socket           = (uint8_t)(sk);              \
    state_change_counter++;                             \
    state_magic           = STATE_MAGIC_EXPECTED;       \
} while(0)


// ============================================================================
// BLACKLIST & FLASH STORAGE CONFIGURATION
// ============================================================================
#ifndef PICO_FLASH_SIZE_BYTES
#define PICO_FLASH_SIZE_BYTES   (2 * 1024 * 1024) // Standard 2MB Flash size
#endif

#define BLACKLIST_SIZE          (64 * 1024)       // Reserve last 64KB for security data
#define NUM_SLOTS               4                 // Divide 64KB into 4 sectors for wear leveling
#define SLOT_SIZE               (BLACKLIST_SIZE / NUM_SLOTS) // 16KB per slot to prevent over-writing
#define BLACKLIST_OFFSET        (PICO_FLASH_SIZE_BYTES - BLACKLIST_SIZE) 
#define BLACKLIST_MAGIC         0x424C4B4CUL      // "BLKL" identifier for flash validity
#define BLACKLIST_VER           1                 // Data structure versioning
#define MAX_BLACKLIST_ENTRY     64                // Max banned IPs stored in RAM/Flash
#define STRIKE_MAX              4                 // Number of strikes before an IP is banned


// ============================================================================
// HARDWARE IDENTIFICATION (MAC ADDRESSES)
// ============================================================================
// Per-socket TX/RX buffer sizes in KB (see SOCKET MEMORY MAP comment above).
// Defined once in slehs.c, passed to wizchip_init() at boot.
extern uint8_t SOCK_BUF_TX_KB[8];
extern uint8_t SOCK_BUF_RX_KB[8];

#define DEVICE_MAC_LAB          {0x00, 0x16, 0x17, 0x62, 0x27, 0x88}
#define DEVICE_MAC_OFFICE       {0x00, 0x16, 0xd3, 0x21, 0xf8, 0x9b}
#define DEVICE_MAC_OFFICE2      {0x02, 0x12, 0x34, 0x56, 0x78, 0x9A}

#if LOCATION == OFFICE
    #define DEVICE_MAC          DEVICE_MAC_OFFICE // Deployment identity
#elif LOCATION == OFFICE2
    #define DEVICE_MAC DEVICE_MAC_OFFICE2         // Deployment identity
#elif LOCATION == LAB
    #define DEVICE_MAC          DEVICE_MAC_LAB    // Test-bench identity
#endif


// ============================================================================
// NETWORK & SESSION PARAMETERS
// ============================================================================
#define ROT_INTERVAL            1024 // Frequency of cryptographic token rotation
#define RTR_VAL                 3000 // Retry Time-value in ms for Wiznet chip (sending SYN and not receiving ACK)
#define RCR_VAL                 3    // Retry Count: drop connection after 3 failed attempts 
#define MAX_SOCKETS             4    // Defines the session limit (must match available RAM slots)

/* Application heartbeats to check if the client is still alive */
#define APP_KEEPALIVE_IDLE_MS   5000  // Wait 5s before asking "Are you there?" (PING)
#define APP_KEEPALIVE_REPLY_MS  8000  // Disconnect if no answer (PONG) within 8s (Note: comment originally said 5s)
#define MAX_PAYLOAD             128   // MAX PAYLOAD for the message transmitted or received

/* Protocol Magic Numbers: Used to verify frame header integrity */
#define PROTOCOL_MAGIC_SEND     0xC2A5
#define PROTOCOL_MAGIC_RECEIVE  0xC2A6
#define PROTOCOL_VER            1

/* Command byte identifiers used in frame_t.cmd */
#define CMD_AUTH                0x01 // Authentication step
#define CMD_DATA                0x10 // Data transfer
#define CMD_ACK                 0x81 // Acknowledgment
#define CMD_INIT                0x11 // Init message
#define CMD_PING                0x04 // Keep-alive probe
#define CMD_PONG                0x05 // Keep-alive response
#define CMD_CLOSE               0x06

#define INIT_TOKEN              0xCAFEBABE // Seed for the first session token
#define DHCP_ACT                1          // 1 enables DHCP; 0 uses Static IP
#define KEEPALIVE_TIME          2          // Hardware TCP keepalive (Value * 5 seconds)
#define KEY_SIZE                16         // Cryptographic key length in bytes
#define DELAY_RECV              30         // Milliseconds to wait for packet arrival check


// ============================================================================
// VISUAL DEBUGGING (LED SIGNALS)
// ============================================================================
#define DHCP_LED_DEBUG          1000  // Slow 1s blink during DHCP discovery
#define SOCKET_LED_DEBUG        2000  // Fast 2s blink when waiting for a client
#define DHCP_BLINK_REPEAT       2     // Number of flashes for DHCP state
#define SOCKET_BLINK_REPEAT     5     // Number of flashes for Socket state
#define BLINK_PAUSE             50    // Milliseconds between pulses
#define LED_PIN                 25    // Default GP25 LED on Pico


// ============================================================================
// DEBUGGER, HARDWARE, & WATCHDOG CONFIGURATION
// ============================================================================
#define DBG_UART_ID             uart1     // Secondary UART to separate logs from main data
#define DBG_BAUD_RATE           115200    // High-speed logging baud rate
#define DBG_TX_PIN              4         // Physical GPIO pin for Serial TX
#define DBG_RX_PIN              5         // Physical GPIO pin for Serial RX

#define MSG_SIZE                32        // Buffer size for application messages
#define ETHERNET_BUF_MAX_SIZE   (1024 * 2) // Total Wiznet buffer memory
#define PLL_SYS_KHZ             (150 * 1000) // Standard clock frequency: 150 MHz

#define SERVER_SOCK             1         // Main socket for client communication

/* Watchdog safety timers to prevent system lockups */
#define TIME_TO_LIFE            1800000   // 30-minute system health reset
#define TIME_FOR_DHCP           60000     // 1-minute timeout if DHCP fails
#define TOKEN_ROTATE            1024      // Trigger for session key change
#define WATCHDOG_REFRESH        5000      // Period (ms) to reset the hardware watchdog
#define WRITE_REPEAT            1         // Repetition count for handshake signals

#define SUCCESS                 1
#define FAIL                    0

#endif // PARAMETERS_H