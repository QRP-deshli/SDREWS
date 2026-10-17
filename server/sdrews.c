// SERVER - REFACTORED VERSION     //
// Netdata functions              //
// Ver. 0.4                       //
// University Work Project        //
// Technical University of Kosice //
// 22.3.2026                      //
// Nikita Kuropatkin              //

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include "parameters.h"
#include "error.h"

/* Wiznet dependencies */
#include "timing.h"
#include "pico/rand.h"
#include "port_common.h"
#include "timer.h"
#include "socket.h"
#include "wizchip_spi.h"
#include "network_data.h"
#include "hardware/watchdog.h"
#include "wizchip_conf.h"
#include "pico/stdlib.h"
#include "hardware/timer.h"
#include "hardware/regs/watchdog.h"
#include "hardware/uart.h"
#include "hardware/sync.h"
#include "dhcp.h"
#include "blacklist.h"
#include "ip_hash.h"
#include "crypto.h"
#include "otp/otp_keys.h"
#include "frame.h"
#include "debug.h"
#include "wiz_listen.h"
#include "restart.h" 
#include "communication.h" 
#include "pico/multicore.h"
#include "pico/util/queue.h"

// WEB
#include "https_handshake.h"
#include "mbedtls/ssl.h"
#include "sntp.h"
#include "sen63c_i2c.h"
#include "sensor_data.h"
#include "sntp_time.h"

/*
Variable for the Sensor driver
*/
extern void sensirion_i2c_hal_init(void);

/*
Variables for the HTTPS operation
*/
// NOTE: the single global `ssl` context is gone — https_handshake.c now
// owns one mbedtls_ssl_context PER SOCKET internally (sockets 0..MAX_SOCKETS-1),
// since TLS runs on all 4 sockets instead of one. Use https_force_reset_all()
// from here instead of reaching into mbedTLS state directly.
absolute_time_t https_start_time;  // Global timer for the 60s window
extern uint8_t https_client_ip[4];  // IP allowed in HTTPS mode (set by the "web" command)
absolute_time_t https_timeout;     // To ensure the port doesn't get stuck in Web mode forever
port_mode_t current_port_mode = PORT_MODE_CUSTOM;
absolute_time_t https_last_activity; // Timer to track the dead tab timeout
bool https_init_flag;              // Handshake init flag


// ANTI-SYN FLOOD TRACKING
// Static array persists across function calls to track how long a socket
// stays in the "Half-Open" (SYNRECV) state.
uint64_t synrecv_start_us[MAX_SOCKETS] = {0};

// Queue for the async print from core 1 (only exists when DEBUG_LOG == 1)
#if DEBUG_LOG
queue_t log_queue;
#endif

// Keyed IP hash of the peer of each half-open (SYNRECV) socket, computed once
// when the SYN is first seen so the poll loop never re-runs HMAC-SHA256.
static uint8_t synrecv_hash[MAX_SOCKETS][IP_HASH_LEN];

/*
Strucutres for the history monitoring 
*/
stats_tracker_t hourly_stats = {0};
absolute_time_t last_stats_reset;
hourly_record_t stats_history[MAX_HISTORY_HOURS] = {0};
uint16_t history_count = 0;
uint16_t history_head = 0; // Ring buffer index

/* ============================================================
 * GLOBAL STATE & RUNTIME FLAGS
 * ============================================================
 * Runtime variables related to blacklist persistence,
 * session storage and timer configuration.
 * ============================================================ 
 */
bool blacklist_dirty = false;              // Flag: true - blacklist was modified and needs saving
absolute_time_t last_blacklist_save = {0}; // Timestamp of the last flash write
blacklist_slot_t g_blacklist = {0};        // Global structure holding blocked IP data
restart_data_t res_data;                   // Var for restart value

/* ============================================================
 * SESSION ARRAY & TIMER CONFIGURATION
 * ============================================================
 * sess[]          - array of session structures.
 * One structure per socket (MAX_SOCKETS).
 * Stores per-connection state and crypto data.
 *
 * blink_period_ms - LED blink interval (visual status indicator).
 *
 * watchdog_period - watchdog refresh interval control.
 *
 * timer1          - repeating timer (used for periodic operations
 * such as DHCP-related handling).
 *
 * timer2          - repeating timer for system timing tasks
 * (e.g., LED blinking / uptime tracking).
 * ============================================================ */
sess_t sess[MAX_SOCKETS]; // Persistent state for each hardware socket

volatile int blink_period_ms = 500;  // Default LED toggle rate
volatile int watchdog_period = 1000; // Watchdog interval in ms
struct repeating_timer timer1;       // Timer handle for system tasks
struct repeating_timer timer2;       // Timer handle for UI/LED tasks

/* ============================================================
 * CRYPTO CONSTANTS
 * ============================================================
 * SESS_INFO   - context string used for session key derivation
 * (MASTER_KEY is not in firmware: it is loaded from OTP, see otp_keys.c)
 *
 * Used during authentication and per-session key generation.
 * ============================================================ */
// Label for HKDF-like derivation //
const uint8_t SESS_INFO[] = "CHASKEY-SESSION-KEY"; 

/* ============================================================
 * SOCKET BUFFER MEMORY MAP
 * ============================================================
 * See the "SOCKET MEMORY MAP" comment in parameters.h for the reasoning.
 * Index = socket number. Passed to wizchip_init() once at boot, below.
 * ============================================================ */
uint8_t SOCK_BUF_TX_KB[8] = {2, 2, 2, 2, 1, 0, 0, 0};
uint8_t SOCK_BUF_RX_KB[8] = {2, 2, 2, 2, 1, 0, 0, 0};

/* ============================================================
 * IP TRACKER: Reputation & Connection History
 * ------------------------------------------------------------
 * Manages a small RAM cache of unique IPs. 
 * Uses an LRU (Least Recently Used) policy to ensure we 
 * always have room for new connection attempts.
 * ============================================================ */
ip_tracker_t ip_tracker[TRACKER_SIZE] = {0};

/*
 * Function: get_ip_tracker
 * Description: Finds an existing IP tracking cache node or configures an open
 * index block slot using an LRU eviction fallback design strategy.
 * Storage is keyed by ip_hash_compute(dip) rather than the raw address (see
 * ip_hash.h) — same at-rest rationale as blacklist.c. `dip` itself is only
 * ever a transient stack value here, so the caller-facing signature is
 * unchanged; the hash is computed internally.
 */
static ip_tracker_t* get_ip_tracker_h(const uint8_t hash[IP_HASH_LEN]) {
    int empty_idx = -1;
    int oldest_idx = 0;
    uint64_t oldest_time = 0xFFFFFFFFFFFFFFFF;

    // 1. Scan for existing entry or potential replacement candidates
    for (int i = 0; i < TRACKER_SIZE; i++) {
        // Match found: return immediately
        if (memcmp(ip_tracker[i].hash, hash, IP_HASH_LEN) == 0) {
            return &ip_tracker[i]; 
        }

        // Identify the first available empty slot
        // CORRECT — check for an actual unoccupied slot
        uint8_t zero[IP_HASH_LEN] = {0};
        if (memcmp(ip_tracker[i].hash, zero, IP_HASH_LEN) == 0 && empty_idx == -1) {
            empty_idx = i;
        }

        // Identify the "oldest" entry (LRU) in case the list is full
        if (ip_tracker[i].last_seen_us < oldest_time) {
            oldest_time = ip_tracker[i].last_seen_us;
            oldest_idx = i;
        }
    }

    // 2. Slot Assignment Logic
    int target_idx;
    if (empty_idx != -1) {
        // Use the first empty slot found
        target_idx = empty_idx;
    } else {
        // Cache is full: Evict the oldest entry to make room
        target_idx = oldest_idx;
    }

    // 3. Initialize/Reset New Entry
    memcpy(ip_tracker[target_idx].hash, hash, IP_HASH_LEN);
    ip_tracker[target_idx].fails = 0; 
    
    // Note: last_seen_us should be updated by the caller upon activity
    return &ip_tracker[target_idx];
}

ip_tracker_t* get_ip_tracker(uint8_t* dip) {
    uint8_t hash[IP_HASH_LEN];
    ip_hash_compute(dip, hash);
    return get_ip_tracker_h(hash);
}


/*
 * Function: tcp_srv_task
 * Description: Per-socket TCP server state execution tracker routine.
 * Handles state processing flags, keeps validation sync routines alive,
 * filters unauthorized clients, updates logging, and runs the protocol parsing machine.
 */
void tcp_srv_task(uint8_t sk) {
    // Local variables for hardware status and frame management
    uint8_t sr;            // Socket Status Register value
    uint8_t ir;            // Socket Interrupt Register value
    uint16_t rx_sz;        // Size of data waiting in the hardware RX buffer
    sess_t *s;             // Pointer to the sess context for this specific sock
    uint8_t dip[4];        // Destination IP (the client's IP)
    int result;
    
    // Map this task to its specific session data structure
    s = &sess[sk];
    
    // Read the current state of the WIZnet socket
    sr = getSn_SR(sk); 
    
    switch (sr) {
        /* --- STATE: CLOSED ---
         * The socket is not initialized. We need to open it in TCP mode.
         */
        case SOCK_CLOSED: {   
            synrecv_start_us[sk] = 0; // Reset any previous handshake timers
            
            // Open the socket: TCP Mode, defined Port, and No Delay 
            result = socket(sk, Sn_MR_TCP, PORT_SERVER, SF_TCP_NODELAY);
            if (result == sk) {
                // Set the hardware-level keepalive timer
                setSn_KPALVTR(sk, KEEPALIVE_TIME); 
                s->active = false;
                s->init_verified = false;
                async_print("Socket %d opened\n", sk);
            }
            break;
        }

        /* --- STATE: SYNRECV (Handshake in Progress) ---
         * A client has sent a SYN, and we have sent a SYN-ACK. 
         * This is a critical state for security (vulnerable to SYN Flooding).
         */
        case SOCK_SYNRECV: {
            uint64_t now_us = to_us_since_boot(get_absolute_time());

            // --- UPDATE PEAK HERE ---
            uint8_t current_count = 0;
            for (int j = 0; j < MAX_SOCKETS; j++) {
                if (sess[j].active) {
                    current_count++;
                }
            }       
            if (current_count > hourly_stats.peak_sockets) {
                hourly_stats.peak_sockets = current_count;
            }
            if (current_count > hourly_stats.peak_sockets_all) {
                hourly_stats.peak_sockets_all = current_count;
            }

            // First poll of this half-open connection: read the peer IP and
            // compute its keyed hash ONCE (one HMAC-SHA256). Every later poll
            // of the same SYNRECV uses the cached hash. Before, the IP was
            // re-read and HMAC'd twice (is_blocked + get_ip_tracker) on EVERY
            // loop pass, which under a SYN flood starved the whole main loop.
            if (synrecv_start_us[sk] == 0) {
                synrecv_start_us[sk] = now_us;
                getSn_DIPR(sk, dip);
                ip_hash_compute(dip, synrecv_hash[sk]);
                async_print("Socket %d: SYNRECV from %d.%d.%d.%d (waiting for ACK)\n",
                            sk, dip[0], dip[1], dip[2], dip[3]);
            }

            // SECURITY CHECK 1: Immediate Blacklist Filtering (hash lookup only)
            if (is_blocked_hash(synrecv_hash[sk])) {
#if DEBUG_LOG
                getSn_DIPR(sk, dip);   // raw IP only needed for the log line
#endif
                uint64_t disconnect_latency_us = now_us - synrecv_start_us[sk];
                close(sk);

                async_print("SECURITY ALERT: Blocked IP %d.%d.%d.%d dropped in SOCK_SYNRECV. Disconnect Latency: %llu us\n",
                            dip[0], dip[1], dip[2], dip[3], disconnect_latency_us);
                s->active = false;
                s->init_verified = false;
                synrecv_start_us[sk] = 0;
                break;
            }

            uint64_t age_us = now_us - synrecv_start_us[sk];

            // Fast path: every possible timeout is >= TIMEOUT_BASE, so while the
            // handshake is younger than that there is nothing to decide. Skip
            // the tracker lookup entirely and just wait for the ACK.
            if (age_us <= TIMEOUT_BASE) {
                break;
            }

            // Fetch the failure history for this IP
            ip_tracker_t* tracker = get_ip_tracker_h(synrecv_hash[sk]);
            tracker->last_seen_us = now_us;

            // Determine dynamic timeout based on network congestion policy
            uint64_t current_timeout_us = TIMEOUT_BASE;
       
            if (tracker->fails >= MID_CONG)  current_timeout_us = TIMEOUT_CONG;
            if (tracker->fails >= HIGH_CONG) current_timeout_us = TIMEOUT_HARD;
            if (tracker->fails >= SYN_FLOOD) current_timeout_us = TIMEOUT_MAX;

            // Threshold Enforcement
            // Check if the current handshake attempt has exceeded the allowed time.
            if (age_us > current_timeout_us) {
                hourly_stats.ack_timeouts++;
                hourly_stats.ack_timeouts_all++;

                // The raw IP is only needed here (strike + log), i.e. once per timeout
                getSn_DIPR(sk, dip);
        
                // CASE A: The "Ultimate" Ban
                if (age_us > ULTIMATE_BAN) {
                    async_print("!!! BAN: %d.%d.%d.%d exceeded ULTIMATE_BAN \n", dip[0], dip[1], dip[2], dip[3]);
                    add_strike(dip, 4); // Apply permanent penalty
                } 
                // CASE B: Standard Retriable Timeout
                else {
                    tracker->fails++; // Log the failure but allow future retries
                    async_print("Socket %d: Lag Timeout (%llu ms) from %d.%d.%d.%d. Total Fails: %d\n",
                                sk, age_us / 1000, dip[0], dip[1], dip[2], dip[3], tracker->fails);
                }

                tracker->handshake_time = 0;

                // Cleanup: Reclaim the socket for the next attempt
                close(sk);
                s->active = false;
                synrecv_start_us[sk] = 0;
            }
            break;
        }

        /* --- STATE: INIT ---
         * Socket is open but not yet listening.
         */
        case SOCK_INIT: {   
            result = wiz_listen_robust(sk); // Put the socket into LISTEN mode (race-free, see wiz_listen.h)
            if (result == SOCK_OK) {
                async_print("Socket %d listening on port %d\n", sk, PORT_SERVER);
            }
            break;
        }

        /* --- STATE: LISTEN ---
         * Passive state: waiting for a client to initiate a connection.
         */
        case SOCK_LISTEN: {
            break;
        }

        /* --- STATE: ESTABLISHED ---
          The TCP connection is fully open. 
          Here we handle the actual application protocol.
        */
        case SOCK_ESTABLISHED: {   
            ir = getSn_IR(sk);
            absolute_time_t now = get_absolute_time();

            // --- UPDATE PEAK HERE ---
            uint8_t current_count = 0;
            for (int j = 0; j < MAX_SOCKETS; j++) {
                if (sess[j].active) {
                    current_count++;
                }
            }       
            if (current_count > hourly_stats.peak_sockets) {
                hourly_stats.peak_sockets = current_count;
            }
            if (current_count > hourly_stats.peak_sockets_all) {
                hourly_stats.peak_sockets_all = current_count;
            }

            // 1. New connection (highest priority, happens once)
            if (ir & Sn_IR_CON) {
                // 1. CLEAR IT IMMEDIATELY
                setSn_IR(sk, Sn_IR_CON);
                getSn_DIPR(sk, dip); // Get IP once
  
                // Check blacklist one last time
                if (is_blocked(dip)) {
                    close(sk);
                    uint64_t disconnect_latency_us = 0;
                    if (synrecv_start_us[sk] != 0) {
                        disconnect_latency_us = to_us_since_boot(now) - synrecv_start_us[sk];
                    }
                    async_print("SECURITY ALERT: Blocked IP %d.%d.%d.%d dropped in SOCK_ESTABLISHED. Disconnect Latency: %llu us\n",
                                dip[0], dip[1], dip[2], dip[3], disconnect_latency_us);
                    return;
                }

                /* Calculating handshake time */
                uint64_t now_us = to_us_since_boot(get_absolute_time());
                uint64_t age_us = 0;
                if (synrecv_start_us[sk] != 0) {
                    age_us = now_us - synrecv_start_us[sk];
                }

                ip_tracker_t* tracker = get_ip_tracker(dip);
                tracker->last_seen_us = now_us;

                // === SMART RECOVERY: one step behind + full reset on quick success ===
                if (synrecv_start_us[sk] != 0) {
                    // <= 3 s -> network is healthy
                    if (age_us <= TIMEOUT_BASE) {
                        tracker->fails = 0;
                    }
                    // Slow but still succeeded "one step behind"
                    else if (tracker->fails > 0) {
                        tracker->fails--;              
                    }
                    // store the actual successful duration 
                    tracker->handshake_time = age_us;   
                    synrecv_start_us[sk] = 0;    // Prevent stale timer
                } 
                else {
                    tracker->fails = 0;
                    tracker->handshake_time = 0;
                }
                
                handle_new_connection(sk, s);
                return;
            }
            
            // ---  PROTOCOL INIT TIMEOUT CHECK ---
            // If the TCP link is up, but we haven't verified the first INIT frame yet
            if (!s->init_verified) {
                int64_t diff_ms = absolute_time_diff_us(s->last_act, now);
        
                if (diff_ms > INIT_PERIOD) { // Grace period for client to send CMD_INIT
                    async_print("Socket %d: Protocol Handshake Timeout (No INIT frame received)\n", sk);
                    close(sk);
                    s->active = false;
                    return;
                }
            }
            
            // 2. Incoming data (only ONE frame per call)
            rx_sz = getSn_RX_RSR(sk);
            if (rx_sz >= FRAME_HEADER_SIZE) {
                // Socket was closed on failure
                if (!process_one_incoming_frame(sk, s)) {
                    return;                  
                }
            }
        
            // 3. Pending DATA response
            if (s->send_data && !s->wait_ack) {
                send_status_update(sk, s);
                return;   // early exit after send
            }
           
            // 4. Keepalive/ping (very cheap, runs last)
            handle_keepalive_ping(sk, s);
            break;
        }

        /* --- STATE: CLOSE_WAIT ---
         * The client has sent a FIN packet. We must disconnect our side.
         */
        case SOCK_CLOSE_WAIT: {
            close(sk);
            s->active = false;
            s->init_verified = false;
            async_print("Socket %d: close wait\n", sk);
            break;
        }
            
        default: {
            break;
        }
    }
    
    // ASYNCHRONOUS EVENT CHECK:
    // Read the hardware interrupts for the socket to handle unexpected events.
    ir = getSn_IR(sk);
  
    // Handle Client Disconnect
    if (ir & Sn_IR_DISCON) {
        setSn_IR(sk, Sn_IR_DISCON); // Clear bit
        close(sk);
        s->active = false;
        s->init_verified = false;
        async_print("Socket %d: disconnected\n", sk);
    }
    
    // Handle TCP Level Timeouts (no hardware ACKs)
    if (ir & Sn_IR_TIMEOUT) {
        setSn_IR(sk, Sn_IR_TIMEOUT); // Clear bit
        close(sk);
        s->active = false;
        s->init_verified = false;
        async_print("Socket %d: timeout\n", sk);
    }
}


/*
 * Function: core1_entry
 * Description: Core 1 printing daemon worker entry point. Pulls incoming logged 
 * statements out of the synchronized queue buffer to avoid stalling critical 
 * processing pathways running on Core 0.
 */
#if DEBUG_LOG
void core1_entry(void) {
    log_entry_t entry;
    while (true) {
        queue_remove_blocking(&log_queue, &entry);  // waits efficiently
        printf("%s", entry.msg);
        fflush(stdout);
        tight_loop_contents();
    }
}
#endif /* DEBUG_LOG */


/*
 * Function: tracker_cleanup
 * Description: Cycles through the client tracking list and clears out historical 
 * context for old IP records that have not initiated active contact within an hour.
 */
void tracker_cleanup(void) {
    uint64_t now = to_us_since_boot(get_absolute_time());
    for (int i = 0; i < TRACKER_SIZE; i++) {
        // If we haven't seen this IP in over an hour, forget its failures
        if (ip_tracker[i].fails > 0) {
            if (now - ip_tracker[i].last_seen_us > HOUR_MS(1) * 1000LL) {
                ip_tracker[i].fails = 0;
                ip_tracker[i].handshake_time = 0;
                memset(ip_tracker[i].hash, 0, IP_HASH_LEN);
            }
        }
    }
}


/*
 * Function: main
 * Description: Main processing system initialization entry point. 
 * Tunes SPI/CRIS lines,
 * assigns static MAC addresses, 
 * fires an active NTP request, 
 * configures sensor tasks, 
 * and runs the continuous processing loop engine.
 */
int main(void) {
    wiz_NetInfo net;
    int i;
    // Overclock RP2350 system clock to suppported value defined in paramerters.h
    set_clock_khz(); 
   
    #if PICO_STDIO_USB_ENABLE
        stdio_usb_init();
    #endif

    // Diagnostics that stay on even with DEBUG_LOG 0 (they print rarely, never per packet)
    if (watchdog_caused_reboot()) {
        printf("*** BOOT: the previous run was reset by the watchdog ***\n");
    }
    
    // Secrets come from OTP; refuse to run on an unprovisioned board
    if (!otp_keys_load()) {
        exit_with_error(ERROR_OTP_KEYS, "OTP keys not provisioned");
    }

#if DEBUG_LOG
    queue_init(&log_queue, sizeof(log_entry_t), LOG_QUEUE_SIZE);

    // Launch printing from second core 
    multicore_launch_core1(core1_entry);
#endif

    // HW Initialization
    wizchip_spi_initialize();
    wizchip_cris_initialize();
    wizchip_reset();
    sleep_ms(100);
    wizchip_initialize();
    wizchip_check();

    // Re-apply our own per-socket buffer split (see parameters.h for the
    // memory map). wizchip_initialize() (in port_common.c) already ran with
    // the vendor's equal-2KB-per-socket defaults; this call overrides that
    // with sockets 0-3 = 2KB (custom protocol + TLS) and socket 4 = 1KB
    // (shared DHCP/SNTP), sockets 5-7 disabled. It must run before any
    // socket is opened and before MAC/IP are applied via network_initialize()
    // below, since wizchip_init() performs an internal soft reset.
    if (wizchip_init(SOCK_BUF_TX_KB, SOCK_BUF_RX_KB) == -1) {
        async_print("FATAL: invalid per-socket buffer allocation (check SOCK_BUF_*_KB sums <= 16KB)\n");
    }
    wizchip_1ms_timer_initialize(repeating_timer_callback);

    // Fine-tune retransmission for responsiveness and SYN flood mitigation
    setRTR(RTR_VAL); // Base timeout
    setRCR(RCR_VAL); // Retransmission count

    // LED Status feedback
    gpio_init(LED_PIN);
    gpio_set_dir(LED_PIN, GPIO_OUT);
    add_repeating_timer_ms(-blink_period_ms, led_blink_irq, NULL, &timer2);
    
    // Network & DHCP configuration
    network_initialize((wiz_NetInfo) {
        .mac = DEVICE_MAC
    });
    net = get_data_dhcp(); // Blocks until IP assigned
    
    network_initialize(net);
    print_network_information(net); 

    time_sync_sntp();

    if (!PICO_PING_ENABLE) {
        disable_ping(); // Security: Ignore ICMP Echo requests
    }
   
    // Reset counter setting 
    res_count_init();       // Checks version. Wipes to 0 *only* if version changed.
    res_count_increment();  // Increments by 1 on every hardware/watchdog reset.

    blacklist_init(); // Initialize blacklist
     
    update_blink_period(SOCKET_LED_DEBUG); 

    // Reset session states
    for (i = 0; i < MAX_SOCKETS; i++) {
        sess[i].active = false;
    }
    
    https_init_system(); // Initialize TLS 1.3 structs

    watchdog_enable(WATCHDOG_REFRESH, true); // Arm hardware watchdog

    // ---- Add SEN63C Initialization ----
    sensirion_i2c_hal_init();
    sen63c_init(SEN63C_I2C_ADDR_6B);
    int16_t sen_err = sen63c_start_continuous_measurement();
    if (sen_err != 0) {
        async_print("Error starting SEN63C measurement: %d\n", sen_err);
    } else {
        async_print("SEN63C Continuous measurement started.\n");
    }

    /*
    Trackers for periodic clean-ups and syncs
    */
    uint32_t last_dhcp_renew_ms = 0;
    static absolute_time_t last_cleanup = {0};
    uint32_t last_sntp_sync_ms = 0; // Track last sync

    // Execution loop 
    while (1) {
        if (current_port_mode == PORT_MODE_CUSTOM) {
            for (i = 0; i < MAX_SOCKETS; i++) {
                tcp_srv_task(i); 
                watchdog_update(); 
            }
        }
        else {  
            watchdog_disable();
            if (https_init_flag == true) {
                // TLS now runs on sockets 0-3 (same physical sockets as the
                // custom protocol), so hard-reset ALL of them + their TLS
                // session state via https_handshake.c, instead of only
                // clearing sess[] here.
                https_force_reset_all();
                for (int j = 0; j < MAX_SOCKETS; j++) {
                    sess[j].active = false;
                }
                printf("[mode] HTTPS ON, allowed client %d.%d.%d.%d\n",
                       https_client_ip[0], https_client_ip[1], https_client_ip[2], https_client_ip[3]);
                https_init_flag = false; // Reset so we don't spam close
                https_last_activity = get_absolute_time(); // Set initial timeout anchor
            }
            
            // --- THE DEAD TIMER ---
            // If the user closes the tab, the browser stops auto-refreshing.
            // If 3 minutes pass without ANY of the 4 HTTPS sockets seeing
            // real traffic, we revert to custom mode. Must stay LONGER than
            // HTTPS_IDLE_TIMEOUT_US (90s, https_handshake.c) so an individual
            // stale socket gets recycled first instead of the whole port
            // collapsing under it. This no longer has to guess at how long a
            // real tab close takes to notice passively — page.h's pagehide ->
            // sendBeacon('/close') signal (handled in https_poll_task) covers
            // that instantly, so this timer only exists as a fallback for an
            // unclean disconnect (crash, network drop, sleep) where the beacon
            // never gets sent.
            if (absolute_time_diff_us(https_last_activity, get_absolute_time()) > SEC(180)) {
                current_port_mode = PORT_MODE_CUSTOM;
                https_force_reset_all();
                printf("[mode] HTTPS OFF (180 s without traffic), back to custom protocol\n");
                
                async_print("HTTPS20 Dead Timer Expired: User closed tab. Reverting to Stealth Mode.\n");
            }

            // Drive all 4 TLS sessions in parallel (was a single fixed socket)
            for (int j = 0; j < MAX_SOCKETS; j++) {
                https_poll_task((uint8_t)j);
            }
        }
        sensor_poll_task();

        /* Periodic SNTP Sync (Fixes the 15s/week drift) */
        uint32_t now_ms = millis();
        if (now_ms - last_sntp_sync_ms >= HOUR_MS(24)) {
            time_sync_sntp();
            last_sntp_sync_ms = now_ms;
            async_print("System: Daily SNTP time resync performed.\n");
        }

        /* DHCP Maintenance */
        if (net.dhcp == NETINFO_DHCP) {
            uint32_t current_now_ms = millis();
            // Renew lease every hour
            if (current_now_ms - last_dhcp_renew_ms >= HOUR_MS(3)) {
                uint32_t remaining = getDHCPLeasetime();
                renew_dhcp();
                last_dhcp_renew_ms = current_now_ms;
                async_print("DHCP renewed at %lu ms (remaining lease: %lu s)\n", 
                            current_now_ms, remaining);
            }
        }

        /* Clean-up inactive strikes */
        absolute_time_t now = get_absolute_time();
        if (absolute_time_diff_us(last_cleanup, now) > MIN_MS(30)) {  // every 30 min
            blacklist_periodic_cleanup();
            last_cleanup = now;
            async_print("Blacklist cleanup: %u entries remaining\n", g_blacklist.num);
        }

        if (absolute_time_diff_us(last_stats_reset, get_absolute_time()) > MIN_MS(60)) {
            // Save to history array 
            stats_history[history_head].success = hourly_stats.success_conns;
            stats_history[history_head].timeout = hourly_stats.ack_timeouts;
            stats_history[history_head].garbage = hourly_stats.garbage_inits;
            stats_history[history_head].peak    = hourly_stats.peak_sockets;
    
            history_head = (history_head + 1) % MAX_HISTORY_HOURS;
            if (history_count < MAX_HISTORY_HOURS) {
                history_count++;
            }

            // 1. Snapshot the current hour's data into the 'last' variables
            hourly_stats.success_conns_last = hourly_stats.success_conns;
            hourly_stats.ack_timeouts_last  = hourly_stats.ack_timeouts;
            hourly_stats.garbage_inits_last = hourly_stats.garbage_inits;
            hourly_stats.peak_sockets_last  = hourly_stats.peak_sockets;

            // 2. Reset the current hour (leave _all variables alone!)
            hourly_stats.success_conns = 0;
            hourly_stats.ack_timeouts = 0;
            hourly_stats.garbage_inits = 0;
            hourly_stats.peak_sockets = 0; 

            last_stats_reset = get_absolute_time();
            async_print("System: Hourly stats and peak-load reset.\n");
        }

        // The tracker only forgets entries idle for > 1 hour, so scanning it on
        // every loop pass is pure overhead. Once a minute is plenty.
        static uint32_t last_tracker_cleanup_ms = 0;
        if (now_ms - last_tracker_cleanup_ms >= 60000) {
            tracker_cleanup();
            last_tracker_cleanup_ms = now_ms;
        }
        tight_loop_contents(); 
    }
   
    return 0;
}