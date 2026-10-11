// SERVER                         //
// Blacklist functions            //
// Ver. 0.5                       //
// University Work Project        //
// Technical University of Kosice //
// 22.3.2026                      //
// Nikita Kuropatkin              //
//
// CHANGE LOG (Ver 0.5):
// - Entries are now keyed by ip_hash_compute(ip) (HMAC-SHA256 truncated to
//   IP_HASH_LEN bytes, see ip_hash.h) instead of the raw IPv4 address, so
//   nothing that sits in this table for up to 24h reveals a real client IP.
// - Lookups (is_blocked, add_strike's "already tracked?" check,
//   clear_blacklist_ip) now go through a small open-addressing hash table
//   (g_ht_index[]) instead of a linear scan of every entry — O(1) average
//   instead of O(n).
// - Storage itself is now a sparse slot array with a 64-bit used-mask
//   instead of a densely-packed, insertion-ordered array. This means
//   removal no longer needs memmove() to shift every following entry down
//   by one slot — it just clears a bit and rebuilds the (tiny, <=64-entry)
//   hash table, which only happens on removal (periodic cleanup / explicit
//   clear), never on the hot per-packet strike/lookup path.
// - print_blacklist() can no longer print the real dotted-quad IP (the
//   table doesn't have it anymore) — it prints the stored hash in hex
//   instead. The transient async_print() of the plaintext IP at strike time
//   in add_strike() is untouched: that's a log line, not persisted storage,
//   so it still gives you something to grep for post-incident.

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include "parameters.h"

/* Wiznet dependencies */
#include "timer.h"
#include "hardware/watchdog.h"
#include "hardware/timer.h"
#include "hardware/regs/watchdog.h"
#include "hardware/uart.h"
#include "hardware/flash.h"
#include "pico/flash.h"
#include "hardware/sync.h"
#include "port_common.h"
#include "blacklist.h"
#include "ip_hash.h"
#include <pico/bootrom.h>
#include "debug.h"

/* ============================================================
 * GLOBAL BLACKLIST STATE (RAM only)
 * ============================================================ */
extern blacklist_slot_t g_blacklist;   // still used by the rest of the code

/* ============================================================
 * SPARSE SLOT ALLOCATION + HASH-TABLE INDEX (internal to this file)
 * ============================================================
 * g_used_mask   : bit i set <=> g_blacklist.entries[i] holds a live entry.
 * g_ht_index[]  : open-addressing table mapping a hash bucket to the slot
 *                 index in g_blacklist.entries[], or -1 if empty. Sized well
 *                 above MAX_BLACKLIST_ENTRY (2x) to keep the load factor low
 *                 and probe chains short.
 * ============================================================ */
#define BLACKLIST_HT_SIZE  128   // must be a power of two, > 2 * MAX_BLACKLIST_ENTRY
#define BLACKLIST_HT_MASK  (BLACKLIST_HT_SIZE - 1)

static uint64_t g_used_mask = 0;
static int16_t  g_ht_index[BLACKLIST_HT_SIZE];

_Static_assert(MAX_BLACKLIST_ENTRY <= 64, "g_used_mask is a 64-bit bitmask");
_Static_assert((BLACKLIST_HT_SIZE & (BLACKLIST_HT_SIZE - 1)) == 0,
               "BLACKLIST_HT_SIZE must be a power of two");

// Bytes from ip_hash_compute() are a keyed HMAC output, already
// ~uniformly distributed, so a straight mask of the first 4 bytes is a
// fine bucket selector (no need for a second mixing hash).
static inline uint32_t ht_bucket(const uint8_t hash[IP_HASH_LEN])
{
    uint32_t v = 0;
    memcpy(&v, hash, sizeof(v) < IP_HASH_LEN ? sizeof(v) : IP_HASH_LEN);
    return v & BLACKLIST_HT_MASK;
}

// Rebuilds the hash table from scratch based on g_used_mask + entries[].
// O(MAX_BLACKLIST_ENTRY) — only called on removal (rare: periodic cleanup
// or an explicit clear), never on the per-packet add_strike()/is_blocked()
// hot path, so this cost is negligible in practice.
static void ht_rebuild(void)
{
    memset(g_ht_index, -1, sizeof(g_ht_index));

    for (uint16_t slot = 0; slot < MAX_BLACKLIST_ENTRY; slot++) {
        if (!(g_used_mask & (1ULL << slot))) continue;

        uint32_t b = ht_bucket(g_blacklist.entries[slot].hash);
        while (g_ht_index[b] != -1) {
            b = (b + 1) & BLACKLIST_HT_MASK;
        }
        g_ht_index[b] = (int16_t)slot;
    }
}

// Inserts a freshly-populated slot into the hash table (no rebuild needed —
// safe to call standalone since we never leave tombstones: removal always
// triggers a full ht_rebuild()).
static void ht_insert(uint16_t slot)
{
    uint32_t b = ht_bucket(g_blacklist.entries[slot].hash);
    while (g_ht_index[b] != -1) {
        b = (b + 1) & BLACKLIST_HT_MASK;
    }
    g_ht_index[b] = (int16_t)slot;
}

// Returns the slot index for `hash`, or -1 if not tracked.
static int ht_lookup(const uint8_t hash[IP_HASH_LEN])
{
    uint32_t b = ht_bucket(hash);
    for (int probes = 0; probes < BLACKLIST_HT_SIZE; probes++) {
        int16_t slot = g_ht_index[b];
        if (slot == -1) return -1;   // no tombstones ever exist -> empty means "not present"
        if (memcmp(g_blacklist.entries[slot].hash, hash, IP_HASH_LEN) == 0) {
            return slot;
        }
        b = (b + 1) & BLACKLIST_HT_MASK;
    }
    return -1;
}

// Finds a free slot (first zero bit in g_used_mask), or -1 if the table is full.
static int find_free_slot(void)
{
    for (uint16_t slot = 0; slot < MAX_BLACKLIST_ENTRY; slot++) {
        if (!(g_used_mask & (1ULL << slot))) return (int)slot;
    }
    return -1;
}

/* ============================================================
 * BLACKLIST IMPLEMENTATION
 * ============================================================ */

/* * Initializes the blacklist metadata and clears out the memory slot, 
 * putting the subsystem into an empty RAM-only state.
 */
void blacklist_init(void)
{
    memset(&g_blacklist, 0, sizeof(g_blacklist));
    g_blacklist.magic = BLACKLIST_MAGIC;
    g_blacklist.ver   = BLACKLIST_VER;
    g_blacklist.seq   = 0;
    g_blacklist.num   = 0;

    g_used_mask = 0;
    memset(g_ht_index, -1, sizeof(g_ht_index));

    printf("Blacklist: RAM-only mode initialised (no persistence, IP-hashed storage)\n");
}

/* * Loops through active RAM records and prints statistics alongside 
 * details for each recorded entry (hash, strikes, block status, and age).
 * NOTE: the real IP is no longer stored, so this prints the keyed hash in
 * hex instead of a dotted-quad address — see add_strike()'s transient log
 * line if you need to correlate a hash back to an IP right at strike time.
 */
void print_blacklist(void)
{
    printf("=== BLACKLIST DUMP (RAM-only, IP-hashed) ===\n");
    printf("Total entries in RAM : %d\n", g_blacklist.num);
    printf("Permanently blocked  : %d\n", get_blocked_count());
    printf("--------------------------------------------------\n");

    if (g_blacklist.num == 0) {
        printf("Blacklist is empty.\n");
        printf("=== END BLACKLIST ===\n\n");
        return;
    }

    for (uint16_t i = 0; i < MAX_BLACKLIST_ENTRY; i++) {
        if (!(g_used_mask & (1ULL << i))) continue;
        blacklist_entry_t *e = &g_blacklist.entries[i];

        printf("[%3u] Hash: %02X%02X%02X%02X   Strikes: %3u   Blocked: %s",
               i,
               e->hash[0], e->hash[1], e->hash[2], e->hash[3],
               e->strikes,
               e->blocked ? "YES" : "NO");

        if (!e->blocked) {
            uint64_t age_us = absolute_time_diff_us(e->last_strike_time, get_absolute_time());
            printf("   (temp, age: %lu s)", (unsigned long)(age_us / 1000000ULL));
        }
        printf("\n");
    }
    printf("=== END BLACKLIST ===\n\n");
}

/* * Searches for a matching IP address (via its hash) in the tracker and 
 * completely removes its record.
 */
void clear_blacklist_ip(uint8_t ip[4])
{
    uint8_t hash[IP_HASH_LEN];
    ip_hash_compute(ip, hash);

    int slot = ht_lookup(hash);
    if (slot < 0) return;

    g_used_mask &= ~(1ULL << slot);
    g_blacklist.num--;
    ht_rebuild();   // cheap (<=64 entries) and only happens on removal
}

/* * Wipes the current global state tracking completely, resetting 
 * version codes and dropping all tracked entries from memory.
 */
void blacklist_clear_all(void)
{
    memset(&g_blacklist, 0, sizeof(g_blacklist));
    g_blacklist.magic = BLACKLIST_MAGIC;
    g_blacklist.ver   = BLACKLIST_VER;
    g_blacklist.seq   = 0;
    g_blacklist.num   = 0;

    g_used_mask = 0;
    memset(g_ht_index, -1, sizeof(g_ht_index));

    printf("=== BLACKLIST FULLY CLEARED (RAM-only) ===\n");
}

/* * Registers incident strikes against an IP address (tracked by its hash), 
 * establishes a new tracking slot if not yet seen, and evicts the oldest 
 * unblocked entry if the table is full.
 */
void add_strike(uint8_t ip[4], uint8_t amount)
{
    uint8_t hash[IP_HASH_LEN];
    ip_hash_compute(ip, hash);

    int slot = ht_lookup(hash);

    if (slot >= 0) {
        blacklist_entry_t *entry = &g_blacklist.entries[slot];
        if (entry->blocked) return;

        entry->strikes += amount;
        if (entry->strikes > 255) entry->strikes = 255;
        entry->last_strike_time = get_absolute_time();

        // Transient log only — the plaintext IP is never persisted, but
        // it's still useful at the moment of the event for correlation.
        async_print("Strike %d for ip: %d.%d.%d.%d\n ", entry->strikes, ip[0], ip[1], ip[2], ip[3]);

        if (entry->strikes >= STRIKE_MAX) {
            entry->blocked = 1;
            async_print("!!! BLACKLISTED: %d.%d.%d.%d\n", ip[0], ip[1], ip[2], ip[3]);
        }
        return;
    }

    // Not yet tracked. Table full? Evict the OLDEST unblocked entry (by
    // last_strike_time) to make room — previously this evicted the first
    // unblocked entry found in array order, which only approximated "oldest"
    // because the array used to be insertion-ordered. Now that slots are
    // reused arbitrarily, we need to actually find the minimum.
    if (g_blacklist.num >= MAX_BLACKLIST_ENTRY) {
        int oldest_slot = -1;
        uint64_t oldest_age_us = 0;

        for (uint16_t j = 0; j < MAX_BLACKLIST_ENTRY; j++) {
            if (!(g_used_mask & (1ULL << j))) continue;
            blacklist_entry_t *cand = &g_blacklist.entries[j];
            if (cand->blocked) continue;

            uint64_t age_us = absolute_time_diff_us(cand->last_strike_time, get_absolute_time());
            if (oldest_slot < 0 || age_us > oldest_age_us) {
                oldest_slot = j;
                oldest_age_us = age_us;
            }
        }

        if (oldest_slot >= 0) {
            g_used_mask &= ~(1ULL << oldest_slot);
            g_blacklist.num--;
            ht_rebuild();
        }
        // If every slot is blocked (permanently banned), the table is
        // genuinely full — the new IP simply isn't tracked this round.
        else {
            async_print("Blacklist full of permanent bans — dropping new strike untracked\n");
            return;
        }
    }

    int new_slot = find_free_slot();
    if (new_slot < 0) return; // shouldn't happen given the eviction above, but stay safe

    blacklist_entry_t *entry = &g_blacklist.entries[new_slot];
    memcpy(entry->hash, hash, IP_HASH_LEN);
    entry->strikes = amount;
    entry->blocked = 0;
    entry->last_strike_time = get_absolute_time();

    g_used_mask |= (1ULL << new_slot);
    g_blacklist.num++;
    ht_insert(new_slot);

    if (entry->strikes >= STRIKE_MAX) {
        entry->blocked = 1;
        async_print("!!! BLACKLISTED: %d.%d.%d.%d\n", ip[0], ip[1], ip[2], ip[3]);
    }
}

/* * Performs an O(1) average hash-table lookup to quickly verify if 
 * a specific IP target has crossed the max strike threshold and 
 * is currently flagged as blocked.
 */
bool is_blocked_hash(const uint8_t hash[IP_HASH_LEN])
{
    int slot = ht_lookup(hash);
    if (slot < 0) return false;
    return g_blacklist.entries[slot].blocked != 0;
}

bool is_blocked(uint8_t ip[4])
{
    uint8_t hash[IP_HASH_LEN];
    ip_hash_compute(ip, hash);
    return is_blocked_hash(hash);
}

/* * Iterates through active slots to clean out stale temporary 
 * strikes (older than 1 hour) or drop expired block bans (older than 24 hours).
 */
void blacklist_periodic_cleanup(void)
{
    // Define grace periods
    const uint64_t STRIKE_TIMEOUT_US = HOUR_MS(1) * 1000LL;   // 1 Hour for temp strikes
    const uint64_t BLOCK_TIMEOUT_US  = HOUR_MS(24) * 1000LL;  // 24 Hours for full blocks
    
    absolute_time_t now = get_absolute_time();
    bool removed_any = false;

    for (uint16_t i = 0; i < MAX_BLACKLIST_ENTRY; i++) {
        if (!(g_used_mask & (1ULL << i))) continue;

        blacklist_entry_t *e = &g_blacklist.entries[i];
        uint64_t age_us = absolute_time_diff_us(e->last_strike_time, now);
        bool should_remove = false;

        if (e->blocked) {
            // If they are blocked, check against the long timeout
            if (age_us > BLOCK_TIMEOUT_US) {
                should_remove = true;
                async_print("Cleanup: Unblocking hash %02X%02X%02X%02X (Ban expired)\n",
                            e->hash[0], e->hash[1], e->hash[2], e->hash[3]);
            }
        } else {
            // If they just have strikes, check against the short timeout
            if (age_us > STRIKE_TIMEOUT_US) {
                should_remove = true;
            }
        }

        if (should_remove) {
            g_used_mask &= ~(1ULL << i);
            g_blacklist.num--;
            removed_any = true;
        }
    }

    // One rebuild for the whole sweep, not one per removed entry.
    if (removed_any) {
        ht_rebuild();
    }
}

/* * Returns the exact numeric total of entries currently flagged 
 * under restricted/blocked status within the structure.
 */
uint16_t get_blocked_count(void)
{
    uint16_t count = 0;
    for (uint16_t i = 0; i < MAX_BLACKLIST_ENTRY; i++) {
        if (!(g_used_mask & (1ULL << i))) continue;
        if (g_blacklist.entries[i].blocked) {
            count++;
        }
    }
    return count;
}