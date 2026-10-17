# SDREWS — Secure DDoS-Resilient Embedded Web Server

A hardware-hardened HTTPS monitoring server for the **RP2350** (Wiznet **W6100-EVB-Pico2** board) that stays reachable for legitimate users while it is being flooded, scanned and probed. Long-term secrets live in the chip's **OTP memory** (not in the firmware image), the debug port can be **permanently disabled**, and the whole thing runs in a **306 kB** firmware image at roughly **0.3 W**.

> Research paper: *"SDREWS: Secure DDoS-Resilient Embedded Web Server: Autonomous Threat Detection and Mitigation at the Edge"* — N. Kuropatkin and M. Drutarovsky, Technical University of Košice, *Advances in Electrical and Electronic Engineering (AEEE)*, 2026.
>
> SDREWS is the successor of **SLEHS** ([QRP-deshli/SLEHS](https://github.com/QRP-deshli/SLEHS)).

University work project, Technical University of Košice. Author: Nikita Kuropatkin.

---

## Table of contents

1. [What it does](#what-it-does)
2. [What is new compared to SLEHS](#what-is-new-compared-to-slehs)
3. [How the connection works](#how-the-connection-works)
4. [Defense mechanisms](#defense-mechanisms)
5. [Key infrastructure and secret protection](#key-infrastructure-and-secret-protection)
6. [Client](#client)
7. [Performance under attack](#performance-under-attack)
8. [Hardware](#hardware)
9. [Repository layout](#repository-layout)
10. [Building](#building) (including the **Mbed TLS** setup)
11. [Provisioning a board](#provisioning-a-board)
12. [Configuration](#configuration)
13. [Security notes](#security-notes)
14. [Citation, acknowledgements, license](#citation)

---

## What it does

SDREWS serves a live monitoring page (Sensirion SEN63C air-quality readings, uptime, NTP time) over **HTTPS with TLS 1.3**. The target use case is a remote installation (solar field, industrial machine) where a full server is too expensive or too power-hungry, but the device still has to be reachable over untrusted networks on a public IP.

Before any browser session is allowed, the client must pass a **lightweight pre-shared-key (PSK) handshake**. Unauthenticated traffic is dropped before any TLS memory is allocated and before any HTTP is parsed, so scanners cannot fingerprint the TLS library and application-layer floods never reach the expensive code. The server also detects and blocks network attacks on its own, with no external firewall.

---

## What is new compared to SLEHS

| Area | SLEHS (prototype) | SDREWS |
|---|---|---|
| Secrets | Pre-shared key in a header file inside the firmware, TLS key and cert in headers | **Master key, TLS private key and IP-hash key are burned into RP2350 OTP**; only the public certificate stays in the firmware |
| Debug port | Open | **SWD permanently disabled** (CRIT1 fuses) after provisioning |
| Key rotation | Reflash | **4 OTP slots**, newest committed slot wins (up to 3 key updates per chip) |
| Handshake MAC | HMAC-based | **Chaskey** MAC (ISO/IEC 29192-6) for key derivation and frame tags; session key re-keyed every 1 000 messages |
| IP storage in RAM | Plain IPv4 | **Keyed HMAC-SHA256 digest** (4 bytes) using the OTP-stored key |
| Client key storage | Plain-text header | **Argon2id** passphrase-wrapped container (`master_key.enc`) |
| Client timing | Passive 10 s waits | **"Close-and-reshoot"**: 3 s connect / 5 s reply, fresh socket on every stall, jittered retries |
| Socket layout | TLS on its own socket | Custom protocol and HTTPS **share sockets 0–3** (never concurrent); DHCP + SNTP share socket 4 |
| Firmware size | 403 kB | **306 kB** |
| Provisioning | Manual | Scripted key generation, host validation tool, two-stage burner firmware |

---

## How the connection works

```
Pre-phase — Anti-SYN timer
  TCP SYN / SYN-ACK / ACK
  The client must send its Init Frame immediately after the final ACK (strict timer).
  Slow or half-open connections are dropped.

Phase I — Mutual cryptographic authentication
  Client → Server   Init Frame   [client nonce Nc, 32 bit, CSPRNG]
  Server → Client   Nonce Frame  [server nonce Ns, 32 bit, hardware entropy]
  Both sides        Ksess    = MAC_Kshrd(Nc ∥ Ns)
  Client → Server   Auth Frame   Tag_auth = MAC_Ksess(auth data)   (64-bit tag)
  Server verifies the tag, which proves the client holds the pre-shared key and
  binds the session to the fresh nonce pair (replayed tags are useless).

  Post-auth commands:
    "stats" → short-term (hourly) diagnostics     (TESTING builds only)
    "info"  → aggregated long-term metrics         (TESTING builds only)
    "web"   → whitelist the client IP and start Phase II
    anything else → uniform fallback reply "system is up"

Phase II — Exclusive HTTPS session
  • TLS 1.3, cipher suite TLS_CHACHA20_POLY1305_SHA256
    x25519 key exchange, ecdsa_secp256r1_sha256 signatures
  • Only the whitelisted IP can connect
  • 15-second window to request the page before the socket is torn down
  • Page refreshes itself every 10 seconds with live telemetry
  • Only one HTTPS session at a time; Phase I is disabled while Phase II is active
```

The custom protocol and HTTPS both listen on **TCP 443**. The server switches between the two modes (`current_port_mode`); they are never active at the same time.

### Frame format

All protocol messages use a packed, byte-aligned layout:

| Field | Size | Meaning |
|---|---|---|
| `magic` | 2 B | Identifier |
| `ver` | 1 B | Protocol version |
| `cmd` | 1 B | Message type |
| `cnt` | 4 B | Sequence counter |
| `len` | 2 B | Payload length (max 128) |
| `tag` | 8 B | Chaskey MAC tag |
| `data` | ≤ 128 B | Payload |

Every incoming frame is checked **before** any payload processing: command order must match the expected state transition, `cnt` must be strictly greater than the previous valid counter (replay protection), and `len` > 128 is rejected immediately. Chaskey was chosen because it needs no lookup tables (no cache-timing side channels), is fast on 32-bit MCUs without accelerators, and has a tiny memory footprint.

---

## Defense mechanisms

All of this runs in RAM on the MCU, in front of the TLS stack.

### Adaptive anti-SYN-flood control

The W6100 has hardware sockets only (4 are used by the server), so a SYN flood can lock all descriptors quickly. SDREWS gives every source IP a timeout for returning the final ACK and tightens it as that IP keeps failing:

| State | ACK timeout |
|---|---|
| New IP (`T_init`) | 250 ms |
| 10 failures (`T_es1`) | 500 ms |
| 15 failures (`T_es2`) | 1 s |
| **18 failures (`N_max`)** | connection terminated, **IP blacklisted** |

The tracking table holds **32 IPs** and idle entries are cleared hourly. A single-socket flood is isolated in about **8 s**, a flood of all four sockets in about **2.5 s**. After the ACK the client has `T_max` = **50 ms** to send the Init Frame.

### Volatile RAM blacklist

* **64 slots**, 14 bytes each (4 B keyed IP hash, 1 B strike count, 1 B status flag, 8 B timestamp) = **896 bytes** (under 0.18 % of the 520 kB SRAM).
* Protocol violations (bad magic, out-of-order `cmd`, stale `cnt`, malformed header) add a **strike**. **4 strikes → 24 h ban.** Strike records are cleared by the hourly flush.
* Every incoming connection is checked against the blacklist first. Banned sources are dropped in **35–222 µs** (typically ~70 µs), which corresponds to roughly 4 500 – 28 500 drops per second (`capacity = 1 000 000 µs / disconnect latency`).
* The table is **RAM only** and is reset by a reboot or power loss.

### Silent to scanners

* ICMP echo is disabled, so ping sweeps see an offline host.
* Port 443 is visible as open to `nmap -sS` / `masscan`, because the W6100 answers SYN in hardware. That cannot be avoided on this chip.
* Service-version detection and TLS cipher enumeration (`ssl-enum-ciphers`) fail: the connection is rejected during Phase I, before Mbed TLS is touched, so the TLS library version, OS and platform stay hidden.

---

## Key infrastructure and secret protection

### Three secrets, all generated offline

| Secret | Size | Purpose |
|---|---|---|
| **Master key** `K_shrd` | 128 bit | Chaskey authentication, session key derivation (Phase I) |
| **TLS private key** `K_tls` | 256 bit ECDSA P-256 | Server authentication in Phase II |
| **IP hash key** `K_ip` | 256 bit | HMAC-SHA256 key for the IP tables, so RAM dumps cannot reveal which IPs were banned |

### OTP layout

The RP2350 OTP is an antifuse matrix: bits can be blown to 1, never cleared. SDREWS uses it in **ECC mode** (16 data bits per 24-bit row) and splits the user area into **four independent 64-row slots**:

| Content | Rows | Size |
|---|---|---|
| `K_shrd` | 0–7 | 16 B |
| `K_tls` | 8–23 | 32 B |
| `K_ip` | 24–39 | 32 B |
| Commit marker `0x4B59` | 40 | 2 B (written **last**) |

* A slot without the commit marker is ignored, so a power failure during burning cannot leave half-written keys in use.
* At boot the firmware scans slots **newest → oldest (3 → 0)** and uses the first committed one. That allows up to three later key updates. If no valid slot exists the device halts instead of running with default keys.
* After burning, the page's lock register is set: **read-only for secure code, inaccessible to non-secure code, debuggers and the USB bootloader (`picotool`)**.
* `K_shrd` and `K_ip` are loaded into RAM at boot. `K_tls` is read **on demand** only when entering Phase II, wrapped into a 51-byte SEC1 `ECPrivateKey` DER structure, parsed by Mbed TLS, and the temporary buffers are zeroized immediately.

### SWD lock

Provisioning stage 2 (`DISABLE-SWD`) sets `DEBUG_DISABLE` and `SECURE_DEBUG_DISABLE` in the CRIT1 OTP register. Without this, anyone with brief physical access to SWCLK/SWDIO could halt the core and dump SRAM, where the keys must live while the device runs. The lock takes effect after the next power cycle and is **irreversible**.

### Limits

OTP locks and the SWD lock protect secrets *at rest*. `K_sess` and the TLS key must still be in RAM while Phase II is active.

---

## Client

`client/` contains a portable C11 command line client with no external dependencies (Argon2 reference sources are bundled).

* **`keywrap`** encrypts the 16-byte master key under a passphrase using **Argon2id** (64 MiB, 3 passes, 1 lane) with a keyed **BLAKE2b** integrity tag, and writes `master_key.enc`. The plaintext key is then deleted.
* **`client_connect`** asks for the passphrase once at start (before any socket is opened), then connects.

**Close-and-reshoot.** The server's windows are tight, and long passive waits on a stalled socket waste the 15 s user budget. The client therefore:

| Parameter | Value | Why |
|---|---|---|
| Connect timeout | 3 s | Abandon a stalled connect and open a fresh socket on a new local port |
| Reply timeout | 5 s | Bound the wait for server replies |
| Retry pause | 300 ms + U[0, 300] ms | Avoids a machine-like cadence that would trigger the server's strike counters |
| Attempts | unlimited | Loops until the `web` command is accepted |

Further optimizations: the Init Frame (with the CSPRNG nonce) is **pre-built before `connect()`** so it goes out immediately after the ACK, and `TCP_NODELAY` is set so the small frame is never buffered.

---

## Performance under attack

Testbed: SDREWS on W6100-EVB-Pico2 with a SEN63C sensor, three Kali Linux machines running `hping3` for the SYN flood, and a legitimate client ~250 ms RTT away (11 hops, 3 countries). The baseline is the same hardware running a standard single-socket Pico SDK HTTPS server with no pre-authentication, no stateful validation and no filtering. Each cell is 250 connection attempts.

**Legitimate client success rate under SYN flood**

| Attack load | SDREWS | Baseline |
|---|---|---|
| 0 PPS | **100 %** (250/250) | 100 % |
| 1 000 PPS | **100 %** (250/250) | 0 % |
| 5 000 PPS | **56 %** (140/250) | 0 % |
| 10 000 PPS | **26 %** (65/250) | 0 % |
| 25 000 PPS | **15 %** (37/250) | 0 % |
| 40 000 PPS | **13 %** (32/250) | 0 % |
| 50 000 PPS | **11 %** (27/250) | 0 % |

The decline at high rates comes from SPI bus contention and socket pool saturation on the W6100, not from a crash. SDREWS stays up and keeps serving.

**Average time to establish an HTTPS session (close-and-reshoot)**

| Attack load | Time | State |
|---|---|---|
| 1 000 PPS | 7 s | Fully responsive |
| 5 000 PPS | 10 s | Minor jitter |
| 10 000 PPS | 14 s | Moderate contention |
| 25 000 PPS | 29 s | High contention |
| 40 000 PPS | 1 m 10 s | Degraded, needs retries |
| 50 000 PPS | 2 m 10 s | Severely degraded, still functional |

**Other attacks**

| Test | SDREWS | Baseline |
|---|---|---|
| Port scan (`nmap`, `masscan`) | Port 443 detected | Port 443 detected |
| TLS version / cipher enumeration | Blocked in Phase I | Full enumeration |
| ICMP echo sweep | Silent | Responded |
| 1 000 concurrent HTTP GETs (`curl`) | Operational | Unresponsive |
| Slow connections (`slowhttptest`) | Operational | Unresponsive |

---

## Hardware

| Component | Details |
|---|---|
| Board | Wiznet W6100-EVB-Pico2 |
| MCU | RP2350, dual-core Cortex-M33 / RISC-V, 150 MHz |
| RAM | 520 kB SRAM |
| Flash | 2 MB, 16 kB XIP cache |
| Network chip | W6100 hardware TCP/IP (TCP, UDP, IPv4/IPv6, ICMP, ARP), 8 sockets, 32 kB buffer |
| Sensor | Sensirion SEN63C over I²C |
| Power draw | ~0.3 W average |
| Firmware size | 306 kB Flash |

Socket use: sockets 0–3 for the custom protocol **and** HTTPS/TLS (never at the same time), socket 4 for DHCP + SNTP, sockets 5–7 unused.

---

## Repository layout

The repository holds **three independent projects**. They do not share code and do not build each other. They only agree on a few small file formats and on one header (`otp_layout.h`).

| Folder | What it is | Runs on | Build |
|---|---|---|---|
| `client/` | `client_connect` and the `keywrap` PIN tool | Linux, Windows, macOS | `make` (plain C) |
| `server/` | HTTPS + custom protocol firmware with SEN63C | RP2350 board | CMake + Pico SDK + WIZnet SDK + Mbed TLS |
| `key_provision/` | Key generation and the one-time OTP burner | Host tools + RP2350 | `make` (host tool), CMake (burner) |

Each folder has its own README with full steps, and any one folder can be used on its own.

```
ssl_config.h               # Mbed TLS configuration, copy into the WIZnet tree (see Building)

server/
├── sdrews.c               # Main application (target name: sdrews)
├── CMakeLists.txt
├── web/
│   ├── certs.h            # PUBLIC certificate only (srv_crt_pem)
│   └── page.h             # Embedded HTML/CSS of the monitoring page
└── src/
    ├── include/           # Headers (parameters.h, otp/otp_layout.h, sensor/ ...)
    ├── chaskey.c          # Chaskey MAC
    ├── crypto.c           # Key derivation, MAC helpers
    ├── communication.c    # Phase I handshake and command handling
    ├── https_handshake.c  # Phase II: Mbed TLS session setup
    ├── blacklist.c        # Strikes and bans
    ├── ip_hash.c          # Keyed HMAC-SHA256 IP hashing
    ├── otp_keys.c         # OTP slot scan, key loading, TLS key DER
    ├── network_data.c     # Telemetry history
    ├── sntp_time.c        # NTP time
    ├── timing.c, restart.c, config.c, debug.c
    └── sensor/            # Sensirion SEN63C driver

client/
├── client_connect.c, keywrap_tool.c
├── src/                   # Network, Chaskey, keywrap, Argon2id glue, config
├── third_party/argon2/    # Reference Argon2 (CC0 / Apache-2.0)
└── tests/                 # Argon2 self-test, mock server

key_provision/
├── keygen.sh / keygen.bat # OpenSSL key generation
├── tools/gen_otp_secrets.c# Host tool: validates keys, emits otp_secrets.h
├── otp_provision.c        # Burner firmware (BURN / DISABLE-SWD)
└── otp_layout.h           # Must be identical to server/src/include/otp/otp_layout.h
```

### How the parts relate

```
 key_provision/keygen.*  ──►  server_key.pem  ──┐
   (OpenSSL, any OS)          server_crt.pem     │  gen_otp_secrets ──► otp_secrets.h ──► otp_provision.uf2
                              ip_hash_key.h    ──┤                                         (burns the board's OTP)
                              master_key.h     ──┘
                                   │
                                   ├──► client/keywrap ──► master_key.enc ──► client_connect (asks for PIN)
                                   └──► same 16 bytes live in the board's OTP ──► server/ reads them at boot
 server_crt.pem ──► pasted into server/web/certs.h (public part only)
```

The only coupling between folders: `server/src/include/otp/otp_layout.h` and `key_provision/otp_layout.h` **must be identical** (the burner's CMake compares them and fails if they differ when both folders are present), and the key file formats below.

---

## Building

### Toolchain versions used in the paper

* [Raspberry Pi Pico SDK](https://github.com/raspberrypi/pico-sdk) **v2.2.0**
* [WIZnet SDK (WIZnet-PICO-C)](https://github.com/WIZnet-ioLibrary/WIZnet-PICO-C) **v2.1.0**
* [Mbed TLS](https://github.com/Mbed-TLS/mbedtls) **v3.6.0**, as `libraries/mbedtls/` inside the WIZnet tree
* GNU Arm Embedded Toolchain **v15.2.Rel1**
* CMake ≥ 3.13 and Ninja

### 1. Prepare the WIZnet tree

The server firmware is **not** a standalone CMake project. It is built as an example inside the WIZnet-PICO-C tree, which provides the Ethernet/DHCP/DNS/SNTP libraries, the Mbed TLS submodule and the Mbed TLS port.

```bash
git clone --recurse-submodules https://github.com/WIZnet-ioLibrary/WIZnet-PICO-C.git
cd WIZnet-PICO-C
git submodule update --init --recursive      # fetches libraries/mbedtls (use v3.6.0)
```

Copy this repository's `server/` folder into the tree's `examples/` directory (so it is two levels below the tree root) and register it like the other examples in `examples/CMakeLists.txt`.

`server/CMakeLists.txt` expects this layout, because it uses:

* `../../libraries/mbedtls` — the Mbed TLS sources
* `../../port/mbedtls` — the WIZnet-provided TLS configuration (contains `ssl_config.h`)
* the `ETHERNET_FILES`, `IOLIBRARY_FILES`, `DHCP_FILES`, `DNS_FILES`, `SNTP_FILES` and `TIMER_FILES` targets from the tree

If your layout differs, change the paths at the top of `server/CMakeLists.txt`. The firmware links `mbedtls`, `mbedx509` and `mbedcrypto`.

### 2. Mbed TLS configuration (`ssl_config.h`)

> **Required before building.** The WIZnet port ships a generic Mbed TLS config. SDREWS needs a specific one to enable what it uses and to switch off the rest so the firmware stays small.

Replace the file

```
port/mbedtls/inc/ssl_config.h
```

with the `ssl_config.h` from the root of this repository **before running `cmake`**. Without it the build either fails or yields a non-functional TLS configuration.

What the configuration provides:

| Area | Setting |
|---|---|
| Protocol | **TLS 1.3 only** (`MBEDTLS_SSL_PROTO_TLS1_3`, ephemeral key exchange), TLS 1.2 dropped |
| Role | Server (`MBEDTLS_SSL_SRV_C`) |
| AEAD | `MBEDTLS_CHACHA20_C`, `MBEDTLS_POLY1305_C`, `MBEDTLS_CHACHAPOLY_C` (→ `TLS_CHACHA20_POLY1305_SHA256`) |
| Key exchange | X25519 (`MBEDTLS_ECP_DP_CURVE25519_ENABLED`, `MBEDTLS_ECDH_C`) |
| Signatures | ECDSA on P-256 (`MBEDTLS_ECDSA_C`, `MBEDTLS_ECP_DP_SECP256R1_ENABLED`) |
| Hash | `MBEDTLS_SHA256_C`, `MBEDTLS_MD_C` (also used for the HMAC-SHA256 IP hashing in `ip_hash.c`) |
| Certificates / keys | `MBEDTLS_X509_CRT_PARSE_C`, `MBEDTLS_PK_PARSE_C`, `MBEDTLS_PEM_PARSE_C`, `MBEDTLS_ASN1_*`, `MBEDTLS_BIGNUM_C` |
| Randomness | `MBEDTLS_CTR_DRBG_C` fed by a Pico entropy source; `MBEDTLS_NO_PLATFORM_ENTROPY` set |
| Size | Error strings stubbed (`MBEDTLS_ERROR_STRERROR_DUMMY`), unneeded ciphers and protocols disabled |

**How SDREWS uses Mbed TLS:**

* Mbed TLS is only reached in **Phase II**. Phase I (Chaskey, framing, blacklist) does not use it, which is why unauthenticated scanners never trigger any TLS allocation.
* The TLS private key is read from OTP on demand, wrapped into a fixed 51-byte SEC1 `ECPrivateKey` DER, parsed with `mbedtls_pk_parse_key`, and the stack buffers are zeroized right after.
* `mbedtls_md_hmac()` with SHA-256 provides the 4-byte keyed IP digests for the blacklist and tracker tables.

*Optional:* hardware SHA-256 can be routed through Mbed TLS by adding `#define MBEDTLS_SHA256_ALT` to `ssl_config.h` and linking `pico_sha256` in `server/CMakeLists.txt`. It is not required and is not enabled by default.

### 3. Provision the board and put the certificate in the firmware

See [Provisioning a board](#provisioning-a-board). The public certificate (`keys/server_crt.pem`) goes into `server/web/certs.h` (`srv_crt_pem`) **before** you build the server. The private key is never pasted anywhere.

### 4. Build the server firmware

```bash
mkdir build && cd build
cmake .. -DPICO_BOARD=pico2 -DPICO_SDK_PATH=<path to pico-sdk>
ninja sdrews
```

The resulting file is `sdrews.uf2`. Hold **BOOTSEL**, plug the board in, and copy the `.uf2` to the USB drive.

### 5. Build the client

```bash
cd client
make                      # Linux / macOS
mingw32-make              # Windows with MinGW
make windows              # cross-compile 64-bit .exe on Linux (needs gcc-mingw-w64-x86-64) -> win64/
make windows32            # 32-bit variant -> win32/
make test                 # Argon2id / BLAKE2b self-test
```

Output: `client_connect` and `keywrap`. No external libraries are needed.

---

## Provisioning a board

> ⚠️ **Every OTP write is permanent, and `DISABLE-SWD` is irreversible.** Try the whole flow on a spare board first. Run `DISABLE-SWD` only after you are happy with the burned keys.

### Generating the keys

`key_provision/keygen.sh` (Linux, macOS, Git Bash, WSL) and `keygen.bat` (Windows) do the same with **OpenSSL**. They write into `key_provision/keys/` and never overwrite existing files:

```sh
cd key_provision
./keygen.sh          # Linux / macOS / Git Bash
keygen.bat           # Windows
```

Optional environment variables for `keygen.sh`: `CERT_CN` (default `pico2-https`), `CERT_DAYS` (default `3650`).

OpenSSL is only the preferred tool. Any other tool works as long as the files look like this:

| File | Content | Used by |
|---|---|---|
| `server_key.pem` | Unencrypted ECDSA **P-256** private key, PEM (SEC1 `EC PRIVATE KEY` or PKCS#8) | `key_provision` (burned into OTP) |
| `server_crt.pem` | X.509 certificate for that key, PEM | pasted into `server/web/certs.h` |
| `master_key.h` | `const uint8_t MASTER_KEY[] = { 0x.., ... };` exactly **16** random, non-zero bytes | `key_provision`, `client/keywrap` |
| `ip_hash_key.h` | `const uint8_t IP_HASH_KEY[] = { 0x.., ... };` exactly **32** random, non-zero bytes | `key_provision` |

Use a cryptographically secure random source for the two symmetric keys.

### Steps

```sh
cd key_provision

# 1. Build the host tool (once)
make                    # with key/certificate match check (needs OpenSSL 3 dev files)
make NO_OPENSSL=1       # without the check

# 2. Generate the burner input (checks bit lengths, rejects all-zero keys and old test vectors)
tools/gen_otp_secrets keys/server_key.pem keys/master_key.h keys/ip_hash_key.h otp_secrets.h keys/server_crt.pem

# 3. Build the burner firmware
cmake -B build -DPICO_SDK_PATH=<path to pico-sdk>
cmake --build build
```

4. Hold BOOTSEL, plug the board in, copy `build/otp_provision.uf2` to the drive.
5. Open the board's USB serial port (**115200 8N1**). The tool waits until you connect.
6. Type **`BURN`**: picks the first free slot, writes the keys, reads them back, writes the commit marker last, then locks the page.
7. Type **`DISABLE-SWD`**: blows the debug-disable fuses (takes effect after the next power cycle).
8. Delete `otp_secrets.h` (`make clean`). Flash the server firmware (BOOTSEL again). Keep `keys/` offline.

### Giving the key to clients

```sh
cd client
./keywrap master_key.h master_key.enc     # asks for a passphrase twice
```

Then delete `master_key.h` and every copy of it. Use a **passphrase**, not a 4-digit PIN: the file can be attacked offline and Argon2id only slows each guess.

### Using the client

```sh
client_connect <IP> web                    # retries until the server accepts, then prints ACTION REQUIRED
client_connect <IP> basic|stats [batch_runs]
```

After `web` is accepted, open `https://<IP>/` in a browser **within 15 seconds**. The certificate is self-signed, so accept it manually or install it on the client. `MASTER_KEY_FILE` overrides the path to `master_key.enc`.

Every failure prints its reason, for example `Failed to read INIT header (closed by the server)` means the server dropped the connection (ACK/Init window missed, or your IP is blacklisted), and `(timed out, no reply)` means the server stayed silent. Do not shorten the retry pause much: the server strikes IPs for failed handshakes.

---

## Configuration

Server parameters are in `server/src/include/parameters.h`.

### Deployment mode (`DEPLOYMENT_OPTION`)

```c
#define TESTING 0   // "stats" and "info" commands enabled
#define PROD    1   // diagnostic commands disabled, minimal attack surface

#define DEPLOYMENT_OPTION TESTING   // <-- change before flashing
```

| Mode | `"stats"` | `"info"` | Use when |
|---|---|---|---|
| `TESTING` | enabled | enabled | Development, evaluation, research |
| `PROD` | disabled | disabled | Any real deployment |

**Set `PROD` before deploying to a public network.** In `PROD` the only meaningful post-auth command is `"web"`, which minimises what an attacker who somehow authenticates can probe.

### Logging (`DEBUG_LOG`)

```c
#define DEBUG_LOG 0
```

`1` enables `async_print()` event logging. `0` compiles every `async_print()` call away: no formatting, no inter-core queue traffic, no USB/UART work, and the core-1 print task is not started. **Use `0` for flood tests and production** so no CPU time goes to logs.

### Other parameters

| Parameter | Meaning |
|---|---|
| `LOCATION` (`LAB` / `OFFICE` / `OFFICE2`) | Selects the device MAC address; edit the `DEVICE_MAC_*` values for your network |
| `MAX_SOCKETS` | Hardware socket limit used by the server (4) |
| `TRACKER_SIZE` | Anti-SYN tracking table size (32) |
| `MAX_BLACKLIST_ENTRY`, `STRIKE_MAX` | Blacklist slots (64) and strikes before a ban (4) |
| `INIT_PERIOD` | Time allowed between final ACK and the Init Frame (50 ms) |
| `TIMEOUT_*`, `MID_CONG`, `HIGH_CONG`, `SYN_FLOOD`, `ULTIMATE_BAN` | Anti-SYN timeout scaling |
| `MAX_HISTORY_HOURS` | Telemetry history length (336 h = 2 weeks) |
| `DHCP_ACT` | `1` DHCP, `0` static IP |
| `TIMEZONE` | SNTP timezone offset |

Client timing is in `client/src/include/parameters.h`.

---

## Security notes

* **OTP is permanent.** Burn only keys you intend to keep. A re-key consumes one of the four slots.
* **`DISABLE-SWD` is permanent.** After it, you cannot attach a debugger to that chip. Use a development board for firmware work.
* **Keep `keys/` offline** and distribute the master key only to legitimate clients, wrapped with `keywrap`.
* **Use a strong passphrase** for `master_key.enc`.
* **Set `DEPLOYMENT_OPTION` to `PROD`** and **`DEBUG_LOG` to `0`** for real deployments.
* The server uses a **self-signed certificate**. Clients must accept it manually or have it pre-installed.
* The blacklist is **volatile**: a reboot or power loss clears it.
* Port 443 will always show as open to scanners (the W6100 answers SYN in hardware). SDREWS hides what is behind it, not that it is there.
* Under very heavy floods the W6100's SPI bus and socket pool saturate and legitimate success rate drops (see the table above). SDREWS keeps running, but it is not a replacement for upstream DDoS filtering against multi-gigabit attacks.

### Secrets: what must never reach git

`.gitignore` should exclude `keys/`, `*.pem`, `master_key.h`, `master_key.enc`, `ip_hash_key.h`, `otp_secrets.h` and all build output. Before the first push run `git status` and make sure none of these appear. If any of them were ever committed or shared, generate fresh keys: git history keeps them forever.

---

<a id="citation"></a>
## Citation

If you use SDREWS in your research, please cite:

> N. Kuropatkin and M. Drutarovsky, "SDREWS: Secure DDoS-Resilient Embedded Web Server: Autonomous Threat Detection and Mitigation at the Edge," *Advances in Electrical and Electronic Engineering*, 2026.

The earlier prototype: N. Kuropatkin, *SLEHS: Secure Lightweight Embedded HTTPS Server*, GitHub, 2026.

## Acknowledgements

Co-financed by the **European Union** through the Slovakia Programme under project No. NFP401101C360 (*Research and development of advanced artificial intelligence solutions for the detection of cyber threats and defense against sophisticated attacks*) and by the **Slovak Cultural and Educational Grant Agency (KEGA)** under Contract No. 041TUKE-4/2025. Hardware provided by **SOS Electronic**.

## License

BSD 2-Clause, see [LICENSE](LICENSE). `client/third_party/argon2` is the reference implementation by the Argon2 authors (CC0 / Apache-2.0, see its own LICENSE).
