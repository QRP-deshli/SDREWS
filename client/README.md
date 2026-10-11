# client

Standalone command line client for the server in `../server`. Plain C, no external dependencies.

## Build
- Linux:               `make`
- Windows (MinGW):     `mingw32-make`
- Windows from Linux:  `sudo apt install gcc-mingw-w64-x86-64 && make windows`  -> `win64/*.exe`
  (32-bit: `make windows32`)
- Self-test of the crypto: `make test`

## One-time: protect the master key with a PIN
The 16-byte master key comes from `key_provision/keygen.sh` / `keygen.bat` (`keys/master_key.h`), or from any other
tool that writes the same format (see the top-level README). It must be the same key that was burned into the server.

    keywrap master_key.h master_key.enc      (asks for a PIN twice)
Then delete `master_key.h` and every copy of it. The client reads `master_key.enc`
and asks for the PIN at start (3 tries). If only the old plain `master_key.h` exists the
client still works but prints a warning. `MASTER_KEY_FILE` overrides the path.

Use a passphrase, not a 4-digit PIN: the file can be brute-forced offline, and Argon2id
only slows each guess (~0.2 s here). A short numeric PIN is cracked in minutes/hours.

## Use
    client_connect <IP> web          keeps retrying until the server accepts, then prints ACTION REQUIRED
    client_connect <IP> basic|stats [batch_runs]

Timing (src/include/parameters.h): connect 3000 ms, reply 5000 ms (originally 10 s each),
retry pause 300-600 ms. Every failure prints its reason, e.g.
`Failed to read INIT header (closed by the server)` = the server dropped the connection
(ACK/INIT window, or this IP is blacklisted); `(timed out, no reply)` = the server stayed silent.
Don't make the retry pause much smaller: the server strikes an IP for failed handshakes
and bans it after a few.

Argon2id/BLAKE2b come from the official P-H-C sources in third_party/argon2 (CC0 / Apache-2.0),
built single-threaded (-DARGON2_NO_THREADS).
