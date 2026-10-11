# Secure OTP server for Raspberry Pi Pico 2 (RP2350) + client + key provisioning

University work project, Technical University of Košice. Author: Nikita Kuropatkin.

The repository holds **three independent projects**. They do not share code and do not
build each other. They only agree on a few small file formats and on one header
(`otp_layout.h`, see below).

| Folder           | What it is                                                                 | Runs on                | Build                       |
|------------------|----------------------------------------------------------------------------|------------------------|-----------------------------|
| `client/`        | Command line client (`client_connect`) and the PIN tool for the master key (`keywrap`) | Linux, Windows, macOS  | `make` (plain C, no deps)   |
| `server/`        | Firmware: HTTPS + custom protocol server on W6100-EVB-Pico2 with a SEN63C sensor | RP2350 board           | CMake + Pico SDK            |
| `key_provision/` | Key generation (`keygen.sh` / `keygen.bat`) and the one-time OTP burner firmware | Host tools + RP2350    | `make` (host tool), CMake (burner) |

Each folder has its own README with the full build and usage steps. You can take one
folder out of the repository and use it alone.

## How the parts relate

```
 key_provision/keygen.*  ──►  server_key.pem  ──┐
   (OpenSSL, any OS)         server_crt.pem     │  gen_otp_secrets  ──► otp_secrets.h ──► otp_provision.uf2
                             ip_hash_key.h    ──┤                                          (burns OTP of the board)
                             master_key.h     ──┘
                                  │
                                  ├──► client/keywrap  ──►  master_key.enc  ──► client_connect (asks for PIN)
                                  └──► same 16 bytes live in the board's OTP ──► server/ reads them at boot
 server_crt.pem ──► pasted into server/web/certs.h (public part only)
```

* The **server** never contains secrets in its source. The master key, the TLS private
  key and the IP hash key are read from the chip's OTP memory.
* The **client** needs the same 16-byte master key as the server. It keeps it in
  `master_key.enc`, protected by a PIN/passphrase (Argon2id).
* The **provisioning** step is done once per board: it generates the keys and burns them
  into OTP.

### The only coupling between the folders

* `server/src/include/otp/otp_layout.h` and `key_provision/otp_layout.h` must be
  identical (where the keys sit in OTP). The burner's CMake compares them automatically
  when both folders are present, and fails if they differ. If you use only one folder,
  keep the copy in sync by hand.
* The key file formats below.

## Generating the keys

`key_provision/keygen.sh` (Linux, macOS, Git Bash, WSL) and `key_provision/keygen.bat`
(Windows cmd) do the same thing with **OpenSSL**:

```sh
cd key_provision
./keygen.sh          # Linux / macOS / Git Bash
keygen.bat           # Windows
```

They write into `key_provision/keys/` (git-ignored) and never overwrite existing files.

**OpenSSL is only our preferred tool.** The other projects only look at the resulting
files, so you may produce them any way you like (other OpenSSL commands, `step`,
`certtool`, Python, a hardware RNG, ...) as long as the files look like this:

| File             | Content                                                                                   | Used by |
|------------------|-------------------------------------------------------------------------------------------|---------|
| `server_key.pem` | Unencrypted ECDSA **P-256** private key, PEM (SEC1 `EC PRIVATE KEY` or PKCS#8 both work)  | `key_provision` (burned into OTP) |
| `server_crt.pem` | X.509 certificate for that key, PEM                                                       | pasted into `server/web/certs.h` |
| `master_key.h`   | `const uint8_t MASTER_KEY[] = { 0x.., ... };` exactly **16** random, non-zero bytes, every byte written as `0xNN` | `key_provision`, `client/keywrap` |
| `ip_hash_key.h`  | `const uint8_t IP_HASH_KEY[] = { 0x.., ... };` exactly **32** random, non-zero bytes      | `key_provision` |

Use a cryptographically secure random source for the two symmetric keys.

## Secrets: what must never reach git

`.gitignore` already excludes `keys/`, `*.pem`, `master_key.h`, `master_key.enc`,
`ip_hash_key.h`, `otp_secrets.h` and all build output. Before the first push run
`git status` and make sure none of these show up. If any of these files were ever
committed or shared before, generate fresh keys: history keeps them forever.

## License

BSD 2-Clause, see [LICENSE](LICENSE). `client/third_party/argon2` is the reference
implementation by the Argon2 authors (CC0 / Apache-2.0, see its own LICENSE).
