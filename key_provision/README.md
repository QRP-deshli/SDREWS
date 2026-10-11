# key_provision

Standalone project: generates the keys and burns them into the OTP memory of an RP2350
(W6100-EVB-Pico2). **Every OTP write is permanent.**

Contents: `keygen.sh` / `keygen.bat` (OpenSSL key generation), `tools/gen_otp_secrets.c`
(host tool, plain C99), `otp_provision.c` + `CMakeLists.txt` (burner firmware for the board).

## Requirements

* OpenSSL command line tool (`openssl`) for `keygen.*`. Windows: install OpenSSL, or use the one
  in Git for Windows (`C:\Program Files\Git\usr\bin`).
* A C compiler (gcc/clang, MinGW on Windows) and `make` for the host tool.
  Optional: OpenSSL 3 development files, they enable the key/certificate match check.
* CMake and the Pico SDK for the burner firmware.

## Steps

1. **Generate keys** (creates `keys/server_key.pem`, `keys/server_crt.pem`,
   `keys/master_key.h`, `keys/ip_hash_key.h`; existing files are kept):

   ```sh
   ./keygen.sh        # Linux / macOS / Git Bash
   keygen.bat         # Windows cmd
   ```

   You can use any other tool instead of OpenSSL as long as the files have the formats listed in the
   [top-level README](../README.md#generating-the-keys). Optional environment variables for
   `keygen.sh`: `CERT_CN` (default `pico2-https`), `CERT_DAYS` (default `3650`).

2. Paste the certificate (`keys/server_crt.pem`) into `../server/web/certs.h` (`srv_crt_pem`).
   The private key is never pasted anywhere.

3. **Build the generator** (once):

   ```sh
   make                  # with key/certificate match check (needs libssl-dev / OpenSSL 3)
   make NO_OPENSSL=1     # without the check
   ```

   On Windows use MinGW / MSYS2 (`mingw32-make`).

4. **Generate the burner input** `otp_secrets.h`:

   ```sh
   tools/gen_otp_secrets keys/server_key.pem keys/master_key.h keys/ip_hash_key.h otp_secrets.h keys/server_crt.pem
   ```

5. **Build the burner**:

   ```sh
   cmake -B build -DPICO_SDK_PATH=<path to pico-sdk>
   cmake --build build
   ```

   `otp_layout.h` here is a copy of the server's (`../server/src/include/otp/otp_layout.h`);
   the build fails if the two differ.

6. Hold BOOTSEL, plug the board in, copy `build/otp_provision.uf2` to the drive.

7. Open the board's USB serial port (115200 8N1), the tool waits until you connect.
   Type `BURN` to write the keys, then `DISABLE-SWD` to disable debugging.

8. Delete `otp_secrets.h` (`make clean`). Flash the server firmware (BOOTSEL again).
   Keep `keys/` offline. Give the 16-byte master key to the clients (see `../client/README.md`).
