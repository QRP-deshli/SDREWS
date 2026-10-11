# server

Standalone firmware for the W6100-EVB-Pico2 (RP2350): HTTPS page plus the custom
authenticated protocol, with a SEN63C sensor on I2C. It contains **no secrets**: the master
key, the TLS private key and the IP hash key are read from the chip's OTP, which is filled
once by `../key_provision`.

## Requirements

* Pico SDK (2.x), `arm-none-eabi-gcc`, CMake, Ninja/Make.
* The WIZnet W6100-EVB-Pico2 example tree. `CMakeLists.txt` expects this folder to sit two levels
  below the tree root, because it uses `../../libraries/mbedtls`, `../../port/mbedtls` and the
  `ETHERNET_FILES`, `IOLIBRARY_FILES`, `DHCP_FILES`, `DNS_FILES`, `SNTP_FILES`, `TIMER_FILES`
  CMake targets provided by it. Adjust the paths at the top of `CMakeLists.txt` if your layout differs.

## Build and flash

1. Provision the board once: see `../key_provision/README.md` (keys into OTP, certificate into
   `web/certs.h`).
2. Build with CMake as any other example of that tree, for example
   `cmake -B build -DPICO_SDK_PATH=<pico-sdk> && cmake --build build`.
3. Hold BOOTSEL, plug the board in, copy `build/slehs_otp.uf2` to the drive.

`src/include/otp/otp_layout.h` must stay identical to `../key_provision/otp_layout.h`.
Network and protocol timing is configured in `src/include/parameters.h`.
