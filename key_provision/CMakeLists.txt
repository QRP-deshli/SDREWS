# == DO NOT EDIT THE FOLLOWING LINES for the Raspberry Pi Pico VS Code Extension to work ==
if(WIN32)
    set(USERHOME $ENV{USERPROFILE})
else()
    set(USERHOME $ENV{HOME})
endif()
set(sdkVersion 2.3.1)
set(toolchainVersion 15_2_Rel1)
set(picotoolVersion 2.3.1)
set(picoVscode ${USERHOME}/.pico-sdk/cmake/pico-vscode.cmake)
if (EXISTS ${picoVscode})
    include(${picoVscode})
endif()
# ====================================================================================
# OTP provisioning tool for RP2350 (W6100-EVB-Pico2)
# Burns MASTER_KEY + TLS private key + IP hash key into OTP, locks the page, optionally disables SWD.
#
#   tools/gen_otp_secrets <key_file> <master_file> <iphash_file> otp_secrets.h <cert_file>   (see tools/gen_otp_secrets.c)
#   cmake -B build -DPICO_SDK_PATH=<path to pico-sdk>
#   cmake --build build
#   -> flash build/otp_provision.uf2 via BOOTSEL, open the USB serial port, follow the prompts.
cmake_minimum_required(VERSION 3.13)

set(PICO_PLATFORM rp2350)
set(PICO_BOARD pico2)

include(pico_sdk_import.cmake)

project(otp_provision C CXX ASM)
set(CMAKE_C_STANDARD 11)

pico_sdk_init()

if(NOT EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/otp_secrets.h)
    message(FATAL_ERROR "otp_secrets.h missing. Run tools/gen_otp_secrets first.")
endif()

# otp_layout.h is a copy of the server firmware's header (src/include/otp/otp_layout.h).
# Both sides must use the same layout or the server cannot read the burned keys,
# so when the server project is found next to this folder the two copies are compared.
find_file(SERVER_LAYOUT otp_layout.h
    PATHS ${CMAKE_CURRENT_SOURCE_DIR}/../server/src/include/otp
    NO_DEFAULT_PATH
    NO_CMAKE_FIND_ROOT_PATH
)
if(SERVER_LAYOUT)
    file(READ ${CMAKE_CURRENT_SOURCE_DIR}/otp_layout.h LAYOUT_OWN)
    file(READ ${SERVER_LAYOUT} LAYOUT_SERVER)
    string(REPLACE "\r\n" "\n" LAYOUT_OWN "${LAYOUT_OWN}")
    string(REPLACE "\r\n" "\n" LAYOUT_SERVER "${LAYOUT_SERVER}")
    if(NOT LAYOUT_OWN STREQUAL LAYOUT_SERVER)
        message(FATAL_ERROR "otp_layout.h differs from ${SERVER_LAYOUT}. Copy one over the other.")
    endif()
endif()

add_executable(otp_provision otp_provision.c)

target_include_directories(otp_provision PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(otp_provision pico_stdlib pico_bootrom)

pico_enable_stdio_usb(otp_provision 1)
pico_enable_stdio_uart(otp_provision 0)
pico_add_extra_outputs(otp_provision)
