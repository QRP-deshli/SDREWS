# Builds the host tool tools/gen_otp_secrets (Linux, macOS, Windows with MinGW / MSYS2).
#
#   make                 with the key/certificate match check (needs OpenSSL 3 dev files:
#                        apt install libssl-dev / brew install openssl / pacman -S mingw-w64-x86_64-openssl)
#   make NO_OPENSSL=1    without the match check (no OpenSSL needed)
#   make clean

ifeq ($(OS),Windows_NT)
    TARGET_EXT = .exe
    RM = del /Q /F
    FIXPATH = $(subst /,\,$1)
else
    TARGET_EXT =
    RM = rm -f
    FIXPATH = $1
endif

CC ?= gcc

ifeq ($(NO_OPENSSL),1)
    CFLAGS  ?= -std=c99 -O2 -Wall -Wextra
    LDFLAGS ?=
else
    CFLAGS  ?= -std=c99 -O2 -Wall -Wextra -DWITH_OPENSSL
    LDFLAGS ?= -lcrypto
endif

SRC    = tools/gen_otp_secrets.c
TARGET = tools/gen_otp_secrets$(TARGET_EXT)

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	-$(RM) $(call FIXPATH,$(TARGET)) otp_secrets.h
