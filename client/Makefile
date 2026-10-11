# Client build - Linux native, Windows native (MinGW / MSYS2) and Windows cross-compile from Linux
#
#   make            native build (Linux, or Windows with MinGW + mingw32-make)
#   make windows    cross-compile 64-bit Windows .exe files into win64/  (needs mingw-w64:
#                   Debian/Ubuntu: sudo apt install gcc-mingw-w64-x86-64)
#   make windows32  same for 32-bit Windows into win32/ (gcc-mingw-w64-i686)
#   make test       run the Argon2id / BLAKE2b self-test (native)
#   make clean

SRC_DIR  = src
HEAD_DIR = src/include

CFLAGS   ?= -O2
A2_DIR   = third_party/argon2
CFLAGS   += -Wall -Wextra -std=gnu99 -I$(HEAD_DIR) -I$(A2_DIR)/include -I$(A2_DIR)/src -DARGON2_NO_THREADS

A2_SRC   = $(A2_DIR)/src/argon2.c $(A2_DIR)/src/core.c $(A2_DIR)/src/ref.c \
           $(A2_DIR)/src/encoding.c $(A2_DIR)/src/blake2/blake2b.c

COMMON   = $(SRC_DIR)/addition.c $(SRC_DIR)/config.c $(SRC_DIR)/network.c \
           $(SRC_DIR)/chaskey.c $(SRC_DIR)/key_file.c $(SRC_DIR)/keywrap.c \
           $(SRC_DIR)/argon2id.c $(SRC_DIR)/platform.c $(A2_SRC)

CLIENT_SRC = client_connect.c $(COMMON)
WRAP_SRC   = keywrap_tool.c $(SRC_DIR)/key_file.c $(SRC_DIR)/keywrap.c \
             $(SRC_DIR)/argon2id.c $(SRC_DIR)/platform.c $(SRC_DIR)/config.c $(A2_SRC)

ifeq ($(OS),Windows_NT)
    CC      ?= gcc
    LIBS     = -lws2_32 -ladvapi32
    LDFLAGS  = -static
    EXE      = .exe
    RM_FILES = del /Q /F
else
    LIBS     =
    LDFLAGS  =
    EXE      =
    RM_FILES = rm -f
endif

WIN_LIBS = -lws2_32 -ladvapi32

.PHONY: all windows windows32 test clean

all: client_connect$(EXE) keywrap$(EXE)

client_connect$(EXE): $(CLIENT_SRC) $(wildcard $(HEAD_DIR)/*.h)
	$(CC) $(CFLAGS) -o $@ $(CLIENT_SRC) $(LDFLAGS) $(LIBS)

keywrap$(EXE): $(WRAP_SRC) $(wildcard $(HEAD_DIR)/*.h)
	$(CC) $(CFLAGS) -o $@ $(WRAP_SRC) $(LDFLAGS) $(LIBS)

# ---- Windows cross builds (run on Linux) ------------------------------------
WIN64_CC ?= x86_64-w64-mingw32-gcc
WIN32_CC ?= i686-w64-mingw32-gcc

windows:
	mkdir -p win64
	$(WIN64_CC) $(CFLAGS) -o win64/client_connect.exe $(CLIENT_SRC) -static $(WIN_LIBS)
	$(WIN64_CC) $(CFLAGS) -o win64/keywrap.exe $(WRAP_SRC) -static $(WIN_LIBS)

windows32:
	mkdir -p win32
	$(WIN32_CC) $(CFLAGS) -o win32/client_connect.exe $(CLIENT_SRC) -static $(WIN_LIBS)
	$(WIN32_CC) $(CFLAGS) -o win32/keywrap.exe $(WRAP_SRC) -static $(WIN_LIBS)

# ---- tests -------------------------------------------------------------------
test: tests/test_argon2.c $(SRC_DIR)/argon2id.c $(A2_SRC)
	$(CC) $(CFLAGS) -o tests/test_argon2$(EXE) tests/test_argon2.c $(SRC_DIR)/argon2id.c $(A2_SRC)
	./tests/test_argon2$(EXE)

clean:
	-$(RM_FILES) client_connect client_connect.exe keywrap keywrap.exe tests/test_argon2 tests/test_argon2.exe
