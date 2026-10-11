#!/bin/sh
# keygen.sh - generate all key material with OpenSSL (Linux, macOS, Git Bash / WSL / MSYS2 on Windows).
# Windows without a POSIX shell: use keygen.bat, it does exactly the same.
#
#   ./keygen.sh [output_dir]        default output_dir: ./keys
#
# Creates (existing files are NEVER overwritten, delete them by hand to rotate):
#   server_key.pem   TLS private key, ECDSA P-256   -> burned into OTP by key_provision. Keep secret.
#   server_crt.pem   self-signed certificate        -> paste into server/web/certs.h (public)
#   master_key.h     16-byte MASTER_KEY             -> wrap it with the client's `keywrap`. Keep secret.
#   ip_hash_key.h    32-byte IP_HASH_KEY            -> burned into OTP by key_provision. Keep secret.
#
# OpenSSL is only the preferred tool. Any tool that produces the same file formats works,
# see key_provision/README.md.

set -eu

OUT="${1:-keys}"
CERT_CN="${CERT_CN:-pico2-https}"
CERT_DAYS="${CERT_DAYS:-3650}"

command -v openssl >/dev/null 2>&1 || {
    echo "openssl not found in PATH. Install it (apt install openssl / brew install openssl)," >&2
    echo "or create the files by hand, see key_provision/README.md." >&2
    exit 1
}

mkdir -p "$OUT"
umask 077   # key files readable by the owner only

# hex string -> "{ 0xAA, 0xBB, ... }" (same layout keygen.bat writes)
hex_to_c_array() {
    printf '%s' "$1" | sed 's/\(..\)/ 0x\1,/g'
}

# write_key_header <file> <C name> <bytes>
write_key_header() {
    file="$1"; name="$2"; bytes="$3"
    if [ -f "$file" ]; then
        echo "kept existing $file"
        return 0
    fi
    hex=$(openssl rand -hex "$bytes")
    printf 'const uint8_t %s[] = {%s };\n' "$name" "$(hex_to_c_array "$hex")" > "$file"
    echo "created $file ($bytes bytes)"
}

# 1. TLS private key + 2. certificate (a pair: only ever created together)
if [ -f "$OUT/server_key.pem" ]; then
    echo "kept existing $OUT/server_key.pem and $OUT/server_crt.pem"
else
    openssl ecparam -name prime256v1 -genkey -noout -out "$OUT/server_key.pem"
    openssl req -new -x509 -sha256 -key "$OUT/server_key.pem" -out "$OUT/server_crt.pem" \
        -days "$CERT_DAYS" -subj "/CN=$CERT_CN"
    echo "created $OUT/server_key.pem and $OUT/server_crt.pem"
fi

# 3. master key (every client needs the same value, so it is kept if it exists)
write_key_header "$OUT/master_key.h" MASTER_KEY 16

# 4. IP hash key
write_key_header "$OUT/ip_hash_key.h" IP_HASH_KEY 32

# 5. show the certificate only. The private key goes to OTP via key_provision, never to a header.
echo
cat "$OUT/server_crt.pem"
echo
echo "Next: paste the certificate into server/web/certs.h, then follow key_provision/README.md."
