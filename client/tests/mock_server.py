#!/usr/bin/env python3
"""Mock of the Pico server's custom protocol, for testing the client's retry loop.

  python3 mock_server.py --key master_key.h --lib libchaskey.so [--port 4443] [--drop N] [--hang N] [--garbage N]

  --drop N     the first N connections are accepted and closed at once
  --hang N     the next N connections are accepted but never answered (client IO timeout)
  --garbage N  the next N connections get a bogus reply to INIT (protocol error)
After that, connections are served normally. Needs the client built with PORT overridden
(see tests/run_tests.sh, which passes -DPORT_OVERRIDE) or a port-forward to 443.
"""
import argparse, ctypes, re, socket, struct, sys, time

ap = argparse.ArgumentParser()
ap.add_argument("--key", required=True); ap.add_argument("--lib", required=True)
ap.add_argument("--port", type=int, default=4443)
ap.add_argument("--drop", type=int, default=0); ap.add_argument("--hang", type=int, default=0)
ap.add_argument("--garbage", type=int, default=0)
a = ap.parse_args()

key = bytes(int(x, 16) for x in re.findall(r"0x([0-9a-fA-F]{2})", open(a.key).read()))
assert len(key) == 16
lib = ctypes.CDLL(a.lib)
U32 = ctypes.c_uint32 * 4

def mac(k, msg):
    kk = U32.from_buffer_copy(k); k1 = U32(); k2 = U32()
    lib.chaskey_subkeys(k1, k2, kk)
    out = ctypes.create_string_buffer(16)
    lib.chaskey_mac(out, 16, msg, len(msg), kk, k1, k2)
    return out.raw

def derive(ikm, salt, info, outlen):
    prk = mac(salt, ikm); t = b""; counter = 1; out = b""
    while len(out) < outlen:
        t = mac(prk, (t if t else b"\0"*16) + info + bytes([counter])); out += t; counter += 1
    return out[:outlen]

HDR = struct.Struct("<HBBIHQ")      # magic, ver, cmd, counter, len, tag  (18 bytes)
def recvn(c, n):
    b = b""
    while len(b) < n:
        d = c.recv(n - len(b))
        if not d: raise ConnectionError
        b += d
    return b

def rotate(cur, counter):
    if counter % 1024: return cur
    salt = cur[:8] + struct.pack("<I", counter // 1024) + bytes([1,2,3,4])
    return derive(cur, salt, b"CHASKEY-ROTATION-KEY", 16)

def frame(cmd, cnt, data, k):
    hdr = HDR.pack(0xC2A5, 1, cmd, cnt, len(data), 0) + data
    tag = mac(k, hdr)[:8]
    return HDR.pack(0xC2A5, 1, cmd, cnt, len(data), struct.unpack("<Q", tag)[0]) + data

def serve(c):
    h = HDR.unpack(recvn(c, 18)); assert h[2] == 0x11 and h[4] == 4
    cn = recvn(c, 4); cnonce = struct.unpack("<I", cn)[0]
    sn = 0x11223344
    c.sendall(HDR.pack(0xC2A5, 1, 0x11, 1, 4, 0) + struct.pack("<I", sn))
    salt = struct.pack("<IIII", sn, cnonce, sn, cnonce)
    sk = derive(key, salt, b"CHASKEY-SESSION-KEY", 16)
    h = HDR.unpack(recvn(c, 18)); assert h[2] == 0x01 and h[3] == 2 and h[4] == 12
    d = recvn(c, 12)
    exp = mac(key, struct.pack("<II", sn, cnonce))[:8]
    assert d[:8] == exp, "bad AUTH hmac"
    sk = rotate(sk, 2)
    c.sendall(frame(0x81, 2, b"", sk))
    h = HDR.unpack(recvn(c, 18)); d = recvn(c, h[4]); assert h[2] == 0x10 and d == b"web"
    sk = rotate(sk, h[3])
    c.sendall(frame(0x81, 3, b"", sk))
    print("  served OK: web accepted", flush=True)

s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", a.port)); s.listen(8)
n = 0
print("mock server ready", flush=True)
while True:
    c, addr = s.accept(); n += 1
    try:
        if n <= a.drop:
            print(f"conn {n}: dropped", flush=True); c.close(); continue
        if n <= a.drop + a.hang:
            print(f"conn {n}: hanging", flush=True); time.sleep(5); c.close(); continue
        if n <= a.drop + a.hang + a.garbage:
            recvn(c, 22); c.sendall(b"\x00" * 22); print(f"conn {n}: garbage reply", flush=True); c.close(); continue
        print(f"conn {n}: serving", flush=True); serve(c); c.close()
        if n > a.drop + a.hang + a.garbage: break
    except Exception as e:
        print(f"conn {n}: ended ({type(e).__name__}: {e})", flush=True)
        try: c.close()
        except Exception: pass
