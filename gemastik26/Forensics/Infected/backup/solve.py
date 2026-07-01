import os, zlib
from pathlib import Path

buf = Path("sn0wden").read_bytes()

def u32le(x):
    return int.from_bytes(x, "little")

def rc4(key, data):
    S = list(range(256))
    j = 0
    out = bytearray()

    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) & 0xff
        S[i], S[j] = S[j], S[i]

    i = j = 0
    for b in data:
        i = (i + 1) & 0xff
        j = (j + S[i]) & 0xff
        S[i], S[j] = S[j], S[i]
        out.append(b ^ S[(S[i] + S[j]) & 0xff])

    return bytes(out)

def xor(key, data):
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))

assert buf[:4] == b"KEII"

count = int.from_bytes(buf[4:6], "big")

# Offset di file ini bergeser 1 byte, jadi perlu shift kanan 8 bit
key_off = u32le(buf[6:10]) >> 8
alg_off = u32le(buf[10:14]) >> 8

key = buf[key_off:]

print("[+] count:", count)
print("[+] key_off:", hex(key_off))
print("[+] alg_off:", hex(alg_off))
print("[+] key:", key.hex())

os.makedirs("out", exist_ok=True)

entry_base = 0x0f
entry_size = 0x31

for i in range(count):
    e = entry_base + i * entry_size

    name = buf[e:e+32].split(b"\x00", 1)[0].decode()
    alg = u32le(buf[e+32:e+36])
    off = u32le(buf[e+36:e+40])
    clen = u32le(buf[e+40:e+44])
    ulen = u32le(buf[e+44:e+48])
    flags = buf[e+48]

    data = buf[off:off+clen]

    # flag 0x80 = encrypted
    if flags & 0x80:
        if alg == 1:
            data = rc4(key, data)
        elif alg == 2:
            data = xor(key, data)

    # flag 0x40 = raw deflate compressed
    if flags & 0x40:
        data = zlib.decompress(data, -15)

    Path("out", name).write_bytes(data)
    print(f"[+] extracted {name}: alg={alg}, flags={hex(flags)}, size={len(data)}/{ulen}")
