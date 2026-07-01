#!/usr/bin/env python3
import socket

ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
W = [1, 3, 7, 11]

def fmix32(x: int) -> int:
    x &= 0xffffffff
    x ^= (x >> 16)
    x = (x * 0x7feb352d) & 0xffffffff
    x ^= (x >> 15)
    x = (x * 0x846ca68b) & 0xffffffff
    x ^= (x >> 16)
    return x & 0xffffffff

def g4_first4(g3: str) -> str:
    x = fmix32(int(g3) ^ 0x9e3779b9)
    out = []
    for _ in range(4):
        x = (x * 0x41c64e6d + 0x3039) & 0xffffffff
        idx = (x >> 27) & 0x1f  # 0..31
        out.append(ALPHABET[idx])
    return "".join(out)

def base36_val(ch: str) -> int:
    if "0" <= ch <= "9":
        return ord(ch) - ord("0")
    return ord(ch) - ord("A") + 10

def g5_checksum(g1: str, g2: str, g3: str, g4_4: str) -> str:
    buf = g1 + g2 + g3 + g4_4 + "0"
    assert len(buf) == 20
    out = []
    for i in range(5):
        s = 0
        chunk = buf[i*4:(i+1)*4]
        for j, c in enumerate(chunk):
            s += base36_val(c) * W[j]
        out.append(ALPHABET[(s + 13*i) % 36])
    return "".join(out)

def make_key(g2_hex: str, g3: str = "00007", g4_last: str = "A") -> str:
    g1 = "TCFST"
    g4_4 = g4_first4(g3)
    g4 = g4_4 + g4_last
    g5 = g5_checksum(g1, g2_hex, g3, g4_4)
    return f"{g1}-{g2_hex}-{g3}-{g4}-{g5}"

def generate_100():
    # G3 fixed: "00007" -> digit sum 7 -> divisible by 7 ✅
    # G2 varied: 4, 8, 12, ... -> divisible by 4 ✅
    for i in range(1, 101):
        g2 = f"{4*i:05X}"
        yield make_key(g2)

if __name__ == "__main__":
    for k in generate_100():
        print(k)
