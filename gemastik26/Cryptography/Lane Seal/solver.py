#!/usr/bin/env python3
"""
Lane Seal solver.

The two captured frames use the same lane/nonce.  Their cargo plaintexts are
known, so the cargo stream can be recovered.  The seal is a GCM/GHASH-style tag;
for equal-length one-block cargo boxes under nonce reuse:

    tag1 xor tag2 = (c1 xor c2) * H^2

in GF(2^128).  Therefore H^2 can be recovered from the two old frames and a
valid tag can be translated from an old cargo box to any new cargo box of the
same length.
"""
from __future__ import annotations

import argparse
import re
import socket
import ssl
from pathlib import Path

R = 0xE1000000000000000000000000000000
IDENTITY = 1 << 127  # multiplicative identity for the standard GCM bit order


def xor_bytes(a: bytes, b: bytes) -> bytes:
    if len(a) != len(b):
        raise ValueError("xor inputs must have equal length")
    return bytes(x ^ y for x, y in zip(a, b))


def gf_mul(x: int, y: int) -> int:
    """GCM GF(2^128) multiplication using x^128 + x^7 + x^2 + x + 1."""
    z = 0
    v = y
    for i in range(128):
        if (x >> (127 - i)) & 1:
            z ^= v
        if v & 1:
            v = (v >> 1) ^ R
        else:
            v >>= 1
    return z


def gf_pow(x: int, n: int) -> int:
    out = IDENTITY
    while n:
        if n & 1:
            out = gf_mul(out, x)
        x = gf_mul(x, x)
        n >>= 1
    return out


def gf_inv(x: int) -> int:
    if x == 0:
        raise ZeroDivisionError("zero has no inverse in GF(2^128)")
    return gf_pow(x, (1 << 128) - 2)


def parse_capture(path: Path):
    text = path.read_text()
    lane = bytes.fromhex(re.search(r"^lane=([0-9a-f]+)$", text, re.M).group(1))
    gate = bytes.fromhex(re.search(r"^gate=([0-9a-f]+)$", text, re.M).group(1))

    blocks = []
    pattern = re.compile(
        r"\[cleared-\d+\]\s+"
        r"qa_cargo=([^\n]+)\s+"
        r"cargo_box=([0-9a-f]+)\s+"
        r"seal=([0-9a-f]+)",
        re.M,
    )
    for m in pattern.finditer(text):
        blocks.append((m.group(1).encode(), bytes.fromhex(m.group(2)), bytes.fromhex(m.group(3))))

    if len(blocks) < 2:
        raise ValueError("need at least two cleared frames")
    return lane, gate, blocks[0], blocks[1]


def forge(capture_path: Path, target_cargo: bytes) -> tuple[bytes, bytes, bytes]:
    lane, gate, old1, old2 = parse_capture(capture_path)
    p1, c1, t1 = old1
    p2, c2, t2 = old2

    if not (len(target_cargo) == len(p1) == len(p2) == len(c1) == len(c2) == 16):
        raise ValueError("this exploit expects one 16-byte cargo block")

    # Reused stream: C = P xor stream.
    stream = xor_bytes(p1, c1)
    c_new = xor_bytes(target_cargo, stream)

    # Reused GCM nonce: tag delta reveals H^2 for one changed ciphertext block.
    dc = int.from_bytes(xor_bytes(c1, c2), "big")
    dt = int.from_bytes(xor_bytes(t1, t2), "big")
    h_squared = gf_mul(dt, gf_inv(dc))

    # Translate tag1 from c1 to c_new.
    d_new = int.from_bytes(xor_bytes(c1, c_new), "big")
    t_new_int = int.from_bytes(t1, "big") ^ gf_mul(d_new, h_squared)
    t_new = t_new_int.to_bytes(16, "big")

    frame = lane + gate + c_new + t_new
    return frame, c_new, t_new


def send_remote(host: str, port: int, frame_hex: str) -> bytes:
    ctx = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=10) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            ssock.settimeout(5)
            chunks = []
            try:
                chunks.append(ssock.recv(4096))
            except TimeoutError:
                pass
            ssock.sendall(frame_hex.encode() + b"\n")
            while True:
                try:
                    chunk = ssock.recv(4096)
                    if not chunk:
                        break
                    chunks.append(chunk)
                except TimeoutError:
                    break
            return b"".join(chunks)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("capture", nargs="?", default="capture.lane", type=Path)
    ap.add_argument("--cargo", default="cargo=9999;adm!!")
    ap.add_argument("--host", default="lane-seal-ctf.forestylab.com")
    ap.add_argument("--port", default=443, type=int)
    ap.add_argument("--remote", action="store_true", help="submit the forged frame to the challenge service")
    args = ap.parse_args()

    target = args.cargo.encode()
    frame, cargo_box, seal = forge(args.capture, target)
    print(f"target cargo : {target!r}")
    print(f"cargo_box    : {cargo_box.hex()}")
    print(f"seal         : {seal.hex()}")
    print(f"frame hex    : {frame.hex()}")

    if args.remote:
        print(send_remote(args.host, args.port, frame.hex()).decode(errors="replace"))


if __name__ == "__main__":
    main()
