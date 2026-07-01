#!/usr/bin/env python3
"""
Archive Gate solver / payload generator.

This forges three Ed25519-like rows whose *non-randomized batch* equation
passes, while every row fails individual verification.

Default attack mode is the intended BadBatch-style known-key forgery using:
    h = SHA512(row || key || R || b"5") mod L
where R is the first 32 bytes of the seal/signature.  This matches the audit
hint: row -> key -> seal -> version digit "5".

If the remote uses the full 64-byte seal inside h, or if you do not know the
row bytes, try --mode identity.  That variant uses the identity public key so
h*A = 0 and does not depend on h at all; it passes unless the service forbids
small-order public keys.
"""

import argparse
from curses import raw
import hashlib
import re
import socket
import ssl
import sys
from typing import Iterable, List, Tuple

# Ed25519 parameters.
P = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493
D = (-121665 * pow(121666, P - 2, P)) % P
I = pow(2, (P - 1) // 4, P)
O = (0, 1)


def inv(x: int) -> int:
    return pow(x, P - 2, P)


def ed_add(P1: Tuple[int, int], P2: Tuple[int, int]) -> Tuple[int, int]:
    x1, y1 = P1
    x2, y2 = P2
    xy = (D * x1 * x2 * y1 * y2) % P
    x3 = ((x1 * y2 + x2 * y1) * inv(1 + xy)) % P
    y3 = ((y1 * y2 + x1 * x2) * inv(1 - xy)) % P
    return x3, y3


def ed_neg(Pt: Tuple[int, int]) -> Tuple[int, int]:
    return (-Pt[0] % P, Pt[1])


def ed_mul(Pt: Tuple[int, int], n: int) -> Tuple[int, int]:
    n %= L
    Q = O
    while n:
        if n & 1:
            Q = ed_add(Q, Pt)
        Pt = ed_add(Pt, Pt)
        n >>= 1
    return Q


# Base point B, y = 4/5; choose even x.
BY = (4 * inv(5)) % P
BX = pow(((BY * BY - 1) * inv(D * BY * BY + 1)) % P, (P + 3) // 8, P)
if (BX * BX - ((BY * BY - 1) * inv(D * BY * BY + 1))) % P:
    BX = (BX * I) % P
if BX & 1:
    BX = P - BX
B = (BX, BY)


def enc(Pt: Tuple[int, int]) -> bytes:
    x, y = Pt
    out = bytearray(y.to_bytes(32, "little"))
    out[31] |= (x & 1) << 7
    return bytes(out)


def dec(buf: bytes):
    if len(buf) != 32:
        return None
    y = int.from_bytes(buf, "little") & ((1 << 255) - 1)
    sign = buf[31] >> 7
    if y >= P:
        return None
    xx = ((y * y - 1) * inv(D * y * y + 1)) % P
    x = pow(xx, (P + 3) // 8, P)
    if (x * x - xx) % P:
        x = (x * I) % P
    if (x * x - xx) % P:
        return None
    if (x & 1) != sign:
        x = P - x
    return x, y


def h_chal(row: bytes, key: bytes, r_or_seal: bytes, version: bytes = b"5") -> int:
    return int.from_bytes(hashlib.sha512(row + key + r_or_seal + version).digest(), "little") % L


def verify_one(row: bytes, key: bytes, seal: bytes, version: bytes = b"5", full_seal_hash: bool = False) -> bool:
    if len(key) != 32 or len(seal) != 64:
        return False
    A = dec(key)
    R = dec(seal[:32])
    if A is None or R is None:
        return False
    S = int.from_bytes(seal[32:], "little")
    if S >= L:
        return False
    hashed = seal if full_seal_hash else seal[:32]
    h = h_chal(row, key, hashed, version)
    return ed_mul(B, S) == ed_add(R, ed_mul(A, h))


def batch_ok(rows: List[bytes], keys: List[bytes], seals: List[bytes], version: bytes = b"5", full_seal_hash: bool = False) -> bool:
    # Non-randomized batch check: sum S_i*B == sum(R_i + h_i*A_i).
    left = O
    right = O
    for row, key, seal in zip(rows, keys, seals):
        if len(key) != 32 or len(seal) != 64:
            return False
        A = dec(key)
        R = dec(seal[:32])
        if A is None or R is None:
            return False
        S = int.from_bytes(seal[32:], "little")
        if S >= L:
            return False
        hashed = seal if full_seal_hash else seal[:32]
        h = h_chal(row, key, hashed, version)
        left = ed_add(left, ed_mul(B, S))
        right = ed_add(right, ed_add(R, ed_mul(A, h)))
    return left == right


def forge_knownkey(rows: List[bytes], version: bytes = b"5") -> Tuple[List[bytes], List[bytes]]:
    """BadBatch forgery with normal-looking public keys.

    For row i, choose known A_i=a_i*B and R_i=r_i*B.  Let h_i be the challenge.
    Set S_i = r_i + h_i*a_i + v_i.  The individual error is v_i*B.  Choose
    non-zero v_i with sum v_i=0 so the non-randomized batch equation cancels.
    """
    # Deterministic small scalars are enough; they are not secret here.
    a = [0x1337, 0x4242, 0xBEEF]
    r = [0x111111, 0x222222, 0x333333]
    v = [1, 2, (-3) % L]
    keys, seals = [], []
    for row, ai, ri, vi in zip(rows, a, r, v):
        key = enc(ed_mul(B, ai))
        Rb = enc(ed_mul(B, ri))
        h = h_chal(row, key, Rb, version)
        S = (ri + h * ai + vi) % L
        keys.append(key)
        seals.append(Rb + S.to_bytes(32, "little"))
    assert batch_ok(rows, keys, seals, version, False)
    assert not any(verify_one(rows[i], keys[i], seals[i], version, False) for i in range(3))
    return keys, seals


def forge_identity(rows: List[bytes]) -> Tuple[List[bytes], List[bytes]]:
    """Hash-independent fallback.

    Uses A = identity so h*A = 0.  Pick R1+R2+R3=0 and S_i=0.
    """
    A0 = enc(O)
    r = [1234567, 7654321]
    R1 = ed_mul(B, r[0])
    R2 = ed_mul(B, r[1])
    R3 = ed_neg(ed_add(R1, R2))
    z32 = b"\x00" * 32
    keys = [A0, A0, A0]
    seals = [enc(R1) + z32, enc(R2) + z32, enc(R3) + z32]
    # Do not assert verify_one here: depending on exact remote h, identity mode does not care.
    return keys, seals


def parse_rows_from_banner(banner: bytes) -> List[bytes]:
    """Best-effort parser for banners containing line0_row=... / row0=... ."""
    txt = banner.decode("latin1", "ignore")
    rows = []
    for i in range(3):
        patterns = [
            rf"line{i}_row\s*=\s*([^\r\n]+)",
            rf"row{i}\s*=\s*([^\r\n]+)",
            rf"line{i}\s*=\s*([^\r\n]+)",
        ]
        found = None
        for pat in patterns:
            m = re.search(pat, txt, re.I)
            if m:
                found = m.group(1).strip().strip('"\'').encode()
                break
        rows.append(found if found is not None else f"line{i}".encode())
    return rows


def format_payload(keys: List[bytes], seals: List[bytes], style: str) -> bytes:
    out = []
    if style == "assignments":
        for i in range(3):
            out.append(f"line{i}_key={keys[i].hex()}\n")
            out.append(f"line{i}_seal={seals[i].hex()}\n")
    elif style == "compact":
        for i in range(3):
            out.append(f"{keys[i].hex()} {seals[i].hex()}\n")
    elif style == "colon":
        for i in range(3):
            out.append(f"{keys[i].hex()}:{seals[i].hex()}\n")
    else:
        raise ValueError("unknown format")
    return "".join(out).encode()


def recv_some(sock, timeout=1.0) -> bytes:
    sock.settimeout(timeout)
    chunks = []
    while True:
        try:
            c = sock.recv(4096)
        except (socket.timeout, ssl.SSLWantReadError):
            break
        if not c:
            break
        chunks.append(c)
        if len(c) < 4096:
            break
    return b"".join(chunks)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="archive-gate-ctf.forestylab.com")
    ap.add_argument("--port", type=int, default=443)
    ap.add_argument("--no-connect", action="store_true", help="only print payload")
    ap.add_argument("--mode", choices=["knownkey", "identity"], default="knownkey")
    ap.add_argument("--format", choices=["assignments", "compact", "colon"], default="assignments")
    ap.add_argument("--rows", default="line0,line1,line2", help="comma-separated row/message bytes, default line0,line1,line2")
    ap.add_argument("--version", default="5")
    args = ap.parse_args()

    rows = [x.encode() for x in args.rows.split(",")]
    if len(rows) != 3:
        raise SystemExit("need exactly three rows")

    version = args.version.encode()
    if args.mode == "knownkey":
        keys, seals = forge_knownkey(rows, version)
    else:
        keys, seals = forge_identity(rows)

    payload = format_payload(keys, seals, args.format)

    print("[+] rows:", [r.decode('latin1', 'ignore') for r in rows], file=sys.stderr)
    print("[+] mode:", args.mode, "format:", args.format, file=sys.stderr)
    print(payload.decode(), end="")

    if args.no_connect:
        return

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    with ctx.wrap_socket(raw, server_hostname=args.host) as s:
        with ctx.wrap_socket(raw, server_hostname=args.host) as s:
            banner = recv_some(s, 1.5)
            if banner:
                sys.stderr.write("\n[+] banner:\n" + banner.decode("latin1", "replace") + "\n")
                # If the service gives explicit row values and we are in knownkey mode,
                # regenerate using those rows before sending.
                parsed = parse_rows_from_banner(banner)
                if args.mode == "knownkey" and parsed != rows:
                    keys, seals = forge_knownkey(parsed, version)
                    payload = format_payload(keys, seals, args.format)
                    sys.stderr.write(f"[+] regenerated for banner rows: {[r.decode('latin1','ignore') for r in parsed]}\n")
            s.sendall(payload)
            s.shutdown(socket.SHUT_WR)
            ans = recv_some(s, 5.0)
            print(ans.decode("latin1", "replace"), end="")


if __name__ == "__main__":
    main()
