from pwn import *
from fractions import Fraction
from Crypto.Util.number import long_to_bytes

def solve():
    host = 'crypto-east.cbd2026.cloud'
    port = 1338
    
    print(f"[*] Menghubungkan ke {host}:{port}...")
    r = remote(host, port)
    
    # 1. Ambil nilai n, e, c
    r.recvuntil(b'> ')
    r.sendline(b'1')
    
    r.recvuntil(b'n = ')
    n = int(r.recvline().strip())
    
    r.recvuntil(b'e = ')
    e = int(r.recvline().strip())
    
    r.recvuntil(b'c = ')
    c = int(r.recvline().strip())

    total_bits = n.bit_length()
    print(f"[+] Ukuran modulus (n): {total_bits} bits")
    
    # 2. Pre-komputasi semua ciphertext (Mencegah Timeout)
    print("[*] Melakukan pre-komputasi payload untuk pipelining...")
    multiplier = pow(2, e, n)
    c_query = c
    
    payloads = []
    for _ in range(total_bits):
        c_query = (c_query * multiplier) % n
        payloads.append(c_query)
        
    # 3. Kirim payload secara batch / massal
    print("[*] Mengirim semua query ke server dalam mode batch...")
    parities = []
    
    # Kirim secara chunk (misal 64 request per batch) agar tidak membanjiri buffer server
    chunk_size = 64
    for i in range(0, total_bits, chunk_size):
        chunk = payloads[i:i+chunk_size]
        
        # Rangkai string payload untuk chunk ini (Format: "2\n<ciphertext>\n")
        batch_payload = b""
        for q in chunk:
            batch_payload += b"2\n" + str(q).encode() + b"\n"
            
        r.send(batch_payload)
        
        # Tangkap respon ganjil/genap dari server
        for _ in range(len(chunk)):
            r.recvuntil(b'ciphertext: ')
            parity = r.recvline().strip().decode()
            parities.append(parity)
            
        print(f"[*] Progress: {len(parities)}/{total_bits} parities terkumpul", end="\r")

    print("\n[+] Semua parities berhasil dikumpulkan! Menganalisa flag...")
    
    # 4. Kalkulasi Binary Search (Offline)
    upper_bound = Fraction(n, 1)
    lower_bound = Fraction(0, 1)
    
    for parity in parities:
        mid = (lower_bound + upper_bound) / 2
        if parity == 'odd':
            lower_bound = mid
        elif parity == 'even':
            upper_bound = mid

    # Ekstraksi Flag
    m_int = int(upper_bound)
    flag = long_to_bytes(m_int)
    
    print("\n==================================")
    print(f"[FLAG] {flag.decode('utf-8', errors='ignore')}")
    print("==================================")

    r.close()

if __name__ == '__main__':
    solve()
