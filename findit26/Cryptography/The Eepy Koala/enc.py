from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import os
import hashlib
import random

# W, H = 1920, 800
BLOCK_SIZE = 16

def permute(n, s):
    indices = list(range(n))
    state = s
    for i in range(n - 1, 0, -1):
        state = (state * 0x41c64e6d + 12345) & 0xFFFFFFFF
        j = (state ^ (state >> 16)) % (i + 1)
        indices[i], indices[j] = indices[j], indices[i]
    return indices

def main():
    with open("plain.ppm", "rb") as f:
        header = f.readline() + f.readline() + f.readline()
        pixel_data = f.read()
        
    secret_seed = random.randint(0, 65535)
    seed_bytes = secret_seed.to_bytes(2, 'big')
    key = hashlib.sha256(seed_bytes).digest()[:16]
    cipher = AES.new(key, AES.MODE_ECB)

    raw = pad(pixel_data, BLOCK_SIZE)
    blocks = [cipher.encrypt(raw[i:i+BLOCK_SIZE]) for i in range(0, len(raw), BLOCK_SIZE)]
    
    n = len(blocks)
    mapping = permute(n, secret_seed)
    
    shuffled_blocks = [None] * n
    for i, pos in enumerate(mapping):
        shuffled_blocks[pos] = blocks[i]
    
    with open("koala-enc.ppm", "wb") as f:
        f.write(header + b"".join(shuffled_blocks))

if __name__ == "__main__":
    main()
