from pathlib import Path

# Fungsi bitwise Rotate Right (ROR) untuk 8-bit
def ror8(value, bits):
    return ((value >> bits) | (value << (8 - bits))) & 0xff

# Baca file module.bin
module = Path("module.bin").read_bytes()

# Verifikasi Magic Header
if module[:4] != b"MOD0":
    raise SystemExit("bad module magic")

# Ambil ukuran output (size) dan payload terenkripsi
size = module[4]
payload = bytearray(module[5:])

if len(payload) != size * 2:
    raise SystemExit("bad module size")

# Ekstraksi Key dan Table dari binari loader (.rodata)
key = bytes.fromhex("1337429921558afe")
table = bytes.fromhex(
    "31a75c19e2448fd327b16e58c40df972"
    "13954aef682cb8d17f06e59a34cb51ac"
    "298314f0663da15bc708de741f9248bd"
    "6c25e9500af437819c12ab63d52e7846"
)

# Tahap 1: Initial payload XOR decryption
for i, value in enumerate(payload):
    payload[i] = value ^ key[i & 7] ^ ((i * 7 + 3) & 0xff)

# Tahap 2: Combine halves dengan ROR dan Table XOR
flag = bytes(
    ror8(payload[size + i] ^ payload[i], 1) ^ table[i]
    for i in range(size)
)

print("Flag:", flag.decode())
