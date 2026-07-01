from sage.all import *
import ast
import re

# Fungsi utilitas untuk konversi
def b2l(b):
    return int.from_bytes(b, "big")

def l2b(x):
    x = int(x)
    return x.to_bytes((x.bit_length() + 7) // 8, "big")

# 1. Parsing data dari output.txt
data = open("output.txt", "r").read()

n = Integer(re.search(r"n = (\d+)", data).group(1))
e = Integer(re.search(r"e = (\d+)", data).group(1))
ciphertexts = ast.literal_eval(
    re.search(r"ciphertexts = (\[.*\])", data, re.S).group(1)
)
ciphertexts = [Integer(c) for c in ciphertexts]

# 2. Persiapan Konstanta dan Ring Polinomial
B = Integer(256) ** 25
Zn = Zmod(n)
R.<x> = PolynomialRing(Zn) # Ring untuk target utama (F atau Z)
T.<t> = PolynomialRing(R)  # Ring sementara untuk mengeliminasi m0 / m4

def relation_poly(ca, cb, a, b):
    """
    Menghasilkan polinomial resultant untuk relasi:
        t^e = ca
        (a*t + b*x)^e = cb
    Dimana 'x' adalah variabel target yang ingin kita isolasi.
    """
    a, b = R(Zn(a)), R(Zn(b))
    ca, cb = R(Zn(ca)), R(Zn(cb))

    f = t**e - ca
    g = (a*t + b*x)**e - cb

    return f.resultant(g).monic()

# 3. Bentuk Polinomial Pertama dari Batch 1 (Relasi c0 & c3)
# m3 = B*m0 + (1 - B^5)*F
P1 = relation_poly(
    ciphertexts[0],
    ciphertexts[3],
    B,
    1 - B**5
)

# 4. Bentuk Polinomial Kedua dari Batch 2 (Relasi c4 & c7)
# m7 = 256*B*m4 + (1 - 256*B^5)*Z
# Faktor 256 ditambahkan karena Z lebih panjang 1 byte.
Pz = relation_poly(
    ciphertexts[4],
    ciphertexts[7],
    256 * B,
    1 - 256 * B**5
)

# Substitusi Z menjadi F: Z = F + delta
delta = (b2l(b"SLOP{") - b2l(b"CBC{")) * (Integer(256) ** 21)
P2 = Pz(x + R(Zn(delta))).monic()

# 5. Cari akar bersamanya (F) menggunakan GCD
# --- Tambahkan fungsi GCD manual ---
def poly_gcd(a, b):
    # Pastikan derajat a lebih besar dari b sebelum mulai
    if a.degree() < b.degree():
        a, b = b, a
        
    while b != 0:
        # Paksa b menjadi monic agar pembagian modulo n selalu valid
        b = b.monic()
        a, b = b, a % b
        
    return a.monic()

# 5. Cari akar bersamanya (F) menggunakan fungsi GCD manual
G = poly_gcd(P1, P2)

print("[+] Derajat GCD:", G.degree())
print("[+] Bentuk GCD:", G)

# Pastikan kita mendapat polinomial linear
assert G.degree() == 1

# Jika GCD berbentuk a*x + b, maka akarnya adalah -b/a mod n
a = ZZ(G[1])
b = ZZ(G[0])

F = (-b * inverse_mod(a, n)) % n
flag = l2b(F)

print("[+] Flag berhasil ditemukan:")
print("    " + flag.decode())
