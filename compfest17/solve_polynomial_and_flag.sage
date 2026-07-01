# solve_polynomial_and_flag.sage
import json
from sageall import *

data = json.load(open("stage1_unmasked.json"))
p = Integer(data["p"])
n = Integer(data["n"])  # p^100
coeffs = list(map(Integer, data["coeffs"]))
poly_result = Integer(data["poly_result"])

# Build f(X) = sum a_i X^i - poly_result  over Z_p
R.<X> = PolynomialRing(GF(p))
a = [Integer(c % p) for c in coeffs]
f = sum(a[i] * X^i for i in range(len(a))) - Integer(poly_result % p)

roots = f.roots(multiplicities=False)
if not roots:
    print("No roots mod p found. (Unlikely, re-check stage1)")
    exit()

print("[*] roots mod p:", roots)

# Hensel lift each root to modulo p^100
k = 100
solutions = []
for r0 in roots:
    # Lift using native Hensel
    Zp = ZpCA(p, prec=k)  # p-adics with precision k
    # Lift coefficients to p-adics
    aZ = [Zp(c) for c in coeffs]
    polyZ = sum(aZ[i] * (Zp(1)*X)^i for i in range(len(aZ))) - Zp(poly_result)
    # Newton lift for root
    # Start r = r0, then repeat refine to precision k
    r = Zp(int(r0))
    for _ in range(2*k):  # plenty iterations
        # poly(r) and poly'(r)
        pr = sum(aZ[i]* (r**i) for i in range(len(aZ))) - Zp(poly_result)
        dpr = sum(aZ[i]* i * (r**(i-1)) for i in range(1,len(aZ)))
        if dpr == 0:
            break  # multiple root case; could handle separately
        r = r - pr/dpr
    # r is p-adic; take integer modulo p^k
    mk = (int(r) % (p**k))
    solutions.append(mk)

# Pick the root that decodes to ASCII flag
def long_to_bytes(x):
    s = []
    while x:
        s.append(x & 0xFF)
        x >>= 8
    return bytes(reversed(s)) if s else b"\x00"

cands = []
for m in solutions:
    b = long_to_bytes(m)
    # search for flag pattern
    if b.startswith(b"CTF{") or b.startswith(b"COMPFEST17{") or b.startswith(b"FLAG{"):
        cands.append(b)

if not cands:
    print("[*] No ASCII-looking flag, dumping candidates (hex):")
    for m in solutions:
        print(hex(m))
else:
    for b in cands:
        print("[+] FLAG:", b.decode(errors="ignore"))
