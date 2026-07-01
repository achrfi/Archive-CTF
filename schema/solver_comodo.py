# common_modulus_attack.py
from base64 import b64decode
from Crypto.PublicKey import RSA
from Crypto.Util.number import bytes_to_long, long_to_bytes, inverse
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import re

# ==== paste persis PEM dari soal (JANGAN dirubah) ====
pem_en = b"""-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA+bcTgKO6LUT1H6MFy02p
x2piclYYLgzi7tWzEqx7IO/zaWrUZV/RgwK83F9txfCGmuV3JDsrza9CqxDHEF5X
fQ5qaeP3G6hxyZJt92B2j2XvaJN2Yg1B4b5+7yjkLYqoiAijLnCWWoR8Tgf5tp7+
9znjwSON1ISew6Cr0ww0fRZZDQgJw5kiejYUhAJJkxhg9kiju4kxzq6QoZrayAXj
nqCBicRlbzkzty506rS0JQU2mEoLBtdkJE65mspRNuu0b3+JMSwawDIPPaUqABVT
H+AR71CtcBtW62ONRmVkqBP5UX2VyjY3oKjzqzLEpaPZowb/0ww+3lrYg2HfqVUk
lwIDBQAF
-----END PUBLIC KEY-----"""
pem_si = b"""-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA+bcTgKO6LUT1H6MFy02p
x2piclYYLgzi7tWzEqx7IO/zaWrUZV/RgwK83F9txfCGmuV3JDsrza9CqxDHEF5X
fQ5qaeP3G6hxyZJt92B2j2XvaJN2Yg1B4b5+7yjkLYqoiAijLnCWWoR8Tgf5tp7+
9znjwSON1ISew6Cr0ww0fRZZDQgJw5kiejYUhAJJkxhg9kiju4kxzq6QoZrayAXj
nqCBicRlbzkzty506rS0JQU2mEoLBtdkJE65mspRNuu0b3+JMSwawDIPPaUqABVT
H+AR71CtcBtW62ONRmVkqBP5UX2VyjY3oKjzqzLEpaPZowb/0ww+3lrYg2HfqVUk
lwIDA7Vv
-----END PUBLIC KEY-----"""
pem_pi = b"""-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4TfMxXg7hsS10OKf4So7
F6NzZf/6R6/DZ3AslXCP7HWU1qoCaIv+WJSsZSobWgVxt74GLigbErCNyF0UFe62
smMV6teZRyycllNdnr/n3IdfQbqz8BOw1QtxsWnhjXK3xdxgCLNAlO/4aZ8b13dN
84XkcTzkDucPdbJkfaqB0SVQURBLWjlXHVbGUvS0+kN3k2sCOIcI/3egiXW2iodl
pPVYBeamOMLrD1lIMgb+tMpFNE8M8Klz/eGCvEwJN8ydKXLgR7aJ73UZ+7fnWXHQ
skX8/d/bGdrUwg0nCiTYycBwFR45P3TCX7gMQrbsIxj9iO8pyfzgA8UV/4rfPNpY
XwIDAQAB
-----END PUBLIC KEY-----"""

# ==== ciphertext base64 dari soal (lengkap, jangan terpotong) ====
b64_en = "fSlq6MA49zXOVYZdKT9E4VAO9jUVvvZm55t3KNSaQ2uEENaDGywhSP1L5SnjFxhjYGrq9qFPDInW8e+H67hk16LxRBWocyhH91jKl4G3yEKIuUJibcV/7ABqY8jQO8Cku7wcpklhGFnaNNPu5Z7gP55s78VVJ3hP1GWR8fnZ9VC3S4O0dgjF7Qv0rOV6rcZA0fER6BUDWC/Uwzdo1K24wpMu1sfmsH/TavELwppYHnDqkymnvwTLUaSBkQ8MnEfUNrdQ7mrvO3W4A5xk2vFL8OT2mXBJWG9aR5qrUd5xHlRLWLOmyfWN4jkwOStOuZDa4PZOvwtDDPraXew1qSjdBw=="
b64_si = "nCwFmlMmicqWM25iYuB4HPEXpQ71fY0LbJzsCE0nV3uIAewjJLFbvfjoB1/TLQ0WnzSpJCaaw0NvGwVkDgDybwEajFE9ImR7I4n5Ps+SyqYYUA12BCCu5AS3WozwR3rv2/r5CaMyXqzbstwsm8f7fwFHIMzQpMt1/Imypgm5Z4D4xJ10/ShpBOiAu0+H5Ev3wdAf0op2K9+UAe7kqQ1tutdZkxyq9u7BYw6uck7888BX0OUJHQozmgnBXjcPgxzbHHNKUBbNy4G36J/hIql8GRPd0+4+72hVRdHKEHwEghgg+FxCHIsM/uboi90lxnV0o3X6YXJLo3MKwyhDT4PQkw=="
b64_pi = "s5m2702L2k+kuZX8Q04EJkmQrLA6AU8vasEQhWLx9Qv5Wq/0zgjLRLLE+MPkRaQB9iQXFMB03IRoQg9wMoeOWBG3wC8B4qeXOhY67QyXLRu+K3OYQ+aF3umItt6/wLadIlkqu7SB1OtxgrZE/FtsC3wHmRtDkSKKeO5zDZ0trjOM1ZodSmm+nRtqphb2mq2k0lfPJ1iAgEDNu4PmwFZu3113vlPQNDvmxtSFMt6tJRRaTmTdjXmxdEN1y0JL7FjdKR7Di7jVEnNJziqgxSd+11NhNl0qKt5+dyP3b1hRg/0dVtqKRNB1vU2FJDNRk7R5BvViEqLvL7KRKUVfovCXNw=="
flag_b64 = "YrBf/zUIzEOljwKKD96Q8eVraTbjtERToVxg4gUAKcQjhf8l991NJHS6NayzVajCK073cwxSnV5fYKP6DlZcGDqd6NLAER5Y5cR5qH8v7XY="

# === helper: integer k-th root (pure integer; no float)
def iroot_k(n: int, k: int) -> int:
    if n == 0: return 0
    # Newton method on integers
    x = int(pow(n, 1.0 / k))  # seed
    while True:
        y = ((k - 1) * x + n // pow(x, k - 1)) // k
        if y >= x:
            return x
        x = y

# === parse keys
rsa_en = RSA.import_key(pem_en)
rsa_si = RSA.import_key(pem_si)
rsa_pi = RSA.import_key(pem_pi)

N_en, e_en = rsa_en.n, rsa_en.e
N_si, e_si = rsa_si.n, rsa_si.e
N_pi, e_pi = rsa_pi.n, rsa_pi.e

assert N_en == N_si, "Common modulus harus sama antara en & si!"
assert N_en != N_pi, "pi mestinya beda modulus (red herring)."

# === decode ciphertext → integer
C_en = bytes_to_long(b64decode(b64_en))
C_si = bytes_to_long(b64decode(b64_si))

# === extended gcd untuk dapat a,b s.t. a*e_en + b*e_si = g
def xgcd(a, b):
    old_r, r = a, b
    old_s, s = 1, 0
    old_t, t = 0, 1
    while r:
        q = old_r // r
        old_r, r = r, old_r - q*r
        old_s, s = s, old_s - q*s
        old_t, t = t, old_t - q*t
    return old_r, old_s, old_t  # gcd, x, y

g, a, b = xgcd(e_en, e_si)
print(f"e_en={e_en}, e_si={e_si}, gcd={g}, a={a}, b={b}")

# === bangun M^g = C_en^a * C_si^b (mod N)
N = N_en
def modexp_signed(base, exp, mod):
    if exp >= 0:
        return pow(base, exp, mod)
    inv = inverse(base, mod)
    return pow(inv, -exp, mod)

M_pow_g = (modexp_signed(C_en, a, N) * modexp_signed(C_si, b, N)) % N

# === ambil akar ke-g (di sini g=5)
M = iroot_k(M_pow_g, g)
# verifikasi (opsional)
assert pow(M, g) == M_pow_g, "Root check gagal; kemungkinan wrap-around (M^g >= N)."

key = long_to_bytes(M)
print(f"Recovered key (hex): {key.hex()}  len={len(key)}")

# === decrypt flag (AES-128-CBC, IV=0)
ciphertext = b64decode(flag_b64)
iv = b"\x00" * 16
pt = unpad(AES.new(key, AES.MODE_CBC, iv=b'\x00'*16).decrypt(b64decode(flag_b64)), 16)

m = re.search(rb'SCH25\{[^}]+\}', pt)
if m:
    print(m.group(0).decode('ascii'))  # aman karena ini ASCII bersih
else:
    # fallback debug kalau CTF beda format
    print("No flag pattern found. Hex dump:", pt.hex())

print(pt.decode())
