import math
import sys
from Crypto.Util.number import long_to_bytes, inverse
from sympy.ntheory import discrete_log

def pollard_p1(n, B=2000000):
    """Mencari p dan q menggunakan serangan Pollard's p-1"""
    print(f"[*] Menjalankan Pollard's p-1 dengan limit B={B}...")
    a = 2
    for j in range(2, B + 1):
        a = pow(a, j, n)
        d = math.gcd(a - 1, n)
        if 1 < d < n:
            return d, n // d
        if j % 200000 == 0:
            print(f"    [-] Progress iterasi: {j}/{B}")
    return 0, 0

def main():
    # --- THE SHAMIR PRIME ---
    ps = 0x200000000000000000000000000000011

    # ==========================================
    # FRAGMENT 1: CARELESS RSA (128-bit)
    # ==========================================
    print("\n[1] MENGHITUNG FRAGMENT 1 (RSA 128-bit)")
    n1 = 0xc750f7f47aef6242736439bc3b838801
    c1 = 0xf36e4a2285924703f9e7db782477ca0f6a
    e = 65537

    factors_n1 = [3, 7, 41, 521, 114419, 5161824536957739003836676223]
    phi1 = 1
    for f in factors_n1:
        phi1 *= (f - 1)

    d1 = inverse(e, phi1)
    y1 = pow(c1, d1, n1)
    print(f"[+] Fragment 1 (y1) : {y1}")

    # ==========================================
    # FRAGMENT 2: STATIC DIFFIE-HELLMAN (42-bit)
    # ==========================================
    print("\n[2] MENGHITUNG FRAGMENT 2 (Diffie-Hellman)")
    p_dh = 0x391d61d453d
    g = 0x2
    A = 0xb6a40ff355
    B = 0x276791d0e7b

    print("[*] Menghitung Discrete Log (Baby-step Giant-step)...")
    a = discrete_log(p_dh, A, g)
    y2 = pow(B, a, p_dh)
    print(f"[+] Fragment 2 (y2) : {y2}")

    # ==========================================
    # FRAGMENT 3: CARELESS RSA PART 2 (512-bit)
    # ==========================================
    print("\n[3] MENGHITUNG FRAGMENT 3 (RSA 512-bit)")
    n2 = 0xbb0b8924ed0b348cb95a4106234d4025b313f03e9909e45a21ce39bc7879f6397b9f94b5d2eea7651122367b1438da177e68be6c616cdb0dc95cb79d13c16855
    c2 = 0x11219f9a7a2ba9c4811657027866881d55e35705c9f9c11cc87d5c99f4e59f740722cd33d85c8b86256de56ca680d3ed

    p2, q2 = pollard_p1(n2)

    if p2 == 0 or q2 == 0:
        print("\n[-] Pollard p-1 gagal. Modulus ini butuh metode ECM.")
        print("[!] Buka: https://www.alpertron.com.ar/ECM.HTM")
        print(f"[!] Masukkan n2: {n2}")
        try:
            p2 = int(input("\n[>] Masukkan p2 dari web: "))
            q2 = int(input("[>] Masukkan q2 dari web: "))
        except ValueError:
            print("[-] Input tidak valid. Keluar.")
            sys.exit(1)

    print(f"[+] Faktor ditemukan!\n    p2 = {p2}\n    q2 = {q2}")
    
    phi2 = (p2 - 1) * (q2 - 1)
    d2 = inverse(e, phi2)
    y3 = pow(c2, d2, n2)
    print(f"[+] Fragment 3 (y3) : {y3}")

    # ==========================================
    # SHAMIR SECRET RECONSTRUCTION
    # ==========================================
    print("\n[4] REKONSTRUKSI SHAMIR SECRET SHARING")
    # Formula modifikasi simpel untuk 3 shares: P(0) = 3*y1 - 3*y2 + y3 mod ps
    term1 = (y1 * 3) % ps
    term2 = (y2 * -3) % ps
    term3 = y3 % ps
    
    secret = (term1 + term2 + term3) % ps
    password = long_to_bytes(secret)
    
    print(f"[+] RECONSTRUCTION SUCCESS!")
    print(f"\n==========================================")
    print(f"[*] ZIP PASSWORD: {password.decode(errors='ignore')}")
    print(f"==========================================\n")

if __name__ == "__main__":
    main()
