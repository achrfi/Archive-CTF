from pwn import *
from sage.all import *
import random

# --- Challenge Parameters ---
P = 5 * (1 << 55) + 1
ALPHA = 3
T = 2
R_F_PRE = 2
R_P = 10
R_F_POST = 2
TOTAL_ROUNDS = R_F_PRE + R_P + R_F_POST

def generate_mds(prime, t, seed=0xDEADBEEF):
    # Perbaikan: cast seed menjadi int() agar dikenali oleh random bawaan Python
    rng = random.Random(int(seed))
    while True:
        xs = [rng.randrange(1, prime) for _ in range(t)]
        ys = [rng.randrange(1, prime) for _ in range(t)]
        ok = (
            len(set(xs)) == t
            and len(set(ys)) == t
            and all((x + y) % prime != 0 for x in xs for y in ys)
        )
        if ok:
            break
    return [
        [pow((xs[i] + ys[j]) % prime, -1, prime) for j in range(t)] for i in range(t)
    ]

def generate_round_constants(prime, t, total_rounds, seed=0xDEADBEEF):
    # Perbaikan: cast seed menjadi int() agar dikenali oleh random bawaan Python
    rng = random.Random(int(seed))
    return [[rng.randrange(prime) for _ in range(t)] for _ in range(total_rounds)]

MDS = generate_mds(P, T)
ROUND_CONSTANTS = generate_round_constants(P, T, TOTAL_ROUNDS)

# Setup SageMath Field and Matrix
F = GF(P)
MDS_F = Matrix(F, MDS)

# --- Polynomial Poseidon Implementation ---

def sbox(v):
    return v^3

def linear_layer(state):
    return [sum(MDS_F[i,j] * state[j] for j in range(T)) for i in range(T)]

def add_round_constants(state, rc):
    return [state[i] + F(rc[i]) for i in range(T)]

def full_round(state, rc):
    s = add_round_constants(state, rc)
    s = [sbox(v) for v in s]
    return linear_layer(s)

def partial_round(state, rc):
    s = add_round_constants(state, rc)
    s[0] = sbox(s[0])
    return linear_layer(s)

def get_hash_polynomial():
    PR.<m> = PolynomialRing(F)
    # Sponge absorbs the preimage block
    state = [m, PR(0)]
    
    rc_idx = 0
    for _ in range(R_F_PRE):
        state = full_round(state, ROUND_CONSTANTS[rc_idx])
        rc_idx += 1
    for _ in range(R_P):
        state = partial_round(state, ROUND_CONSTANTS[rc_idx])
        rc_idx += 1
    for _ in range(R_F_POST):
        state = full_round(state, ROUND_CONSTANTS[rc_idx])
        rc_idx += 1
        
    return state[0]

# --- Exploit Execution ---
if __name__ == "__main__":
    print("[*] Building the Poseidon polynomial. This takes a few seconds...")
    poly = get_hash_polynomial()
    print(f"[+] Polynomial built! Degree: {poly.degree()}")

    # Connect to the challenge server
    # PENTING: Pastikan server CTF masih hidup dan port-nya sesuai
    io = remote('crypto.cbd2026.cloud', 50001)
    
    io.recvuntil(b'Hash: ')
    target_hash = int(io.recvline().strip())
    print(f"[+] Target hash received: {target_hash}")

    # Set up the equation: poly(m) - target_hash = 0
    target_poly = poly - F(target_hash)
    
    print("[*] Finding roots for the target hash (ini memakan waktu beberapa detik)...")
    roots = target_poly.roots(multiplicities=False)
    print(f"[+] Found {len(roots)} potential preimage(s): {roots}")

    for root in roots:
        print(f"[*] Trying root: {root}")
        io.recvuntil(b'Enter preimage: ')
        io.sendline(str(root).encode())
        
        resp = io.recvline().decode()
        if "Correct preimage and hash match!" in resp:
            print("[+] Success! Here is your flag:")
            print(io.recvall().decode())
            break
        elif "Correct hash but wrong preimage" in resp:
            print("[-] Collision found, but not the original preimage. Trying next root...")
            continue
        else:
            print(f"[!] Unknown response: {resp}")
            break
