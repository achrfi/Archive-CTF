# solve_mt_and_unmask.py
# Python 3.11+, no external deps. Bisa makan RAM ~100-200MB saat eliminasi.

import re, sys, json
from math import ceil

N = 624
M = 397
MATRIX_A = 0x9908B0DF
UPPER_MASK = 0x80000000
LOWER_MASK = 0x7FFFFFFF

# ---------- Tempering (CPython _random) ----------
def temper(y):
    y ^= (y >> 11)
    y ^= (y << 7) & 0x9D2C5680
    y ^= (y << 15) & 0xEFC60000
    y ^= (y >> 18)
    return y & 0xFFFFFFFF

# Precompute alpha: LSB( temper(unit_bit_i) ) = alpha[i]
def lsb_alpha():
    al = [0]*32
    for i in range(32):
        y = temper(1 << i)
        al[i] = y & 1
    return al

ALPHA = lsb_alpha()

# --------- Represent each 32-bit word as 32 basis vectors over 19937 vars ----------
# We store each bit-vector as python int of length 19937 bits.
DIM = N*32  # 19968
def basis_word_bits():
    # word_bits[w][b] is int with 1 at position (w*32 + b)
    wb = [[0]*32 for _ in range(N)]
    for w in range(N):
        for b in range(32):
            idx = w*32 + b
            wb[w][b] = 1 << idx
    return wb

# Compute one row-vector (length DIM) for current pre-tempered 32-bit word
# using ALPHA (which bits in that word influence output LSB after temper).
def row_from_word_bits(word_bits):
    row = 0
    for b in range(32):
        if ALPHA[b]:
            row ^= word_bits[b]
    return row

# Perform one "twist" generating next 624 pre-tempered words in terms of current state's word_bits
def twist(words):
    # words: list of N each = [32 bit-vectors], returns new list same shape
    res = [[0]*32 for _ in range(N)]
    for i in range(N):
        j = (i+1) % N
        m = (i + M) % N

        # x = (words[i] & UPPER) | (words[j] & LOWER)
        # Bits of x:
        #  - bit31 comes from words[i][31]
        #  - bits 0..30 come from words[j][0..30]
        x_bits = [0]*32
        x_bits[31] = words[i][31]
        for k in range(31):
            x_bits[k] = words[j][k]

        # x >> 1: bit k becomes x_bits[k+1], and bit31 gets 0
        xshr_bits = [0]*32
        for k in range(31):
            xshr_bits[k] = x_bits[k+1]
        xshr_bits[31] = 0

        # lsb(x) = x_bits[0] = words[j][0]
        lsb_x = x_bits[0]  # bit-vector signalling this boolean

        # (A if lsb(x) else 0) is linear: XOR of A's ones scaled by lsb_x
        # Precompute bits of MATRIX_A:
        A_bits = [((MATRIX_A >> k) & 1) for k in range(32)]

        # newword = words[m] ^ xshr ^ (A * lsb_x)
        for k in range(32):
            v = words[m][k] ^ xshr_bits[k]
            if A_bits[k]:
                v ^= lsb_x  # multiply by bit signals XOR with lsb_x
            res[i][k] = v
    return res

# Build matrix A (19968 rows) and RHS b from 'even/odd' sequence, also advance to the point
# right after those 19968 outputs (so we know "current" state to generate 1024-bit noises).
def build_system_and_advance(parities):
    assert len(parities) == DIM
    words = basis_word_bits()
    rows = []
    bvec = []
    idx = 0
    for out_idx in range(DIM):
        # current pre-tempered word is words[idx]
        row = row_from_word_bits(words[idx])
        rows.append(row)
        bvec.append(0 if parities[out_idx] == "even" else 1)
        idx += 1
        if idx == N:
            words = twist(words)
            idx = 0
    return rows, bvec, words, idx

# Solve A * s = b over GF(2), where rows are bit-int and s is DIM-bit int
def gauss_solve(rows, b):
    nrow = len(rows)
    ncol = DIM
    rows = rows[:]  # copy
    b = b[:]

    col = 0
    where = [-1]*ncol
    for r in range(nrow):
        # find pivot col where rows[r] has 1
        piv = -1
        rr = rows[r]
        # find first 1-bit from current col
        mask = rr >> col
        if mask == 0:
            # need to swap with a lower row that has any 1 at/after col
            sw = r
            found = False
            while sw < nrow:
                if (rows[sw] >> col) != 0:
                    rows[r], rows[sw] = rows[sw], rows[r]
                    b[r], b[sw] = b[sw], b[r]
                    rr = rows[r]
                    found = True
                    break
                sw += 1
            if not found:
                # advance col until we find possible pivot
                while col < ncol and all(((rows[k] >> col) & 1) == 0 for k in range(r, nrow)):
                    col += 1
                if col >= ncol:
                    break
                # re-check current row
                if ((rows[r] >> col) & 1) == 0:
                    # try swap again
                    sw = r
                    while sw < nrow:
                        if ((rows[sw] >> col) & 1):
                            rows[r], rows[sw] = rows[sw], rows[r]
                            b[r], b[sw] = b[sw], b[r]
                            rr = rows[r]
                            break
                        sw += 1
        # find exact pivot bit
        while col < ncol and ((rows[r] >> col) & 1) == 0:
            col += 1
        if col >= ncol:
            break
        where[col] = r

        # eliminate this pivot from other rows
        for i in range(nrow):
            if i != r and ((rows[i] >> col) & 1):
                rows[i] ^= rows[r]
                b[i] ^= b[r]
        col += 1

    # build solution
    s = 0
    for j in range(ncol):
        if where[j] != -1:
            bit = b[where[j]] & 1
            if bit:
                s |= (1 << j)
        else:
            # free var -> assume 0 (should be full rank here)
            pass
    # verify
    for i in range(nrow):
        lhs = (bin(rows[i] & s).count("1") & 1)
        if lhs != b[i]:
            raise ValueError("No solution / mismatch at row {}".format(i))
    return s

def words_from_solution(sol_bits):
    # Extract 624 words of 32 bits from the DIM-bit solution
    words = [0]*N
    for w in range(N):
        val = 0
        for b in range(32):
            if (sol_bits >> (w*32 + b)) & 1:
                val |= (1 << b)
        words[w] = val
    return words

# Given state words and idx, generate k 32-bit outputs like CPython's MT
def mt_gen32(words, idx, k):
    out = []
    w = words[:]
    i = idx
    while k > 0:
        if i == N:
            # twist
            nw = [0]*N
            for a in range(N):
                y = (w[a] & UPPER_MASK) | (w[(a+1)%N] & LOWER_MASK)
                nw[a] = w[(a+M)%N] ^ (y >> 1) ^ (MATRIX_A if (y & 1) else 0)
            w = nw
            i = 0
        y = w[i]
        i += 1
        out.append(temper(y))
        k -= 1
    return out, w, i

def getrandbits_1024(gen_state_words, gen_idx):
    # get 1024 random bits as CPython: concatenate 32-bit blocks (high to low)
    outs, w2, i2 = mt_gen32(gen_state_words, gen_idx, 32)  # 32 * 32 = 1024
    acc = 0
    for v in outs:
        acc = ((acc << 32) | v) & ((1 << 1024) - 1)
    return acc, w2, i2

# ---------- Main pipeline ----------
def main():
    if len(sys.argv) < 2:
        print("Usage: python solve_mt_and_unmask.py TRANSCRIPT.txt")
        sys.exit(1)

    txt = open(sys.argv[1], 'r', encoding='utf-8', errors='ignore').read().strip().splitlines()
    parities = []
    p=e=n=None
    coeffs=None
    c1t=c2t=c1s=c2s=None

    for line in txt:
        if line.strip() in ("even","odd"):
            parities.append(line.strip())
        elif line.startswith("p ="):
            p = int(line.split("=",1)[1].strip())
        elif line.startswith("e ="):
            e = int(line.split("=",1)[1].strip())
        elif line.startswith("n ="):
            n = int(line.split("=",1)[1].strip())
        elif line.startswith("coeffs ="):
            coeffs = eval(line.split("=",1)[1].strip())
        elif line.startswith("c1_test ="):
            c1t = int(line.split("=",1)[1].strip())
        elif line.startswith("c2_test ="):
            c2t = int(line.split("=",1)[1].strip())
        elif line.startswith("c1_secret ="):
            c1s = int(line.split("=",1)[1].strip())
        elif line.startswith("c2_secret ="):
            c2s = int(line.split("=",1)[1].strip())

    assert len(parities) == DIM, f"Need {DIM} parity lines, got {len(parities)}"
    assert None not in (p,e,n,coeffs,c1t,c2t,c1s,c2s)

    print("[*] Building linear system...")
    rows, bvec, words_lin, idx_lin = build_system_and_advance(parities)

    print("[*] Solving GF(2) system (this may take a bit)...")
    sol = gauss_solve(rows, bvec)

    print("[*] Reconstructing initial extractable words...")
    init_words = words_from_solution(sol)

    # Now advance exactly 19968 outputs (already mirrored by build_system), so current state equals words_lin/idx_lin
    # We will generate exactly as CPython for 4 x 1024-bit noises
    print("[*] Generating 4x1024-bit noises...")
    n1, w2, i2 = getrandbits_1024(init_words, 0)  # we start from the very beginning of the same output sequence
    # but above produced first 1024 bits; our parities consumed 19968 outputs!
    # So we must skip DIM 32-bit outputs first:
    skip, w3, i3 = mt_gen32(init_words, 0, DIM)
    n1, w4, i4 = getrandbits_1024(w3, i3)
    n2, w5, i5 = getrandbits_1024(w4, i4)
    n3, w6, i6 = getrandbits_1024(w5, i5)
    n4, w7, i7 = getrandbits_1024(w6, i6)

    print("[*] Unmasking ciphertexts...")
    c1_test = c1t - n1
    c2_test = c2t - n2
    c1_secret = c1s - n3
    c2_secret = c2s - n4

    print("[*] Sanity check c1_test == c1_secret:", c1_test == c1_secret)

    # test_msg is constant in chall
    test_msg = int.from_bytes(b"This is just a test message.", "big")

    # modular inverses
    def inv(a, mod):
        return pow(a, -1, mod)

    s_test = (c2_test * inv(test_msg, n)) % n
    poly_result = (c2_secret * inv(s_test, n)) % n

    out = {
        "p": p, "n": n, "e": e,
        "coeffs": coeffs,
        "c1_test": str(c1_test),
        "c2_test": str(c2_test),
        "c1_secret": str(c1_secret),
        "c2_secret": str(c2_secret),
        "s_test": str(s_test),
        "poly_result": str(poly_result)
    }
    with open("stage1_unmasked.json","w") as f:
        json.dump(out, f, indent=2)
    print("[+] Wrote stage1_unmasked.json")

if __name__ == "__main__":
    main()
