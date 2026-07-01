# Run this in SageMath

# --- Paste the challenge data here ---
n = 45
m = 130
q = 10009
Alpha = [...] 
beta = [...] 
ciphertexts = [...] 
# -------------------------------------

print("[*] Constructing the lattice...")
# Matrix dimensions: (m + n + 1) rows, (m + 1) columns
B = Matrix(ZZ, m + n + 1, m + 1)

# Insert q * I_m
for i in range(m):
    B[i, i] = q

# Insert A matrix
for i in range(n):
    for j in range(m):
        B[m + i, j] = Alpha[i][j]

# Insert beta vector
for j in range(m):
    B[m + n, j] = beta[j]

# Kannan's embedding weight
B[m + n, m] = 1

print("[*] Running LLL reduction...")
B_red = B.LLL()

e = None
# Look for the embedded row
for row in B_red:
    if abs(row[-1]) == 1:
        e = row[:-1]
        # Normalize the sign if it was flipped
        if row[-1] == -1:
            e = -e
        break

if e is None:
    print("[-] Failed to find the error vector.")
else:
    print(f"[+] Found error vector with length {e.norm().n():.2f}")

print("[*] Recovering the secret key (s)...")
A_mat = Matrix(GF(q), Alpha)
beta_minus_e = vector(GF(q), [beta[i] - e[i] for i in range(m)])

# Solve s * A = beta - e (mod q)
s = A_mat.solve_left(beta_minus_e)

print("[*] Decrypting ciphertexts...")
bits = []
for u, v in ciphertexts:
    u_vec = vector(GF(q), u)
    
    # Calculate v - s*u
    val = (v - s.dot_product(u_vec)) % q
    
    # Distinguish between 0 and 1 using q/2 (approx 5004) as the threshold
    if q // 4 < val < 3 * q // 4:
        bits.append(1)
    else:
        bits.append(0)

# Reconstruct the string from binary chunks
flag = "".join(chr(int("".join(map(str, bits[i:i+8])), 2)) for i in range(0, len(bits), 8))

print(f"[+] Flag: {flag}")
