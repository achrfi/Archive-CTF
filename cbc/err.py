# Create a ready-to-run solver script using a 4-way meet-in-the-middle (Schroeppel–Shamir style)
# to recover the flag from the provided `output` file. It should work fast for n=48.
# The script prints the recovered flag.
from textwrap import dedent

code = dedent(r'''
import re, ast, sys, time, heapq

def extract_list(name, text):
    m = re.search(rf'{name}\s*=\s*(\[.*?\])', text, flags=re.S)
    if not m:
        raise ValueError(f"Could not find {name} in the file.")
    return ast.literal_eval(m.group(1))

def load_output(path):
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        raw = f.read()
    pubKey = extract_list('pubKey', raw)
    ct_lst = extract_list('ct_lst', raw)
    return pubKey, ct_lst

def compute_group(weights, indices):
    m = len(indices)
    sums = []
    masks = []
    # 2^m subsets
    for mask in range(1<<m):
        s = 0
        mm = mask
        while mm:
            lsb = mm & -mm
            i = (lsb.bit_length()-1)
            s += weights[indices[i]]
            mm ^= lsb
        sums.append(s)
        masks.append(mask)
    # sort by sums
    order = sorted(range(len(sums)), key=sums.__getitem__)
    sums = [sums[i] for i in order]
    masks = [masks[i] for i in order]
    return sums, masks

def solve_block(T, SA, MA, SB, MB, SC, MC, SD, MD):
    nA = len(SA); nB = len(SB); nC = len(SC); nD = len(SD)
    # Initialize AB min-heap and CD max-heap
    heap_ab = [(SA[i] + SB[0], i, 0) for i in range(nA)]
    heapq.heapify(heap_ab)
    heap_cd = [(-(SC[k] + SD[-1]), k, nD-1) for k in range(nC)]
    heapq.heapify(heap_cd)
    while heap_ab and heap_cd:
        s_ab, i, j = heap_ab[0]
        s_cd = -heap_cd[0][0]
        total = s_ab + s_cd
        if total == T:
            s_ab, i, j = heapq.heappop(heap_ab)
            s_cd_neg, k, l = heapq.heappop(heap_cd)
            return MA[i], MB[j], MC[k], MD[l]
        elif total < T:
            s_ab, i, j = heapq.heappop(heap_ab)
            if j+1 < nB:
                heapq.heappush(heap_ab, (SA[i] + SB[j+1], i, j+1))
        else:
            s_cd_neg, k, l = heapq.heappop(heap_cd)
            if l-1 >= 0:
                heapq.heappush(heap_cd, (-(SC[k] + SD[l-1]), k, l-1))
    return None

def bits_from_masks(n, masks, group_size):
    # masks: (maskA, maskB, maskC, maskD)
    bitvec = [0]*n
    offs = 0
    for g, m in enumerate(masks):
        for i in range(group_size):
            if (m >> i) & 1:
                bitvec[offs + i] = 1
        offs += group_size
    return bitvec

def main():
    path = sys.argv[1] if len(sys.argv) > 1 else 'output'
    pubKey, ct_lst = load_output(path)
    n = len(pubKey)
    assert n % 4 == 0, "n must be divisible by 4"
    g = n // 4
    # Index groups
    groups = [list(range(i*g, (i+1)*g)) for i in range(4)]
    # Precompute group sums
    SA, MA = compute_group(pubKey, groups[0])
    SB, MB = compute_group(pubKey, groups[1])
    SC, MC = compute_group(pubKey, groups[2])
    SD, MD = compute_group(pubKey, groups[3])
    # Solve each block
    all_bits = []
    for idx, T in enumerate(ct_lst):
        t0 = time.time()
        masks = solve_block(T, SA, MA, SB, MB, SC, MC, SD, MD)
        if masks is None:
            print(f"[!] Block {idx}: No solution found")
            return
        bits = bits_from_masks(n, masks, g)
        all_bits.extend(bits)
        t1 = time.time()
        print(f"[*] Block {idx} solved in {t1-t0:.2f}s")
    # Rebuild integer from little-endian bit order
    msg_int = 0
    for k, b in enumerate(all_bits):
        if b:
            msg_int |= (1 << k)
    flag_bytes = msg_int.to_bytes(n, 'big')
    try:
        print("[+] Flag:", flag_bytes.decode('utf-8'))
    except UnicodeDecodeError:
        print("[+] Flag (utf-8 w/ replacement):", flag_bytes.decode('utf-8', errors='replace'))
        print("[+] Raw bytes:", flag_bytes)

if __name__ == "__main__":
    main()
''')

with open('/mnt/data/solver.py', 'w', encoding='utf-8') as f:
    f.write(code)

print("Created solver at /mnt/data/solver.py")
