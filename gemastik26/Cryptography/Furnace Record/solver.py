#!/usr/bin/env python3
import json
import hashlib
import math

def factor_known_n(n):
    # Dari hasil faktorisasi n:
    p = 18446744073709551557
    q = 18446744073709551629

    assert p * q == n
    return p, q

def lcm(a, b):
    return a // math.gcd(a, b) * b

def main():
    with open("spool.bin", "rb") as f:
        raw = f.read().splitlines()[1]

    spool = json.loads(raw)

    n = int(spool["n"], 16)
    a = int(spool["a"], 16)
    turns = spool["turns"]
    capsule = bytes.fromhex(spool["capsule"])

    p, q = factor_known_n(n)

    lambda_n = lcm(p - 1, q - 1)

    # x setelah t kali squaring adalah:
    # x = a^(2^turns) mod n
    #
    # Karena n sudah difaktorkan, eksponen dapat direduksi modulo lambda(n).
    e = pow(2, turns, lambda_n)

    x = pow(a, e, n)

    seed = x.to_bytes((n.bit_length() + 7) // 8, "big")

    stream = b""
    counter = 0
    while len(stream) < len(capsule):
        stream += hashlib.sha256(seed + counter.to_bytes(4, "big")).digest()
        counter += 1

    plaintext = bytes(c ^ k for c, k in zip(capsule, stream))

    print(plaintext.decode())

if __name__ == "__main__":
    main()
