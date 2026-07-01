#!/usr/bin/env python3
import socket
import sys
import math
import re
from typing import Iterator, Tuple, List

HOSTS = ["ctf.compfest.id"]
PORTS = [7102, 6102]  # main, backup

BOUND_DECIMAL = str(1 << 1000)  # 2^1000

# ------------------ util big-int ------------------

def is_square(n: int) -> Tuple[bool, int]:
    if n < 0:
        return (False, 0)
    r = math.isqrt(n)
    return (r*r == n, r)

def i2b(n: int) -> bytes:
    if n == 0:
        return b"\x00"
    length = (n.bit_length() + 7) // 8
    return n.to_bytes(length, "big")

# ------------------ continued fraction ------------------

def contfrac_num_denom(num: int, den: int) -> List[int]:
    """Continued fraction of num/den (Euclidean algorithm)."""
    a = []
    while den:
        q, num, den = num // den, den, num % den
        a.append(q)
    return a

def convergents(cf: List[int]) -> Iterator[Tuple[int, int]]:
    """Yield convergents p/q from continued fraction terms."""
    p0, q0 = 1, 0
    p1, q1 = cf[0], 1
    yield (p1, q1)
    for a in cf[1:]:
        p2 = a * p1 + p0
        q2 = a * q1 + q0
        yield (p2, q2)
        p0, q0, p1, q1 = p1, q1, p2, q2

# ------------------ factor from phi' ------------------

def factor_from_phi_prime(N: int, phi_prime: int) -> Tuple[int, int]:
    """
    phi' = (p^2 - 1)(q^2 - 1) = N^2 - (p^2 + q^2) + 1
    => (p+q)^2 = (N+1)^2 - phi'
       (p-q)^2 = (N-1)^2 - phi'
    """
    S2 = (N + 1) * (N + 1) - phi_prime
    D2 = (N - 1) * (N - 1) - phi_prime

    okS, S = is_square(S2)
    okD, D = is_square(D2)
    if not (okS and okD):
        raise ValueError("Not square structure")

    # p = (S + D)/2, q = (S - D)/2
    if (S + D) % 2 != 0 or (S - D) % 2 != 0:
        raise ValueError("Parity mismatch")
    p = (S + D) // 2
    q = (S - D) // 2
    if p * q != N:
        # try swapped sign for D (|p-q|)
        p = (S - D) // 2
        q = (S + D) // 2
        if p * q != N:
            raise ValueError("pq != N")
    return (int(p), int(q))

# ------------------ main attack ------------------

def recover_phi_and_factor(N: int, e: int, max_convergents: int = 20000) -> Tuple[int, int, int]:
    """
    Use CF on N^2 / e. The true (k,s) is a convergent of N^2/e (very tight),
    and satisfies (e*k + 1) % s == 0. Then phi' = (e*k + 1)//s.
    """
    num = N * N
    den = e
    cf = contfrac_num_denom(num, den)

    tried = 0
    for (k, s) in convergents(cf):
        tried += 1
        # safety bound: convergents can be many; break if exceeding reasonable count
        if tried > max_convergents:
            break

        # k/s must be positive; s>0 always here
        if k <= 0:
            continue

        # Check divisibility condition: phi' * s = e*k + 1
        t = e * k + 1
        if t % s != 0:
            continue

        phi_prime = t // s

        # Quick sanity: phi' must be huge ~ N^2 scale
        # Reject obviously wrong sizes
        if phi_prime.bit_length() < N.bit_length() + 1000:  # heuristic
            continue

        # Try factorization via square structure
        try:
            p, q = factor_from_phi_prime(N, phi_prime)
            return phi_prime, p, q
        except Exception:
            continue

    raise RuntimeError("Failed to recover phi' via convergents. Try again or adjust limits.")

def modinv(a: int, m: int) -> int:
    # Python 3.8+ has pow(a, -1, m)
    return pow(a, -1, m)

# ------------------ remote I/O ------------------

def recv_all_until(sock: socket.socket, token: bytes, timeout: float = 10.0) -> bytes:
    sock.settimeout(timeout)
    buf = b""
    while token not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            break
        buf += chunk
    return buf

def parse_int_after(prefix: str, text: str) -> int:
    # e.g. lines like "N:  12345"
    m = re.search(re.escape(prefix) + r"\s*([0-9]+)", text)
    if not m:
        raise ValueError(f"Cannot find integer after '{prefix}'")
    return int(m.group(1))

def interact_and_fetch_params(host: str, port: int) -> Tuple[int, int, int]:
    with socket.create_connection((host, port), timeout=10.0) as s:
        # Read until it asks for bound (after printing N)
        data = recv_all_until(s, b"Enter bound")
        text = data.decode(errors="ignore")
        # print(text)  # debug if needed

        N = parse_int_after("N:", text)

        # Send bound
        s.sendall(BOUND_DECIMAL.encode() + b"\n")

        # Get the rest (should include e and ct)
        data2 = recv_all_until(s, b"ct:")
        # Then one more read to grab the number after "ct:" line
        data2 += s.recv(8192)
        text2 = data2.decode(errors="ignore")
        # print(text2)  # debug

        e = parse_int_after("e:", text2)
        ct = parse_int_after("ct:", text2)
        return N, e, ct

# ------------------ runner ------------------

def main():
    # Try main then backup automatically
    last_err = None
    for h in HOSTS:
        for p in PORTS:
            try:
                print(f"[+] Connecting to {h}:{p} ...")
                N, e, ct = interact_and_fetch_params(h, p)
                print("[+] Received parameters")
                print("    N bits:", N.bit_length())
                print("    e bits:", e.bit_length())

                print("[*] Recovering phi' and factors using CF on N^2/e...")
                phi_prime, P, Q = recover_phi_and_factor(N, e)
                print("[+] Factored N")
                print("    p bits:", P.bit_length())
                print("    q bits:", Q.bit_length())

                d = modinv(e, phi_prime)
                m = pow(ct, d, N)
                msg = i2b(m)

                # Try to decode as bytes; print raw and ascii-safe
                print("[+] Decrypted message (hex):", msg.hex())
                try:
                    print("[+] As ASCII:", msg.decode("utf-8", errors="ignore"))
                except Exception:
                    pass
                return
            except Exception as ex:
                print(f"[!] Attempt {h}:{p} failed: {ex}")
                last_err = ex
                continue
    raise SystemExit(f"All connection attempts failed: {last_err}")

if __name__ == "__main__":
    main()
