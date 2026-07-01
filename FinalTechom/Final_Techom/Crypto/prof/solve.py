#!/usr/bin/env python3
import socket
import ast
import re
import math

HOST = "techcomfest.1pc.tf"
PORT = 33055

def recv_until(sock, marker: bytes) -> bytes:
    data = b""
    while marker not in data:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
    return data

def parse_var(text: str, name: str):
    # match like: N=123... or l=[...] or cts=[...] or secret=...
    m = re.search(rf"{name}\s*=\s*(.+)", text)
    if not m:
        raise ValueError(f"Failed to find {name} in output")
    rhs = m.group(1).strip()
    # sometimes extra lines after; try to take only the first logical python literal
    # We'll parse progressively if needed.
    try:
        return ast.literal_eval(rhs)
    except Exception:
        # fallback: take until line end
        line = rhs.splitlines()[0].strip()
        return ast.literal_eval(line)

def solve_instance(N: int, l: list, cts: list, secret_final: int):
    inv5 = pow(5, -1, N)
    S = sum(l) % N

    for delta in range(1, 6767):
        if math.gcd(delta, N) != 1:
            continue
        base = (-delta * S * inv5) % N

        ok = True
        cs = []
        for li, ct in zip(l, cts):
            c = (base + li * delta) % N
            if pow(c, 5, N) != ct:
                ok = False
                break
            cs.append(c)

        if ok:
            ori = secret_final
            for c in cs:
                ori ^= c
            return delta, base, cs, ori

    raise ValueError("No delta matched (unexpected)")

def main():
    with socket.create_connection((HOST, PORT)) as s:
        blob = recv_until(s, b"Your guess:")
        text = blob.decode(errors="replace")
        # print(text)  # uncomment for debugging

        N = parse_var(text, "N")
        l = parse_var(text, "l")
        cts = parse_var(text, "cts")
        secret_final = parse_var(text, "secret")

        delta, base, cs, ori = solve_instance(N, l, cts, secret_final)
        print(f"[+] Found delta={delta}")
        print(f"[+] Computed ori={ori}")

        s.sendall((str(ori) + "\n").encode())

        out = s.recv(65535).decode(errors="replace")
        print(out.strip())

        # If server prints: FLAG: <int>
        m = re.search(r"FLAG:\s*(\d+)", out)
        if m:
            flag_int = int(m.group(1))
            flag_bytes = flag_int.to_bytes((flag_int.bit_length() + 7) // 8, "big")
            try:
                print("[+] FLAG bytes:", flag_bytes)
                print("[+] FLAG text :", flag_bytes.decode())
            except Exception:
                print("[+] FLAG bytes:", flag_bytes)

if __name__ == "__main__":
    main()
