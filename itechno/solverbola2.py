#!/usr/bin/env python3
# ttcomp_unpack.py
# Unpack TTComp (header 2-byte) -> PKWARE DCL Implode -> raw payload via 'blast'
# Usage: python ttcomp_unpack.py <input.tt> <output.bin>

import sys, os, shutil, subprocess

DICT_MAP = {0x04: 1024, 0x05: 2048, 0x06: 4096}

def find_blast():
    # prefer local ./blast, else PATH
    local = os.path.join(os.path.dirname(__file__), "blast")
    if os.path.isfile(local) and os.access(local, os.X_OK):
        return local
    return shutil.which("blast")

def usage():
    print("Usage: python ttcomp_unpack.py <input.tt> <output.bin>")
    sys.exit(1)

def main():
    if len(sys.argv) != 3:
        usage()

    inf, outf = sys.argv[1], sys.argv[2]
    if not os.path.isfile(inf):
        print(f"[ERR] Input not found: {inf}")
        sys.exit(1)

    with open(inf, "rb") as f:
        data = f.read()

    if len(data) < 3:
        print("[ERR] File too small to be TTComp (needs >= 3 bytes).")
        sys.exit(1)

    mode = data[0]  # 0=binary, 1=text (praktisnya: cuma metadata)
    dict_byte = data[1]
    payload = data[2:]

    dict_sz = DICT_MAP.get(dict_byte, None)
    mode_str = "binary" if mode == 0x00 else ("text" if mode == 0x01 else f"unknown(0x{mode:02x})")
    dict_str = f"{dict_sz} bytes" if dict_sz else f"unknown_code(0x{dict_byte:02x})"

    print(f"[*] TTComp header: mode={mode_str}, dict={dict_str}")
    print(f"[*] Imploded payload size: {len(payload)} bytes")

    blast = find_blast()
    if not blast:
        print("[ERR] 'blast' binary not found.")
        print("      Quick build (Linux):")
        print("        curl -LO https://zlib.net/zlib_fossils/contrib/blast/blast.c")
        print("        gcc -O2 blast.c -o blast")
        print("      Lalu taruh 'blast' di PATH atau di folder skrip ini.")
        sys.exit(2)

    # Run blast with payload on stdin
    try:
        res = subprocess.run(
            [blast],
            input=payload,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False
        )
    except Exception as e:
        print(f"[ERR] Failed to run blast: {e}")
        sys.exit(2)

    if res.returncode != 0:
        # Mark Adler's blast prints errors to stderr; -3 sering muncul jika header TTComp belum di-strip.
        print(f"[ERR] blast exit code {res.returncode}")
        if res.stderr:
            sys.stderr.write(res.stderr.decode(errors="replace"))
        print("\n[HINT] Pastikan 2 byte header TTComp sudah di-strip (skrip ini sudah melakukannya).")
        print("       Jika tetap gagal, kemungkinan stream korup/truncated.")
        sys.exit(3)

    outdata = res.stdout
    with open(outf, "wb") as f:
        f.write(outdata)

    print(f"[OK] Wrote {len(outdata)} bytes -> {outf}")

    # Bonus: quick peek for common flag markers
    try:
        text = outdata.decode("utf-8", errors="ignore")
        for marker in ("ITECHNO2025{", "ITechno2025{", "flag{", "FLAG{"):
            if marker in text:
                print(f"[!] Possible flag marker spotted: '{marker}'")
                break
    except Exception:
        pass

if __name__ == "__main__":
    main()
