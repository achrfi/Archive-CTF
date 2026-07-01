# save as hunt_flag_unity.py
import sys, os, re, codecs

PATTERNS = [
    re.compile(rb"ITECHNO2025\{[^}]{0,200}\}", re.I),
    re.compile(rb"ITECHNO2025", re.I),
    re.compile(rb"\bflag\b", re.I),
]

def utf16le_to_ascii(b):
    try:
        return b.decode("utf-16le", "ignore").encode("latin-1", "ignore")
    except:
        return b""

def rot(s, k):
    out = bytearray()
    for c in s:
        if 65 <= c <= 90:
            out.append((c-65+k)%26+65)
        elif 97 <= c <= 122:
            out.append((c-97+k)%26+97)
        else:
            out.append(c)
    return bytes(out)

def try_variants(buf):
    variants = [("raw", buf)]
    # UTF-16LE
    variants.append(("utf16le->latin1", utf16le_to_ascii(buf)))
    # reversed
    variants.append(("reversed", buf[::-1]))
    # rot13/rot5/rot18 etc (kecil-kecilan)
    for k in (13, 5, 18):
        variants.append((f"rot{k}", rot(buf, k)))
    # XOR ringan
    for key in (0x10, 0x20, 0x30, 0x55, 0xAA, 0xFF):
        variants.append((f"xor{key:02x}", bytes([b ^ key for b in buf])))
    return variants

def search_file(path, max_size=60*1024*1024):
    hits = []
    try:
        if os.path.getsize(path) > max_size:
            return hits
        with open(path, "rb") as f:
            data = f.read()
    except:
        return hits

    for tag, v in try_variants(data):
        for rx in PATTERNS:
            for m in rx.finditer(v):
                s, e = m.start(), m.end()
                ctx = v[max(0, s-80):min(len(v), e+160)]
                hits.append((tag, rx.pattern.decode("latin-1","ignore"), s, e, ctx))
    return hits

def main():
    root = sys.argv[1] if len(sys.argv) > 1 else "."
    targets = []
    for r, d, files in os.walk(root):
        for fn in files:
            p = os.path.join(r, fn)
            # fokusin Unity Data
            if any(x in p for x in ("_Data", "sharedassets", ".resS", ".assets", "Resources")):
                targets.append(p)
    if not targets:
        for r, d, files in os.walk(root):
            for fn in files:
                targets.append(os.path.join(r, fn))

    total = 0
    for p in targets:
        hs = search_file(p)
        if hs:
            print(f"\n[+] {p}")
            for tag, pat, s, e, ctx in hs:
                prev = ctx.replace(b"\n", b" ").replace(b"\r", b" ")
                print(f"  - variant={tag} pat={pat} off={s}..{e}")
                print(f"    ctx: {prev[:300].decode('latin-1','ignore')}")
                total += 1
    if total == 0:
        print("No hits. Coba decompile jalur B.")

if __name__ == "__main__":
    main()
