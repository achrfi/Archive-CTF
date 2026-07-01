#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import sys, os, re

FLAG_PATS = [b"ITECHNO2025{", b"ITECHNO{", b"FLAG{", b"CTF{"]

# ============== Utilities ==============
def ensure_dir(p):
    d = os.path.dirname(p)
    if d and not os.path.isdir(d):
        os.makedirs(d, exist_ok=True)

def dump(path, blob):
    ensure_dir(path)
    with open(path, "wb") as f:
        f.write(blob)

def looks_texty(b):
    if not b or len(b) < 64: return False
    ascii_ratio = sum(32 <= x <= 126 for x in b) / len(b)
    return ascii_ratio > 0.25 or any(p in b for p in FLAG_PATS)

def scan_flags(tag, b):
    hit = False
    for pat in FLAG_PATS:
        for m in re.finditer(re.escape(pat), b, flags=re.IGNORECASE):
            s = max(0, m.start() - 64); e = min(len(b), m.end() + 128)
            ctx = b[s:e].decode("latin1", "ignore")
            print(f"\n[FLAG?] {tag} @ {m.start()}:\n{ctx}")
            hit = True
    # generic {...}
    for m in re.finditer(br"[A-Z0-9_]{3,}\{[^\}\n]{3,120}\}", b):
        s = max(0, m.start()-32); e = min(len(b), m.end()+32)
        ctx = b[s:e].decode("latin1","ignore")
        print(f"\n[BRACED] {tag} @ {m.start()}:\n{ctx}")
        hit = True
    return hit

# ============== Simple obfuscation decoders ==============
def rot47(data):
    out = bytearray()
    for c in data:
        if 33 <= c <= 126:
            out.append(33 + ((c - 33 + 47) % 94))
        else:
            out.append(c)
    return bytes(out)

def rot_alpha(data, k):
    out = bytearray()
    for c in data:
        if 65 <= c <= 90:
            out.append(65 + ((c - 65 + k) % 26))
        elif 97 <= c <= 122:
            out.append(97 + ((c - 97 + k) % 26))
        else:
            out.append(c)
    return bytes(out)

def brute_obfuscations(tag, blob, outdir):
    hits = False
    # 1) ROT47
    d = rot47(blob)
    if scan_flags(tag + ".rot47", d):
        dump(os.path.join(outdir, f"{tag}.rot47.bin"), d)
        hits = True
    # 2) ROT-alpha 0..25
    for k in range(26):
        d = rot_alpha(blob, k)
        if scan_flags(tag + f".rot{k}", d):
            dump(os.path.join(outdir, f"{tag}.rot{k}.bin"), d)
            hits = True
    # 3) XOR 0..255
    for k in range(256):
        d = bytes([b ^ k for b in blob])
        if scan_flags(tag + f".xor{k:02x}", d):
            dump(os.path.join(outdir, f"{tag}.xor{k:02x}.bin"), d)
            hits = True
    # 4) ADD/SUB 0..255
    for k in range(1, 256):
        d = bytes([(b + k) & 0xff for b in blob])
        if scan_flags(tag + f".add{k}", d):
            dump(os.path.join(outdir, f"{tag}.add{k}.bin"), d)
            hits = True
        d = bytes([(b - k) & 0xff for b in blob])
        if scan_flags(tag + f".sub{k}", d):
            dump(os.path.join(outdir, f"{tag}.sub{k}.bin"), d)
            hits = True
    return hits

# ============== Bit reader ==============
class BitReader:
    def __init__(self, data, msb_first=True, start_bit=0):
        self.data = data
        self.msb = msb_first
        self.pos = start_bit  # global bit pos
    def read_bits(self, n):
        v = 0
        for _ in range(n):
            bi = self.pos >> 3
            if bi >= len(self.data):
                raise EOFError
            b = self.data[bi]
            bit_index = self.pos & 7
            shift = (7 - bit_index) if self.msb else bit_index
            v = (v << 1) | ((b >> shift) & 1)
            self.pos += 1
        return v

# ============== LZSS (TTComp-like) ==============
def lzss_try(stream, cfg, start_bit):
    r = BitReader(stream, msb_first=cfg['msb_first'], start_bit=start_bit)
    out = bytearray()
    flag_buf = []
    def read_flag():
        nonlocal flag_buf
        if cfg['flag_mode'] == 'bit':
            return r.read_bits(1)
        if not flag_buf:
            fb = r.read_bits(8)
            if cfg['msb_first']:
                flag_buf = [(fb >> (7-i)) & 1 for i in range(8)]
            else:
                flag_buf = [(fb >> i) & 1 for i in range(8)]
        return flag_buf.pop(0)
    try:
        while len(out) < cfg['limit']:
            f = read_flag()
            if f == cfg['flag_literal']:
                out.append(r.read_bits(8))
            else:
                ofs = r.read_bits(cfg['ofs_bits']) + cfg['ofs_bias']
                ln  = r.read_bits(cfg['len_bits']) + cfg['len_base']
                if ofs <= 0 or ofs > len(out) or ofs > cfg['win']:
                    raise ValueError("bad backref")
                for _ in range(ln):
                    out.append(out[-ofs])
    except EOFError:
        pass
    return bytes(out)

def lzss_variants():
    VARS = []
    for win in (2048,):  # TTComp fokus 2KB
        for ofs_bits in (10, 11, 12):
            for len_bits in (4, 5, 6):
                for len_base in (1, 2, 3, 4):
                    for ofs_bias in (0, 1): # beberapa format ofs-1
                        for flag_mode in ("bit", "byte"):
                            for flag_literal in (0, 1):
                                for msb_first in (True, False):
                                    VARS.append({
                                        "win": win, "ofs_bits": ofs_bits, "len_bits": len_bits,
                                        "len_base": len_base, "ofs_bias": ofs_bias,
                                        "flag_mode": flag_mode, "flag_literal": flag_literal,
                                        "msb_first": msb_first, "limit": 32_000_000
                                    })
    return VARS

def decode_ttcomp_all(raw, outdir):
    any_hit = False
    VARS = lzss_variants()
    # skip beberapa byte di depan, krn header-nya terlihat penuh 0x05
    for skip in range(0, 129):  # 0..128
        sub = raw[skip:]
        # brute bit alignment
        for start_bit in range(0, 8):
            for i, cfg in enumerate(VARS):
                try:
                    dec = lzss_try(sub, cfg, start_bit)
                    if not looks_texty(dec):
                        continue
                    tag = f"sk{skip}_b{start_bit}_w{cfg['win']}_o{cfg['ofs_bits']}+{cfg['ofs_bias']}_l{cfg['len_bits']}+{cfg['len_base']}_{cfg['flag_mode']}{cfg['flag_literal']}_{'msb' if cfg['msb_first'] else 'lsb'}"
                    path = os.path.join(outdir, f"{tag}.bin")
                    dump(path, dec)
                    # scan langsung
                    if scan_flags(tag, dec):
                        any_hit = True
                    # brute obfuscation on decoded
                    if brute_obfuscations(tag, dec, outdir):
                        any_hit = True
                except Exception:
                    continue
    return any_hit

def brute_on_raw(raw, outdir):
    """Kalau ternyata raw sudah 'plaintext obfuscated', coba brute langsung."""
    any_hit = False
    tag = "raw"
    dump(os.path.join(outdir, "tt.raw.bin"), raw)
    if looks_texty(raw):
        if scan_flags(tag, raw):
            any_hit = True
    if brute_obfuscations(tag, raw, outdir):
        any_hit = True
    return any_hit

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 solver_tt_v4.py hidden.tt")
        sys.exit(1)
    raw = open(sys.argv[1], "rb").read()
    outdir = "out_tt"; os.makedirs(outdir, exist_ok=True)
    print(f"[+] Loaded {len(raw)} bytes from {sys.argv[1]}")
    # 1) Brute langsung di RAW (jaga-jaga kalau sudah terdekompres tapi diobfuscate)
    any_flag = brute_on_raw(raw, outdir)
    # 2) Brute TTComp-like LZSS dengan skip & bit-offset
    print("[+] Brute TTComp-like LZSS… (this is heavy)")
    any_flag = decode_ttcomp_all(raw, outdir) or any_flag
    if not any_flag:
        print("\n[-] Belum ketemu. Coba manual:")
        print("    strings -n 4 out_tt/*.bin | grep -i -E 'ITECHNO2025|FLAG\\{|CTF\\{'")
        print("    atau kirim 1-2 file kandidat *.bin yg paling 'bahasa manusia' ke sini.")

if __name__ == "__main__":
    main()
