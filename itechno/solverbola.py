#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import sys, os, re

FLAG_PATS = [b"ITECHNO2025{", b"FLAG{", b"CTF{"]

# --- Bit reader sederhana dgn dukungan start bit offset & MSB/LSB ---
class BitReader:
    def __init__(self, data, msb_first=True, start_bit=0):
        self.data = data
        self.msb = msb_first
        self.pos = start_bit  # bit position from start of stream
    def read_bits(self, n):
        v = 0
        for _ in range(n):
            bi = self.pos >> 3
            if bi >= len(self.data): raise EOFError
            b = self.data[bi]
            bit_index = self.pos & 7
            shift = (7 - bit_index) if self.msb else bit_index
            v = (v << 1) | ((b >> shift) & 1)
            self.pos += 1
        return v

def lzss_try(stream, cfg, start_bit):
    r = BitReader(stream, msb_first=cfg['msb_first'], start_bit=start_bit)
    out = bytearray()

    flag_cache = []
    def read_flag():
        nonlocal flag_cache
        if cfg['flag_mode'] == 'bit':
            return r.read_bits(1)
        # byte-mode: 8 flags per byte (urutan tergantung msb/lsb)
        if not flag_cache:
            fb = r.read_bits(8)
            if cfg['msb_first']:
                flag_cache = [(fb >> (7 - i)) & 1 for i in range(8)]
            else:
                flag_cache = [(fb >> i) & 1 for i in range(8)]
        return flag_cache.pop(0)

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

def variants():
    VARS = []
    for win in (2048,):                  # fokus TTComp: 2KB
        for ofs_bits in (11, 12):        # umum di 2KB
            for len_bits in (4, 5, 6):   # panjang match
                for len_base in (1, 2, 3):   # base len
                    for ofs_bias in (0, 1):  # kadang ofs-1
                        for flag_mode in ("bit", "byte"):
                            for flag_literal in (0, 1):  # 1=literal atau 0=literal
                                for msb_first in (True, False):
                                    VARS.append({
                                        "win": win, "ofs_bits": ofs_bits, "len_bits": len_bits,
                                        "len_base": len_base, "ofs_bias": ofs_bias,
                                        "flag_mode": flag_mode, "flag_literal": flag_literal,
                                        "msb_first": msb_first, "limit": 16_000_000
                                    })
    return VARS

def looks_texty(b):
    if not b or len(b) < 64: return False
    asci = sum(32 <= x <= 126 for x in b)
    return (asci / len(b)) > 0.25 or any(p in b for p in FLAG_PATS)

def scan_flags(tag, b):
    hit = False
    for pat in FLAG_PATS:
        for m in re.finditer(re.escape(pat), b, flags=re.IGNORECASE):
            s = max(0, m.start()-48); e = min(len(b), m.end()+96)
            ctx = b[s:e].decode("latin1","ignore")
            print(f"\n[FLAG?] {tag} @{m.start()}:\n{ctx}")
            hit = True
    for m in re.finditer(br"[A-Z0-9_]{3,}\{[^}\n]{3,120}\}", b):
        s = max(0, m.start()-32); e = min(len(b), m.end()+32)
        print(f"\n[BRACED] {tag} @{m.start()}:\n{b[s:e].decode('latin1','ignore')}")
        hit = True
    return hit

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 solver_tt_v3.py hidden.tt")
        sys.exit(1)
    raw = open(sys.argv[1], "rb").read()
    os.makedirs("out_tt", exist_ok=True)
    open("out_tt/tt.raw.bin","wb").write(raw)

    any_hit = False
    vlist = variants()
    for start_bit in range(0, 8):  # **kunci**: brute bit alignment
        for i, cfg in enumerate(vlist):
            try:
                dec = lzss_try(raw, cfg, start_bit)
                if looks_texty(dec):
                    tag = f"b{start_bit}_w{cfg['win']}_o{cfg['ofs_bits']}+{cfg['ofs_bias']}_l{cfg['len_bits']}+{cfg['len_base']}_{cfg['flag_mode']}{cfg['flag_literal']}_{'msb' if cfg['msb_first'] else 'lsb'}"
                    path = f"out_tt/{tag}.bin"
                    open(path, "wb").write(dec)
                    if scan_flags(tag, dec): any_hit = True
            except Exception:
                continue
    if not any_hit:
        print("[-] Belum nemu flag. Cek manual: strings -n 4 out_tt/*.bin | grep -i ITECHNO")

if __name__ == "__main__":
    main()
