#!/usr/bin/env python3
import string
from itertools import product

ALPH = string.ascii_uppercase
CT = "BXMOS0_S3VHLC4C6Y4H_G4K_NTO4I_C3K3"  # isi di dalam kurung kurawal

# ---------- util ----------
def sh(idx): return ALPH[idx % 26]
def idx(ch): return ALPH.index(ch)

def caesar_all(s):
    outs=[]
    for k in range(26):
        t="".join(sh(idx(c)+k) if c in ALPH else c for c in s)
        outs.append(("caesar", f"k={k}", t))
    return outs

def vigenere_dec(s, key):
    out, j = [], 0
    for c in s:
        if c in ALPH:
            k = idx(key[j % len(key)])
            out.append(sh(idx(c) - k))
            j += 1
        else:
            out.append(c)
    return "".join(out)

def vigenere_try(s):
    keys = ["FIBONACCI","GENESIS","GENEZIS","GENEZIZ","MATEMATIKA","MTK"]
    return [("vigenere", f"key={k}", vigenere_dec(s,k)) for k in keys]

# Fibonacci generator
def fibs(a=1,b=1):
    while True:
        yield a
        a, b = b, a + b

def fib_shift(s, add=False, start=(1,1), reset_per_segment=True, reverse=False, letters_only=True):
    t = s[::-1] if reverse else s
    segments = t.split("_") if reset_per_segment else [t]
    outs = []
    for seg in segments:
        a,b = start
        out=[]
        for ch in seg:
            if ch in ALPH:
                shf = a % 26
                if add: out.append(sh(idx(ch) + shf))
                else:   out.append(sh(idx(ch) - shf))
                a,b = b, a+b
            else:
                out.append(ch if not letters_only else ch)
        outs.append("".join(out))
    u = "_".join(outs)
    return u[::-1] if reverse else u

def fib_modes(s):
    outs=[]
    for add in (False, True):
        for start in ((1,1),(0,1),(1,2),(2,3),(3,5)):
            for reset in (True, False):
                for rev in (False, True):
                    t = fib_shift(s, add=add, start=start, reset_per_segment=reset, reverse=rev)
                    outs.append(("fibshift", f"add={add},start={start},reset={reset},rev={rev}", t))
    return outs

# Triad model: interpret "A d B" as B = A ± F(d)
F = {str(i):v for i,v in zip(range(0,10), [0,1,1,2,3,5,8,13,21,34])}
def triad_decode(s, mode="+"):
    out=[]
    i=0
    n=len(s)
    while i<n:
        c=s[i]
        if c in ALPH and i+2<n and s[i+1].isdigit() and s[i+2] in ALPH:
            d = F.get(s[i+1], None)
            if d is None: 
                out.append(c); i+=1; continue
            if mode=="+":  # c + F(d) -> should match s[i+2]; recover base by reversing
                base = sh(idx(s[i+2]) - d)
            else:          # c - F(d) -> should match s[i+2]
                base = sh(idx(s[i+2]) + d)
            out.append(base)
            i += 3
        else:
            # keep digits/underscores as separators; drop digits by default
            if c in "0123456789":
                i += 1
                continue
            out.append(c); i+=1
    return "".join(out)

def triad_modes(s):
    return [("triad", "mode=+", triad_decode(s, "+")),
            ("triad", "mode=-", triad_decode(s, "-"))]

# simple scoring for flag-likeness
def score(s):
    ok_chars = set(ALPH + "0123456789_{}")
    bad = sum(ch not in ok_chars for ch in s)
    # bonus if looks like words
    bonus = sum(w in s for w in ["FIB","FIBO","GEN","LOCK","MATH","ITECH","FLAG","TECH","TELKOM"])
    bonus += s.count("_")
    return -bad + 0.1*bonus

def try_all(s):
    cands = []
    for name,param,t in (
        caesar_all(s)+
        vigenere_try(s)+
        fib_modes(s)+
        triad_modes(s)
    ):
        cands.append((score(t), name, param, t))
    cands.sort(reverse=True, key=lambda x: x[0])
    return cands

def main():
    print("[*] Cipher inside braces:", CT)
    cands = try_all(CT)
    top = []
    for sc, name, param, t in cands[:60]:
        inner = t.strip("_")
        out = f"ITECHNO2025{{{inner}}}"
        # print top variants that look sane
        if all(ch in (ALPH+"0123456789_") for ch in inner):
            print(f"{sc:>5.1f}  {name:8s}  {param:30s}  {out}")
            top.append(out)
    # final hint: print unique few best
    print("\n[*] Top guess(es) (dedup):")
    seen=set()
    for o in top:
        if o not in seen:
            print(o)
            seen.add(o)

if __name__ == "__main__":
    main()
