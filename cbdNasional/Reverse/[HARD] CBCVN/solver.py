#!/usr/bin/env python3
"""
CBCVN solver
Usage:
  python3 CBCVN_solver.py CBCVN.zip
  python3 CBCVN_solver.py /path/to/data.xp3
  python3 CBCVN_solver.py /path/to/extracted_folder

Requires: z3-solver, pillow
Output: credentials and flag.png
"""
import argparse, os, re, struct, sys, tempfile, zipfile, zlib
from dataclasses import dataclass, field
from pathlib import Path

MOD32 = 1 << 32

def u32(x): return x & 0xffffffff

# ---------------- XP3 extractor ----------------
def _u64(b, o): return struct.unpack_from('<Q', b, o)[0]
def _u32(b, o): return struct.unpack_from('<I', b, o)[0]

def extract_xp3(xp3_path, outdir):
    data = Path(xp3_path).read_bytes()
    if not data.startswith(b'XP3\r\n \n\x1a\x8bg\x01'):
        raise SystemExit('Not an XP3 archive')

    idx_ofs = _u64(data, 11)
    while True:
        flags = data[idx_ofs]
        if flags & 0x80:
            cand1 = _u64(data, idx_ofs + 1)
            cand2 = _u64(data, idx_ofs + 9)
            idx_ofs = cand2 if 0 <= cand2 < len(data) else cand1
            continue
        break

    p = idx_ofs + 1
    if data[idx_ofs] & 1:
        comp_size = _u64(data, p)
        orig_size = _u64(data, p + 8)
        p += 16
        idx = zlib.decompress(data[p:p + comp_size])
        assert len(idx) == orig_size
    else:
        size = _u64(data, p)
        p += 8
        idx = data[p:p + size]

    out = Path(outdir)
    out.mkdir(parents=True, exist_ok=True)
    pos = 0
    while pos + 12 <= len(idx):
        tag = idx[pos:pos + 4]
        length = _u64(idx, pos + 4)
        payload = idx[pos + 12:pos + 12 + length]
        pos += 12 + length
        if tag != b'File':
            continue

        name = None
        segments = []
        q = 0
        while q + 12 <= len(payload):
            st = payload[q:q + 4]
            sl = _u64(payload, q + 4)
            sp = payload[q + 12:q + 12 + sl]
            q += 12 + sl
            if st == b'info':
                n = struct.unpack_from('<H', sp, 20)[0]
                name = sp[22:22 + n * 2].decode('utf-16le', errors='replace')
            elif st == b'segm':
                r = 0
                while r + 28 <= len(sp):
                    seg_flag = struct.unpack_from('<I', sp, r)[0]
                    off = struct.unpack_from('<Q', sp, r + 4)[0]
                    orig = struct.unpack_from('<Q', sp, r + 12)[0]
                    arc = struct.unpack_from('<Q', sp, r + 20)[0]
                    segments.append((seg_flag, off, orig, arc))
                    r += 28

        if not name:
            continue
        chunks = []
        for seg_flag, off, orig, arc in segments:
            seg = data[off:off + arc]
            if seg_flag & 1:
                seg = zlib.decompress(seg)
            if len(seg) != orig:
                raise RuntimeError(f'segment size mismatch for {name}')
            chunks.append(seg)
        dst = out / name
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_bytes(b''.join(chunks))
    return out

# ---------------- TJS2 bytecode loader/disassembler ----------------
VM_NAMES = '''NOP CONST CP CL CCL TT TF CEQ CDEQ CLT CGT SETF SETNF LNOT NF JF JNF JMP INC INCPD INCPI INCP DEC DECPD DECPI DECP LOR LORPD LORPI LORP LAND LANDPD LANDPI LANDP BOR BORPD BORPI BORP BXOR BXORPD BXORPI BXORP BAND BANDPD BANDPI BANDP SAR SARPD SARPI SARP SAL SALPD SALPI SALP SR SRPD SRPI SRP ADD ADDPD ADDPI ADDP SUB SUBPD SUBPI SUBP MOD MODPD MODPI MODP DIV DIVPD DIVPI DIVP IDIV IDIVPD IDIVPI IDIVP MUL MULPD MULPI MULP BNOT TYPEOF TYPEOFD TYPEOFI EVAL EEXP CHKINS ASC CHR NUM CHS INV CHKINV INT REAL STR OCTET CALL CALLD CALLI NEW GPD SPD SPDE SPDEH GPI SPI SPIE GPDS SPDS GPIS SPIS SETP GETP DELD DELI SRV RET ENTRY EXTRY THROW CHGTHIS GLOBAL ADDCI REGMEMBER DEBUGGER'''.split()
ZERO = {0,14,119,121,126,127}
ONE = {3,5,6,11,12,13,15,16,17,18,22,82,83,86,87,89,90,91,92,93,94,95,96,97,98,118,122,124}
TWO = {1,2,4,7,8,9,10,26,30,34,38,42,46,50,54,58,62,66,70,74,78,88,114,115,120,123,125}
THREE = {21,25,29,33,37,41,45,49,53,57,61,65,69,73,77,81,84,85,103,104,105,106,107,108,109,110,111,112,113,116,117}
FOUR = {19,20,23,24,27,28,31,32,35,36,39,40,43,44,47,48,51,52,55,56,59,60,63,64,67,68,71,72,75,76,79,80}

@dataclass
class Obj:
    idx: int; name: str; parent: int; ctx: int; maxv: int; varres: int; maxf: int; argc: int
    unbase: int; collapse: int; setter: int; getter: int; scg: int
    code: list = field(default_factory=list)
    data: list = field(default_factory=list)
    props: list = field(default_factory=list)

class Loader:
    def __init__(self, b):
        self.b = b; self.pos = 0
        self.byte = []; self.short = []; self.long = []; self.ll = []; self.dbl = []; self.str = []; self.oct = []
        self.objects = []; self.toplevel = -1
    def r(self, fmt):
        v = struct.unpack_from(fmt, self.b, self.pos)[0]
        self.pos += struct.calcsize(fmt)
        return v
    def load(self):
        assert self.b[:8] == b'TJS2100\0'
        self.pos = 8
        self.r('<I')
        assert self.b[self.pos:self.pos + 4] == b'DATA'
        self.pos += 4; self.r('<I'); self.read_data()
        assert self.b[self.pos:self.pos + 4] == b'OBJS'
        self.pos += 4; self.r('<I'); self.read_objs()
    def read_data(self):
        n = self.r('<I')
        for _ in range(n): self.byte.append(self.r('<b'))
        self.pos += (4 - (n % 4)) % 4
        n = self.r('<I')
        for _ in range(n): self.short.append(self.r('<h'))
        if n % 2: self.pos += 2
        n = self.r('<I')
        for _ in range(n): self.long.append(self.r('<i'))
        n = self.r('<I')
        for _ in range(n): self.ll.append(self.r('<q'))
        n = self.r('<I')
        for _ in range(n): self.dbl.append(self.r('<d'))
        n = self.r('<I')
        for _ in range(n):
            ln = self.r('<I')
            chars = [self.r('<H') for __ in range(ln)]
            self.str.append(''.join(map(chr, chars)))
            if ln % 2: self.pos += 2
        n = self.r('<I')
        for _ in range(n):
            ln = self.r('<I')
            self.oct.append(self.b[self.pos:self.pos + ln])
            self.pos += ((ln + 3) // 4) * 4
    def resolve(self, dt, idx):
        if dt == 0: return None
        if dt == 1: return ('obj', idx)
        if dt == 2: return ('inter_obj', idx)
        if dt == 3: return self.str[idx]
        if dt == 4: return self.oct[idx]
        if dt == 5: return self.dbl[idx]
        if dt == 6: return self.byte[idx]
        if dt == 7: return self.short[idx]
        if dt == 8: return self.long[idx]
        if dt == 9: return self.ll[idx]
        return (dt, idx)
    def read_objs(self):
        self.toplevel = self.r('<i')
        n = self.r('<I')
        for objidx in range(n):
            assert self.b[self.pos:self.pos + 4] == b'TJS2'
            self.pos += 4
            objsize = self.r('<I')
            start = self.pos
            parent = self.r('<i'); nameidx = self.r('<I'); ctx = self.r('<I'); maxv = self.r('<I')
            varres = self.r('<I'); maxf = self.r('<I'); argc = self.r('<I'); unbase = self.r('<I')
            collapse = self.r('<i'); setter = self.r('<i'); getter = self.r('<i'); scg = self.r('<i')
            spn = self.r('<I')
            if spn:
                for _ in range(spn): self.r('<I')
                for _ in range(spn): self.r('<I')
            cc = self.r('<I')
            code = [self.r('<h') for _ in range(cc)]
            if cc % 2: self.pos += 2
            dc = self.r('<I')
            dat = []
            for _ in range(dc):
                dt = self.r('<h'); idx = self.r('<h')
                dat.append(self.resolve(dt, idx))
            scgc = self.r('<I')
            for _ in range(scgc): self.r('<I')
            pc = self.r('<I')
            props = [(self.r('<I'), self.r('<I')) for _ in range(pc)]
            name = self.str[nameidx] if nameidx < len(self.str) else ''
            self.objects.append(Obj(objidx, name, parent, ctx, maxv, varres, maxf, argc, unbase, collapse, setter, getter, scg, code, dat, props))
            self.pos = start + objsize

def insts(code):
    ip = 0
    while ip < len(code):
        op = code[ip]
        if op in ZERO: sz = 1
        elif op in ONE: sz = 2
        elif op in TWO: sz = 3
        elif op in THREE: sz = 4
        elif op in FOUR: sz = 5
        elif op in (99, 102): sz = 4 + max(0, code[ip + 3])
        elif op in (100, 101): sz = 5 + max(0, code[ip + 4])
        else: sz = 1
        yield ip, op, code[ip + 1:ip + sz], sz, VM_NAMES[op]
        ip += sz

# ---------------- Minimal TJS interpreter ----------------
class GlobalObj: pass
class BuiltinArray: pass
GLOBAL = GlobalObj(); ARRAY = BuiltinArray()

def truthy(v): return bool(v)

class TJSInterp:
    def __init__(self, path):
        self.L = Loader(Path(path).read_bytes()); self.L.load()
        self.by_name = {o.name: o for o in self.L.objects if o.name}
        self.by_idx = {o.idx: o for o in self.L.objects}
        self.global_props = {'Array': ARRAY}
        self.global_props.update(self.by_name)
        if self.L.toplevel in self.by_idx:
            self.call_obj(self.by_idx[self.L.toplevel], [])
    def const(self, obj, idx):
        v = obj.data[idx]
        if isinstance(v, tuple) and v[0] == 'inter_obj':
            return self.by_idx[v[1]]
        return v
    def getprop(self, obj, prop):
        if obj is GLOBAL:
            if prop in self.global_props: return self.global_props[prop]
            if prop == '_M32': return MOD32
            raise KeyError(prop)
        if isinstance(obj, (str, list)) and prop == 'length': return len(obj)
        raise KeyError((obj, prop))
    def getidx(self, obj, idx):
        if isinstance(obj, str): return obj[idx]
        if isinstance(obj, list): return obj[idx] if 0 <= idx < len(obj) else None
        raise TypeError(type(obj))
    def setidx(self, obj, idx, val):
        if idx >= len(obj): obj.extend([None] * (idx - len(obj) + 1))
        obj[idx] = val
    def call_val(self, f, args):
        if f is ARRAY:
            return [None] * args[0] if len(args) == 1 and isinstance(args[0], int) else list(args)
        if hasattr(f, 'idx'):
            return self.call_obj(f, args)
        if isinstance(f, str):
            return self.call(f, args)
        raise TypeError(f'not callable: {f!r}')
    def call(self, name, args): return self.call_obj(self.by_name[name], args)
    def call_obj(self, obj, args):
        regs = {-1: GLOBAL, -2: GLOBAL}
        for i, a in enumerate(args): regs[-3 - i] = a
        def R(r): return None if r == 0 else regs.get(r)
        def W(r, v):
            if r != 0: regs[r] = v
        inst_map = {ip: (ops, sz, nm) for ip, op, ops, sz, nm in insts(obj.code)}
        ip = 0; flag = False; srv = None; steps = 0
        while ip < len(obj.code):
            ops, sz, nm = inst_map[ip]
            steps += 1
            if steps > 10000000: raise RuntimeError('too many VM steps')
            nxt = ip + sz
            if nm == 'NOP': pass
            elif nm == 'CONST': W(ops[0], self.const(obj, ops[1]))
            elif nm == 'CP': W(ops[0], R(ops[1]))
            elif nm in ('CL', 'CCL'): W(ops[0], None)
            elif nm == 'TT': flag = truthy(R(ops[0]))
            elif nm == 'TF': flag = not truthy(R(ops[0]))
            elif nm == 'CEQ': flag = (R(ops[0]) == R(ops[1]))
            elif nm == 'CDEQ': flag = (R(ops[0]) is R(ops[1]))
            elif nm == 'CLT': flag = (R(ops[0]) < R(ops[1]))
            elif nm == 'CGT': flag = (R(ops[0]) > R(ops[1]))
            elif nm == 'SETF': W(ops[0], 1 if flag else 0)
            elif nm == 'SETNF': W(ops[0], 0 if flag else 1)
            elif nm == 'LNOT': W(ops[0], 0 if truthy(R(ops[0])) else 1)
            elif nm == 'NF': flag = not flag
            elif nm == 'JF':
                if flag: nxt = ip + ops[0]
            elif nm == 'JNF':
                if not flag: nxt = ip + ops[0]
            elif nm == 'JMP': nxt = ip + ops[0]
            elif nm == 'INC': W(ops[0], (R(ops[0]) or 0) + 1)
            elif nm == 'DEC': W(ops[0], (R(ops[0]) or 0) - 1)
            elif nm == 'BOR': W(ops[0], R(ops[0]) | R(ops[1]))
            elif nm == 'BXOR': W(ops[0], R(ops[0]) ^ R(ops[1]))
            elif nm == 'BAND': W(ops[0], R(ops[0]) & R(ops[1]))
            elif nm == 'SAR': W(ops[0], R(ops[0]) >> R(ops[1]))
            elif nm == 'SAL': W(ops[0], R(ops[0]) << R(ops[1]))
            elif nm == 'SR': W(ops[0], u32(R(ops[0])) >> R(ops[1]))
            elif nm == 'ADD': W(ops[0], R(ops[0]) + R(ops[1]))
            elif nm == 'SUB': W(ops[0], R(ops[0]) - R(ops[1]))
            elif nm == 'MOD': W(ops[0], R(ops[0]) % R(ops[1]))
            elif nm == 'DIV': W(ops[0], R(ops[0]) / R(ops[1]))
            elif nm == 'IDIV': W(ops[0], R(ops[0]) // R(ops[1]))
            elif nm == 'MUL': W(ops[0], R(ops[0]) * R(ops[1]))
            elif nm == 'BNOT': W(ops[0], ~R(ops[0]))
            elif nm == 'CHS': W(ops[0], -R(ops[0]))
            elif nm == 'ASC':
                v = R(ops[0]); W(ops[0], ord(v[0]) if isinstance(v, str) else v)
            elif nm == 'CHR': W(ops[0], chr(R(ops[0])))
            elif nm == 'INT': W(ops[0], int(R(ops[0])))
            elif nm == 'REAL': W(ops[0], float(R(ops[0])))
            elif nm == 'STR': W(ops[0], str(R(ops[0])))
            elif nm in ('CALL', 'NEW'):
                dest, func_reg, argc = ops[:3]
                W(dest, self.call_val(R(func_reg), [R(a) for a in ops[3:3 + argc]]))
            elif nm in ('CALLD', 'CALLI'):
                dest, objreg, name_ref, argc = ops[:4]
                name = self.const(obj, name_ref) if nm == 'CALLD' else R(name_ref)
                f = self.getprop(R(objreg), name)
                W(dest, self.call_val(f, [R(a) for a in ops[4:4 + argc]]))
            elif nm in ('GPD', 'GPDS'): W(ops[0], self.getprop(R(ops[1]), self.const(obj, ops[2])))
            elif nm in ('GPI', 'GPIS'): W(ops[0], self.getidx(R(ops[1]), R(ops[2])))
            elif nm in ('SPI', 'SPIE', 'SPIS'): self.setidx(R(ops[0]), R(ops[1]), R(ops[2]))
            elif nm == 'ADDPI': self.setidx(R(ops[1]), R(ops[2]), (self.getidx(R(ops[1]), R(ops[2])) or 0) + R(ops[3]))
            elif nm == 'BXORPI': self.setidx(R(ops[1]), R(ops[2]), (self.getidx(R(ops[1]), R(ops[2])) or 0) ^ R(ops[3]))
            elif nm in ('SPDS', 'SPDE', 'SPDEH'):
                target = R(ops[0]); name = self.const(obj, ops[1]); val = R(ops[2])
                if target is GLOBAL: self.global_props[name] = val
            elif nm == 'CHGTHIS': pass
            elif nm == 'GLOBAL': W(ops[0], GLOBAL)
            elif nm == 'SRV': srv = R(ops[0])
            elif nm == 'RET': return srv
            else: raise NotImplementedError(f'{obj.name} {ip} {nm} {ops}')
            ip = nxt
        return srv

# ---------------- Math solver ----------------
def egcd(a, b):
    if b == 0: return a, 1, 0
    g, x1, y1 = egcd(b, a % b)
    return g, y1, x1 - (a // b) * y1

def inv_mod(a, m):
    g, x, _ = egcd(a % m, m)
    if g != 1: raise ValueError('pivot is not invertible')
    return x % m

def solve_linear_mod(A, b, m=MOD32):
    n = len(A)
    M = [[A[i][j] % m for j in range(n)] + [b[i] % m] for i in range(n)]
    row = 0
    for col in range(n):
        piv = next((r for r in range(row, n) if M[r][col] & 1), None)
        if piv is None: raise ValueError(f'no odd pivot in column {col}')
        M[row], M[piv] = M[piv], M[row]
        inv = inv_mod(M[row][col], m)
        M[row] = [(x * inv) % m for x in M[row]]
        for r in range(n):
            if r != row and M[r][col]:
                factor = M[r][col]
                M[r] = [(M[r][c] - factor * M[row][c]) % m for c in range(n + 1)]
        row += 1
    return [M[i][-1] % m for i in range(n)]

def extract_matrix_and_targets(val):
    o = val.by_name['IIII']
    items = []
    targets = []
    for ip, op, ops, sz, nm in insts(o.code):
        if 882 <= ip < 3483 and nm == 'CONST' and len(ops) == 2 and ops[0] == 3:
            items.append(val.const(o, ops[1]))
        if 3499 <= ip < 3652 and nm == 'CONST' and len(ops) == 2 and ops[0] == 3:
            targets.append(val.const(o, ops[1]))
    if len(items) != 17 * 17 or len(targets) != 17:
        raise RuntimeError('matrix/target extraction failed')
    return [items[i * 17:(i + 1) * 17] for i in range(17)], targets

def solve_credentials(extracted):
    import z3
    val = TJSInterp(Path(extracted) / 'validator.tjs')
    A, target = extract_matrix_and_targets(val)
    y = solve_linear_mod(A, target)

    def BV(v): return z3.BitVecVal(v & 0xffffffff, 32)
    def sym_eval(obj, args):
        regs = {-1: None, -2: None}
        for i, a in enumerate(args): regs[-3 - i] = a
        def R(r): return BV(0) if r == 0 else regs.get(r, BV(0))
        def W(r, v):
            if r != 0: regs[r] = v
        srv = None
        for ip, op, ops, sz, nm in insts(obj.code):
            if nm == 'CP': W(ops[0], R(ops[1]))
            elif nm == 'CONST': W(ops[0], BV(obj.data[ops[1]]))
            elif nm == 'BAND': W(ops[0], R(ops[0]) & R(ops[1]))
            elif nm == 'BOR': W(ops[0], R(ops[0]) | R(ops[1]))
            elif nm == 'BXOR': W(ops[0], R(ops[0]) ^ R(ops[1]))
            elif nm == 'BNOT': W(ops[0], ~R(ops[0]))
            elif nm == 'ADD': W(ops[0], R(ops[0]) + R(ops[1]))
            elif nm == 'SUB': W(ops[0], R(ops[0]) - R(ops[1]))
            elif nm == 'MUL': W(ops[0], R(ops[0]) * R(ops[1]))
            elif nm == 'MOD': W(ops[0], z3.URem(R(ops[0]), R(ops[1])) )
            elif nm == 'SAL': W(ops[0], R(ops[0]) << R(ops[1]))
            elif nm == 'SR': W(ops[0], z3.LShR(R(ops[0]), R(ops[1])))
            elif nm == 'SAR': W(ops[0], R(ops[0]) >> R(ops[1]))
            elif nm == 'CHS': W(ops[0], -R(ops[0]))
            elif nm in ('CL', 'CCL'): W(ops[0], BV(0))
            elif nm == 'SRV': srv = R(ops[0])
            elif nm == 'RET': return srv
            else: raise NotImplementedError(f'{obj.name} {ip} {nm} {ops}')
        return srv

    u = [z3.BitVec(f'u{i}', 32) for i in range(10)]
    p = [z3.BitVec(f'p{i}', 32) for i in range(20)]
    regmap = {}
    for i, x in enumerate(u): regmap[-5 - i] = x
    for i, x in enumerate(p): regmap[-15 - i] = x

    eqs = []
    o = val.by_name['IIII']
    for ip, op, ops, sz, nm in insts(o.code):
        if 500 <= ip <= 860 and nm == 'CALLD' and len(ops) >= 4:
            dest, objreg, nameidx, argc = ops[:4]
            name = o.data[nameidx]
            if isinstance(name, str) and name.startswith('_f'):
                eqs.append((name, ops[4:4 + argc]))
    assert len(eqs) == 17

    s = z3.Solver()
    for ch in u + p:
        s.add(z3.UGE(ch, 32), z3.ULE(ch, 126))
    for idx, (name, argregs) in enumerate(eqs):
        expr = sym_eval(val.by_name[name], [regmap[r] for r in argregs])
        s.add(expr == BV(y[idx]))
    if s.check() != z3.sat:
        raise RuntimeError('Z3 returned UNSAT')
    m = s.model()
    username = ''.join(chr(m.eval(x).as_long()) for x in u)
    password = ''.join(chr(m.eval(x).as_long()) for x in p)
    key = (username + password)[:16]
    return username, password, key

def decrypt_flag(extracted, key_s, out_path):
    from PIL import Image
    text = Path(extracted, 'flag_data.tjs').read_text(encoding='utf-8')
    w = int(re.search(r'_FLAG_W\s*=\s*(\d+)', text).group(1))
    h = int(re.search(r'_FLAG_H\s*=\s*(\d+)', text).group(1))
    arr = re.search(r'_FLAG_ENC\s*=\s*\[(.*?)\]', text, re.S).group(1)
    enc = [int(x, 0) for x in re.findall(r'0x[0-9a-fA-F]+|\d+', arr)]
    c = TJSInterp(Path(extracted) / 'cipher.tjs')
    plain = c.call('cipher', [[ord(ch) for ch in key_s], [0] * 16, enc])
    img = Image.frombytes('RGB', (w, h), bytes(x & 255 for x in plain[:w * h * 3]))
    img.save(out_path)
    return out_path

def prepare_input(inp, workdir):
    inp = Path(inp)
    if inp.is_dir():
        if (inp / 'validator.tjs').exists(): return inp
        if (inp / 'data.xp3').exists(): return extract_xp3(inp / 'data.xp3', Path(workdir) / 'extracted')
        raise SystemExit('Directory must contain validator.tjs or data.xp3')
    if inp.suffix.lower() == '.zip':
        zdir = Path(workdir) / 'zip'
        zdir.mkdir(parents=True, exist_ok=True)
        queue = [inp]
        seen = set()
        while queue:
            cur = queue.pop(0)
            if cur in seen:
                continue
            seen.add(cur)
            dest = zdir / cur.stem
            dest.mkdir(parents=True, exist_ok=True)
            with zipfile.ZipFile(cur) as zf:
                zf.extractall(dest)
            xp3s = list(dest.rglob('data.xp3'))
            if xp3s:
                return extract_xp3(xp3s[0], Path(workdir) / 'extracted')
            queue.extend(dest.rglob('*.zip'))
        raise SystemExit('data.xp3 not found in zip or nested zip')
    if inp.suffix.lower() == '.xp3' or inp.name == 'data.xp3':
        return extract_xp3(inp, Path(workdir) / 'extracted')
    raise SystemExit('Input must be CBCVN.zip, data.xp3, or extracted folder')

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('input')
    ap.add_argument('-o', '--output', default='flag.png')
    ap.add_argument('--keep-workdir', help='optional directory to keep extracted files')
    args = ap.parse_args()

    if args.keep_workdir:
        workdir = Path(args.keep_workdir); workdir.mkdir(parents=True, exist_ok=True)
        extracted = prepare_input(args.input, workdir)
        username, password, key = solve_credentials(extracted)
        out = decrypt_flag(extracted, key, args.output)
    else:
        with tempfile.TemporaryDirectory() as td:
            extracted = prepare_input(args.input, td)
            username, password, key = solve_credentials(extracted)
            out = decrypt_flag(extracted, key, args.output)

    print(f'username: {username}')
    print(f'password: {password}')
    print(f'key     : {key}')
    print(f'flag image written to: {out}')
    print('flag: CBC{R3v3r5ingV1sua1N0vel1sFun}')

if __name__ == '__main__':
    main()
