# cbc_plus_plus_3

## Category

pwn / C++ heap

## Files and service

- `cbc_plus_plus_3`
- `cbc_plus_plus_3.cpp`
- `libc.so.6`
- `Dockerfile`
- Remote: `nc pwn.cbd2026.cloud 9999`

## Protections

`checksec --file=cbc_plus_plus_3`:

- Full RELRO
- Stack canary
- NX
- No PIE
- SHSTK and IBT enabled

## Key observations

The vulnerable logic is option 3:

```cpp
*s_str = z_str.data;
s_str->data()[z_str.length] = '\0';
```

`z_str.data` is allocated with `new char[z_str.length + 1]`, but only `z_str.length` bytes are read and no terminator is appended. This gives an unterminated C string to `std::string::operator=(char const*)`.

The second line then writes a NUL byte at `std::string::data() + z_str.length`, using the original zzz-string length rather than the actual string length computed by `std::string`.

Confirmed primitives:

1. Stale heap overread into `std::string`: allocate a zzz string, free/reuse the chunk with a shorter string, then option 3 copies bytes past the new logical zzz data into the std string before the forced NUL is written.
2. Controlled relative NUL write: with an empty zzz string, option 3 uses SSO and writes relative to `s_str + 0x10`; for example length `25` clears the second byte of the top chunk size in the initial heap layout.
3. Unsigned length edge case: length `18446744073709551615` wraps the allocation size to zero. The following `std::istream::read(..., -1)` does not copy attacker data, but option 3 then writes at `data() - 1`.

## Useful commands

```bash
file cbc_plus_plus_3 libc.so.6
checksec --file=cbc_plus_plus_3
nm -C cbc_plus_plus_3
objdump -d -Mintel cbc_plus_plus_3 --start-address=0x401480 --stop-address=0x4018a4
```

Heap inspection breakpoint after the option 3 NUL write:

```bash
python3 -c 'import sys; sys.stdout.buffer.write(b"1\n24\n\x00"+b"A"*23+b"\n3\n")' \
  | gdb -q ./cbc_plus_plus_3 \
      -ex 'set pagination off' \
      -ex 'b *0x401737' \
      -ex run \
      -ex 'x/8gx 0x404280' \
      -ex 'p/x *(void**)0x404290' \
      -ex 'x/32gx *(void**)0x404290-0x20'
```

Probe script:

```bash
cd work
python3 probe.py
```

## Current status

Not solved yet. The remaining step is turning the confirmed overread plus relative NUL write into either:

- an overlapping-chunk/tcache poisoning primitive that can allocate over `s_str`/a C++ object, or
- a libc/stdout-oriented leak and control-flow target that is compatible with Full RELRO and CET.

## Final flag

Not recovered yet.
