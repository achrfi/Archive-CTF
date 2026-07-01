# solver.py
import base64

payload = "PTEmKyYhO1dTWlsUH1YNXB5bKxxXADEIRwg8AxswFlYEWQBeKwFTXAAECQ=="
key = b"techno"

ct = base64.b64decode(payload)
pt = bytes([c ^ key[i % len(key)] for i, c in enumerate(ct)])
print(pt.decode())
