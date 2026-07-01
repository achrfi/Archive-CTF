import sys
import dis
import builtins

# Simpan exec asli
original_exec = builtins.exec

def hooked_exec(code, globals=None, locals=None):
    print(f"\n[+] Intercepted execution of code object: {code}")
    try:
        # Bongkar bytecode yang akan dijalankan
        dis.dis(code)
    except:
        pass
    # Jalankan kode aslinya agar program tidak crash
    return original_exec(code, globals, locals)

# Pasang jebakan
builtins.exec = hooked_exec

print("[*] Starting hook...")
# Import app target kamu di sini
try:
    import app # Ganti dengan nama script utamamu
except:
    pass
