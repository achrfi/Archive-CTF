import os, sys, marshal, hashlib

DUMP_DIR = "dumped_codes"
os.makedirs(DUMP_DIR, exist_ok=True)

seen = set()

def prof(frame, event, arg):
    if event != "call":
        return prof

    co = frame.f_code
    fn = co.co_filename or ""
    # Filter: hanya yang berasal dari app ini (biar dump gak kebanyakan)
    if fn.endswith("app.py"):
        raw = marshal.dumps(co)
        h = hashlib.sha256(raw).hexdigest()
        if h not in seen:
            seen.add(h)
            # header pyc dummy (16 byte) supaya gampang diproses tools lain
            out = os.path.join(DUMP_DIR, f"{h}.pyc")
            with open(out, "wb") as f:
                f.write(b"\0" * 16)
                f.write(raw)
            print("[dumped]", out)

    return prof

sys.setprofile(prof)

# ini akan menjalankan pyarmor stub, yang kemudian mengeksekusi code aslinya
import app  # noqa
