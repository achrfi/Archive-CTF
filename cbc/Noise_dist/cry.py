
import re, ast, binascii, numpy as np
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from PIL import Image, ImageOps

WIDTH = 2000
HEIGHT = 1545

def parse_output(path):
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        text = f.read()
    m = re.search(r"enc\s*=\s*(\[[\s\S]*\])", text)
    enc = ast.literal_eval(m.group(1))
    return enc

def derive_password(enc_list, width, sample_pixels=400_000):
    import string
    subset = list(dict.fromkeys(string.ascii_letters + string.digits + "_{}!@#$%^&*()-=+[];:',.<>/?\\|`~ "))
    def score(cbytes, ch):
        key = PBKDF2(ch.encode(), b"salt", dkLen=16, count=1000)
        cipher = AES.new(key, AES.MODE_ECB)
        n = (sample_pixels // 16) * 16
        dec = cipher.decrypt(cbytes[:n])
        arr = np.frombuffer(dec, dtype=np.uint8)
        w = width
        h = (len(arr)//w)
        arr = arr[:w*h].reshape((h,w))
        def corr(a,b):
            a = a.astype(np.float32).ravel(); b = b.astype(np.float32).ravel()
            if a.size<2: return 0.0
            am, bm = a.mean(), b.mean()
            num = ((a-am)*(b-bm)).mean()
            den = (a.std()*b.std()) + 1e-6
            return float(num/den)
        c1 = corr(arr[:, :-1], arr[:, 1:])
        c2 = corr(arr[:-1, :], arr[1:, :])
        c3 = corr(arr[1:, 1:], arr[:-1, :-1])
        return max(0.0,c1)+max(0.0,c2)+max(0.0,c3)

    pwd_chars = []
    for i, hexs in enumerate(enc_list):
        cbytes = binascii.unhexlify(hexs)
        best = (-1.0, '?')
        for ch in subset:
            s = score(cbytes, ch)
            if s > best[0]:
                best = (s, ch)
        pwd_chars.append(best[1])
        print(f"Frame {i}: '{best[1]}' score={best[0]:.6f}")
    return "".join(pwd_chars)

def decrypt_frames(enc_list, password, width, height):
    frames = []
    for i, (hexs, ch) in enumerate(zip(enc_list, password)):
        key = PBKDF2(ch.encode(), b"salt", dkLen=16, count=1000)
        cipher = AES.new(key, AES.MODE_ECB)
        data = binascii.unhexlify(hexs)
        dec = cipher.decrypt(data)
        arr = np.frombuffer(dec, dtype=np.uint8).reshape((height, width))
        frames.append(arr)
    return np.stack(frames, axis=0)

def recover_mask(frames, out_prefix="/mnt/data/recovered"):
    std_map = frames.astype(np.float32).std(axis=0)
    p5, p95 = np.percentile(std_map, [5, 95])
    th = (p5+p95)/2
    std_img = (np.clip(std_map/(p95 if p95>0 else 1), 0, 1)*255).astype(np.uint8)
    mask = (std_map > th).astype(np.uint8)*255
    Image.fromarray(std_img).save(out_prefix+"_std.png")
    Image.fromarray(mask).save(out_prefix+"_mask.png")
    ImageOps.invert(Image.fromarray(mask)).save(out_prefix+"_mask_inv.png")
    return out_prefix+"_mask.png", out_prefix+"_mask_inv.png", out_prefix+"_std.png"

if __name__ == "__main__":
    enc_list = parse_output("output")
    print(f"Loaded {len(enc_list)} frames")
    # Password recovered earlier; keep auto-derivation optional due to time.
    password = "){`{ek`)```{ek`G"
    print("Using password:", password)
    frames = decrypt_frames(enc_list, password, WIDTH, HEIGHT)
    paths = recover_mask(frames, out_prefix="recovered")
    print("Saved:", paths)
