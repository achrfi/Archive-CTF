#!/usr/bin/env python3
import argparse
import re
import sys
import time
from datetime import datetime, timezone

def fmt6(x: int) -> str:
    return f"{x % 1_000_000:06d}"

def pin_candidates_from_epoch(epoch: int):
    """
    Kandidat-kandidat PIN yang paling sering muncul kalau dev 'menggunakan UTC timestamp sekarang'.
    """
    dt = datetime.fromtimestamp(epoch, tz=timezone.utc)

    cands = []

    # 1) Paling umum: last 6 digits dari Unix time (UTC)
    cands.append(("unix_mod_1e6", fmt6(epoch)))

    # 2) Variasi "counter" (lebih mirip TOTP tanpa secret)
    cands.append(("unix_div30_mod_1e6", fmt6(epoch // 30)))
    cands.append(("unix_div60_mod_1e6", fmt6(epoch // 60)))

    # 3) Variasi jam UTC (mudah ditebak dev): HHMMSS
    cands.append(("utc_hhmmss", dt.strftime("%H%M%S")))

    # 4) Variasi tanggal+jam: ddHHMM (juga 6 digit)
    cands.append(("utc_ddhhmm", dt.strftime("%d%H%M")))

    # 5) Detik sejak midnight UTC (00:00) -> 0..86399 (dipad 6 digit)
    sod = dt.hour * 3600 + dt.minute * 60 + dt.second
    cands.append(("utc_seconds_since_midnight", f"{sod:06d}"))

    return dt, cands

def pin_candidates_from_timeprobe(hex_token: str):
    """
    Kalau kamu punya token 'timeprobe-XXXXXXXX' (8 hex),
    ini 2 cara paling umum untuk jadi PIN 6 digit.
    """
    h = int(hex_token, 16)
    cands = []
    # A) langsung mod 1e6
    cands.append(("timeprobe_hex_mod_1e6", fmt6(h)))
    # B) HOTP-style mask sign bit dulu (sering dipakai orang)
    cands.append(("timeprobe_hex_mask7fffffff_mod_1e6", fmt6(h & 0x7fffffff)))
    return cands

def extract_hex_token(s: str):
    s = s.strip()
    m = re.search(r"timeprobe-([0-9a-fA-F]{8})", s)
    if m:
        return m.group(1).lower()
    if re.fullmatch(r"[0-9a-fA-F]{8}", s):
        return s.lower()
    return None

def main():
    ap = argparse.ArgumentParser(description="CTF Textual PIN solver (UTC timestamp based).")
    ap.add_argument("--watch", action="store_true", help="Update setiap detik (biar gampang copy/paste).")
    ap.add_argument("--window", type=int, default=0, help="Tampilkan kandidat untuk epoch now±N detik.")
    ap.add_argument("--token", type=str, default=None, help="Isi 'e9097860' atau 'timeprobe-e9097860' untuk mode timeprobe.")
    args = ap.parse_args()

    if args.token:
        tok = extract_hex_token(args.token)
        if not tok:
            print("[-] Token tidak valid. Contoh: --token e9097860 atau --token timeprobe-e9097860")
            sys.exit(1)

        cands = pin_candidates_from_timeprobe(tok)
        print(f"[+] timeprobe token: {tok}")
        for name, pin in cands:
            print(f"    {name:<35} {pin}")
        return

    def print_now(epoch: int):
        dt, cands = pin_candidates_from_epoch(epoch)
        print(f"UTC now: {dt.strftime('%Y-%m-%d %H:%M:%S')}Z | epoch={epoch}")
        for name, pin in cands:
            print(f"    {name:<35} {pin}")

    if args.watch:
        # mode live: setiap detik refresh output
        try:
            while True:
                epoch = int(time.time())  # ini sudah “UTC epoch”
                # clear screen
                print("\x1b[2J\x1b[H", end="")
                print_now(epoch)
                if args.window:
                    print("")
                    for d in range(-args.window, args.window + 1):
                        e2 = epoch + d
                        dt2, c2 = pin_candidates_from_epoch(e2)
                        # fokus hanya formula paling umum biar tidak kebanyakan
                        only = dict(c2)
                        print(f"  epoch{d:+d} => unix_mod_1e6={only['unix_mod_1e6']}  utc_hhmmss={only['utc_hhmmss']}")
                time.sleep(1)
        except KeyboardInterrupt:
            return
    else:
        epoch = int(time.time())
        print_now(epoch)
        if args.window:
            print("")
            for d in range(-args.window, args.window + 1):
                e2 = epoch + d
                dt2, c2 = pin_candidates_from_epoch(e2)
                only = dict(c2)
                print(f"epoch{d:+d} => unix_mod_1e6={only['unix_mod_1e6']}  utc_hhmmss={only['utc_hhmmss']}")

if __name__ == "__main__":
    main()
