#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import remote, context
from binascii import unhexlify, hexlify
from zlib import crc32

context.log_level = "info"

HOST, PORT = "103.185.52.103", 3004
N = 624  # MT19937 state size

# -------------------- MT19937 helpers (untemper & predict) --------------------
# Tempering (CPython MT): 
# y ^= (y >> 11)
# y ^= (y << 7) & 0x9d2c5680
# y ^= (y << 15) & 0xefc60000
# y ^= (y >> 18)

def undo_right(y, shift):
    # invert: y ^= y >> shift  (right)
    result = 0
    for i in range(32):
        bit = (y >> (31 - i)) & 1
        if i >= shift:
            bit ^= (result >> (32 - shift)) & 1
        result = (result << 1) | bit
    return result

def undo_left_and(y, shift, mask):
    # invert: y ^= (y << shift) & mask (left)
    result = 0
    for i in range(32):
        bit = (y >> i) & 1
        if i >= shift:
            bit ^= ((result >> (i - shift)) & 1) & ((mask >> i) & 1)
        result |= (bit << i)
    return result

def untemper(z):
    y = undo_right(z, 18)
    y = undo_left_and(y, 15, 0xefc60000)
    y = undo_left_and(y, 7,  0x9d2c5680)
    y = undo_right(y, 11)
    return y & 0xffffffff

UPPER_MASK = 0x80000000
LOWER_MASK = 0x7fffffff
MAGIC = 0x9908b0df

def twist(mt):
    """Produce next MT state (len=624) from current untempered state array."""
    new = [0]*N
    for i in range(N):
        x = (mt[i] & UPPER_MASK) | (mt[(i+1) % N] & LOWER_MASK)
        xA = x >> 1
        if x & 1:
            xA ^= MAGIC
        new[i] = (mt[(i+397) % N] ^ xA) & 0xffffffff
    return new

def temper(y):
    y ^= (y >> 11)
    y ^= (y << 7) & 0x9d2c5680
    y ^= (y << 15) & 0xefc60000
    y ^= (y >> 18)
    return y & 0xffffffff

# --------------------------- Service interaction ------------------------------
def recv_menu(r):
    r.recvuntil(b"[G]et ticket")
    r.recvuntil(b"[I]nsert ticket")
    r.recvuntil(b"[Q]uit")

def get_ticket(r, team=b"aa"):
    recv_menu(r)
    r.sendlineafter(b">> ", b"G")
    r.sendafter(b"Your team name: ", team)
    line = r.recvline()  # "Your encrypted ticket is: <hex>"
    assert b"Your encrypted ticket is:" in line
    pkt_hex = line.decode().strip().split(":",1)[1].strip()
    line = r.recvline()  # "Team OTP: <hex>"
    assert b"Team OTP:" in line
    otp_hex_printed = line.decode().strip().split(":",1)[1].strip()
    return pkt_hex, otp_hex_printed

def try_submit(r, pkt_hex):
    recv_menu(r)
    r.sendlineafter(b">> ", b"I")
    r.sendafter(b"Your encrypted ticket (hex): ", pkt_hex.encode())
    chunks = []
    for _ in range(6):
        try:
            s = r.recvline(timeout=0.4)
            if not s: break
            chunks.append(s.decode("latin1","ignore").strip())
        except Exception:
            break
    return "\n".join(chunks)

# --------------------------------- Main ---------------------------------------
def main():
    r = remote(HOST, PORT)

    # Kumpulkan 624 OTP yang dicetak (masing-masing = keluaran MT sesi sebelumnya)
    printed = []
    last_pkt = None
    for i in range(N):
        pkt_hex, otp_hex = get_ticket(r, team=b"aa")
        last_pkt = pkt_hex
        # OTP dicetak format hex tanpa '0x' dan bisa drop leading zero -> aman untuk int(..,16)
        printed.append(int(otp_hex, 16))

    # Reconstruct untempered state
    mt_untempered = [untemper(z) for z in printed]  # 624 buah
    # Prediksi OTP SAAT INI: setelah panggilan G ke-624, server set OTP = output berikutnya
    # Itu = temper(twist(mt)[0])
    mt_next = twist(mt_untempered)
    predicted_current_otp = temper(mt_next[0])

    print(f"[i] Prediksi OTP saat ini: {predicted_current_otp:08x}")

    # Coba submit tiket terakhir apa adanya
    resp = try_submit(r, last_pkt)
    print("\n[RESP] Submit tiket terakhir:")
    print(resp if resp else "(no response)")

    # Diagnosis (kalau memang broken seperti di source yang kamu kasih)
    print("\n=== Catatan Penting ===")
    print("- Kita sudah bisa prediksi OTP aktif via rekonstruksi MT19937 (tanpa panggil G lagi).")
    print("- Tapi format tiket terenkripsi tidak memuat '-<OTP>' sebagai bagian ke-3.")
    print("- Dengan MAC (SHA1(key[:16]||data)), memodifikasi plaintext tanpa keystream ekstra → gagal.")
    print("- Hasil: sekalipun OTP tepat, validasi tetap 'Expired!' (logic service mengunci).")

    r.close()

if __name__ == "__main__":
    main()
