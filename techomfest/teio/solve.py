from pwn import *
import time

HOST = 'techcomfest.1pc.tf'
PORT = 8301

context.log_level = 'info'

def wait_for_start_of_second():
    """
    Fungsi ini akan menahan script sampai detik jam sistem berganti.
    Contoh: Jika sekarang 12:00:00.900, dia akan menunggu sampai 12:00:01.005
    Tujuannya agar kita punya window waktu maksimal untuk race condition.
    """
    log.info("Menunggu pergantian detik (Time Alignment)...")
    # Ambil waktu saat ini
    t = time.time()
    # Bulatkan ke atas (detik berikutnya)
    target = int(t) + 1
    
    # Loop kosong sampai waktu sistem menyentuh target
    while time.time() < target:
        pass
    
    log.success("Waktu sinkron! Connecting now...")

def solve():
    # --- STEP 0: Sinkronisasi Waktu ---
    wait_for_start_of_second()
    
    # --- STEP 1: Buka Dua Koneksi (Race Condition) ---
    # Kita buka secepat mungkin setelah detik berganti
    p1 = remote(HOST, PORT)
    p2 = remote(HOST, PORT)
    
    log.info("Koneksi P1 dan P2 terbuka. Memulai serangan...")

    try:
        # Loop 624 kali
        for i in range(624):
            # 1. Pancing P1
            p1.recvuntil(b'>> ')
            p1.sendline(str(i + 1).encode())
            
            # 2. Ambil angka dari P1
            try:
                leak_line = p1.recvline().strip()
                # Cek jika P1 error duluan
                if b'!' in leak_line:
                    log.error("P1 Gagal (Wrong Input/Duplicate).")
                    return
                leak_val = int(leak_line.decode())
            except ValueError:
                log.error(f"Error parsing P1: {leak_line}")
                return

            # 3. Suapi P2
            p2.recvuntil(b'>> ')
            p2.sendline(str(leak_val).encode()) # Kirim angka dari P1
            
            # 4. Baca respon P2 (Verifikasi Silent)
            resp_p2 = p2.recvline().strip()
            
            # Cek apakah P2 langsung ngasih flag (lucky case)
            if b'Winning' in resp_p2 or b'CTF{' in resp_p2:
                log.success("\n[!!!] FLAG FOUND EARLY [!!!]")
                print(resp_p2.decode())
                p2.interactive()
                return
            
            # Cek jika P2 marah ('!')
            if b'!' in resp_p2:
                log.error(f"P2 Gagal di index {i}! Seed pasti berbeda.")
                return

            # Log minimalis biar terminal ga penuh
            if i % 100 == 0:
                log.info(f"Paket {i}/624 terkirim. Sinkronisasi aman sejauh ini.")

        # --- STEP 2: Finish Line ---
        log.success("Loop selesai. Menunggu flag dari P2...")
        
        # Masuk mode interaktif untuk membaca sisa buffer (Flag)
        p2.interactive()

    except Exception as e:
        log.error(f"Error: {e}")
    finally:
        try:
            p1.close()
        except:
            pass

if __name__ == "__main__":
    solve()
