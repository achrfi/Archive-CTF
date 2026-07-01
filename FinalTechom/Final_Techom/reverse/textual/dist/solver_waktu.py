import time
from datetime import datetime

print("--- Solver PIN Waktu UTC ---")
print("Menjalankan... Tekan Ctrl+C untuk berhenti.")
print("Gunakan PIN yang ditampilkan di bawah ini pada aplikasi target.")

try:
    while True:
        # Dapatkan waktu UTC saat ini
        utc_now = datetime.utcnow()
        
        # Format menjadi JJMMDD
        pin = utc_now.strftime('%H%M%S')
        
        # Cetak PIN ke baris yang sama setiap kali
        # \r mengembalikan cursor ke awal baris
        print(f"PIN Saat Ini: {pin}", end='\r')
        
        # Tunggu sebentar agar tidak membebani CPU
        time.sleep(0.1)
except KeyboardInterrupt:
    print("\nSolver dihentikan.")

