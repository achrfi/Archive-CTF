
import datetime
import time

# Dapatkan waktu UTC saat ini
utc_now = datetime.datetime.now(datetime.timezone.utc)

# Ubah menjadi stempel waktu Unix (detik sejak zaman)
timestamp = int(utc_now.timestamp())

# PIN adalah nilai integer dari stempel waktu
pin = timestamp

# Cetak PIN agar bisa disalurkan ke tantangan
print(pin)
