from hashlib import sha256
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

infected_user = b"sn0wden"

# Blob encrypted yang ditemukan dari hasil reverse payload binary
blob = bytes.fromhex(
    "77275d15d5e1ddd4b621f0b1"
    "f004dcaef31be6cb9612dabd698bf8b5fa"
    "0534c4ab99f9b7d74e9aa7ae0cfb37be"
    "5b538f8d8b3923e63a4ed39a5fb1c2af"
    "616adc0598ac4ed28c9b77803b771b75"
    "efae9c569393da3a12bb9c81d35e96da"
    "b3cb73e0a7a4c5c38992b34184b077a5"
    "df806af420a109f09615ab5a8996e2e2"
)

# Payload hanya memakai 0x58 byte pertama
data = blob[:0x58]

key = sha256(infected_user).digest()
nonce = data[:12]
ciphertext = data[12:]

flag = AESGCM(key).decrypt(nonce, ciphertext, None)
print(flag.decode())
