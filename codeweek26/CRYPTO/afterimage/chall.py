#!/usr/bin/env python3
import os, json, random
from Crypto.Util.number import getPrime, bytes_to_long, GCD

BITS = 1024
LOW_UNKNOWN_BITS = 256    
NUM_DECOY_HINTS = 520
NOISE_RATE = 0.03
FLAG = os.environ.get('FLAG', 'GCW{REDACTED}').encode()

def gen_keys():
    while True:
        p = getPrime(BITS)
        q = getPrime(BITS)
        if p == q:
            continue
        phi = (p-1)*(q-1)
        e1 = 3
        a = 65537
        e2 = e1 * a
        if GCD(e1, phi) == 1 and GCD(e2, phi) == 1:
            return p, q, p*q, phi, e1, e2

def padded_message(flag: bytes) -> bytes:
    marker = b'TF3|'
    sep = b'|END|'
    target_len = 220
    pad_len = target_len - len(marker) - len(sep) - len(flag)
    if pad_len < 96:
        raise ValueError('flag too long oii')
    return marker + os.urandom(pad_len) + sep + flag

def make_decoy_hints(q: int):
    bits = bin(q)[2:].zfill(BITS)
    positions = sorted(random.sample(range(BITS), NUM_DECOY_HINTS))
    out = []
    for pos in positions:
        b = int(bits[pos])
        if random.random() < NOISE_RATE:
            b ^= 1
        out.append([pos, b])
    return out

def main():
    p, q, n, phi, e1, e2 = gen_keys()
    msg = padded_message(FLAG)
    m = bytes_to_long(msg)
    assert m < n

    public = {
        'title': 'Triple Fault',
        'n': n,
        'e1': e1,
        'e2': e2,
        'c1': pow(m, e1, n),
        'c2': pow(m, e2, n),
        'hints': make_decoy_hints(q),
        'telemetry': {
            'limb_head': hex(p >> LOW_UNKNOWN_BITS),
            'limb_tail_bits': LOW_UNKNOWN_BITS,
        }
    }
    with open('challenge_data.json', 'w') as f:
        json.dump(public, f, indent=2)

    private = dict(public)
    private['_p'] = str(p)
    private['_q'] = str(q)
    private['_msg_hex'] = msg.hex()
    with open('challenge_data_full.json', 'w') as f:
        json.dump(private, f, indent=2)

    print('[+] wrote challenge_data.json')
    print(f'[+] n bits = {n.bit_length()}')
    print(f'[+] e1={e1}, e2={e2}, gcd={GCD(e1, e2)}')
    print(f'[+] c1 cube-root shortcut check: m^3 > n is {m**3 > n}')
    print(f'[+] unknown low bits of p = {LOW_UNKNOWN_BITS}')

if __name__ == '__main__':
    main()
