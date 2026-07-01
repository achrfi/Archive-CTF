#!/usr/bin/env python3
from secrets import randbits
import os

FLAG = open(os.environ.get('FLAG_PATH', '/flag.txt')).read().strip().encode()
E = 65537


def is_prime(n):
    if n < 2:
        return False
    small = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29]
    for p in small:
        if n % p == 0:
            return n == p

    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1

    tests = [2, 325, 9375, 28178, 450775, 9780504, 1795265022]
    for a in tests:
        if a % n == 0:
            continue
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        good = False
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                good = True
                break
        if good:
            continue
        return False
    return True


def get_prime(bits):
    while True:
        x = randbits(bits)
        x |= 1
        x |= 1 << (bits - 1)
        if is_prime(x):
            return x


def menu():
    print('1. show data', flush=True)
    print('2. check ciphertext', flush=True)
    print('3. quit', flush=True)


def main():
    p = get_prime(512)
    q = get_prime(512)
    n = p * q
    phi = (p - 1) * (q - 1)
    d = pow(E, -1, phi)
    m = int.from_bytes(FLAG, 'big')
    c = pow(m, E, n)

    print('rsa parity oracle', flush=True)
    print('one bit only', flush=True)

    while True:
        menu()
        choice = input('> ').strip()

        try:
            if choice == '1':
                print('n = ' + str(n), flush=True)
                print('e = ' + str(E), flush=True)
                print('c = ' + str(c), flush=True)

            elif choice == '2':
                x = int(input('ciphertext: ').strip())
                m2 = pow(x % n, d, n)
                if m2 & 1:
                    print('odd', flush=True)
                else:
                    print('even', flush=True)

            elif choice == '3':
                return

            else:
                print('unknown', flush=True)

        except Exception:
            print('invalid', flush=True)


if __name__ == '__main__':
    main()
