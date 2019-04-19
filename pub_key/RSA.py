# -*- coding: utf-8 -*-
"""
    RSA test
    No padding, just a test
"""
from __future__ import print_function
import math
import random
import operator

_small_primes_product = 1
_primes_bits = [[] for i in range(11)]

def get_primes(mx):
    _primes = []
    _is_prime = [0] * (mx + 1)
    cnt = 0
    for i in range(2, mx):
        if _is_prime[i] == 0:
            _primes.append(i)
            cnt += 1
        for j in range(cnt):
            if _primes[j] * i > mx:
                break
            _is_prime[_primes[j] * i] = 1
            if i % _primes[j] == 0:
                break
    return _primes

def init():
    global _small_primes_product, _primes_bits
    _primes = get_primes(1024)
    for p in _primes:
        _primes_bits[p.bit_length()].append(p)
    _small_primes_product = reduce(operator.mul, _primes)
    return

def gcd(a, b):
    if b == 0:
        return a
    return gcd(b, a % b)

def ex_gcd(a, b):
    if b == 0:
        return a, 1, 0
    ret, x, y = ex_gcd(b, a % b)
    return ret, y, x - a // b * y

def mod_inverse(a, b):
    g, x, _ = ex_gcd(a, b)
    assert g == 1
    return (x + b) % b

def prime_test(p, k = 25):
    # Miller-Rabin primality test
    if p < 2: return False
    if p <= 3: return True
    if p & 1 == 0: return False
    p_1 = p - 1

    # write p-1 as 2^s*d where d is odd
    s, d = 0, p_1
    while not d & 1:
        s, d = s + 1, d >> 1
    assert 2 ** s * d == p_1 and d & 1

    for i in range(k):
        a = random.randrange(2, p_1)
        if gcd(a, p) != 1:
            return False

        x = pow(a, d, p)
        if x in (1, p_1):
            continue

        for j in range(s):
            x = pow(x, 2, p)
            if x == 1:
                return False
            if x == p_1:
                if j >= s - 1: return False
                break
        else:
            return False
    return True

def gen_prime(size, k = 25):
    assert size >= 2
    if size <= 10:
        return random.choice(_primes_bits[size])
    low = 1 << (size - 1)
    hi = (1 << size) 
    while True:
        n = random.randrange(low, hi) | 1
        if gcd(_small_primes_product, n) != 1:
            continue
        if prime_test(n, k):
            return n
    return 
        

def gen_key(size):
    p = gen_prime(size)
    q = gen_prime(size)

    e = 65537
    n = p * q
    phi = (p - 1) * (q - 1)
    d = mod_inverse(e, phi)
    return [(e, n), (d, n)]

def encrypt(plain_text, (e, n)):
    return pow(plain_text, e, n)

def decrypt(cipher_text, (d, n)):
    return pow(cipher_text, d, n)

if __name__ == "__main__":
    init()
    plain_text = 2125454848484648496459841949849845
    public_key, private_key = gen_key(512) 
    print(public_key)
    print(private_key)
    cipher_text = encrypt(plain_text, public_key)
    print("Encrypt text: ", cipher_text)

    plain_text = decrypt(cipher_text, private_key)
    print("Decrypt text: ", plain_text)
