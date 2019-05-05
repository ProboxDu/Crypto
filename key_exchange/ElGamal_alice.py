# -*- coding: utf-8 -*-

from __future__ import print_function
import socket
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
    
def find_primitive_root(p):
    if p == 2:
        return 1
    p1 = 2
    p2 = (p - 1) // p1
    while True:
        g = random.randrange(2, p)
        if not (pow(g, p1, p) == 1):
            if not (pow(g, p2, p) == 1):
                return g

def gen_key(size):
    p = gen_prime(size)
    g = find_primitive_root(p)
    x = random.randrange(0, p - 1)
    y = pow(g, x, p)
    return [(p, g, y), (p, x)]

def encrypt(m, (p, g, y)):
    r = random.randrange(0, p - 1)
    y1 = pow(g, r, p)
    y2 = m * pow(y, r, p) % p
    return (y1, y2)

def signature(m, (p, g, y), (_, x)):
    k = random.randrange(0, p - 1)
    while (gcd(k, p - 1) != 1):
        k = random.randrange(0, p - 1)
    r = pow(g, k, p)
    s = ((m - x * r) * mod_inverse(k, p - 1)) % (p - 1)
    return (r, s)

def elgamal_alice((p, g, y), (_, x)):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((socket.gethostname(), 9999))
        sock.listen(10)
    except socket.error as msg:
        print(msg)
        exit(1)
    client, addr = sock.accept()
    a = random.randrange(0, p)
    #print('Alice gen random a: ', a)
    A = pow(g, a, p)
    #p & g
    client.sendall(str(p))
    client.sendall(str(g))  #注意连发3个可能粘包
    print(p, g)
    client.sendall(str(x))
    while True:
        plain_text = int(input())
        y1, y2 = encrypt(plain_text,(p, g, y))
        client.sendall(str(y1))
        client.sendall(str(y2))
        print("Encrypted message:")
        print(y1, y2)
        sy1, sy2 = signature(plain_text, (p, g, y), (_, x))
        client.sendall(str(sy1))
        client.sendall(str(sy2))
        print("Signature message:")
        print(sy1, sy2)

    client.close()
    sock.close()

if __name__ == "__main__":
    init()
    public_key, private_key = gen_key(512) 
    elgamal_alice(public_key, private_key)

    