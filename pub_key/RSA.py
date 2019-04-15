# -*- coding: utf-8 -*-
"""
    RSA test
    No padding, just a test
"""
from __future__ import print_function
import libnum

def ex_gcd(a, b):
    if b == 0:
        return a, 1, 0
    ret, x, y = ex_gcd(b, a % b)
    return ret, y, x - a // b * y

def mod_inverse(a, b):
    g, x, _ = ex_gcd(a, b)
    assert g == 1
    return (x + b) % b

def gen_key(size):
    p = libnum.generate_prime(size)
    q = libnum.generate_prime(size)
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
    plain_text = 21254548484846484964598419498498
    public_key, private_key = gen_key(128) 
    print(public_key)
    print(private_key)
    cipher_text = encrypt(plain_text, public_key)
    print("Encrypt text: ", cipher_text)

    plain_text = decrypt(cipher_text, private_key)
    print("Decrypt text: ", plain_text)