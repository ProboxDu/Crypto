# -*- coding: utf-8 -*-

from __future__ import print_function
import socket
import random

def ex_gcd(a, b):
    if b == 0:
        return a, 1, 0
    ret, x, y = ex_gcd(b, a % b)
    return ret, y, x - a // b * y

def mod_inverse(a, b):
    g, x, _ = ex_gcd(a, b)
    assert g == 1
    return (x + b) % b

def decrypt((y1, y2), (p, x)): 
    return y2 * mod_inverse(pow(y1, x, p), p) % p

def validate(m, (p, g, y), (r, s)):
    t1 = pow(g, m, p)
    t2 = (pow(y, r, p) % p) * (pow(r, s, p) % p) % p
    if t1 == t2:
        return True
    return False

def elgamal_bob():
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((socket.gethostname(), 9999))
    except socket.error as msg:
        print(msg)
        exit(1)
    #p & g
    p = int(sock.recv(1024))
    g = int(sock.recv(1024))
    print(p, g)

    x = int(sock.recv(1024)) 
    print('Bob recv x: ', x)
    y = pow(g, x, p)
    
    while True:
        y1 = int(sock.recv(1024))
        y2 = int(sock.recv(1024))
        print('Recv encrypted message:')
        print(y1, y2)
        m = decrypt((y1, y2), (p, x))
        sy1 = int(sock.recv(1024))
        sy2 = int(sock.recv(1024))
        print('Recv signature message:')
        print(sy1, sy2)
        if validate(m, (p, g, y), (sy1, sy2)):
            print('Decrypted & validated message:')
            print(m)
        else:
            print('validate error.')
    sock.close()

if __name__ == "__main__":
    elgamal_bob()