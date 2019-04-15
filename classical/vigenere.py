# -*- coding: utf-8 -*-
from __future__ import print_function


def encrypt(plain_text, key):
    m = len(plain_text)
    n = len(key)
    q = m // n;
    ret = ""

    for i in range(0, q):
        for j in range(0, n):
            ret += chr(int((ord(plain_text[i * n + j]) - ord('a') + ord(key[j]) - ord('a')) % 26 + ord('a')))
    for i in range(0,  m % n):
        ret += chr(int((ord(plain_text[q * n + i]) - ord('a') + ord(key[i]) - ord('a')) % 26 + ord('a')))

    return ret


def decrypt(cipher_text, key):
    m = len(cipher_text)
    n = len(key)
    q = m // n;
    ret = ""

    for i in range(0, q):
        for j in range(0, n):
            c = int((ord(cipher_text[i * n + j]) - ord('a') - (ord(key[j]) - ord('a'))) % 26 + ord('a'))
            ret += chr(c)

    for i in range(0, m % n):
        c = int((ord(cipher_text[q * n + i]) - ord('a') - (ord(key[i]) - ord('a'))) % 26 + ord('a'))
        ret += chr(c)

    return ret


if __name__ == "__main__":
    plain_text = raw_input("Please input the plain text : ")
    key = raw_input("Please input the key : ")

    cipher_text = encrypt(plain_text, key)
    print("Encrypt text: ", cipher_text)

    plain_text = decrypt(cipher_text, key)
    print("Decrypt text: ", plain_text)