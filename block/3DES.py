# -*- coding: utf-8 -*-
"""
    Supported ECB.
    No padding, that is plain text and cipher text must be a multiply of 8.
    key -> Bytes containing the encryption key. 8 bytes for DES, 16 or 24 bytes for Triple DES
"""
from __future__ import print_function

ROUNDS = 16

IP = [58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8, 57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3, 61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7]

IP_1 = [40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29, 36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27, 34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25]

E = [32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1]

SBOX = [[[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7], [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8], [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0], [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]], [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10], [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5], [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15], [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]], [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8], [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1], [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7], [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]], [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15], [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9], [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4], [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]], [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9], [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6], [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14], [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]], [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11], [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8], [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6], [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]], [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1], [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6], [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2], [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]], [[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7], [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2], [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8], [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]]]

P = [16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10, 2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25]

PC_1 = [57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36, 63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4]

PC_2 = [14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2, 41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32]

R = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]


#Turn the string data, into a list of bits
def char_to_bits( ch ):
    ret = bin(ord(ch))[2:]
    return map(int, list(ret.rjust(8, '0')))

def str_to_bits( st ):
    ret = []
    for ch in st:
        ret.extend(char_to_bits(ch))
    return ret

# Turn the list of bits , into a string
def bits_to_chr( bits ):
    ret = int(''.join(map(str, bits)), 2)
    return chr(ret)

def bits_to_str( bits ):
    ret = ""
    for i in range(0, len(bits), 8):
        ret += bits_to_chr(bits[i:i + 8])
    return ret

def bits_xor(l, r):
    return map(lambda (x, y):x ^ y, zip(l, r))

def F(hblk, roundkey):
    bits = [hblk[x - 1] for x in E]
    bits = bits_xor(bits, roundkey)
    ret = []
    for i in range(0, len(bits), 6):
        # Work out the offsets
        row = (bits[i] << 1) + bits[i + 5]
        col = (bits[i + 1] << 3) + (bits[i + 2] << 2) + (bits[i + 3] << 1) + bits[i + 4]
        
        val = bin(SBOX[i / 6][row][col])[2:]
        ret.extend(map(int, list(val.rjust(4, '0'))))
    ret = [ret[x - 1] for x in P]
    return ret

def gen_roundkey(key):
    kbits = str_to_bits(key)
    kbits = [kbits[x - 1] for x in PC_1]
    left = kbits[:28]
    right = kbits[28:]
    roundkeys = []
    for i in range(ROUNDS):
        left = left[R[i]:] + left[:R[i]]
        right = right[R[i]:] + right[:R[i]]
        cur = left + right
        roundkeys.append([cur[x - 1] for x in PC_2])
    if roundkeys[0] == roundkeys[1] or roundkeys[0] == roundkeys[2]:
        raise Exception("Boom")
    return roundkeys

def encrypt_block(block, roundkeys):
    assert len(block) == 8
    bits = str_to_bits(block)
    bits = [bits[x - 1] for x in IP]
    for i in range(ROUNDS):
        left = bits[:32]
        right = bits[32:]
        left = bits_xor(left, F(right, roundkeys[i]))
        bits = right + left
    bits = left + right
    bits = [bits[x - 1] for x in IP_1]
    return bits_to_str(bits)

def encrypt(plain_text, key):
    assert len(plain_text) % 8 == 0
    roundkeys = gen_roundkey(key)
    cipher_text = ''
    l = len(plain_text)
    for i in range(0, l, 8):
        cipher_text += encrypt_block(plain_text[i:i + 8], roundkeys)
    return cipher_text

def decrypt_block(block, roundkeys):
    assert len(block) == 8
    bits = str_to_bits(block)
    bits = [bits[x - 1] for x in IP]
    for i in range(ROUNDS):
        left = bits[:32]
        right = bits[32:]
        left = bits_xor(left, F(right, roundkeys[ROUNDS - 1 - i]))
        bits = right + left
    bits = left + right
    bits = [bits[x - 1] for x in IP_1]
    return bits_to_str(bits)

def decrypt(cipher_text, key):
    assert len(cipher_text) % 8 == 0
    roundkeys = gen_roundkey(key)
    plain_text = ''
    l = len(cipher_text)
    for i in range(0, l, 8):
        plain_text += decrypt_block(cipher_text[i:i + 8], roundkeys)
    return plain_text

def DES_test(plain_text, key):

    plain_text = plain_text.decode('hex')
    key = key.decode('hex')
    
    cipher_text = encrypt(plain_text, key)
    print("DES encrypt text: ", cipher_text.encode('hex'))

    plain_text = decrypt(cipher_text, key)
    print("DES decrypt text: ", plain_text.encode('hex'))

"""
    Triple DES is just running the DES algorithm 3 times over the data with the specified key. 
    The supplied key is split up into 3 parts, each part being 8 bytes long (the mandatory key size for DES).

    The triple DES algorithm uses the DES-EDE3 method when a 24 byte key is supplied.
    This means there are three DES operations in the sequence encrypt-decrypt-encrypt with the three different keys. 
    The first key will be bytes 1 to 8, the second key bytes 9 to 16 and the third key bytes 17 to 24.

    If a 16 byte key is supplied instead, the triple DES method used will be DES-EDE2. 
    This means there are three DES operations in the sequence encrypt-decrypt-encrypt, but the first and third operations use the same key. 
    The first/third key will be bytes 1 to 8 and the second key bytes 9 to 16.

    If a 8 byte key is supplied instead, the triple DES method is equivalent to DES.
"""
def triple_DES_test(plain_text, key):
    assert len(key) in (8, 16, 24)

    print("Your plain text in hexadecimal: ", plain_text.encode('hex'))

    key1 = key[:8]
    if len(key) > 8:
        key2 = key[8:16]
    else:
        key2 = key1
    if len(key) > 16:
        key3 = key[16:]
    else:
        key3 = key1
    cipher_text = encrypt(decrypt(encrypt(plain_text, key1), key2), key3)
    print("Triple DES encrypt text: ", cipher_text.encode('hex'))
    plain_text = decrypt(encrypt(decrypt(cipher_text, key3), key2), key1)
    print("Triple DES decrypt text: ", plain_text.encode('hex'))

if __name__ == "__main__":
    # An example on a textbook
    plain_text = "02468aceeca86420"
    key = "0f1571c947d9e859"
    DES_test(plain_text, key);
    #plain_text = raw_input("Please input the plain text : ")
    #key = raw_input("Please input the key : ")
    plain_text = "abcdefgh"
    key = "qwertyuiasdfghjk"
    triple_DES_test(plain_text, key)