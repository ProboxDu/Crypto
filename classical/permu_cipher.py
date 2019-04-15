# -*- coding: utf-8 -*-
from __future__ import print_function
import numpy as np

key = []
# 索引变换函数，将秘钥转换为输出/插入的索引列
def index_exchange(n):
    output_index = range(0, n)
    for i in range(0, n): #将密钥与输出序列相对应
        for j in range(0, n):
            if (key[j] > key[i]):
                key[j], key[i] = key[i], key[j]
                output_index[j], output_index[i] = output_index[i], output_index[j]
    #print(output_index)
    return output_index

#加密返回密文
def encrypt(plain_text, m, n, key): #m行n列的转化矩阵
    arr = np.empty((m, n), dtype=np.character)
    #1.分离
    index = 0
    for i in range(0, m):
        for j in range(0, n):
            if index < len(plain_text):
                arr[i, j] = plain_text[index]
                index += 1
            else:
                print('depart complete')
    #print(arr)
    #2.转换
    output_index = index_exchange(n)
    #3.输出
    cipher_text = []
    for i in output_index:
        #print(arr[:, i])
        for j in range(0,m):
            cipher_text.append(arr[j, i])
    return cipher_text

#解密并返回
def decrypt(cipher_text, m, n, key):
    arr = np.zeros((m, n), dtype = np.character)
    output_index = index_exchange(n)
    #将密文插入
    index = 0
    for insert_index in output_index:
        for i in range(0, m):
            arr[i, insert_index] = cipher_text[index]
            index += 1
    ret = []
    for i in range(0, m):
        for j in range(0, n):
            ret.append(arr[i][j])
    return ret

if __name__ == "__main__":
    plain_text = raw_input("Input plain text: ")
    tkey = raw_input("Input key: ")
    n = len(tkey)
    for i in tkey:
        key.append(ord(i) - ord('a') + 1)

    if len(plain_text) % n != 0:
        print("Illegal input!")
        exit(0)

    m = len(plain_text) // n

    cipher_text = "".join(encrypt(plain_text, m, n, key))
    print("Encrypt text: ", cipher_text)

    plain_text = "".join(decrypt(cipher_text, m, n, key))
    print("Decrypt text: ", plain_text)



