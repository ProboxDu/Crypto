import socket
from ElGamal_key import *

def elgamal_alice(public_key1, private_key1, public_key2, private_key2):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((socket.gethostname(), 9999))
        sock.listen(10)
    except socket.error as msg:
        print(msg)
        exit(1)
    client, addr = sock.accept()

    p = gen_prime(512)
    g = find_primitive_root(p)
    #DH p & g
    client.sendall(str(p).encode())
    client.sendall(str(g).encode())  #可能粘包, 没有特殊处理
    print('Diffie-Hellman p & g:')
    print(p, g)

    a = random.randrange(0, p)
    print('Alice gen random a: ', a)
    A = pow(g, a, p)

    #Send, Encrypted & Signed A
    y1, y2 = encrypt(A, public_key1)
    client.sendall(str(y1).encode())
    client.sendall(str(y2).encode())
    print("Encrypted message:")
    print(y1, y2)
    sy1, sy2 = signature(A, public_key2, private_key2)
    client.sendall(str(sy1).encode())
    client.sendall(str(sy2).encode())
    print("Signature message:")
    print(sy1, sy2)

    #Recv, Decrypted & Validate B
    y1 = int(client.recv(1024).decode())
    y2 = int(client.recv(1024).decode())
    print('Recv encrypted message:')
    print(y1, y2)
    sy1 = int(client.recv(1024).decode())
    sy2 = int(client.recv(1024).decode())
    print('Recv signature message:')
    print(sy1, sy2)
    B = decrypt((y1, y2), private_key1)
    assert (validate(B, public_key2, (sy1, sy2)))

    client.close()
    sock.close()
    return pow(B, a, p)

if __name__ == "__main__":
    init()
    Ka = elgamal_alice(public_key1, private_key1, public_key2, private_key2)
    print('Alice compute Ka = pow(B, a, p) :', Ka)
