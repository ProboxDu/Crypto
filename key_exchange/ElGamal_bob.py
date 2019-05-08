import socket
from ElGamal_key import *

def elgamal_bob(public_key1, private_key1, public_key2, private_key2):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((socket.gethostname(), 9999))
    except socket.error as msg:
        print(msg)
        exit(1)
    #DH p & g

    p = int(sock.recv(1024).decode())
    g = int(sock.recv(1024).decode())
    print('Diffie-Hellman p & g:')
    print(p, g)

    #Recv, Decrypted & Validate A
    y1 = int(sock.recv(1024).decode())
    y2 = int(sock.recv(1024).decode())
    print('Recv encrypted message:')
    print(y1, y2)
    sy1 = int(sock.recv(1024).decode())
    sy2 = int(sock.recv(1024).decode())
    print('Recv signature message:')
    print(sy1, sy2)
    A = decrypt((y1, y2), private_key1)
    assert (validate(A, public_key2, (sy1, sy2)))

    b = random.randrange(0, p)
    print('Bob gen random b: ', b)
    B = pow(g, b, p)

    #Send, Encrypted & Signed B
    y1, y2 = encrypt(B, public_key1)
    sock.sendall(str(y1).encode())
    sock.sendall(str(y2).encode())
    print("Encrypted message:")
    print(y1, y2)
    sy1, sy2 = signature(B, public_key2, private_key2)
    sock.sendall(str(sy1).encode())
    sock.sendall(str(sy2).encode())
    print("Signature message:")
    print(sy1, sy2)
    
    sock.close()
    return pow(A, b, p)

if __name__ == "__main__":
    Kb = elgamal_bob(public_key1, private_key1, public_key2, private_key2)
    print('Bob compute Kb = pow(A, b, p) :', Kb)