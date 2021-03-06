
import socket
import random

def diffie_hellman_bob():
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((socket.gethostname(), 9999))
    except socket.error as msg:
        print(msg)
        exit(1)
    #p & g
    p = int(sock.recv(1024).decode())
    g = int(sock.recv(1024).decode())
    print(p, g)
    b = random.randrange(0, p)
    print('Bob gen random b: ', b)

    A = int(sock.recv(1024).decode()) 
    print('Bob recv A: ', A)

    B = pow(g, b, p)
    print('Bob send B -> alice: ', B)
    sock.sendall(str(B).encode())
    sock.close()

    return pow(A, b, p)

if __name__ == "__main__":
    Kb = diffie_hellman_bob()
    print('Bob compute Kb = pow(A, b, p) :', Kb)
    