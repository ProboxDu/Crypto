import hashlib
import math
from copy import deepcopy

## Generic utility functions
def _left_rotate(n, l, w):
    """Left rotate a w-bit integer n by l bits."""
    return ((n << l) | (n >> (w - l))) % (1 << w)

def _fromHexStringToLane(string):
    """Convert a string of bytes written in hexadecimal to a lane value"""
    print(string)
    assert len(string) % 2 == 0
    temp = b''
    nrBytes = len(string) // 2
    for i in range(nrBytes):
        offset = (nrBytes - i - 1) * 2
        temp += string[offset:offset + 2]
    return int(temp)

def _fromLaneToHexString(lane, w):
    """Convert a lane value to a string of bytes written in hexadecimal"""
    laneHexBE = ((b'%%0%dX' % (w // 4)) % lane)
    temp = b''
    nrBytes = len(laneHexBE) // 2
    for i in range(nrBytes):
        offset = (nrBytes - i - 1) * 2
        temp += laneHexBE[offset:offset + 2]
    return temp

def _convertStrToTable(string, w, b):
    """Convert a string of hex-chars to its 5x5 matrix representation
    string: string of bytes of hex-coded bytes (e.g. '9A2C...')"""
    assert w % 8 == 0 and len(string) * 4 == b
    output = [[0, 0, 0, 0, 0],
            [0, 0, 0, 0, 0],
            [0, 0, 0, 0, 0],
            [0, 0, 0, 0, 0],
            [0, 0, 0, 0, 0]]

    bits_per_char = 2 * w // 8
    for x in range(5):
        for y in range(5):
            offset = (5 * y + x) * bits_per_char
            hexstring = string[offset:offset + bits_per_char]
            output[x][y] = _fromHexStringToLane(hexstring)
    return output

def _convertTableToStr(table, w):
    """Convert a 5x5 matrix representation to its string representation"""
    assert w % 8 == 0 and len(table) == 5 and (True in [len(row)==5 for row in table])

    output = [b''] * 25
    for x in range(5):
        for y in range(5):
            output[5 * y + x] = _fromLaneToHexString(table[x][y], w)
    output = b''.join(output).lower()
    return output

class Keccak(object):

    RC = [0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000, 
        0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009, 
        0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
        0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
        0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
        0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008]
    
    ## Rotation offsets
    r = [[0,  36,   3,  41,  18],
        [1,  44,  10,  45,   2],
        [62,  6,  43,  15,  61],
        [28, 55,  25,  21,  56],
        [27, 20,  39,  8,   14]]
    
    def __init__(self, r = 1024, c = 576, suffix = 0x01, n = 1024, data = None):
        self.r = r
        self.c = c
        self.n = n
        self.b = r + c
        self.suffix = suffix
        self.w = self.b // 25
        self.l = int(math.log(self.w, 2))
        self.nr = 12 + 2 * self.l
        
        self.S = [[0] * 5] * 5
        self._data = b''
        self._last_digest = None

        if data:
            self.update(data)

    @staticmethod
    def Round(A, RCfixed, w):
        #Initialization of temporary variables
        B = [[0] * 5] * 5
        C = [0] * 5
        D = [0] * 5

        #Theta step
        for x in range(5):
            C[x] = A[x][0] ^ A[x][1] ^ A[x][2] ^ A[x][3] ^ A[x][4]
        
        for x in range(5):
            D[x] = C[(x - 1) % 5] ^ _left_rotate(C[(x + 1) % 5], 1, w)
        
        for x in range(5):
            for y in range(5):
                A[x][y] = A[x][y] ^ D[x]
        
        #Rho and Pi steps
        for x in range(5):
            for y in range(5):
                B[y][(2 * x + 3 * y) % 5] = _left_rotate(A[x][y], Keccak.r[x][y], w)
        
        #Chi step
        for x in range(5):
            for y in range(5):
                A[x][y] = B[x][y] ^ ((~B[(x + 1) % 5][y]) & B[(x + 2) % 5][y])
        
        #Iota step
        A[0][0] = A[0][0] ^ RCfixed

        return A


    @staticmethod
    def KeccakF(A, nr, w):

        for i in range(nr):
            A = Keccak.Round(A, Keccak.RC[i] % (1 << w), w)
        return A

    @staticmethod
    def pad10star1(M, n):

        [my_bytes_length, my_bytes] = M
        assert n % 8 == 0
        if len(my_bytes) % 2 != 0:
            my_bytes += '0'
        assert my_bytes_length <= (len(my_bytes) // 2 * 8)
        nr_bytes_filled = my_bytes_length // 8
        nbr_bits_filled = my_bytes_length % 8
        l = my_bytes_length % n
        if ((n - 8) <= l <= (n - 2)):
            if (nbr_bits_filled == 0):
                new_byte = 0
            else:
                new_byte = int(my_bytes[nr_bytes_filled * 2:nr_bytes_filled * 2 + 2], 16)
            new_byte = (new_byte >> (8 - nbr_bits_filled))
            new_byte = bytes(new_byte + 2 ** (nbr_bits_filled) + 2 ** 7)
            my_bytes = my_bytes[0:nr_bytes_filled * 2] + new_byte
        else:
            if (nbr_bits_filled == 0):
                new_byte = 0
            else:
                new_byte = int(my_string[nr_bytes_filled * 2:nr_bytes_filled * 2 + 2], 16)
            new_byte = (new_byte >> (8 - nbr_bits_filled))
            new_byte = bytes(new_byte + 2 ** (nbr_bits_filled))
            my_bytes = my_bytes[0:nr_bytes_filled * 2] + new_byte
            while((8 * len(my_bytes) // 2) % n < (n - 8)):
                my_bytes = my_bytes + b'00'
            my_bytes = my_bytes + b'80'
        return my_bytes

    def update(self, data):
        self._last_digest = None
        self._data += data
        extra_bits = 0
        if len(self._data) * 4 >= self.r:
            extra_bits = len(self._data) * 4 % self.r
    
        # An exact fit!
        if extra_bits == 0:
            P = self._data
            self._data = b''
        else:
            P = self._data[:-extra_bits // 4]
            self._data = self._data[-extra_bits // 4:]

        for i in range((len(P) * 8 // 2) // self.r):
            to_convert = P[i * (2 * self.r // 8):(i + 1) * (2 * self.r // 8)] + b'00' * (self.c // 8)
            P_i = _convertStrToTable(to_convert, self.w, self.b)

            for y in range(5):
                for x in range(5):
                    self.S[x][y] = self.S[x][y] ^ P_i[x][y]
            self.S = Keccak.KeccakF(self.S, self.nr, self.w)

    def digest(self):
        """Return the digest of the strings passed to the update() method so far.
        This is a string of digest_size bytes which may contain non-ASCII
        characters, including null bytes."""

        if self._last_digest:
            return self._last_digest

        # UGLY WARNING
        # Handle bytestring/hexstring conversions
        print(self._data)
        M = (len(self._data) * 4, self._data)

        # First finish the padding and force the final update:
        self._data = Keccak.pad10star1(M, self.r)
        self.update(b'')
        # UGLY WARNING over

        assert len(self._data) == 0, "Why is there data left in the buffer? %s with length %d" % (self._data, len(self._data) * 4)

        # Squeezing time!
        Z = ''
        outputLength = self.n
        while outputLength > 0:
            string = _convertTableToStr(self.S, self.w)
        # Read the first 'r' bits of the state
        Z = Z + string[:self.r * 2 // 8]
        outputLength -= self.r
        if outputLength > 0:
            S = KeccakF(S)

        self._last_digest = Z[:2 * self.n // 8].decode('hex')
        return self._last_digest

    def hexdigest(self):
        """Like digest() except the digest is returned as a string of hex digits
        This may be used to exchange the value safely in email or other
        non-binary environments."""
        return self.digest().encode('hex')

    def copy(self):
        return deepcopy(self)

def sha3_224(data=None):
  return Keccak(c=448, r=1152, n=224, data=data)

def sha3_256(data=None):
  return Keccak(c=512, r=1088, n=256, data=data)

def sha3_384(data=None):
  return Keccak(c=768, r=832, n=384, data=data)

def sha3_512(data=None):
  return Keccak(c=1024, r=576, n=512, data=data)

if __name__ == "__main__":
    sha3 = sha3_512(b'123456')
    print('sha3_512 digest:', sha3.digest())
    sha3 = hashlib.sha3_512()
    sha3.update(b'123456')
    print('sha3_512 digest:', sha3.hexdigest())

    
    