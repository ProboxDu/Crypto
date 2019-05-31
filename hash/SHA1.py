import hashlib
import struct
import copy

def _left_rotate(n, l):
    """Left rotate a 32-bit integer n by l bits."""
    return ((n << l) | (n >> (32 - l))) & 0xffffffff

def _process_block(data, h0, h1, h2, h3, h4):
    assert len(data) == 64
    w = [0] * 80
    for i in range(16):
        w[i] = struct.unpack(b'>I', data[i * 4: i * 4 + 4])[0]
    
    for i in range(16, 80):
        w[i] = _left_rotate(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1)
    
    a, b, c, d, e = h0, h1, h2, h3, h4

    for i in range(80):
        if 0 <= i <= 19:
            # Use alternative 1 for f from FIPS PB 180-1 to avoid bitwise not
            f = d ^ (b & (c ^ d))
            k = 0x5A827999
        elif 20 <= i <= 39:
            f = b ^ c ^ d
            k = 0x6ED9EBA1
        elif 40 <= i <= 59:
            f = (b & c) | (b & d) | (c & d)
            k = 0x8F1BBCDC
        elif 60 <= i <= 79:
            f = b ^ c ^ d
            k = 0xCA62C1D6
        a, b, c, d, e = (_left_rotate(a, 5) + f + e + k + w[i]) & 0xffffffff, a, _left_rotate(b, 30), c, d
    
    h0 = (h0 + a) & 0xffffffff
    h1 = (h1 + b) & 0xffffffff
    h2 = (h2 + c) & 0xffffffff
    h3 = (h3 + d) & 0xffffffff
    h4 = (h4 + e) & 0xffffffff
    
    return h0, h1, h2, h3, h4

class sha1Hash(object):
    
    name = 'sha1'
    digest_size = 20
    block_size = 64
    message_length = 20

    def __init__(self):
        self._h = (0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0)
        self._data = b''
        self._byte_length = 0

    def update(self, data):

        data = self._data + data
        l = len(data)
        block = data[:64]
        for i in range(64, l, 64):
            self._h = _process_block(block, *self._h)
            self._byte_length += 64
            block = data[i: i + 64]
        
        self._data = block


    def copy(self):
        return copy.copy(self)

    def _process_digest(self):
        data = self._data
        byte_length = self._byte_length + len(data)

        data += bytes([0x80])
        data += bytes([0x00] * ((56 - (byte_length + 1) % 64) % 64))
         # append length of message (before pre-processing), in bits, as 64-bit big-endian integer
        bit_length = byte_length * 8
        data += struct.pack(b'>Q', bit_length)

        h = _process_block(data[:64], *self._h)
        if len(data) == 64:
            return h
        return _process_block(data[64:], *h)

    def digest(self):
        """Produce the final hash value (big-endian) as a bytes object"""
        return b''.join(struct.pack(b'>I', h) for h in self._process_digest())

    def hexdigest(self):
        """Produce the final hash value (big-endian) as a hex string"""
        return '%08x%08x%08x%08x%08x' % self._process_digest()

if __name__ == "__main__":
    data = b'Hello'
    sha1 = sha1Hash()
    sha1.update(data)
    print('sha1-digest:',sha1.hexdigest())
    sha1 = hashlib.sha1()
    sha1.update(data)
    print('sha1-digest:', sha1.hexdigest())


