from SHA1 import sha1Hash
import hashlib
import hmac

_IPAD = bytes((x ^ 0x36) for x in range(256))
_OPAD = bytes((x ^ 0x5C) for x in range(256))

class HMAC(object):
    
    block_size = 64

    def __init__(self, key, msg = None, digestmod = None):
        if digestmod is None:
            digestmod = sha1Hash

        if callable(digestmod):
            self.digest_cons = digestmod

        self.outer = self.digest_cons()     #这里不能直接用digestmod
        self.inner = self.digest_cons()

        self.digest_size = self.inner.digest_size

        if hasattr(self.inner, 'block_size'):
            block_size = self.inner.block_size
        
        if len(key) > block_size:
            key = self.inner(key).digest()

        key = key.ljust(block_size, b'\0')
        
        self.inner.update(key.translate(_IPAD))
        self.outer.update(key.translate(_OPAD))

        if msg is not None:
            self.update(msg)
    
    @property
    def name(self):
        return 'hmac-' + self.inner.name

    def update(self, msg):
        self.inner.update(msg)
    
    def copy(self):
        other = self.__class__.__new__(self.__class__)
        other.inner = self.inner.copy()
        other.outer = self.outer.copy()
        return other

    def _current(self):
        h = self.outer.copy()
        h.update(self.inner.digest())
        return h

    def digest(self):
        return self._current().digest()
        
    def hexdigest(self):
        return self._current().hexdigest()

if __name__ == "__main__":
    data = b'Hello world!'
    key = b'secret'
    print('hmac-sha1 digest:', HMAC(key, data, sha1Hash).hexdigest())
    print('hmac-sha1 digest:', hmac.new(key, data, hashlib.sha1).hexdigest())

