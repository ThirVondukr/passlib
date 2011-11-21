"""passlib.utils.scrypt - SCrypt key derivation function in pure-python.

(c) 2011 Eli Collins <elic@assurancetechnologies.com>

NOTICE
======
This module is just a feasibility study, to see if it's possible
to implement SCrypt in pure Python in any meaningful way.

The current approach uses lists of integers, allowing them to be
passed directly into salsa20 without decoding. Byte strings, array objects,
have all proved slower.

If run as a script, this module will run a limited number of the SCrypt
test vectors... though currently any value of ``n>128`` is too slow
to be useful, and that's far too low for secure purposes.
"""
#==========================================================================
# imports
#==========================================================================
# core
from itertools import izip, chain
import operator
import struct
from warnings import warn
# pkg
from passlib.utils import BEMPTY
from passlib.utils.pbkdf2 import pbkdf2
from passlib.utils.scrypt._salsa import salsa20
# local
__all__ =[
    "scrypt",
]
#==========================================================================
# constants
#==========================================================================

MAX_KEYLEN = ((1<<32)-1)*32
MAX_RP = (1<<30)

class ScryptCompatWarning(UserWarning):
    pass

#==========================================================================
# scrypt engine
#==========================================================================
class _ScryptEngine(object):
    """helper class used to run scrypt kdf, see scrypt() for frontend"""
    #=================================================================
    # instance attrs
    #=================================================================

    #: scrypt config
    n = 0
    r = 0
    p = 0

    #=================================================================
    # init
    #=================================================================
    def __init__(self, n, r, p):
        # validate config
        if p < 1:
            raise ValueError("p must be >= 1")
        if r*p >= MAX_RP:
            # pbkdf2 limitation - it will be requested to generate
            # p*(2*r)*64 bytes worth of data from sha-256.
            # pbkdf2 can do max of (2**31-1) blocks,
            # and sha-256 has 64 byte block size.
            raise ValueError("r*p must be < (1<<30)")
        if n < 1:
            raise ValueError("n must be >= 1")
        n_is_log2 = not (n&(n-1))
        if not n_is_log2:
            # NOTE: this is due to the way the reference scrypt integerify is
            #       only coded for powers of two, and doesn't have a fallback.
            warn("Running scrypt with an 'N' value that's not a power of 2, "
                 "such values aren't supported by the reference SCrypt implementation",
                 ScryptCompatWarning)

        # store config
        self.n = n
        self.n_is_log2 = n_is_log2
        self.r = r
        self.p = p
        self.smix_bytes = r<<7 # num bytes in smix input - 2*r*16*4
        self.iv_bytes = self.smix_bytes * p
        self.bmix_len = bmix_len = r<<5 # length of bmix block list - 32*r integers
        self.bmix_half_len = r<<4
        assert struct.calcsize("I") == 4
        self.bmix_struct = struct.Struct("<" + str(bmix_len) + "I")

        # pick optimized bmix for certain cases
        if r == 1:
            self.bmix = self._bmix_1

        # pick best integerify function - integerify(bmix_block) should
        # take last 64 bytes of block and return a little-endian integer.
        # since it's immediately converted % n, we only have to extract
        # the first 32 bytes if n < 2**32 - which due to the current
        # internal representation, is already unpacked as a 32-bit int.
        if n <= 0xFFFFffff:
            integerify = operator.itemgetter(-16)
        else:
            assert n <= 0xFFFFffffFFFFffff
            ig1 = operator.itemgetter(-16)
            ig2 = operator.itemgetter(-17)
            def integerify(X):
                return ig1(X) | (ig2(X)<<32)
        self.integerify = integerify

    #=================================================================
    # frontend
    #=================================================================
    def scrypt(self, secret, salt, keylen):
        """run scrypt kdf for specified secret, salt, and keylen"""
        # validate inputs
        if keylen > MAX_KEYLEN:
            raise ValueError("keylen too large")

        # stretch salt into initial byte array via pbkdf2
        iv_bytes = self.iv_bytes
        input = pbkdf2(secret, salt, rounds=1,
                       keylen=iv_bytes, prf="hmac-sha256")

        # split initial byte array into 'p' mflen-sized chunks,
        # and run each chunk through smix() to generate output chunk.
        smix = self.smix
        if self.p == 1:
            output = smix(input)
        else:
            smix_bytes = self.smix_bytes
            output = BEMPTY.join(
                smix(input[offset:offset+smix_bytes])
                for offset in range(0, iv_bytes, smix_bytes)
            )

        # stretch final byte array into output via pbkdf2
        return pbkdf2(secret, output, rounds=1,
                      keylen=keylen, prf="hmac-sha256")

    #=================================================================
    # smix()
    #=================================================================
    def smix(self, input):
        """run SCrypt smix function on a single input block

        :arg input:
            byte string containing input data.
            interpreted as 32*r little endian 4 byte integers.

        :returns:
            byte string containing output data
            derived by mixing input using n & r parameters.
        """
        # gather locals
        bmix = self.bmix
        bmix_struct = self.bmix_struct
        integerify = self.integerify
        n = self.n

        # parse input into 32*r integers
        X = list(bmix_struct.unpack(input))

        # starting with X, derive V s.t. V[0]=X; V[i] = bmix(X, V[i-1]);
        # final X should equal bmix(X,V[n-1])
        def vgen():
            i = 0
            while i < n:
                tmp = tuple(X)
                yield tmp
                bmix(tmp,X)
                i += 1
        V = list(vgen())

        # generate result from X & V.
        gv = V.__getitem__
        i = 0
        if self.n_is_log2:
            mask = n-1
            while i < n:
                j = integerify(X) & mask
                tmp = tuple(a^b for a,b in izip(X, gv(j)))
                bmix(tmp,X)
                i += 1
        else:
            while i < n:
                j = integerify(X) % n
                tmp = tuple(a^b for a,b in izip(X, gv(j)))
                bmix(tmp,X)
                i += 1

        # repack tmp
        return bmix_struct.pack(*X)

    #=================================================================
    # bmix()
    #=================================================================
    def bmix(self, source, target):
        """block mixing function used by smix()
        uses salsa20/8 core to mix block contents.

        :arg source:
            source to read from.
            should be list of 32*r integers.
        :arg target:
            target to write to.
            should be list of 32*r integers.

        source & target should NOT be same list.
        """
        # Y[-1] = B[2r-1], Y[i] = hash( Y[i-1] xor B[i])
        # B' <-- (Y_0, Y_2 ... Y_{2r-2}, Y_1, Y_3 ... Y_{2r-1}) */
        half = self.bmix_half_len # 16*r out of 32*r - start of Y_1
        X = source[-16:]
        siter = iter(source)
        j = 0
        while j < half:
            jn = j+16
            target[j:jn] = X = salsa20(a ^ b for a, b in izip(X, siter))
            target[half+j:half+jn] = X = salsa20(a ^ b
                                                 for a, b in izip(X, siter))
            j = jn

    def _bmix_1(self, source, target):
        "special bmix for handling r=1 case"
        B = source[16:]
        target[:16] = X = salsa20(a ^ b for a, b in izip(B, iter(source)))
        target[16:] = salsa20(a ^ b for a, b in izip(X, B))

    #=================================================================
    # eoc
    #=================================================================

def scrypt(secret, salt, n, r, p, keylen):
    """run SCrypt key derivation function using specified parameters.

    :arg secret: passphrase as bytes
    :arg salt: salt as bytes
    :arg n: integer 'N' parameter
    :arg r: integer 'r' parameter
    :arg p: integer 'p' parameter
    :arg keylen: number of bytes of key to generate

    :returns: a *keylen*-sized bytes instance

    :raises ValueError:
        If any of the following constraints are false:

        * ``r*p<2**30`` - due to a limitation of PBKDF2-HMAC-SHA256.
        * ``keylen < (2**32-1)*32`` - due to a limitation of PBKDF2-HMAC-SHA256.
        * ``n`` must a be a power of 2 - for compatibility with
          the reference SCrypt implementation, which omits support for other
          values of ``n``.
    """
    if not isinstance(secret, bytes):
        raise TypeError("secret must be bytes, not %s" % (type(secret),))
    if not isinstance(salt, bytes):
        raise TypeError("salt must be bytes, not %s" % (type(salt),))
    engine = _ScryptEngine(n,r,p)
    return engine.scrypt(secret, salt, keylen)

#==========================================================================
# tests
#==========================================================================
import re
from binascii import unhexlify, hexlify

def uh(value):
    return unhexlify(re.sub(r"[\s:]","", value))

def test1():
#    return scrypt("","",1<<9,8,1,64)

    assert scrypt("", "", 16, 1, 1, 64) == uh("""
        77 d6 57 62 38 65 7b 20 3b 19 ca 42 c1 8a 04 97
        f1 6b 48 44 e3 07 4a e8 df df fa 3f ed e2 14 42
        fc d0 06 9d ed 09 48 f8 32 6a 75 3a 0f c8 1f 17
        e8 d3 e0 fb 2e 0d 36 28 cf 35 e2 0c 38 d1 89 06
        """)

    assert scrypt("password", "NaCl", 1024, 8, 16, 64) == uh("""
        fd ba be 1c 9d 34 72 00 78 56 e7 19 0d 01 e9 fe
        7c 6a d7 cb c8 23 78 30 e7 73 76 63 4b 37 31 62
        2e af 30 d9 2e 22 a3 88 6f f1 09 27 9d 98 30 da
        c7 27 af b9 4a 83 ee 6d 83 60 cb df a2 cc 06 40
        """)

def test_reference_vectors():
    # run quick test on salsa bit.
    assert struct.pack("<16I",*salsa20(range(16))) == \
        uh('f518dd4fb98883e0a87954c05cab867083bb8808552810752285a05822f56c16'
           '9d4a2a0fd2142523d758c60b36411b682d53860514b871d27659042a5afa475d')

    # test vectors from scrypt whitepaper -
    # http://www.tarsnap.com/scrypt/scrypt.pdf
    assert scrypt("", "", 16, 1, 1, 64) == uh("""
        77 d6 57 62 38 65 7b 20 3b 19 ca 42 c1 8a 04 97
        f1 6b 48 44 e3 07 4a e8 df df fa 3f ed e2 14 42
        fc d0 06 9d ed 09 48 f8 32 6a 75 3a 0f c8 1f 17
        e8 d3 e0 fb 2e 0d 36 28 cf 35 e2 0c 38 d1 89 06
        """)

    assert scrypt("password", "NaCl", 1024, 8, 16, 64) == uh("""
        fd ba be 1c 9d 34 72 00 78 56 e7 19 0d 01 e9 fe
        7c 6a d7 cb c8 23 78 30 e7 73 76 63 4b 37 31 62
        2e af 30 d9 2e 22 a3 88 6f f1 09 27 9d 98 30 da
        c7 27 af b9 4a 83 ee 6d 83 60 cb df a2 cc 06 40
        """)

    assert scrypt("pleaseletmein", "SodiumChloride", 16384, 8, 1, 64) == uh("""
        70 23 bd cb 3a fd 73 48 46 1c 06 cd 81 fd 38 eb
        fd a8 fb ba 90 4f 8e 3e a9 b5 43 f6 54 5d a1 f2
        d5 43 29 55 61 3f 0f cf 62 d4 97 05 24 2a 9a f9
        e6 1e 85 dc 0d 65 1e 40 df cf 01 7b 45 57 58 87
        """)
    return

    assert scrypt("pleaseletmein", "SodiumChloride", 1048576, 8,1,64) == uh("""
        21 01 cb 9b 6a 51 1a ae ad db be 09 cf 70 f8 81
        ec 56 8d 57 4a 2f fd 4d ab e5 ee 98 20 ad aa 47
        8e 56 fd 8f 4b a5 d0 9f fa 1c 6d 92 7c 40 f4 c3
        37 30 40 49 e8 a9 52 fb cb f4 5c 6f a7 7a 41 a4
        """)

if __name__ == "__main__":
    test_reference_vectors()
    print "tests passed"

#==========================================================================
# eof
#==========================================================================
