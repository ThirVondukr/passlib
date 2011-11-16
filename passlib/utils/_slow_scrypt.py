"""passlib._slow_scrypt - fallback pure-python SCrypt implementation

(c) 2011 Eli Collins <elic@assurancetechnologies.com>

NOTICE
======
This module is just a feasibility study, to see if it's possible
to implement SCrypt in pure Python in any meaningful way.

The current approach uses byte arrays, unpacking them for the Salsa 20/8 round.
One approach yet to be tried is converting this to work with arrays
of 32 bit integers, eliminating the unpack stage, and possibly simplifying
the xor operations.

If run as a script, this module will run a limited number of the SCrypt
test vectors... though currently any value of ``n>128`` is too slow
to be useful, and that's far too low for secure purposes. 
"""
#==========================================================================
# imports
#==========================================================================
# core
import array
import struct
# pkg
from passlib.utils import xor_bytes
from passlib.utils.pbkdf2 import pbkdf2
# local
__all__ =[
    "scrypt",
]
#==========================================================================
# constants
#==========================================================================

_SALSA_OPS = [
        # row = (target idx, source idx 1, source idx 2, rotate)
        # interpreted as salsa operation over uint32...
        #   target = (source1+source2)<<rotate

        ##/* Operate on columns. */
        ##define R(a,b) (((a) << (b)) | ((a) >> (32 - (b))))
        ##x[ 4] ^= R(x[ 0]+x[12], 7);  x[ 8] ^= R(x[ 4]+x[ 0], 9);
        ##x[12] ^= R(x[ 8]+x[ 4],13);  x[ 0] ^= R(x[12]+x[ 8],18);
        (  4,  0, 12,  7),
        (  8,  4,  0,  9),
        ( 12,  8,  4, 13),
        (  0, 12,  8, 18),       

        ##x[ 9] ^= R(x[ 5]+x[ 1], 7);  x[13] ^= R(x[ 9]+x[ 5], 9);
        ##x[ 1] ^= R(x[13]+x[ 9],13);  x[ 5] ^= R(x[ 1]+x[13],18);
        (  9,  5,  1,  7),
        ( 13,  9,  5,  9),
        (  1, 13,  9, 13),
        (  5,  1, 13, 18),

        ##x[14] ^= R(x[10]+x[ 6], 7);  x[ 2] ^= R(x[14]+x[10], 9);
        ##x[ 6] ^= R(x[ 2]+x[14],13);  x[10] ^= R(x[ 6]+x[ 2],18);
        ( 14, 10,  6,  7),
        (  2, 14, 10,  9),
        (  6,  2, 14, 13),
        ( 10,  6,  2, 18),

        ##x[ 3] ^= R(x[15]+x[11], 7);  x[ 7] ^= R(x[ 3]+x[15], 9);
        ##x[11] ^= R(x[ 7]+x[ 3],13);  x[15] ^= R(x[11]+x[ 7],18);
        (  3, 15, 11,  7),
        (  7,  3, 15,  9),
        ( 11,  7,  3, 13),
        ( 15, 11,  7, 18),
        
        ##/* Operate on rows. */
        ##x[ 1] ^= R(x[ 0]+x[ 3], 7);  x[ 2] ^= R(x[ 1]+x[ 0], 9);
        ##x[ 3] ^= R(x[ 2]+x[ 1],13);  x[ 0] ^= R(x[ 3]+x[ 2],18);
        (  1,  0,  3,  7),
        (  2,  1,  0,  9),
        (  3,  2,  1, 13),
        (  0,  3,  2, 18),

        ##x[ 6] ^= R(x[ 5]+x[ 4], 7);  x[ 7] ^= R(x[ 6]+x[ 5], 9);
        ##x[ 4] ^= R(x[ 7]+x[ 6],13);  x[ 5] ^= R(x[ 4]+x[ 7],18);
        (  6,  5,  4,  7),
        (  7,  6,  5,  9),
        (  4,  7,  6, 13),
        (  5,  4,  7, 18),

        ##x[11] ^= R(x[10]+x[ 9], 7);  x[ 8] ^= R(x[11]+x[10], 9);
        ##x[ 9] ^= R(x[ 8]+x[11],13);  x[10] ^= R(x[ 9]+x[ 8],18);
        ( 11, 10,  9,  7),
        (  8, 11, 10,  9),
        (  9,  8, 11, 13),
        ( 10,  9,  8, 18),

        ##x[12] ^= R(x[15]+x[14], 7);  x[13] ^= R(x[12]+x[15], 9);
        ##x[14] ^= R(x[13]+x[12],13);  x[15] ^= R(x[14]+x[13],18);
        ( 12, 15, 14,  7),
        ( 13, 12, 15,  9),
        ( 14, 13, 12, 13),
        ( 15, 14, 13, 18),    
]

_salsa_iter1 = range(0,8,2)
_salsa_iter2 = range(0,16)

s = struct.Struct("<16I")
_salsa_unpack = s.unpack
_salsa_pack = s.pack
del s

MASK32 = 0xFfffFfff
MAX_KEYLEN = ((1<<32)-1)*32
MAX_RP = (1<<30)

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
        if n&(n-1):
            # NOTE: this is due to the way smix() is coded,
            #       it's not set up to deal w/ other values of 'n',
            #       though they are technically valid under scrypt.
            raise ValueError("n must be power of 2")
            
        # store config
        self.n = n
        self.r = r
        self.p = p
        
    #=================================================================
    # frontend
    #=================================================================
    def scrypt(self, secret, salt, keylen):
        """run scrypt kdf for specified secret, salt, and keylen"""
        # validate inputs
        if keylen > MAX_KEYLEN:
            raise ValueError("keylen too large")
        
        # stretch salt into initial byte array via pbkdf2
        n,r,p = self.n, self.r, self.p
        mflen = 2*64*r 
        input = pbkdf2(secret, salt, rounds=1,
                       keylen=p*mflen, prf="hmac-sha256")
   
        assert struct.calcsize("I") == 4
        
        # split initial byte array into 'p' mflen-sized chunks,
        # and run each chunk through smix() to generate output chunk.
        smix = self.smix
        output = ''.join(
            smix(input[offset:offset+mflen])
            for offset in range(0,p*mflen, mflen)        
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
            interpreted as 2*r 64-byte blocks.
        
        :returns:
            byte string containing output data
            derived by mixing input using n & r parameters.
        """
        # load config
        bmix = self.bmix
        n,r = self.n, self.r
        tr = r<<1 # 2*r
        smix_byte_count = r<<5 # 2*r*64 = total bytes in input
        
        # break input into 2*r 16-element uint32 arrays.
        assert len(input) == smix_byte_count
        input = [
            array.array('I', input[i:i+64])
            for i in xrange(0,smix_byte_count,64)
        ]        
        
        # start with input chunk,
        # populate V vector s.t.
        # V[i] = blockmix_salsa8(X) composed i times
        def gen():
            X = input
            for i in xrange(0,n):
                yield X
                X = bmix(X)
            yield X #return tail value, popped off V later
        V = list(gen())
        
        # grab last value out of generator
        X = V.pop()
        assert len(V) == n
    
        # work out struct params for integerify
        unpack, isz = self._get_integerify_info(n)
        istart = -64
        iend = istart + isz
        
        # generate final X from buffer.
        i = 0
        while i < n:
            # "integerify" X mod N.
            # scrypt takes last 64 bytes of X
            # as little-endian integer.
            j = unpack(X[istart:iend])[0] % n
                
            # calc next X
            for i,v in enumerate(V[j]):
                X[i] ^= v
            X = bmix(xor_bytes(X, V[j]))
            i += 1
            
        return "".join(X.tostring())

    @staticmethod
    def _get_integerify_info(n):
        if n <= 0xffff:
            isz = 2
            ifl = "<H"
        elif n <= 0xFfffFfff:
            isz = 4
            ifl = "<I"
        else:
            assert n <= 0xFfffFfffFfffFfff
            isz = 8
            ifl = "<Q"
        unpack = struct.Struct(ifl).unpack
        return unpack, isz
            
    #=================================================================
    # bmix() 
    #=================================================================
    def bmix(self, B):
        """block mixing function used by smix()
        
        uses salsa20/8 core to mix block contents.
        
        :arg B:
            interpreted as 2*r 64-byte blocks.
        
        :returns:
            byte string containing output data
            derived by mixing input.
        """
        # break B into 64-byte chunks, and run through salsa20
        # Y[-1] = B[2r-1], Y[i] = hash( Y[i-1] xor B[i])
        # B' <-- (Y_0, Y_2 ... Y_{2r-2}, Y_1, Y_3 ... Y_{2r-1}) */
        # salsa hash size = 64, hence the '<<6'
        r = self.r
        tr = r<<1
        blocklen = tr<<6
        salsa = self.salsa
        #assert len(B) == blocklen
        result = [None] * tr
        i = 0
        j = 0
        #X = B[-64:]
        X = B[-1]
        while i < blocklen:
            #iend = i+64
            iend = i+1
            X = result[j] = salsa(xor_bytes(X, B[i:iend]))
            j += 2
            if j >= tr:
                j = 1
            i = iend
        return result
        #return "".join(result)
        #    
        #def gen():
        #    X = B[-64:]
        #    for offset in xrange(0, 128*r, 64):
        #        X = xor_bytes(X, B[offset:offset+64])
        #        X = salsa20_8(X)
        #        yield X
        #Y = list(gen())    
        ###
        ###    for (i = 0; i < r; i++)
        ###        blkcpy(&B[i * 64], &Y[(i * 2) * 64], 64);
        ###    for (i = 0; i < r; i++)
        ###        blkcpy(&B[(i + r) * 64], &Y[(i * 2 + 1) * 64], 64);
        ###}
        #return "".join(Y[::2] + Y[1::2])   
        
    #=================================================================
    # backend hash function
    #=================================================================
    @staticmethod
    def salsa(input):
        "apply the salsa20/8 core in-place to the provided list of 16 uint32"
        # input should be 64-byte byte string
        assert len(input) == 64
        
        # break input 16 32-bit integers (little endian)
        buffer = array.array('I', input)
        #buffer = list(_salsa_unpack(input))
    
        tmp = list(buffer)
        get = tmp.__getitem__
     
        i = 0
        while i < 4:
            for target, source1, source2, rotate in _SALSA_OPS:
                # perform salsa op: target = (source1+source2)<<<rotate 
                # using 32 bit uint arithmetic
                v = (get(source1) + get(source2)) & MASK32
                v = ((v << rotate) & MASK32) | (v >> (32 - rotate))
                tmp[target] ^= v
            i += 1
                  
        # add temp back into original
        output = (
            (a + b) & MASK32
            for a,b in zip(buffer, tmp)
        )
    
        # convert to little-endian bytes
        return array.array('I', *output)
        #return _salsa_pack(*output)
    
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
    
    constraints:
    
        - r*p<2**30.
        - keylen < (2**32-1)*32.
        - n must be power of 2.
    """
    engine = _ScryptEngine(n,r,p)
    return engine.scrypt(secret, salt, keylen)
        
#==========================================================================
# tests
#==========================================================================
import re
from binascii import unhexlify, hexlify

def uh(value):
    return unhexlify(re.sub(r"[\s:]","", value))
        
def test():
    # run quick test on salsa bit.
    salsa = _ScryptEngine.salsa
    assert salsa(struct.pack("<16I",*range(16))) == \
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
    
    # run quick kdf with n=128 for timing tests.
    scrypt("secret","salt", 128, 1, 1, 64)
    
    return

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
    
    assert scrypt("pleaseletmein", "SodiumChloride", 1048576, 8,1,64) == uh("""
        21 01 cb 9b 6a 51 1a ae ad db be 09 cf 70 f8 81
        ec 56 8d 57 4a 2f fd 4d ab e5 ee 98 20 ad aa 47
        8e 56 fd 8f 4b a5 d0 9f fa 1c 6d 92 7c 40 f4 c3
        37 30 40 49 e8 a9 52 fb cb f4 5c 6f a7 7a 41 a4
        """)

if __name__ == "__main__":
    test()
    print "tests passed"

#==========================================================================
# eof
#==========================================================================
