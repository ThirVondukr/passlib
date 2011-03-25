"""passlib.pbkdf2 - PBKDF2 support

"""
#=================================================================================
#imports
#=================================================================================
#core
from binascii import unhexlify
from cStringIO import StringIO
import hashlib
import hmac
import logging; log = logging.getLogger(__name__)
import re
from struct import pack
from warnings import warn
#site
try:
    from M2Crypto import EVP as _EVP
except ImportError:
    _EVP = None
#pkg
from passlib.utils import xor_bytes
#local
__all__ = [
    "hmac_sha1",
    "pbkdf2",
]

#=================================================================================
#hmac sha1 support
#=================================================================================
def hmac_sha1(key, msg):
    "perform raw hmac-sha1 of a message"
    return hmac.new(key, msg, hashlib.sha1).digest()

if _EVP:
    #default *should* be sha1, which saves us a wrapper function, but might as well check.
    try:
        result = _EVP.hmac('x','y')
    except ValueError: #pragma: no cover
        #this is probably not a good sign if it happens.
        warn("PassLib: M2Crypt.EVP.hmac() unexpected threw value error during passlib startup test")
    else:
        if result == ',\x1cb\xe0H\xa5\x82M\xfb>\xd6\x98\xef\x8e\xf9oQ\x85\xa3i':
            hmac_sha1 = _EVP.hmac

#=================================================================================
#backend
#=================================================================================
MAX_BLOCKS = 0xffffffffL #2**32-1
MAX_HMAC_SHA1_KEYLEN = MAX_BLOCKS*20

def _resolve_prf(prf):
    "resolve prf string or callable -> func & digest_size"
    if isinstance(prf, str):
        if prf.startswith("hmac-"):
            digest = prf[5:]

            #check if m2crypto is present and supports requested digest
            if _EVP:
                try:
                    result = _EVP.hmac('x', 'y', digest)
                except ValueError:
                    pass
                else:
                    #it does. so use M2Crypto's hmac & digest code
                    hmac_const = _EVP.hmac
                    def encode_block(key, msg):
                        return hmac_const(key, msg, digest)
                    digest_size = len(result)
                    return encode_block, digest_size

            #fall back to stdlib implementation
            digest_const = getattr(hashlib, digest, None)
            if not digest_const:
                raise ValueError, "unknown hash algorithm: %r" % (digest,)
            digest_size = digest_const().digest_size
            hmac_const = hmac.new
            def encode_block(key, msg):
                return hmac_const(key, msg, digest_const).digest()
            return encode_block, digest_size

        else:
            raise ValueError, "unknown prf algorithm: %r" % (prf,)

    elif callable(prf):
        #assume it's a callable, use it directly
        digest_size = len(prf('',''))
        return prf, digest_size

    else:
        raise TypeError, "prf must be string or callable"

def pbkdf2(secret, salt, rounds, keylen, prf="hmac-sha1"):
    """pkcs#5 password-based key derivation v2.0

    :arg secret: passphrase to use to generate key
    :arg salt: salt string to use when generating key
    :param rounds: number of rounds to use to generate key
    :arg keylen: number of bytes to generate
    :param prf:
        psuedo-random function to use for key strengthening.
        should be a callable of the form ``prf(secret, plaintext) -> ciphertext``,
        or a string ``hmac-xxx`` where ``xxx`` is the name
        of a hash function recognized by :func:`M2Crypto.EVP.hmac` (if present),
        or :func:`hashlib.new`.
        Defaults to ``hmac-sha1``, the only prf defined
        by the PBKDF2 specification.

    This function attempts to use M2Crypto as a backend
    if available and if the digest is a string supported
    by M2Crypto. Otherwise it falls back to a software implementation.

    :returns:
        raw bytes of generated key
    """

    #prepare secret
    if isinstance(secret, unicode):
        secret = secret.encode("utf-8")
    elif not isinstance(secret, str):
        raise TypeError("secret must be str or unicode")

    #prepare salt
    if isinstance(salt, unicode):
        salt = salt.encode("utf-8")
    elif not isinstance(salt, str):
        raise TypeError("salt must be str or unicode")

    #preprare rounds
    if not isinstance(rounds, (int, long)):
        raise TypeError("rounds must be an integer")
    if rounds < 1:
        raise ValueError("rounds must be at least 1")

    #special case for m2crypto + hmac-sha1
    if prf == "hmac-sha1" and _EVP:
        #NOTE: doing check here, because M2crypto won't take longs (which this is, under 32bit)
        if keylen > MAX_HMAC_SHA1_KEYLEN:
            raise ValueError, "key length too long"
        
        #NOTE: M2crypto reliably segfaults for me if given keylengths
        # larger than 40 (crashes at 41 on one system, 61 on another).
        # so just avoiding it for longer calls.
        if keylen < 41:
            return _EVP.pbkdf2(secret, salt, rounds, keylen)

    #resolve prf
    encode_block, digest_size = _resolve_prf(prf)

    #figure out how many blocks we'll need
    bcount = (keylen+digest_size-1)//digest_size
    if bcount >= MAX_BLOCKS:
        raise ValueError, "key length to long"

    #build up key from blocks
    out = StringIO()
    write = out.write
    for i in xrange(1,bcount+1):
        block = tmp = encode_block(secret, salt + pack(">L", i))
        #NOTE: could potentially unroll this loop somewhat for speed,
        # or find some faster way to accumulate & xor tmp values together
        for j in xrange(rounds-1):
            tmp = encode_block(secret, tmp)
            block = xor_bytes(block, tmp)
        write(block)

    #and done
    return out.getvalue()[:keylen]

#=================================================================================
#eof
#=================================================================================
