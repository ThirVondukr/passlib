"""passlib.pbkdf2 - PBKDF2 support

this module is getting increasingly poorly named.
maybe rename to "kdf" since it's getting more key derivation functions added.
"""
#=================================================================================
#imports
#=================================================================================
#core
from binascii import unhexlify
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
from passlib.exc import PasslibRuntimeWarning
from passlib.utils import xor_bytes, to_native_str
from passlib.utils.compat import b, bytes, BytesIO, irange, callable, int_types
#local
__all__ = [
    "hmac_sha1",
    "get_prf",
    "pbkdf1",
    "pbkdf2",
]

#=============================================================================
# hash helpers
#=============================================================================

# known hash names
_nhn_formats = dict(hashlib=0, iana=1)
_nhn_hash_names = [
    # (hashlib/ssl name, iana name or standin, ... other known aliases)

    # hashes with official IANA-assigned names
    # (as of 2012-03 - http://www.iana.org/assignments/hash-function-text-names)
    ("md2", "md2"),
    ("md5", "md5"),
    ("sha1", "sha-1"),
    ("sha224", "sha-224", "sha2-224"),
    ("sha256", "sha-256", "sha2-256"),
    ("sha384", "sha-384", "sha2-384"),
    ("sha512", "sha-512", "sha2-512"),

    # hashlib/ssl-supported hashes without official IANA names,
    # hopefully compatible stand-ins have been chosen.
    ("md4", "md4"),
    ("sha", "sha-0", "sha0"),
    ("ripemd", "ripemd"),
    ("ripemd160", "ripemd-160"),
]

# cache for norm_hash_name()
_nhn_cache = {}

def norm_hash_name(name, format="hashlib"):
    """normalize hash function name

    :arg name:
        un-normalized hash function name.

        this name can be a Python :mod:`~hashlib` digest name,
        a SCRAM mechanism name, IANA assigned hash name, etc;
        case is ignored, underscores converted to hyphens.

    :param format:
        naming convention to normalize hash names to.
        possible values are:

        * ``"hashlib"`` (the default) - normalizes name to be compatible
          with Python's :mod:`!hashlib`.

        * ``"iana"`` - normalizes name to IANA-assigned hash function name.
          for hashes which IANA hasn't assigned a name for, issues a warning,
          and then uses a heuristic to give a "best guess".

    :returns:
        hash name, returned as native string.
    """
    # check cache
    try:
        idx = _nhn_formats[format]
    except KeyError:
        raise ValueError("unknown format: %r" % (format,))
    try:
        return _nhn_cache[name][idx]
    except KeyError:
        pass
    orig = name

    # normalize input
    if not isinstance(name, str):
        name = to_native_str(name, 'utf-8', 'hash name')
    name = re.sub("[_ /]", "-", name.strip().lower())
    if name.startswith("scram-"):
        name = name[6:]
        if name.endswith("-plus"):
            name = name[:-5]

    # look through standard names and known aliases
    def check_table(name):
        for row in _nhn_hash_names:
            if name in row:
                _nhn_cache[orig] = row
                return row[idx]
    result = check_table(name)
    if result:
        return result

    # try to clean name up, and recheck table
    m = re.match("^(?P<name>[a-z]+)-?(?P<rev>\d)?-?(?P<size>\d{3,4})?$", name)
    if m:
        name, rev, size = m.group("name", "rev", "size")
        if rev:
            name += rev
        if size:
            name += "-" + size
        result = check_table(name)
        if result:
            return result

    # else we've done what we can
    warn("norm_hash_name(): unknown hash: %r" % (orig,), PasslibRuntimeWarning)
    name2 = name.replace("-", "")
    row = _nhn_cache[orig] = (name2, name)
    return row[idx]

#=================================================================================
#quick hmac_sha1 implementation used various places
#=================================================================================
def hmac_sha1(key, msg):
    "perform raw hmac-sha1 of a message"
    return hmac.new(key, msg, hashlib.sha1).digest()

if _EVP:
    #default *should* be sha1, which saves us a wrapper function, but might as well check.
    try:
        result = _EVP.hmac(b('x'),b('y'))
    except ValueError: #pragma: no cover
        #this is probably not a good sign if it happens.
        from passlib.exc import PasslibRuntimeWarning
        warn("PassLib: M2Crypt.EVP.hmac() unexpected threw value error during "
             "passlib startup test", PasslibRuntimeWarning)
    else:
        if result == b(',\x1cb\xe0H\xa5\x82M\xfb>\xd6\x98\xef\x8e\xf9oQ\x85\xa3i'):
            hmac_sha1 = _EVP.hmac

#=================================================================================
#general prf lookup
#=================================================================================
def _get_hmac_prf(digest):
    "helper to return HMAC prf for specific digest"
    #check if m2crypto is present and supports requested digest
    if _EVP:
        try:
            result = _EVP.hmac(b('x'), b('y'), digest)
        except ValueError:
            pass
        else:
            #it does. so use M2Crypto's hmac & digest code
            hmac_const = _EVP.hmac
            def prf(key, msg):
                "prf(key,msg)->digest; generated by passlib.utils.pbkdf2.get_prf()"
                return hmac_const(key, msg, digest)
            prf.__name__ = "hmac_" + digest
            digest_size = len(result)
            return prf, digest_size

    #fall back to stdlib implementation
    digest_const = getattr(hashlib, digest, None)
    if not digest_const:
        raise ValueError("unknown hash algorithm: %r" % (digest,))
    digest_size = digest_const().digest_size
    hmac_const = hmac.new
    def prf(key, msg):
        "prf(key,msg)->digest; generated by passlib.utils.pbkdf2.get_prf()"
        return hmac_const(key, msg, digest_const).digest()
    prf.__name__ = "hmac_" + digest
    return prf, digest_size

#cache mapping prf name/func -> (func, digest_size)
_prf_cache = {}

def _clear_prf_cache():
    "helper for unit tests"
    _prf_cache.clear()

def get_prf(name):
    """lookup pseudo-random family (prf) by name.

    :arg name:
        this must be the name of a recognized prf.
        currently this only recognizes names with the format
        :samp:`hmac-{digest}`, where :samp:`{digest}`
        is the name of a hash function such as
        ``md5``, ``sha256``, etc.

        this can also be a callable with the signature
        ``prf(secret, message) -> digest``,
        in which case it will be returned unchanged.

    :raises ValueError: if the name is not known
    :raises TypeError: if the name is not a callable or string

    :returns:
        a tuple of :samp:`({func}, {digest_size})`.

        * :samp:`{func}` is a function implementing
          the specified prf, and has the signature
          ``func(secret, message) -> digest``.

        * :samp:`{digest_size}` is an integer indicating
          the number of bytes the function returns.

    usage example::

        >>> from passlib.utils.pbkdf2 import get_prf
        >>> hmac_sha256, dsize = get_prf("hmac-sha256")
        >>> hmac_sha256
        <function hmac_sha256 at 0x1e37c80>
        >>> dsize
        32
        >>> digest = hmac_sha256('password', 'message')

    this function will attempt to return the fastest implementation
    it can find; if M2Crypto is present, and supports the specified prf,
    :func:`M2Crypto.EVP.hmac` will be used behind the scenes.
    """
    global _prf_cache
    if name in _prf_cache:
        return _prf_cache[name]
    if isinstance(name, str):
        if name.startswith("hmac-") or name.startswith("hmac_"):
            retval = _get_hmac_prf(name[5:])
        else:
            raise ValueError("unknown prf algorithm: %r" % (name,))
    elif callable(name):
        #assume it's a callable, use it directly
        digest_size = len(name(b('x'),b('y')))
        retval = (name, digest_size)
    else:
        raise TypeError("prf must be string or callable")
    _prf_cache[name] = retval
    return retval

#=================================================================================
#pbkdf1 support
#=================================================================================
def pbkdf1(secret, salt, rounds, keylen, hash="sha1"):
    """pkcs#5 password-based key derivation v1.5

    :arg secret: passphrase to use to generate key
    :arg salt: salt string to use when generating key
    :param rounds: number of rounds to use to generate key
    :arg keylen: number of bytes to generate.
    :param hash:
        hash function to use.
        if specified, it must be one of the following:

        * a callable with the prototype ``hash(message) -> raw digest``
        * a string matching one of the hashes recognized by hashlib

    :returns:
        raw bytes of generated key

    .. note::

        This algorithm is deprecated, new code should use PBKDF2.
        Among other reasons, ``keylen`` cannot be larger
        than the digest size of the specified hash.

    """
    #prepare secret & salt
    if not isinstance(secret, bytes):
        raise TypeError("secret must be bytes, not %s" % (type(secret),))
    if not isinstance(salt, bytes):
        raise TypeError("salt must be bytes, not %s" % (type(salt),))

    #prepare rounds
    if not isinstance(rounds, int_types):
        raise TypeError("rounds must be an integer")
    if rounds < 1:
        raise ValueError("rounds must be at least 1")

    #prep keylen
    if keylen < 0:
        raise ValueError("keylen must be at least 0")

    #resolve hash
    if isinstance(hash, str):
        #check for builtin hash
        hf = getattr(hashlib, hash, None)
        if hf is None:
            #check for ssl hash
            #NOTE: if hash unknown, will throw ValueError, which we'd just
            # reraise anyways; so instead of checking, we just let it get
            # thrown during first use, below
            def hf(msg):
                return hashlib.new(hash, msg)

    #run pbkdf1
    block = hf(secret + salt).digest()
    if keylen > len(block):
        raise ValueError("keylength too large for digest: %r > %r" %
                         (keylen, len(block)))
    r = 1
    while r < rounds:
        block = hf(block).digest()
        r += 1
    return block[:keylen]

#=================================================================================
#pbkdf2
#=================================================================================
MAX_BLOCKS = 0xffffffff #2**32-1
MAX_HMAC_SHA1_KEYLEN = MAX_BLOCKS*20

def pbkdf2(secret, salt, rounds, keylen, prf="hmac-sha1"):
    """pkcs#5 password-based key derivation v2.0

    :arg secret: passphrase to use to generate key
    :arg salt: salt string to use when generating key
    :param rounds: number of rounds to use to generate key
    :arg keylen:
        number of bytes to generate.
        if -1, will use digest size of prf.
    :param prf:
        psuedo-random family to use for key strengthening.
        this can be any string or callable accepted by :func:`get_prf`.
        this defaults to ``hmac-sha1`` (the only prf explicitly listed in
        the PBKDF2 specification)

    :returns:
        raw bytes of generated key
    """
    #prepare secret & salt
    if not isinstance(secret, bytes):
        raise TypeError("secret must be bytes, not %s" % (type(secret),))
    if not isinstance(salt, bytes):
        raise TypeError("salt must be bytes, not %s" % (type(salt),))

    #prepare rounds
    if not isinstance(rounds, int_types):
        raise TypeError("rounds must be an integer")
    if rounds < 1:
        raise ValueError("rounds must be at least 1")

    #special case for m2crypto + hmac-sha1
    if prf == "hmac-sha1" and _EVP:
        if keylen == -1:
            keylen = 20
        # NOTE: doing check here, because M2crypto won't take 'long' instances
        # (which this is when running under 32bit)
        if keylen > MAX_HMAC_SHA1_KEYLEN:
            raise ValueError("key length too long")

        # NOTE: as of 2012-4-4, m2crypto has buffer overflow issue
        # which may cause segfaults if keylen > 32 (EVP_MAX_KEY_LENGTH).
        # therefore we're avoiding m2crypto for large keys until that's fixed.
        # see https://bugzilla.osafoundation.org/show_bug.cgi?id=13052
        if keylen < 32:
            return _EVP.pbkdf2(secret, salt, rounds, keylen)

    #resolve prf
    encode_block, digest_size = get_prf(prf)
    if keylen == -1:
        keylen = digest_size

    #figure out how many blocks we'll need
    bcount = (keylen+digest_size-1)//digest_size
    if bcount >= MAX_BLOCKS:
        raise ValueError("key length too long")

    #build up key from blocks
    out = BytesIO()
    write = out.write
    for i in irange(1,bcount+1):
        block = tmp = encode_block(secret, salt + pack(">L", i))
        #NOTE: could potentially unroll this loop somewhat for speed,
        # or find some faster way to accumulate & xor tmp values together
        j = 1
        while j < rounds:
            tmp = encode_block(secret, tmp)
            block = xor_bytes(block, tmp)
            j += 1
        write(block)

    #and done
    return out.getvalue()[:keylen]

#=================================================================================
#eof
#=================================================================================
