"""passlib.pbkdf2 - PBKDF2 support

this module is getting increasingly poorly named.
maybe rename to "kdf" since it's getting more key derivation functions added.
"""
#=============================================================================
# imports
#=============================================================================
# core
import hashlib
import logging; log = logging.getLogger(__name__)
import re
from struct import pack
from warnings import warn
# site
try:
    import M2Crypto.EVP as _EVP
except ImportError:
    _EVP = None
#_EVP = None
# pkg
from passlib.exc import PasslibRuntimeWarning, ExpectedTypeError
from passlib.utils import join_bytes, to_native_str, bytes_to_int, int_to_bytes, join_byte_values
from passlib.utils.compat import BytesIO, irange, int_types
# local
__all__ = [
    # hash utils
    "norm_hash_name",
    "get_hash_info",

    # prf utils
    "get_prf",
    "get_keyed_prf",

    # kdfs
    "pbkdf1",
    "pbkdf2",
]

def _clear_caches():
    """unittest helper -- clears get_hash_info() / get_prf() caches"""
    _ghi_cache.clear()
    _prf_cache.clear()
    _nhn_cache.clear()

#=============================================================================
# hash helpers
#=============================================================================

# indexes into _nhn_hash_names
_nhn_formats = dict(hashlib=0, iana=1)

# known hash names
_nhn_hash_names = [
    # format: (hashlib/ssl name, iana name or standin, other known aliases ...)

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
    """Normalize hash function name

    :arg name:
        Original hash function name.

        This name can be a Python :mod:`~hashlib` digest name,
        a SCRAM mechanism name, IANA assigned hash name, etc.
        Case is ignored, and underscores are converted to hyphens.

    :param format:
        Naming convention to normalize to.
        Possible values are:

        * ``"hashlib"`` (the default) - normalizes name to be compatible
          with Python's :mod:`!hashlib`.

        * ``"iana"`` - normalizes name to IANA-assigned hash function name.
          for hashes which IANA hasn't assigned a name for, issues a warning,
          and then uses a heuristic to give a "best guess".

    :returns:
        Hash name, returned as native :class:`!str`.

    .. versionadded:: 1.6
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

def _get_hash_const(name):
    """internal helper used by :func:`get_hash_info`"""
    # typecheck
    if not isinstance(name, str):
        raise TypeError("expected digest name")

    # abort on bad values, and on hashlib attrs which aren't hashes
    if name.startswith("_") or name in ("new", "algorithms"):
        return None

    # first, check hashlib.<attr> for an efficient constructor
    try:
        return getattr(hashlib, name)
    except AttributeError:
        pass

    # second, check hashlib.new() in case SSL supports the digest
    try:
        # new() should throw ValueError if alg is unknown
        tmp = hashlib.new(name, b"")
    except ValueError:
        pass
    else:
        # create wrapper function
        # XXX: find a better way to just return hash constructor
        def const(msg=b""):
            return hashlib.new(name, msg)
        const.__name__ = "new(%r)" % name
        const.__module__ = "hashlib"
        const.__doc__ = "wrapper for %s hash constructor" % name
        return const

    # third, use md4 fallback if needed
    if name == "md4":
        from passlib.utils.md4 import md4
        return md4

    # finally, give up!
    return None

# cache for get_hash_const() lookups
_ghi_cache = {}

def get_hash_info(name):
    """Lookup hash constructor & stats by name.

    This is a thin wrapper around :mod:`hashlib`. It looks up a hash by name,
    and returns a hash constructor, along with the digest & block sizes.
    Calls to this method are cached, making it a lot faster
    than looking up a hash and then creating a temporary instance
    in order to read the digest size. Additionally, this function includes
    workarounds and fallbacks for various VM-specific issues.

    :arg name: hashlib-compatible name of hash function

    :raises ValueError: if hash is unknown or unsupported.

    :returns: `(hash_constructor, digest_size, block_size)`

    .. versionadded:: 1.7
    """
    try:
        return _ghi_cache[name]
    except KeyError:
        pass
    const = _get_hash_const(name)
    if not const:
        raise ValueError("unknown hash algorithm: %r" % name)
    tmp = const()
    if len(tmp.digest()) != tmp.digest_size:
        raise RuntimeError("%r constructor failed sanity check" % name)
    record = _ghi_cache[name] = (const, tmp.digest_size, tmp.block_size)
    return record

#=============================================================================
# prf lookup
#=============================================================================

_BNULL = b'\x00'

# sanity check
_TEST_HMAC_SHA1 = b',\x1cb\xe0H\xa5\x82M\xfb>\xd6\x98\xef\x8e\xf9oQ\x85\xa3i'

# xlat tables used by hmac routines
_TRANS_5C = join_byte_values((x ^ 0x5C) for x in irange(256))
_TRANS_36 = join_byte_values((x ^ 0x36) for x in irange(256))

# prefixes for recognizing hmac-{digest} prf names
_HMAC_PREFIXES = ("hmac_", "hmac-")

#------------------------------------------------------------------------
# general prf lookup
#------------------------------------------------------------------------
def _get_hmac_prf(digest):
    """helper for get_prf() -- returns HMAC-based prf for specified digest"""
    # helpers
    def tag_wrapper(prf):
        """helper to document generated wrappers"""
        prf.__name__ = "hmac_" + digest
        prf.__doc__ = ("hmac_%s(key, msg) -> digest;"
                       " generated by passlib.utils.pbkdf2.get_prf()" %
                       digest)

    # use m2crypto if it's present and supports requested digest
    if _EVP:
        # use m2crypto function directly for sha1, since that's its default digest
        if digest == "sha1":
            if _EVP.hmac(b'x', b'y') != _TEST_HMAC_SHA1:
                # don't expect to ever get here, but just in case
                raise RuntimeError("M2Crypto.EVP.hmac() failed sanity check")
            return _EVP.hmac, 20

        # else check if it supports given digest as an option
        try:
            result = _EVP.hmac(b'x', b'y', digest)
        except ValueError:
            pass
        else:
            const = _EVP.hmac
            def prf(key, msg):
                return const(key, msg, digest)
            digest_size = len(result)
            tag_wrapper(prf)
            return prf, digest_size

    # fall back to hashlib-based implementation --
    # this is a simplified version of stdlib's hmac module.
    const, digest_size, block_size = get_hash_info(digest)
    assert block_size >= 16, "unacceptably low block size"
    def prf(key, msg):
        klen = len(key)
        if klen > block_size:
            key = const(key).digest()
            klen = digest_size
        if klen < block_size:
            key += _BNULL * (block_size - klen)
        tmp = const(key.translate(_TRANS_36) + msg).digest()
        return const(key.translate(_TRANS_5C) + tmp).digest()
    tag_wrapper(prf)
    return prf, digest_size

# cache mapping prf name/func -> (func, digest_size)
_prf_cache = {}

def get_prf(name):
    """Lookup pseudo-random family (PRF) by name.

    :arg name:
        This must be the name of a recognized prf.
        Currently this only recognizes names with the format
        :samp:`hmac-{digest}`, where :samp:`{digest}`
        is the name of a hash function such as
        ``md5``, ``sha256``, etc.

        This can also be a callable with the signature
        ``prf_func(secret, message) -> digest``,
        in which case it will be returned unchanged.

    :raises ValueError: if the name is not known
    :raises TypeError: if the name is not a callable or string

    :returns:
        a tuple of :samp:`({prf_func}, {digest_size})`, where:

        * :samp:`{prf_func}` is a function implementing
          the specified PRF, and has the signature
          ``prf_func(secret, message) -> digest``.

        * :samp:`{digest_size}` is an integer indicating
          the number of bytes the function returns.

    Usage example::

        >>> from passlib.utils.pbkdf2 import get_prf
        >>> hmac_sha256, dsize = get_prf("hmac-sha256")
        >>> hmac_sha256
        <function hmac_sha256 at 0x1e37c80>
        >>> dsize
        32
        >>> digest = hmac_sha256('password', 'message')

    This function will attempt to return the fastest implementation
    it can find. Primarily, if M2Crypto is present, and supports the specified PRF,
    :func:`M2Crypto.EVP.hmac` will be used behind the scenes.
    """
    global _prf_cache
    if name in _prf_cache:
        return _prf_cache[name]
    if isinstance(name, str):
        if name.startswith(_HMAC_PREFIXES):
            record = _get_hmac_prf(name[5:])
        else:
            raise ValueError("unknown prf algorithm: %r" % (name,))
    elif callable(name):
        # assume it's a callable, use it directly
        digest_size = len(name(b'x', b'y'))
        record = (name, digest_size)
    else:
        raise ExpectedTypeError(name, "str or callable", "prf name")
    _prf_cache[name] = record
    return record

#------------------------------------------------------------------------
# keyed prf generation
#------------------------------------------------------------------------

def _get_keyed_hmac_prf(digest, key):
    """get_keyed_prf() helper -- returns efficent hmac() function
    hardcoded with specific digest and key.
    """
    # all the following was adapted from stdlib's hmac module

    # resolve digest, get info
    const, digest_size, block_size = get_hash_info(digest)
    assert block_size >= 16, "unacceptably low block size"

    # prepare key
    klen = len(key)
    if klen > block_size:
        key = const(key).digest()
        klen = digest_size
    if klen < block_size:
        key += _BNULL * (block_size - klen)

    # return optimized hmac function for given key
    inner_proto = const(key.translate(_TRANS_36))
    outer_proto = const(key.translate(_TRANS_5C))
    def kprf(msg):
        inner = inner_proto.copy()
        inner.update(msg)
        outer = outer_proto.copy()
        outer.update(inner.digest())
        return outer.digest()

    ##kprf.__name__ = "keyed_%s_hmac" % digest
    ##kprf.__doc__ = "keyed %s-hmac function, " \
    ##              "generated by passlib.utils.pbkdf2.get_keyed_prf()" % digest
    return kprf, digest_size

def get_keyed_prf(name, key):
    """Lookup psuedo-random function family by name,
    and return a psuedo-random function bound to a specific key.

    :arg name:
        name of psuedorandom family.
        accepts same inputs as :func:`get_prf`.

    :arg key:
        key encoded as bytes.

    :returns:
        tuple of :samp:`({bound_prf_func}, {digest_size})`,
        where function has signature `bound_prf_func(message) -> digest`.

    .. versionadded:: 1.7
    """
    # check for optimized functions (common case)
    if isinstance(name, str) and name.startswith(_HMAC_PREFIXES):
        return _get_keyed_hmac_prf(name[5:], key)

    # fallback to making a generic wrapper
    prf, digest_size = get_prf(name)
    def kprf(message):
        return prf(key, message)

    ##kprf.__name__ = "keyed_%s" % prf.__name__
    ##kprf.__doc__ = "keyed %s function, " \
    ##    "generated by passlib.utils.pbkdf2.get_keyed_prf()" % prf.__name__
    return kprf, digest_size

#=============================================================================
# pbkdf1 support
#=============================================================================
def pbkdf1(secret, salt, rounds, keylen=None, hash="sha1"):
    """pkcs#5 password-based key derivation v1.5

    :arg secret: passphrase to use to generate key
    :arg salt: salt string to use when generating key
    :param rounds: number of rounds to use to generate key
    :arg keylen: number of bytes to generate (if ``None``, uses digest's native size)
    :param hash:
        hash function to use. must be name of a hash recognized by hashlib.

    :returns:
        raw bytes of generated key

    .. note::

        This algorithm has been deprecated, new code should use PBKDF2.
        Among other limitations, ``keylen`` cannot be larger
        than the digest size of the specified hash.
    """
    # validate secret & salt
    if not isinstance(secret, bytes):
        raise ExpectedTypeError(secret, "bytes", "secret")
    if not isinstance(salt, bytes):
        raise ExpectedTypeError(salt, "bytes", "salt")

    # validate rounds
    if not isinstance(rounds, int_types):
        raise ExpectedTypeError(rounds, "int", "rounds")
    if rounds < 1:
        raise ValueError("rounds must be at least 1")

    # resolve hash
    const, digest_size, block_size = get_hash_info(hash)

    # validate keylen
    if keylen is None:
        keylen = digest_size
    elif not isinstance(keylen, int_types):
        raise ExpectedTypeError(keylen, "int or None", "keylen")
    elif keylen < 0:
        raise ValueError("keylen must be at least 0")
    elif keylen > digest_size:
        raise ValueError("keylength too large for digest: %r > %r" %
                         (keylen, digest_size))

    # main pbkdf1 loop
    block = secret + salt
    for _ in irange(rounds):
        block = const(block).digest()
    return block[:keylen]

#=============================================================================
# pbkdf2
#=============================================================================

# NOTE: the pbkdf2 spec does not specify a maximum number of rounds.
#       however, many of the hashes in passlib are currently clamped
#       at the 32-bit limit, just for sanity. Once realistic pbkdf2 rounds
#       start approaching 24 bits or so, this limit will be raised.
_MAX_BLOCKS = 0xffffffff # 2**32-1

def pbkdf2(secret, salt, rounds, keylen=None, prf="hmac-sha1"):
    """pkcs#5 password-based key derivation v2.0

    :arg secret: passphrase to use to generate key
    :arg salt: salt string to use when generating key
    :param rounds: number of rounds to use to generate key
    :arg keylen:
        number of bytes to generate.
        if set to ``None``, will use digest size of selected prf.
    :param prf:
        psuedo-random family to use for key strengthening.
        this can be any string or callable accepted by :func:`get_prf`.
        this defaults to ``"hmac-sha1"`` (the only prf explicitly listed in
        the PBKDF2 specification)

    :returns:
        raw bytes of generated key
    """
    # validate secret & salt
    if not isinstance(secret, bytes):
        raise ExpectedTypeError(secret, "bytes", "secret")
    if not isinstance(salt, bytes):
        raise ExpectedTypeError(salt, "bytes", "salt")

    # validate rounds
    if not isinstance(rounds, int_types):
        raise ExpectedTypeError(rounds, "int", "rounds")
    if rounds < 1:
        raise ValueError("rounds must be at least 1")

    # generated keyed prf helper
    keyed_prf, digest_size = get_keyed_prf(prf, secret)

    # validate keylen
    if keylen is None:
        keylen = digest_size
    elif not isinstance(keylen, int_types):
        raise ExpectedTypeError(keylen, "int or None", "keylen")
    elif keylen < 0:
        raise ValueError("keylen must be at least 0")

    # m2crypto's pbkdf2-hmac-sha1 is faster than ours, so use it if available.
    # NOTE: as of 2012-4-4, m2crypto has buffer overflow issue which frequently
    #       causes segfaults if keylen > 32 (EVP_MAX_KEY_LENGTH).
    #       therefore we're avoiding m2crypto for large keys until that's fixed.
    #       (https://bugzilla.osafoundation.org/show_bug.cgi?id=13052)
    if prf == "hmac-sha1" and _EVP and keylen < 32:
        return _EVP.pbkdf2(secret, salt, rounds, keylen)

    # work out min block count s.t. keylen <= block_count * digest_size
    block_count = (keylen + digest_size - 1) // digest_size
    if block_count >= _MAX_BLOCKS:
        raise ValueError("keylen too long for digest")

    # build up result from blocks
    def gen():
        for i in irange(block_count):
            digest = keyed_prf(salt + pack(">L", i+1))
            accum = bytes_to_int(digest)
            # speed-critical loop of pbkdf2
            # NOTE: currently converting digests to integers since that XORs faster.
            for _ in irange(rounds-1):
                digest = keyed_prf(digest)
                accum ^= bytes_to_int(digest)
            yield int_to_bytes(accum, digest_size)
    return join_bytes(gen())[:keylen]

#=============================================================================
# eof
#=============================================================================
