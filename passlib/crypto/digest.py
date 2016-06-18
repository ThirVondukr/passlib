"""passlib.crypto.digest -- crytographic helpers used by the password hashes in passlib

.. versionadded:: 1.7
"""
#=============================================================================
# imports
#=============================================================================
from __future__ import division
# core
import hashlib
import logging; log = logging.getLogger(__name__)
import re
import os
from struct import Struct
from warnings import warn
# site
try:
    from M2Crypto.EVP import pbkdf2 as _m2crypto_pbkdf2_hmac_sha1
except ImportError:
    _m2crypto_pbkdf2_hmac_sha1 = None
# pkg
from passlib import exc
from passlib.utils import join_bytes, to_native_str, join_byte_values, to_bytes, SequenceMixin
from passlib.utils.compat import irange, int_types, unicode_or_bytes_types, PY3
# local
__all__ = [
    # hash utils
    "lookup_hash",
    "HashInfo",
    "norm_hash_name",

    # hmac utils
    "compile_hmac",

    # kdfs
    "pbkdf1",
    "pbkdf2_hmac",
]

#=============================================================================
# generic constants
#=============================================================================

#: max 32-bit value
MAX_UINT4 = (1<<32)-1

#: max 64-bit value
MAX_UINT8 = (1<<64)-1

#=============================================================================
# hash utils
#=============================================================================

#: list of known hash names, used by lookup_hash()'s _norm_hash_name() helper
_known_hash_names = [
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

    # TODO: add sha3 to this table.

    # hashlib/ssl-supported hashes without official IANA names,
    # (hopefully-) compatible stand-ins have been chosen.
    ("md4", "md4"),
    ("sha", "sha-0", "sha0"),
    ("ripemd", "ripemd"),
    ("ripemd160", "ripemd-160"),
]

#: cache of hash info instances used by lookup_hash()
_hash_info_cache = {}

def _get_hash_aliases(name):
    """
    internal helper used by :func:`lookup_hash` --
    normalize arbitrary hash name to hashlib format.
    if name not recognized, returns dummy record and issues a warning.

    :arg name:
        unnormalized name

    :returns:
        tuple with 2+ elements: ``(hashlib_name, iana_name|None, ... 0+ aliases)``.
    """

    # normalize input
    orig = name
    if not isinstance(name, str):
        name = to_native_str(name, 'utf-8', 'hash name')
    name = re.sub("[_ /]", "-", name.strip().lower())
    if name.startswith("scram-"): # helper for SCRAM protocol (see passlib.handlers.scram)
        name = name[6:]
        if name.endswith("-plus"):
            name = name[:-5]

    # look through standard names and known aliases
    def check_table(name):
        for row in _known_hash_names:
            if name in row:
                return row
    result = check_table(name)
    if result:
        return result

    # try to clean name up some more
    m = re.match("(?i)^(?P<name>[a-z]+)-?(?P<rev>\d)?-?(?P<size>\d{3,4})?$", name)
    if m:
        # roughly follows "SHA2-256" style format, normalize representation,
        # and checked table.
        iana_name, rev, size = m.group("name", "rev", "size")
        if rev:
            iana_name += rev
        hashlib_name = iana_name
        if size:
            iana_name += "-" + size
            if rev:
                hashlib_name += "_"
            hashlib_name += size
        result = check_table(iana_name)
        if result:
            return result

        # not found in table, but roughly recognize format. use names we built up as fallback.
        log.info("normalizing unrecognized hash name %r => %r / %r",
                 orig, hashlib_name, iana_name)

    else:
        # just can't make sense of it. return something
        iana_name = name
        hashlib_name = name.replace("-", "_")
        log.warning("normalizing unrecognized hash name and format %r => %r / %r",
                    orig, hashlib_name, iana_name)

    return hashlib_name, iana_name


def _get_hash_const(name):
    """
    internal helper used by :func:`lookup_hash` --
    lookup hash constructor by name

    :arg name:
        name (normalized to hashlib format, e.g. ``"sha256"``)

    :returns:
        hash constructor, e.g. ``hashlib.sha256()``;
        or None if hash can't be located.
    """
    # check hashlib.<attr> for an efficient constructor
    if not name.startswith("_") and name not in ("new", "algorithms"):
        try:
            return getattr(hashlib, name)
        except AttributeError:
            pass

    # check hashlib.new() in case SSL supports the digest
    new_ssl_hash = hashlib.new
    try:
        # new() should throw ValueError if alg is unknown
        new_ssl_hash(name, b"")
    except ValueError:
        pass
    else:
        # create wrapper function
        # XXX: is there a faster way to wrap this?
        def const(msg=b""):
            return new_ssl_hash(name, msg)
        const.__name__ = name
        const.__module__ = "hashlib"
        const.__doc__ = ("wrapper for hashlib.new(%r),\n"
                         "generated by passlib.crypto.digest.lookup_hash()") % name
        return const

    # use builtin md4 as fallback when not supported by hashlib
    if name == "md4":
        from passlib.crypto._md4 import md4
        return md4

    # XXX: any other modules / registries we should check?
    # TODO: add pysha3 support.

    return None

def lookup_hash(digest, return_unknown=False):
    """
    Returns a :class:`HashInfo` record containing information about a given hash function.
    Can be used to look up a hash constructor by name, normalize hash name representation, etc.

    :arg digest:
        This can be a digest constructor (e.g. :func:`hashlib.sha256`),
        a string containing a :mod:`!hashlib` digest name (e.g. ``"sha256"``),
        an IANA-assigned hash name. Case is ignored, underscores are converted to hyphens,
        and various other cleanups are made.

    :param return_unknown:
        By default, this function will throw a :exc:`~passlib.exc.KnownHashError` if no hash constructor
        can be found.  However, if this flag is False, it will instead return a dummy record
        without a constructor function.  This is mainly used by :func:`norm_hash_name`.

    Multiple calls made with the same input, or made with inputs that reference the same hash,
    should all return the same :class:`!lookup_hash` instance.

    :returns:
        :class:`HashInfo` instance for specified digest.
    """
    # check for cached entry
    cache = _hash_info_cache
    try:
        return cache[digest]
    except (KeyError, TypeError):
        # NOTE: TypeError is to catch 'TypeError: unhashable type' (e.g. HashInfo)
        pass

    # resolve ``digest`` to ``const`` & ``name_record``
    cache_by_name = True
    if isinstance(digest, unicode_or_bytes_types):
        # normalize name
        name_list = _get_hash_aliases(digest)
        name = name_list[0]
        assert name

        # if name wasn't normalized to hashlib format,
        # get info for normalized name and reuse it.
        if name != digest:
            info = lookup_hash(name, return_unknown=return_unknown)
            if info.const is None:
                # pass through dummy record
                assert return_unknown
                return info
            cache[digest] = info
            return info

        # else look up constructor
        const = _get_hash_const(name)
        if const is None:
            if return_unknown:
                # return a dummy record (but don't cache it, so normal lookup still returns error)
                return HashInfo(None, name_list)
            else:
                raise exc.UnknownHashError(name)

    elif isinstance(digest, HashInfo):
        # handle border case where HashInfo is passed in.
        return digest

    elif callable(digest):
        # try to lookup digest based on it's self-reported name
        # (which we trust to be the canonical "hashlib" name)
        const = digest
        name_list = _get_hash_aliases(const().name)
        name = name_list[0]
        other_const = _get_hash_const(name)
        if other_const is None:
            # this is probably a third-party digest we don't know about,
            # so just pass it on through, and register reverse lookup for it's name.
            pass

        elif other_const is const:
            # if we got back same constructor, this is just a known stdlib constructor,
            # which was passed in before we had cached it by name. proceed normally.
            pass

        else:
            # if we got back different object, then ``const`` is something else
            # (such as a mock object), in which case we want to skip caching it by name,
            # as that would conflict with real hash.
            cache_by_name = False

    else:
        raise exc.ExpectedTypeError(digest, "digest name or constructor", "digest")

    # create new instance
    info = HashInfo(const, name_list)

    # populate cache
    cache[const] = info
    if cache_by_name:
        for name in name_list:
            if name:  # (skips iana name if it's empty)
                assert cache.get(name) in [None, info], "%r already in cache" % name
                cache[name] = info
    return info

#: UT helper for clearing internal cache
lookup_hash.clear_cache = _hash_info_cache.clear


def norm_hash_name(name, format="hashlib"):
    """Normalize hash function name (convenience wrapper for :func:`lookup_hash`).

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
    """
    info = lookup_hash(name, return_unknown=True)
    if not info.const:
        warn("norm_hash_name(): unknown hash: %r" % (name,), exc.PasslibRuntimeWarning)
    if format == "hashlib":
        return info.name
    elif format == "iana":
        return info.iana_name
    else:
        raise ValueError("unknown format: %r" % (format,))


class HashInfo(SequenceMixin):
    """
    Record containing information about a given hash algorithm, as returned :func:`lookup_hash`.

    This class exposes the following attributes:

    .. autoattribute:: const
    .. autoattribute:: digest_size
    .. autoattribute:: block_size
    .. autoattribute:: name
    .. autoattribute:: iana_name
    .. autoattribute:: aliases

    Also acts as a sequence of ``(const, digest_size, block_size)``.
    """
    #=========================================================================
    # instance attrs
    #=========================================================================

    #: Canonical (hashlib-compatible) name (e.g. ``"sha256"``).
    name = None

    #: IANA assigned name (e.g. ``"sha-256"``), may be ``None`` if unknown.
    iana_name = None

    #: Tuple of other known aliases (may be empty)
    aliases = ()

    #: Hash constructor function (e.g. :func:`hashlib.sha256`)
    const = None

    #: Hash's digest size
    digest_size = None

    #: Hash's block size
    block_size = None

    def __init__(self, const, names):
        """
        initialize new instance.
        :arg const:
            hash constructor
        :arg names:
            list of 2+ names. should be list of ``(name, iana_name, ... 0+ aliases)``.
            names must be lower-case. only iana name may be None.
        """
        self.name = names[0]
        self.iana_name = names[1]
        self.aliases = names[2:]

        self.const = const
        if const is None:
            return

        hash = const()
        self.digest_size = hash.digest_size
        self.block_size = hash.block_size

        # do sanity check on digest size
        if len(hash.digest()) != hash.digest_size:
            raise RuntimeError("%r constructor failed sanity check" % self.name)

        # do sanity check on name.
        if hash.name != self.name:
            warn("inconsistent digest name: %r resolved to %r, which reports name as %r" %
                 (self.name, const, hash.name), exc.PasslibRuntimeWarning)

    #=========================================================================
    # methods
    #=========================================================================
    def __repr__(self):
        return "<lookup_hash(%r): digest_size=%r block_size=%r)" % \
               (self.name, self.digest_size, self.block_size)

    def _as_tuple(self):
        return self.const, self.digest_size, self.block_size

    #=========================================================================
    # eoc
    #=========================================================================

#=============================================================================
# hmac utils
#=============================================================================

#: translation tables used by compile_hmac()
_TRANS_5C = join_byte_values((x ^ 0x5C) for x in irange(256))
_TRANS_36 = join_byte_values((x ^ 0x36) for x in irange(256))

def compile_hmac(digest, key, multipart=False):
    """
    This function returns an efficient HMAC function, hardcoded with a specific digest & key.
    It can be used via ``hmac = compile_hmac(digest, key)``.

    :arg digest:
        digest name or constructor.

    :arg key:
        secret key as :class:`!bytes` or :class:`!unicode` (unicode will be encoded using utf-8).

    :param multipart:
        request a multipart constructor instead (see return description).

    :returns:
        By default, the returned function has the signature ``hmac(msg) -> digest output``.

        However, if ``multipart=True``, the returned function has the signature
        ``hmac() -> update, finalize``, where ``update(msg)`` may be called multiple times,
        and ``finalize() -> digest_output`` may be repeatedly called at any point to
        calculate the HMAC digest so far.

        The returned object will also have a ``digest_info`` attribute, containing
        a :class:`lookup_hash` instance for the specified digest.

    This function exists, and has the weird signature it does, in order to squeeze as
    provide as much efficiency as possible, by omitting much of the setup cost
    and features of the stdlib :mod:`hmac` module.
    """
    # all the following was adapted from stdlib's hmac module

    # resolve digest (cached)
    digest_info = lookup_hash(digest)
    const, digest_size, block_size = digest_info
    assert block_size >= 16, "block size too small"

    # prepare key
    if not isinstance(key, bytes):
        key = to_bytes(key, param="key")
    klen = len(key)
    if klen > block_size:
        key = const(key).digest()
        klen = digest_size
    if klen < block_size:
        key += b'\x00' * (block_size - klen)

    # create pre-initialized hash constructors
    _inner_copy = const(key.translate(_TRANS_36)).copy
    _outer_copy = const(key.translate(_TRANS_5C)).copy

    if multipart:
        # create multi-part function
        # NOTE: this is slightly slower than the single-shot version,
        #       and should only be used if needed.
        def hmac():
            """generated by compile_hmac(multipart=True)"""
            inner = _inner_copy()
            def finalize():
                outer = _outer_copy()
                outer.update(inner.digest())
                return outer.digest()
            return inner.update, finalize
    else:

        # single-shot function
        def hmac(msg):
            """generated by compile_hmac()"""
            inner = _inner_copy()
            inner.update(msg)
            outer = _outer_copy()
            outer.update(inner.digest())
            return outer.digest()

    # add info attr
    hmac.digest_info = digest_info
    return hmac

#=============================================================================
# pbkdf1 
#=============================================================================
def pbkdf1(digest, secret, salt, rounds, keylen=None):
    """pkcs#5 password-based key derivation v1.5

    :arg digest:
        digest name or constructor.
        
    :arg secret:
        secret to use when generating the key.
        may be :class:`!bytes` or :class:`unicode` (encoded using UTF-8).
        
    :arg salt:
        salt string to use when generating key.
        may be :class:`!bytes` or :class:`unicode` (encoded using UTF-8).

    :param rounds:
        number of rounds to use to generate key.

    :arg keylen:
        number of bytes to generate (if omitted / ``None``, uses digest's native size)

    :returns:
        raw :class:`bytes` of generated key

    .. note::

        This algorithm has been deprecated, new code should use PBKDF2.
        Among other limitations, ``keylen`` cannot be larger
        than the digest size of the specified hash.
    """
    # resolve digest
    const, digest_size, block_size = lookup_hash(digest)
    
    # validate secret & salt
    secret = to_bytes(secret, param="secret")
    salt = to_bytes(salt, param="salt")

    # validate rounds
    if not isinstance(rounds, int_types):
        raise exc.ExpectedTypeError(rounds, "int", "rounds")
    if rounds < 1:
        raise ValueError("rounds must be at least 1")

    # validate keylen
    if keylen is None:
        keylen = digest_size
    elif not isinstance(keylen, int_types):
        raise exc.ExpectedTypeError(keylen, "int or None", "keylen")
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

_pack_uint4 = Struct(">L").pack

def pbkdf2_hmac(digest, secret, salt, rounds, keylen=None):
    """pkcs#5 password-based key derivation v2.0 using HMAC + arbitrary digest.

    :arg digest:
        digest name or constructor.

    :arg secret:
        passphrase to use to generate key.
        may be :class:`!bytes` or :class:`unicode` (encoded using UTF-8).

    :arg salt:
        salt string to use when generating key.
        may be :class:`!bytes` or :class:`unicode` (encoded using UTF-8).

    :param rounds:
        number of rounds to use to generate key.

    :arg keylen:
        number of bytes to generate.
        if omitted / ``None``, will use digest's native output size.

    :returns:
        raw bytes of generated key
    """
    # validate secret & salt
    secret = to_bytes(secret, param="secret")
    salt = to_bytes(salt, param="salt")

    # TODO: check for hashlib.pbkdf2_hmac() helper, new in 2.7.8 / 3.4.
    #       it may be SSL or pure-python. should time pure-python and see if we should use it.
    #       SSL version will *definitely* be faster.

    # validate rounds
    if not isinstance(rounds, int_types):
        raise exc.ExpectedTypeError(rounds, "int", "rounds")
    if rounds < 1:
        raise ValueError("rounds must be at least 1")

    # generated keyed hmac
    keyed_hmac = compile_hmac(digest, secret)
    digest_size = keyed_hmac.digest_info.digest_size

    # validate keylen
    if keylen is None:
        keylen = digest_size
    elif not isinstance(keylen, int_types):
        raise exc.ExpectedTypeError(keylen, "int or None", "keylen")
    elif keylen < 0:
        raise ValueError("keylen must be at least 0")

    # m2crypto's pbkdf2-hmac-sha1 is faster than ours, so use it if available.
    # NOTE: as of 2012-4-4, m2crypto has buffer overflow issue which frequently
    #       causes segfaults if keylen > 32 (EVP_MAX_KEY_LENGTH).
    #       therefore we're avoiding m2crypto for large keys until that's fixed.
    #       (https://bugzilla.osafoundation.org/show_bug.cgi?id=13052)
    if digest == "sha1" and _m2crypto_pbkdf2_hmac_sha1 and keylen < 32:
        return _m2crypto_pbkdf2_hmac_sha1(secret, salt, rounds, keylen)

    # find smallest block count s.t. keylen <= block_count * digest_size
    block_count = (keylen + digest_size - 1) // digest_size
    if block_count >= MAX_UINT4:
        raise ValueError("keylen too long for digest")

    # get helper to calculate blocks, and return result
    calc_block = _get_pbkdf2_looper(digest_size)
    return join_bytes(
        calc_block(keyed_hmac, keyed_hmac(salt + _pack_uint4(i)), rounds)
        for i in irange(1, block_count + 1)
    )[:keylen]

#-------------------------------------------------------------------------------------
# pick best choice for pure-python helper
# TODO: consider some alternatives, such as C-accelerated xor_bytes helper if available
#-------------------------------------------------------------------------------------
# NOTE: this env var is only present to support the admin/benchmark_pbkdf2 script
_force_backend = os.environ.get("PASSLIB_PBKDF2_BACKEND") or "any"

if PY3 and _force_backend in ["any", "from_bytes"]:
    from functools import partial

    def _get_pbkdf2_looper(digest_size):
        return partial(_pbkdf2_looper, digest_size)

    def _pbkdf2_looper(digest_size, keyed_hmac, digest, rounds):
        """
        py3-only implementation of pbkdf2 inner loop;
        uses 'int.from_bytes' + integer XOR
        """
        from_bytes = int.from_bytes
        BIG = "big"  # endianess doesn't matter, just has to be consistent
        accum = from_bytes(digest, BIG)
        for _ in irange(rounds - 1):
            digest = keyed_hmac(digest)
            accum ^= from_bytes(digest, BIG)
        return accum.to_bytes(digest_size, BIG)

    _builtin_backend = "from_bytes"

elif _force_backend in ["any", "unpack", "from_bytes"]:
    from struct import Struct
    from passlib.utils import sys_bits

    _have_64_bit = (sys_bits >= 64)

    #: cache used by _get_pbkdf2_looper
    _looper_cache = {}

    def _get_pbkdf2_looper(digest_size):
        """
        We want a helper function which performs equivalent of the following::

          def helper(keyed_hmac, digest, rounds):
              accum = digest
              for _ in irange(rounds - 1):
                  digest = keyed_hmac(digest)
                  accum ^= digest
              return accum

        However, no efficient way to implement "bytes ^ bytes" in python.
        Instead, using approach where we dynamically compile a helper function based
        on digest size.  Instead of a single `accum` var, this helper breaks the digest
        into a series of integers.

        It stores these in a series of`accum_<i>` vars, and performs `accum ^= digest`
        by unpacking digest and perform xor for each "accum_<i> ^= digest_<i>".
        this keeps everything in locals, avoiding excessive list creation, encoding or decoding,
        etc.

        :param digest_size:
            digest size to compile for, in bytes. (must be multiple of 4).

        :return:
            helper function with call signature outlined above.
        """
        #
        # cache helpers
        #
        try:
            return _looper_cache[digest_size]
        except KeyError:
            pass

        #
        # figure out most efficient struct format to unpack digest into list of native ints
        #
        if _have_64_bit and not digest_size & 0x7:
            # digest size multiple of 8, on a 64 bit system -- use array of UINT8
            count = (digest_size >> 3)
            fmt = "=%dQ" % count
        elif not digest_size & 0x3:
            if _have_64_bit:
                # digest size multiple of 4, on a 64 bit system -- use array of UINT8 + 1 UINT4
                count = (digest_size >> 3)
                fmt = "=%dQI" % count
                count += 1
            else:
                # digest size multiple of 4, on a 32 bit system -- use array of UINT4
                count = (digest_size >> 2)
                fmt = "=%dI" % count
        else:
            # stopping here, cause no known hashes have digest size that isn't multiple of 4 bytes.
            # if needed, could go crazy w/ "H" & "B"
            raise NotImplementedError("unsupported digest size: %d" % digest_size)
        struct = Struct(fmt)

        #
        # build helper source
        #
        tdict = dict(
            digest_size=digest_size,
            accum_vars=", ".join("acc_%d" % i for i in irange(count)),
            digest_vars=", ".join("dig_%d" % i for i in irange(count)),
        )

        # head of function
        source = (
                        "def helper(keyed_hmac, digest, rounds):\n"
                        "    '''pbkdf2 loop helper for digest_size={digest_size}'''\n"
                        "    unpack_digest = struct.unpack\n"
                        "    {accum_vars} = unpack_digest(digest)\n"
                        "    for _ in irange(1, rounds):\n"
                        "        digest = keyed_hmac(digest)\n"
                        "        {digest_vars} = unpack_digest(digest)\n"
        ).format(**tdict)

        # xor digest
        for i in irange(count):
            source +=   "        acc_%d ^= dig_%d\n" % (i, i)

        # return result
        source +=       "    return struct.pack({accum_vars})\n".format(**tdict)

        #
        # compile helper
        #
        code = compile(source, "<generated by passlib.crypto.digest._get_pbkdf2_looper()>", "exec")
        gdict = dict(irange=irange, struct=struct)
        ldict = dict()
        eval(code, gdict, ldict)
        helper = ldict['helper']
        helper.__source__ = source

        #
        # store in cache
        #
        _looper_cache[digest_size] = helper
        return helper

    _builtin_backend = "unpack"

else:
    assert _force_backend in ["any", "hexlify"]

    # XXX: older & slower approach that used int(hexlify()),
    #      keeping it around for a little while just for benchmarking.

    from binascii import hexlify as _hexlify
    from passlib.utils import int_to_bytes

    def _get_pbkdf2_looper(digest_size):
        return _pbkdf2_looper

    def _pbkdf2_looper(keyed_hmac, digest, rounds):
        hexlify = _hexlify
        accum = int(hexlify(digest), 16)
        for _ in irange(rounds - 1):
            digest = keyed_hmac(digest)
            accum ^= int(hexlify(digest), 16)
        return int_to_bytes(accum, len(digest))

    _builtin_backend = "hexlify"

# helper for benchmark script -- disable m2crypto support if builtin requested
if _force_backend == _builtin_backend:
    _m2crypto_pbkdf2_hmac_sha1 = None

# expose info about what backends are active
PBKDF2_BACKENDS = ",".join(b for b in [
    "m2crypto-sha1" if _m2crypto_pbkdf2_hmac_sha1 else None,
    "builtin/" + _builtin_backend
] if b is not None)

#=============================================================================
# eof
#=============================================================================
