"""passlib.crypto.digest -- crytographic helpers used by the password hashes in passlib

.. versionadded:: 1.7
"""

from __future__ import annotations

import contextlib
import hashlib
import os
import re
from warnings import warn

from passlib import exc
from passlib._logging import logger
from passlib.utils import SequenceMixin, as_bool, to_bytes, to_native_str
from passlib.utils.compat import unicode_or_bytes
from passlib.utils.decor import memoized_property

# local
__all__ = [
    # hash utils
    "lookup_hash",
    "clear_lookup_hash_cache",
    "HashInfo",
    "norm_hash_name",
    # hmac utils
    "compile_hmac",
    # kdfs
    "pbkdf1",
    "pbkdf2_hmac",
]

#: max 32-bit value
MAX_UINT32 = (1 << 32) - 1

#: max 64-bit value
MAX_UINT64 = (1 << 64) - 1

#: list of known hash names, used by lookup_hash()'s _norm_hash_name() helper
_known_hash_names = [
    # format: (hashlib/ssl name, iana name or standin, other known aliases ...)
    # ----------------------------------------------------
    # hashes with official IANA-assigned names
    # (as of 2012-03 - http://www.iana.org/assignments/hash-function-text-names)
    # ----------------------------------------------------
    ("md2", "md2"),  # NOTE: openssl dropped md2 support in v1.0.0
    ("md5", "md5"),
    ("sha1", "sha-1"),
    ("sha224", "sha-224", "sha2-224"),
    ("sha256", "sha-256", "sha2-256"),
    ("sha384", "sha-384", "sha2-384"),
    ("sha512", "sha-512", "sha2-512"),
    # TODO: add sha3 to this table.
    # ----------------------------------------------------
    # hashlib/ssl-supported hashes without official IANA names,
    # (hopefully-) compatible stand-ins have been chosen.
    # ----------------------------------------------------
    ("blake2b", "blake-2b"),
    ("blake2s", "blake-2s"),
    ("md4", "md4"),
    # NOTE: there was an older "ripemd" and "ripemd-128",
    #       but python 2.7+ resolves "ripemd" -> "ripemd160",
    #       so treating "ripemd" as alias here.
    ("ripemd160", "ripemd-160", "ripemd"),
]

#: dict mapping hashlib names to hardcoded digest info;
#: so this is available even when hashes aren't present.
_fallback_info = {
    # name: (digest_size, block_size)
    "blake2b": (64, 128),
    "blake2s": (32, 64),
    "md4": (16, 64),
    "md5": (16, 64),
    "sha1": (20, 64),
    "sha224": (28, 64),
    "sha256": (32, 64),
    "sha384": (48, 128),
    "sha3_224": (28, 144),
    "sha3_256": (32, 136),
    "sha3_384": (48, 104),
    "sha3_512": (64, 72),
    "sha512": (64, 128),
    "shake128": (16, 168),
    "shake256": (32, 136),
}


def _gen_fallback_info():
    """
    internal helper used to generate ``_fallback_info`` dict.
    currently only run manually to update the above list;
    not invoked at runtime.
    """
    out = {}
    for alg in sorted(hashlib.algorithms_available | {"md4"}):
        info = lookup_hash(alg)
        out[info.name] = (info.digest_size, info.block_size)
    return out


#: cache of hash info instances used by lookup_hash()
_hash_info_cache: dict[str, str] = {}


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
        name = to_native_str(name, "utf-8", "hash name")
    name = re.sub("[_ /]", "-", name.strip().lower())
    if name.startswith(
        "scram-"
    ):  # helper for SCRAM protocol (see passlib.handlers.scram)
        name = name[6:]
        name = name.removesuffix("-plus")

    # look through standard names and known aliases
    def check_table(name):
        for row in _known_hash_names:
            if name in row:
                return row
        return None

    result = check_table(name)
    if result:
        return result

    # try to clean name up some more
    m = re.match(r"(?i)^(?P<name>[a-z]+)-?(?P<rev>\d)?-?(?P<size>\d{3,4})?$", name)
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
        logger.info(
            "normalizing unrecognized hash name %r => %r / %r",
            orig,
            hashlib_name,
            iana_name,
        )

    else:
        # just can't make sense of it. return something
        iana_name = name
        hashlib_name = name.replace("-", "_")
        logger.warning(
            "normalizing unrecognized hash name and format %r => %r / %r",
            orig,
            hashlib_name,
            iana_name,
        )

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
        const.__doc__ = (
            f"wrapper for hashlib.new({name!r}),\n"
            "generated by passlib.crypto.digest.lookup_hash()"
        )
        return const

    # use builtin md4 as fallback when not supported by hashlib
    if name == "md4":
        from passlib.crypto._md4 import md4

        return md4

    # XXX: any other modules / registries we should check?
    # TODO: add pysha3 support.

    return None


def lookup_hash(
    digest,  # *,
    return_unknown=False,
    required=True,
):
    """
    Returns a :class:`HashInfo` record containing information about a given hash function.
    Can be used to look up a hash constructor by name, normalize hash name representation, etc.

    :arg digest:
        This can be any of:

        * A string containing a :mod:`!hashlib` digest name (e.g. ``"sha256"``),
        * A string containing an IANA-assigned hash name,
        * A digest constructor function (e.g. ``hashlib.sha256``).

        Case is ignored, underscores are converted to hyphens,
        and various other cleanups are made.

    :param required:
        By default (True), this function will throw an :exc:`~passlib.exc.UnknownHashError` if no hash constructor
        can be found, or if the hash is not actually available.

        If this flag is False, it will instead return a dummy :class:`!HashInfo` record
        which will defer throwing the error until it's constructor function is called.
        This is mainly used by :func:`norm_hash_name`.

    :param return_unknown:

        .. deprecated:: 1.7.3

            deprecated, and will be removed in passlib 2.0.
            this acts like inverse of **required**.

    :returns HashInfo:
        :class:`HashInfo` instance containing information about specified digest.

        Multiple calls resolving to the same hash should always
        return the same :class:`!HashInfo` instance.
    """
    # check for cached entry
    cache = _hash_info_cache
    try:
        return cache[digest]
    except (KeyError, TypeError):
        # NOTE: TypeError is to catch 'TypeError: unhashable type' (e.g. HashInfo)
        pass

    # legacy alias
    if return_unknown:
        required = False

    # resolve ``digest`` to ``const`` & ``name_record``
    cache_by_name = True
    if isinstance(digest, unicode_or_bytes):
        # normalize name
        name_list = _get_hash_aliases(digest)
        name = name_list[0]
        assert name

        # if name wasn't normalized to hashlib format,
        # get info for normalized name and reuse it.
        if name != digest:
            info = lookup_hash(name, required=required)
            cache[digest] = info
            return info

        # else look up constructor
        # NOTE: may return None, which is handled by HashInfo constructor
        const = _get_hash_const(name)

        # if mock fips mode is enabled, replace with dummy constructor
        # (to replicate how it would behave on a real fips system).
        if const and mock_fips_mode and name not in _fips_algorithms:

            def const(source=b""):
                raise ValueError(
                    f"{name!r} disabled for fips by passlib set_mock_fips_mode()"
                )

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
    info = HashInfo(const=const, names=name_list, required=required)

    # populate cache
    if const is not None:
        cache[const] = info
    if cache_by_name:
        for name in name_list:
            if name:  # (skips iana name if it's empty)
                assert cache.get(name) in [None, info], f"{name!r} already in cache"
                cache[name] = info
    return info


def clear_lookup_hash_cache() -> None:
    _hash_info_cache.clear()


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
          For hashes which IANA hasn't assigned a name for, this issues a warning,
          and then uses a heuristic to return a "best guess" name.

    :returns:
        Hash name, returned as native :class:`!str`.
    """
    info = lookup_hash(name, required=False)
    if info.unknown:
        warn("norm_hash_name(): " + info.error_text, exc.PasslibRuntimeWarning)
    if format == "hashlib":
        return info.name
    if format == "iana":
        return info.iana_name
    raise ValueError(f"unknown format: {format!r}")


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
    .. autoattribute:: supported

    This object can also be treated a 3-element sequence
    containing ``(const, digest_size, block_size)``.
    """

    #: Canonical / hashlib-compatible name (e.g. ``"sha256"``).
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

    #: set when hash isn't available, will be filled in with string containing error text
    #: that const() will raise.
    error_text = None

    #: set when error_text is due to hash algorithm being completely unknown
    #: (not just unavailable on current system)
    unknown = False

    def __init__(
        self,  # *,
        const,
        names,
        required=True,
    ):
        """
        initialize new instance.
        :arg const:
            hash constructor
        :arg names:
            list of 2+ names. should be list of ``(name, iana_name, ... 0+ aliases)``.
            names must be lower-case. only iana name may be None.
        """
        # init names
        name = self.name = names[0]
        self.iana_name = names[1]
        self.aliases = names[2:]

        def use_stub_const(msg: str) -> None:
            """
            helper that installs stub constructor which throws specified error <msg>.
            """

            def const(source=b""):
                raise exc.UnknownHashError(msg, name)

            if required:
                # if caller only wants supported digests returned,
                # just throw error immediately...
                const()

            self.error_text = msg
            self.const = const
            with contextlib.suppress(KeyError):
                self.digest_size, self.block_size = _fallback_info[name]

        # handle "constructor not available" case
        if const is None:
            if names in _known_hash_names:
                msg = f"unsupported hash: {name!r}"
            else:
                msg = f"unknown hash: {name!r}"
                self.unknown = True
            use_stub_const(msg)
            # TODO: load in preset digest size info for known hashes.
            return

        # create hash instance to inspect
        try:
            hash = const()
        except ValueError as err:
            # per issue 116, FIPS compliant systems will have a constructor;
            # but it will throw a ValueError with this message.  As of 1.7.3,
            # translating this into DisabledHashError.
            # "ValueError: error:060800A3:digital envelope routines:EVP_DigestInit_ex:disabled for fips"
            if "disabled for fips" in str(err).lower():
                msg = f"{name!r} hash disabled for fips"
            else:
                msg = f"internal error in {name!r} constructor\n({type(err).__name__}: {err})"
            use_stub_const(msg)
            return

        # store stats about hash
        self.const = const
        self.digest_size = hash.digest_size
        self.block_size = hash.block_size

        # do sanity check on digest size
        if len(hash.digest()) != hash.digest_size:
            raise RuntimeError(f"{self.name!r} constructor failed sanity check")

        # do sanity check on name.
        if hash.name != self.name:
            warn(
                f"inconsistent digest name: {self.name!r} resolved to {const!r}, which reports name as {hash.name!r}",
                exc.PasslibRuntimeWarning,
            )

    def __repr__(self):
        return f"<lookup_hash({self.name!r}): digest_size={self.digest_size!r} block_size={self.block_size!r})"

    def _as_tuple(self):
        return self.const, self.digest_size, self.block_size

    @memoized_property
    def supported(self):
        """
        whether hash is available for use
        (if False, constructor will throw UnknownHashError if called)
        """
        return self.error_text is None


#: flag for detecting if mock fips mode is enabled.
mock_fips_mode = False

#: algorithms allowed under FIPS mode (subset of hashlib.algorithms_available);
#: per https://csrc.nist.gov/Projects/Hash-Functions FIPS 202 list.
_fips_algorithms = {
    # FIPS 180-4  and FIPS 202
    "sha1",
    "sha224",
    "sha256",
    "sha384",
    "sha512",
    # 'sha512/224',
    # 'sha512/256',
    # FIPS 202 only
    "sha3_224",
    "sha3_256",
    "sha3_384",
    "sha3_512",
    "shake_128",
    "shake_256",
}


def _set_mock_fips_mode(enable: bool = True) -> None:
    """
    UT helper which monkeypatches lookup_hash() internals to replicate FIPS mode.
    """
    global mock_fips_mode  # noqa: PLW0603
    mock_fips_mode = enable
    clear_lookup_hash_cache()  # type: ignore[attr-defined]


# helper for UTs
if as_bool(os.environ.get("PASSLIB_MOCK_FIPS_MODE")):
    _set_mock_fips_mode()

#: translation tables used by compile_hmac()
_TRANS_5C = bytes((x ^ 0x5C) for x in range(256))
_TRANS_36 = bytes((x ^ 0x36) for x in range(256))


def compile_hmac(digest: str, key: str | bytes, multipart: bool = False):
    """
    This function returns an efficient HMAC function, hardcoded with a specific digest & key.
    It can be used via ``hmac = compile_hmac(digest, key)``.

    :arg digest:
        digest name or constructor.

    :arg key:
        secret key as :class:`!bytes` or :class:`!str` (str will be encoded using utf-8).

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
        key += b"\x00" * (block_size - klen)

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
        def hmac(msg):  # type: ignore[misc]
            """generated by compile_hmac()"""
            inner = _inner_copy()
            inner.update(msg)
            outer = _outer_copy()
            outer.update(inner.digest())
            return outer.digest()

    # add info attr
    hmac.digest_info = digest_info  # type: ignore[attr-defined]
    return hmac


def pbkdf1(digest, secret, salt, rounds, keylen=None):
    """pkcs#5 password-based key derivation v1.5

    :arg digest:
        digest name or constructor.

    :arg secret:
        secret to use when generating the key.
        may be :class:`!bytes` or :class:`str` (encoded using UTF-8).

    :arg salt:
        salt string to use when generating key.
        may be :class:`!bytes` or :class:`str` (encoded using UTF-8).

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
    if not isinstance(rounds, int):
        raise exc.ExpectedTypeError(rounds, "int", "rounds")
    if rounds < 1:
        raise ValueError("rounds must be at least 1")

    # validate keylen
    if keylen is None:
        keylen = digest_size
    elif not isinstance(keylen, int):
        raise exc.ExpectedTypeError(keylen, "int or None", "keylen")
    elif keylen < 0:
        raise ValueError("keylen must be at least 0")
    elif keylen > digest_size:
        raise ValueError(
            f"keylength too large for digest: {keylen!r} > {digest_size!r}"
        )

    # main pbkdf1 loop
    block = secret + salt
    for _ in range(rounds):
        block = const(block).digest()
    return block[:keylen]


def pbkdf2_hmac(digest: bytes, secret: bytes, salt: bytes, rounds: int, keylen=None):
    """pkcs#5 password-based key derivation v2.0 using HMAC + arbitrary digest.

    :arg digest:
        digest name or constructor.

    :arg secret:
        passphrase to use to generate key.
        may be :class:`!bytes` or :class:`str` (encoded using UTF-8).

    :arg salt:
        salt string to use when generating key.
        may be :class:`!bytes` or :class:`str` (encoded using UTF-8).

    :param rounds:
        number of rounds to use to generate key.

    :arg keylen:
        number of bytes to generate.
        if omitted / ``None``, will use digest's native output size.

    :returns:
        raw bytes of generated key

    .. versionchanged:: 1.7

        This function will use the first available of the following backends:

        * :func:`hashlib.pbkdf2_hmac` (only available in py2 >= 2.7.8, and py3 >= 3.4)

        See :data:`passlib.crypto.digest.PBKDF2_BACKENDS` to determine
        which backend(s) are in use.
    """
    secret = to_bytes(secret, param="secret")
    salt = to_bytes(salt, param="salt")

    # resolve digest
    digest_info = lookup_hash(digest)

    return hashlib.pbkdf2_hmac(digest_info.name, secret, salt, rounds, keylen)


PBKDF2_BACKENDS = [
    "hashlib-ssl",
]
