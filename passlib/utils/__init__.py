"""passlib.utils -- helpers for writing password hashes"""

from __future__ import annotations

import codecs
import hmac
import inspect
import itertools
import math
import os
import random
import stringprep
import sys
import time
import timeit
import unicodedata
from collections.abc import Iterable, Sequence
from typing import AnyStr

from passlib.exc import ExpectedStringError, ExpectedTypeError
from passlib.utils.binary import (
    AB64_CHARS,
    # [remove these aliases in 2.0]
    BASE64_CHARS,
    BCRYPT_CHARS,
    HASH64_CHARS,
    Base64Engine,
    LazyBase64Engine,
    ab64_decode,
    ab64_encode,
    b64s_decode,
    b64s_encode,
    bcrypt64,
    h64,
    h64big,
)
from passlib.utils.compat import (
    add_doc,
    get_method_function,
    join_bytes,
    join_unicode,
    unicode_or_bytes,
)
from passlib.utils.decor import (
    classproperty,
    # [remove these aliases in 2.0]
    deprecated_function,
    deprecated_method,
    hybrid_method,
    memoized_property,
)

__all__ = [
    "AB64_CHARS",
    "BASE64_CHARS",
    "BCRYPT_CHARS",
    "Base64Engine",
    "HASH64_CHARS",
    "LazyBase64Engine",
    "ab64_decode",
    "ab64_encode",
    "b64s_decode",
    "b64s_encode",
    "bcrypt64",
    "classproperty",
    "consteq",
    "deprecated_method",
    "generate_password",
    "getrandbytes",
    "getrandstr",
    "h64",
    "h64big",
    "has_crypt",
    "has_rounds_info",
    "has_salt_info",
    "hybrid_method",
    "is_ascii_safe",
    "is_crypt_context",
    "is_crypt_handler",
    "is_same_codec",
    "join_bytes",
    "join_unicode",
    "memoized_property",
    "render_bytes",
    "rng",
    "rounds_cost_values",
    "safe_crypt",
    "saslprep",
    "sys_bits",
    "test_crypt",
    "tick",
    "to_bytes",
    "to_native_str",
    "to_unicode",
    "unix_crypt_schemes",
    "xor_bytes",
]

# bitsize of system architecture (32 or 64)
sys_bits = int(math.log2(sys.maxsize) + 1.5)

# list of hashes algs supported by crypt() on at least one OS.
# XXX: move to .registry for passlib 2.0?
unix_crypt_schemes = [
    "sha512_crypt",
    "sha256_crypt",
    "sha1_crypt",
    "bcrypt",
    "md5_crypt",
    # "bsd_nthash",
    "bsdi_crypt",
    "des_crypt",
]

rounds_cost_values = ["linear", "log2"]

_BEMPTY = b""
_UEMPTY = ""
_USPACE = " "

# maximum password size which passlib will allow; see exc.PasswordSizeError
MAX_PASSWORD_SIZE = int(os.environ.get("PASSLIB_MAX_PASSWORD_SIZE") or 4096)


class SequenceMixin:
    """
    helper which lets result object act like a fixed-length sequence.
    subclass just needs to provide :meth:`_as_tuple()`.
    """

    def _as_tuple(self):
        raise NotImplementedError("implement in subclass")

    def __repr__(self):
        return repr(self._as_tuple())

    def __getitem__(self, idx):
        return self._as_tuple()[idx]

    def __iter__(self):
        return iter(self._as_tuple())

    def __len__(self):
        return len(self._as_tuple())

    def __eq__(self, other):
        return self._as_tuple() == other

    def __ne__(self, other):
        return not self.__eq__(other)


# getargspec() is deprecated, use this under py3.
# even though it's a lot more awkward to get basic info :|

_VAR_KEYWORD = inspect.Parameter.VAR_KEYWORD
_VAR_ANY_SET = {_VAR_KEYWORD, inspect.Parameter.VAR_POSITIONAL}


def accepts_keyword(func, key):
    """test if function accepts specified keyword"""
    params = inspect.signature(get_method_function(func)).parameters
    if not params:
        return False
    arg = params.get(key)
    if arg and arg.kind not in _VAR_ANY_SET:
        return True
    # XXX: annoying what we have to do to determine if VAR_KWDS in use.
    return params[list(params)[-1]].kind == _VAR_KEYWORD


def update_mixin_classes(
    target, add=None, remove=None, append=False, before=None, after=None, dryrun=False
):
    """
    helper to update mixin classes installed in target class.

    :param target:
        target class whose bases will be modified.

    :param add:
        class / classes to install into target's base class list.

    :param remove:
        class / classes to remove from target's base class list.

    :param append:
        by default, prepends mixins to front of list.
        if True, appends to end of list instead.

    :param after:
        optionally make sure all mixins are inserted after
        this class / classes.

    :param before:
        optionally make sure all mixins are inserted before
        this class / classes.

    :param dryrun:
        optionally perform all calculations / raise errors,
        but don't actually modify the class.
    """
    if isinstance(add, type):
        add = [add]

    bases = list(target.__bases__)

    # strip out requested mixins
    if remove:
        if isinstance(remove, type):
            remove = [remove]
        for mixin in remove:
            if add and mixin in add:
                continue
            if mixin in bases:
                bases.remove(mixin)

    # add requested mixins
    if add:
        for mixin in add:
            # if mixin already present (explicitly or not), leave alone
            if any(issubclass(base, mixin) for base in bases):
                continue

            # determine insertion point
            if append:
                for idx, base in enumerate(bases):
                    if issubclass(mixin, base):
                        # don't insert mixin after one of it's own bases
                        break
                    if before and issubclass(base, before):
                        # don't insert mixin after any <before> classes.
                        break
                else:
                    # append to end
                    idx = len(bases)
            elif after:
                for end_idx, base in enumerate(reversed(bases)):
                    if issubclass(base, after):
                        # don't insert mixin before any <after> classes.
                        idx = len(bases) - end_idx
                        assert bases[idx - 1] == base
                        break
                else:
                    idx = 0
            else:
                # insert at start
                idx = 0

            # insert mixin
            bases.insert(idx, mixin)

    # modify class
    if not dryrun:
        target.__bases__ = tuple(bases)


def batch(source, size):
    """
    split iterable into chunks of <size> elements.
    """
    if size < 1:
        raise ValueError("size must be positive integer")
    if isinstance(source, Sequence):
        end = len(source)
        i = 0
        while i < end:
            n = i + size
            yield source[i:n]
            i = n
    elif isinstance(source, Iterable):
        itr = iter(source)
        while True:
            chunk_itr = itertools.islice(itr, size)
            try:
                first = next(chunk_itr)
            except StopIteration:
                break
            yield itertools.chain((first,), chunk_itr)
    else:
        raise TypeError("source must be iterable")


def consteq(left, right):
    if type(left) is not type(right):
        raise TypeError

    left = left.encode() if isinstance(left, str) else left
    right = right.encode() if isinstance(right, str) else right
    return hmac.compare_digest(left, right)


def splitcomma(source, sep=","):
    """split comma-separated string into list of elements,
    stripping whitespace.
    """
    source = source.strip()
    if source.endswith(sep):
        source = source[:-1]
    if not source:
        return []
    return [elem.strip() for elem in source.split(sep)]


def saslprep(source, param="value"):
    """Normalizes unicode strings using SASLPrep stringprep profile.

    The SASLPrep profile is defined in :rfc:`4013`.
    It provides a uniform scheme for normalizing unicode usernames
    and passwords before performing byte-value sensitive operations
    such as hashing. Among other things, it normalizes diacritic
    representations, removes non-printing characters, and forbids
    invalid characters such as ``\\n``. Properly internationalized
    applications should run user passwords through this function
    before hashing.

    :arg source:
        unicode string to normalize & validate

    :param param:
        Optional noun identifying source parameter in error messages
        (Defaults to the string ``"value"``). This is mainly useful to make the caller's error
        messages make more sense contextually.

    :raises ValueError:
        if any characters forbidden by the SASLPrep profile are encountered.

    :raises TypeError:
        if input is not :class:`!unicode`

    :returns:
        normalized unicode string

    .. note::

        This function is not available under Jython,
        as the Jython stdlib is missing the :mod:`!stringprep` module
        (`Jython issue 1758320 <http://bugs.jython.org/issue1758320>`_).

    .. versionadded:: 1.6
    """
    # saslprep - http://tools.ietf.org/html/rfc4013
    # stringprep - http://tools.ietf.org/html/rfc3454
    #              http://docs.python.org/library/stringprep.html

    # validate type
    # XXX: support bytes (e.g. run through want_unicode)?
    #      might be easier to just integrate this into cryptcontext.
    if not isinstance(source, str):
        raise TypeError(f"input must be string, not {type(source)}")

    # mapping stage
    #   - map non-ascii spaces to U+0020 (stringprep C.1.2)
    #   - strip 'commonly mapped to nothing' chars (stringprep B.1)
    data = "".join(
        _USPACE if stringprep.in_table_c12(c) else c
        for c in source
        if not stringprep.in_table_b1(c)
    )

    # normalize to KC form
    data = unicodedata.normalize("NFKC", data)
    if not data:
        return _UEMPTY

    # check for invalid bi-directional strings.
    # stringprep requires the following:
    #   - chars in C.8 must be prohibited.
    #   - if any R/AL chars in string:
    #       - no L chars allowed in string
    #       - first and last must be R/AL chars
    # this checks if start/end are R/AL chars. if so, prohibited loop
    # will forbid all L chars. if not, prohibited loop will forbid all
    # R/AL chars instead. in both cases, prohibited loop takes care of C.8.
    is_ral_char = stringprep.in_table_d1
    if is_ral_char(data[0]):
        if not is_ral_char(data[-1]):
            raise ValueError("malformed bidi sequence in " + param)
        # forbid L chars within R/AL sequence.
        is_forbidden_bidi_char = stringprep.in_table_d2
    else:
        # forbid R/AL chars if start not setup correctly; L chars allowed.
        is_forbidden_bidi_char = is_ral_char

    # check for prohibited output - stringprep tables A.1, B.1, C.1.2, C.2 - C.9
    forbidden_ = [
        (stringprep.in_table_a1, "unassigned code points forbidden in "),
        (stringprep.in_table_c21_c22, "control characters forbidden in "),
        (stringprep.in_table_c3, "private use characters forbidden in "),
        (stringprep.in_table_c4, "non-char code points forbidden in "),
        (stringprep.in_table_c4, "non-char code points forbidden in "),
        (stringprep.in_table_c4, "non-char code points forbidden in "),
        (stringprep.in_table_c5, "surrogate codes forbidden in "),
        (stringprep.in_table_c6, "non-plaintext chars forbidden in "),
        (stringprep.in_table_c7, "non-canonical chars forbidden in "),
        (
            stringprep.in_table_c8,
            "display-modifying / deprecated chars forbidden in",
        ),
        (stringprep.in_table_c9, "tagged characters forbidden in "),
        # do bidi constraint check chosen by bidi init, above
        (is_forbidden_bidi_char, "forbidden bidi character in "),
    ]
    for c in data:
        # check for chars mapping stage should have removed
        assert not stringprep.in_table_b1(c), "failed to strip B.1 in mapping stage"
        assert not stringprep.in_table_c12(c), (
            "failed to replace C.1.2 in mapping stage"
        )

        for func, err_msg in forbidden_:
            if func(c):
                raise ValueError(f"{err_msg} {param}")

    return data


def render_bytes(source, *args):
    """Peform ``%`` formating using bytes in a uniform manner across Python 2/3.

    This function is motivated by the fact that
    :class:`bytes` instances do not support ``%`` or ``{}`` formatting under Python 3.
    This function is an attempt to provide a replacement:
    it converts everything to unicode (decoding bytes instances as ``latin-1``),
    performs the required formatting, then encodes the result to ``latin-1``.

    Calling ``render_bytes(source, *args)`` should function roughly the same as
    ``source % args`` under Python 2.

    .. todo::
        python >= 3.5 added back limited support for bytes %,
        can revisit when 3.3/3.4 is dropped.
    """
    if isinstance(source, bytes):
        source = source.decode("latin-1")
    result = source % tuple(
        arg.decode("latin-1") if isinstance(arg, bytes) else arg for arg in args
    )
    return result.encode("latin-1")


def bytes_to_int(value):
    return int.from_bytes(value, "big")


def int_to_bytes(value, count):
    return value.to_bytes(count, "big")


add_doc(bytes_to_int, "decode byte string as single big-endian integer")
add_doc(int_to_bytes, "encode integer as single big-endian byte string")


def xor_bytes(left: bytes, right: bytes) -> bytes:
    """Perform bitwise-xor of two byte strings (must be same size)"""
    return int_to_bytes(bytes_to_int(left) ^ bytes_to_int(right), len(left))


def repeat_string(source: AnyStr, size: int) -> AnyStr:
    """
    repeat or truncate <source> string, so it has length <size>
    """
    mult = 1 + (size - 1) // len(source)
    return (source * mult)[:size]


def utf8_repeat_string(source: bytes, size: int) -> bytes:
    """
    variant of repeat_string() which truncates to nearest UTF8 boundary.
    """
    mult = 1 + (size - 1) // len(source)
    return utf8_truncate(source * mult, size)


_BNULL = b"\x00"
_UNULL = "\x00"


def right_pad_string(source: AnyStr, size: int, pad: AnyStr | None = None) -> AnyStr:
    """right-pad or truncate <source> string, so it has length <size>"""
    if pad is None:
        pad = _UNULL if isinstance(source, str) else _BNULL

    length = len(source)
    if size > length:
        return source + pad * (size - length)
    return source[:size]


def utf8_truncate(source: bytes, index: int) -> bytes:
    """
    helper to truncate UTF8 byte string to nearest character boundary ON OR AFTER <index>.
    returned prefix will always have length of at least <index>, and will stop on the
    first byte that's not a UTF8 continuation byte (128 - 191 inclusive).
    since utf8 should never take more than 4 bytes to encode known unicode values,
    we can stop after ``index+3`` is reached.
    """
    # general approach:
    #
    # * UTF8 bytes will have high two bits (0xC0) as one of:
    #   00 -- ascii char
    #   01 -- ascii char
    #   10 -- continuation of multibyte char
    #   11 -- start of multibyte char.
    #   thus we can cut on anything where high bits aren't "10" (0x80; continuation byte)
    #
    # * UTF8 characters SHOULD always be 1 to 4 bytes, though they may be unbounded.
    #   so we just keep going until first non-continuation byte is encountered, or end of str.
    #   this should work predictably even for malformed/non UTF8 inputs.

    if not isinstance(source, bytes):
        raise ExpectedTypeError(source, bytes, "source")

    # validate index
    end = len(source)
    if index < 0:
        index = max(0, index + end)
    if index >= end:
        return source

    # can stop search after 4 bytes, won't ever have longer utf8 sequence.
    end = min(index + 3, end)

    # loop until we find non-continuation byte
    while index < end:
        if source[index] & 0xC0 != 0x80:
            # found single-char byte, or start-char byte.
            break
        # else: found continuation byte.
        index += 1
    else:
        assert index == end

    # truncate at final index
    result = source[:index]

    def sanity_check():
        # try to decode source
        try:
            text = source.decode("utf-8")
        except UnicodeDecodeError:
            # if source isn't valid utf8, byte level match is enough
            return True

        # validate that result was cut on character boundary
        assert text.startswith(result.decode("utf-8"))
        return True

    assert sanity_check()

    return result


_ASCII_TEST_BYTES = b"\x00\n aA:#!\x7f"
_ASCII_TEST_UNICODE = _ASCII_TEST_BYTES.decode("ascii")


def is_ascii_codec(codec: str) -> bool:
    """Test if codec is compatible with 7-bit ascii (e.g. latin-1, utf-8; but not utf-16)"""
    return _ASCII_TEST_UNICODE.encode(codec) == _ASCII_TEST_BYTES


def is_same_codec(left: str, right: str) -> bool:
    """Check if two codec names are aliases for same codec"""
    if left == right:
        return True
    if not (left and right):
        return False
    return codecs.lookup(left).name == codecs.lookup(right).name


_B80 = b"\x80"[0]
_U80 = "\x80"


def is_ascii_safe(source: AnyStr) -> bool:
    """Check if string (bytes or unicode) contains only 7-bit ascii"""
    r = _B80 if isinstance(source, bytes) else _U80
    return all(c < r for c in source)


def to_bytes(
    source: str | bytes,
    encoding: str = "utf-8",
    param: str = "value",
    source_encoding: str | None = None,
) -> bytes:
    """Helper to normalize input to bytes.

    :arg source:
        Source bytes/unicode to process.

    :arg encoding:
        Target encoding (defaults to ``"utf-8"``).

    :param param:
        Optional name of variable/noun to reference when raising errors

    :param source_encoding:
        If this is specified, and the source is bytes,
        the source will be transcoded from *source_encoding* to *encoding*
        (via unicode).

    :raises TypeError: if source is not str or bytes.

    :returns:
        * unicode strings will be encoded using *encoding*, and returned.
        * if *source_encoding* is not specified, byte strings will be
          returned unchanged.
        * if *source_encoding* is specified, byte strings will be transcoded
          to *encoding*.
    """
    assert encoding
    if isinstance(source, bytes):
        if source_encoding and not is_same_codec(source_encoding, encoding):
            return source.decode(source_encoding).encode(encoding)
        return source
    if isinstance(source, str):
        return source.encode(encoding)
    raise ExpectedStringError(source, param)


def to_unicode(source: AnyStr, encoding="utf-8", param="value") -> str:
    """Helper to normalize input to unicode.

    :arg source:
        source bytes/unicode to process.

    :arg encoding:
        encoding to use when decoding bytes instances.

    :param param:
        optional name of variable/noun to reference when raising errors.

    :raises TypeError: if source is not str or bytes.

    :returns:
        * returns unicode strings unchanged.
        * returns bytes strings decoded using *encoding*
    """
    assert encoding
    if isinstance(source, str):
        return source
    if isinstance(source, bytes):
        return source.decode(encoding)

    raise ExpectedStringError(source, param)


def to_native_str(source: AnyStr, encoding="utf-8", param="value") -> str:
    """Take in str or bytes, returns str.
    leaves str alone, decodes bytes using specified encoding.

    :param source: source unicode or bytes string
    :param encoding: encoding to use when encoding unicode or decoding bytes
    :param param: optional name of variable/noun to reference when raising errors
    """
    if isinstance(source, bytes):
        return source.decode(encoding)
    if isinstance(source, str):
        return source
    raise ExpectedStringError(source, param)


@deprecated_function(deprecated="1.6", removed="1.7")
def to_hash_str(source, encoding="ascii"):  # pragma: no cover -- deprecated & unused
    """deprecated, use to_native_str() instead"""
    return to_native_str(source, encoding, param="hash")


_true_set = set(["true", "t", "yes", "y", "on", "1", "enable", "enabled"])
_false_set = set(["false", "f", "no", "n", "off", "0", "disable", "disabled"])
_none_set = set(["", "none"])


def as_bool(
    value: str | bytes | None, none: bool | None = None, param="boolean"
) -> bool | None:
    """
    helper to convert value to boolean.
    recognizes strings such as "true", "false"
    """
    assert none in [True, False, None]
    if isinstance(value, unicode_or_bytes):
        clean = value.lower().strip()
        if clean in _true_set:
            return True
        if clean in _false_set:
            return False
        if clean in _none_set:
            return none
        raise ValueError(f"unrecognized {param} value: {value!r}")
    if isinstance(value, bool):
        return value
    if value is None:
        return none
    return bool(value)


has_crypt = False


timer = timeit.default_timer
# legacy alias, will be removed in passlib 2.0
tick = timer

# NOTE:
# generating salts (e.g. h64_gensalt, below) doesn't require cryptographically
# strong randomness. it just requires enough range of possible outputs
# that making a rainbow table is too costly. so it should be ok to
# fall back on python's builtin mersenne twister prng, as long as it's seeded each time
# this module is imported, using a couple of minor entropy sources.

try:
    os.urandom(1)
    has_urandom = True
except NotImplementedError:  # pragma: no cover
    has_urandom = False


def genseed(value=None):
    """generate prng seed value from system resources"""
    from hashlib import sha512

    if hasattr(value, "getstate") and hasattr(value, "getrandbits"):
        # caller passed in RNG as seed value
        try:
            value = value.getstate()
        except NotImplementedError:
            # this method throws error for e.g. SystemRandom instances,
            # so fall back to extracting 4k of state
            value = value.getrandbits(1 << 15)
    text = "{} {} {} {:.15f} {:.15f} {}".format(
        # if caller specified a seed value, mix it in
        value,
        # add current process id
        # NOTE: not available in some environments, e.g. GAE
        os.getpid() if hasattr(os, "getpid") else None,
        # id of a freshly created object.
        # (at least 1 byte of which should be hard to predict)
        id(object()),
        # the current time, to whatever precision os uses
        time.time(),
        tick(),
        # if urandom available, might as well mix some bytes in.
        os.urandom(32).decode("latin-1") if has_urandom else 0,
    )
    # hash it all up and return it as int/long
    return int(sha512(text.encode("utf-8")).hexdigest(), 16)


if has_urandom:  # noqa: SIM108
    rng: random.Random = random.SystemRandom()
else:  # pragma: no cover -- runtime detection
    # NOTE: to reseed use ``rng.seed(genseed(rng))``
    # XXX: could reseed on every call
    rng = random.Random(genseed())


# ------------------------------------------------------------------------
# some rng helpers
# ------------------------------------------------------------------------
def getrandbytes(rng, count):
    """return byte-string containing *count* number of randomly generated bytes, using specified rng"""
    # NOTE: would be nice if this was present in stdlib Random class

    ###just in case rng provides this...
    ##meth = getattr(rng, "getrandbytes", None)
    ##if meth:
    ##    return meth(count)

    if not count:
        return _BEMPTY

    def helper():
        # XXX: break into chunks for large number of bits?
        value = rng.getrandbits(count << 3)
        i = 0
        while i < count:
            yield value & 0xFF
            value >>= 3
            i += 1

    return bytes(helper())


def getrandstr(rng, charset, count):
    """return string containing *count* number of chars/bytes, whose elements are drawn from specified charset, using specified rng"""
    # NOTE: tests determined this is 4x faster than rng.sample(),
    # which is why that's not being used here.

    # check alphabet & count
    if count < 0:
        raise ValueError("count must be >= 0")
    letters = len(charset)
    if letters == 0:
        raise ValueError("alphabet must not be empty")
    if letters == 1:
        return charset * count

    # get random value, and write out to buffer
    def helper():
        # XXX: break into chunks for large number of letters?
        value = rng.randrange(0, letters**count)
        i = 0
        while i < count:
            yield charset[value % letters]
            value //= letters
            i += 1

    if isinstance(charset, str):
        return "".join(helper())
    return bytes(helper())


_52charset = "2346789ABCDEFGHJKMNPQRTUVWXYZabcdefghjkmnpqrstuvwxyz"


@deprecated_function(
    deprecated="1.7",
    removed="2.0",
    replacement="passlib.pwd.genword() / passlib.pwd.genphrase()",
)
def generate_password(size=10, charset=_52charset):
    """generate random password using given length & charset

    :param size:
        size of password.

    :param charset:
        optional string specified set of characters to draw from.

        the default charset contains all normal alphanumeric characters,
        except for the characters ``1IiLl0OoS5``, which were omitted
        due to their visual similarity.

    :returns: :class:`!str` containing randomly generated password.

    .. note::

        Using the default character set, on a OS with :class:`!SystemRandom` support,
        this function should generate passwords with 5.7 bits of entropy per character.
    """
    return getrandstr(rng, charset, size)


_handler_attrs = (
    "name",
    "setting_kwds",
    "context_kwds",
    "verify",
    "hash",
    "identify",
)


def is_crypt_handler(obj):
    """check if object follows the :ref:`password-hash-api`"""
    # XXX: change to use isinstance(obj, PasswordHash) under py26+?
    return all(hasattr(obj, name) for name in _handler_attrs)


_context_attrs = (
    "needs_update",
    "genconfig",
    "genhash",
    "verify",
    "encrypt",
    "identify",
)


def is_crypt_context(obj):
    """check if object appears to be a :class:`~passlib.context.CryptContext` instance"""
    # XXX: change to use isinstance(obj, CryptContext)?
    return all(hasattr(obj, name) for name in _context_attrs)


##def has_many_backends(handler):
##    "check if handler provides multiple baceknds"
##    # NOTE: should also provide get_backend(), .has_backend(), and .backends attr
##    return hasattr(handler, "set_backend")


def has_rounds_info(handler):
    """check if handler provides the optional :ref:`rounds information <rounds-attributes>` attributes"""
    return (
        "rounds" in handler.setting_kwds
        and getattr(handler, "min_rounds", None) is not None
    )


def has_salt_info(handler):
    """check if handler provides the optional :ref:`salt information <salt-attributes>` attributes"""
    return (
        "salt" in handler.setting_kwds
        and getattr(handler, "min_salt_size", None) is not None
    )
