"""passlib utility functions"""
#=================================================================================
#imports
#=================================================================================
#core
from base64 import b64encode, b64decode
from codecs import lookup as _lookup_codec
from functools import update_wrapper
from hashlib import sha256
import logging; log = logging.getLogger(__name__)
from math import log as logb
import os
import sys
import random
import stringprep
import time
import unicodedata
from warnings import warn
#site
#pkg
from passlib.utils.compat import irange, PY3, sys_bits, unicode, bytes, u, b, \
                                 _add_doc
#local
__all__ = [
    #decorators
    "classproperty",
##    "memoized_class_property",
##    "abstractmethod",
##    "abstractclassmethod",

    #byte compat aliases
    'bytes',

    #misc
    'os_crypt',

    #tests
    'is_crypt_handler',
    'is_crypt_context',

    #bytes<->unicode
    'to_bytes',
    'to_unicode',
    'is_same_codec',

    # string manipulation
    'consteq',
    'saslprep',

    #byte manipulation
    "xor_bytes",

    # base64 helpers
    "BASE64_CHARS", "HASH64_CHARS", "BCRYPT_CHARS", "AB64_CHARS",
    "Base64Engine", "h64", "h64big",
    "ab64_encode", "ab64_decode",

    #random
    'tick',
    'rng',
    'getrandbytes',
    'getrandstr',

    #constants
    'unix_crypt_schemes',
]

#=================================================================================
#constants
#=================================================================================

#: list of names of hashes found in unix crypt implementations...
unix_crypt_schemes = [
    "sha512_crypt", "sha256_crypt",
    "sha1_crypt", "bcrypt",
    "md5_crypt",
    "bsdi_crypt", "des_crypt"
    ]

#: list of rounds_cost constants
rounds_cost_values = [ "linear", "log2" ]

#: special byte string containing all possible byte values, used in a few places.
#XXX: treated as singleton by some of the code for efficiency.
if PY3:
    ALL_BYTE_VALUES = bytes(irange(256))
else:
    ALL_BYTE_VALUES = ''.join(chr(x) for x in irange(256))

NoneType = type(None)

class MissingBackendError(RuntimeError):
    """Error raised if multi-backend handler has no available backends;
    or if specifically requested backend is not available.

    :exc:`!MissingBackendError` derives
    from :exc:`RuntimeError`, since this usually indicates
    lack of an external library or OS feature.

    This is primarily used by handlers which derive
    from :class:`~passlib.utils.handlers.HasManyBackends`.
    """

class PasslibPolicyWarning(UserWarning):
    """Warning issued when non-fatal issue is found in policy configuration.

    This occurs primarily in one of two cases:

    * the policy contains rounds limits which exceed the hard limits
      imposed by the underlying algorithm.
    * an explicit rounds value was provided which exceeds the limits
      imposed by the policy.

    In both of these cases, the code will perform correctly & securely;
    but the warning is issued as a sign the configuration may need updating.
    """

#=================================================================================
#os crypt helpers
#=================================================================================

#expose crypt function as 'os_crypt', set to None if not available.
try:
    from crypt import crypt as os_crypt
except ImportError: #pragma: no cover
    safe_os_crypt = os_crypt = None
else:
    # NOTE: see docstring below as to why we're wrapping os_crypt()
    if PY3:
        def safe_os_crypt(secret, hash):
            if isinstance(secret, bytes):
                # decode secret using utf-8, and make sure it re-encodes to
                # match the original - otherwise the call to os_crypt()
                # will encode the wrong password.
                orig = secret
                try:
                    secret = secret.decode("utf-8")
                except UnicodeDecodeError:
                    return False, None
                if secret.encode("utf-8") != orig:
                    # just in case original encoding wouldn't be reproduced
                    # during call to os_crypt. not sure if/how this could
                    # happen, but being paranoid.
                    warn("utf-8 password didn't re-encode correctly!")
                    return False, None
            result = os_crypt(secret, hash)
            return (result is not None), result
    else:
        def safe_os_crypt(secret, hash):
            # NOTE: this guard logic is designed purely to match py3 behavior,
            # with the exception that it accepts secret as bytes.
            if isinstance(secret, unicode):
                secret = secret.encode("utf-8")
            if isinstance(hash, bytes):
                raise TypeError("hash must be unicode")
            else:
                hash = hash.encode("utf-8")
            result = os_crypt(secret, hash)
            if result is None:
                return False, None
            else:
                return True, result.decode("ascii")

    _add_doc(safe_os_crypt, """wrapper around stdlib's crypt.

        Python 3's crypt behaves slightly differently from Python 2's crypt.
        for one, it takes in and returns unicode.
        internally, it converts to utf-8 before hashing.
        Annoyingly, *there is no way to call it using bytes*.
        thus, it can't be used to hash non-ascii passwords
        using any encoding but utf-8 (eg, using latin-1).

        This wrapper attempts to gloss over all those issues:
        Under Python 2, it accept passwords as unicode or bytes,
        accepts hashes only as unicode, and always returns unicode.
        Under Python 3, it will signal that it cannot hash a password
        if provided as non-utf-8 bytes, but otherwise behave the same as crypt.

        :arg secret: password as bytes or unicode
        :arg hash: hash/salt as unicode
        :returns:
            ``(False, None)`` if the password can't be hashed (3.x only),
            or ``(True, result: unicode)`` otherwise.
        """)

#=================================================================================
#decorators and meta helpers
#=================================================================================
class classproperty(object):
    """Function decorator which acts like a combination of classmethod+property (limited to read-only properties)"""

    def __init__(self, func):
        self.im_func = func

    def __get__(self, obj, cls):
        return self.im_func(cls)

    @property
    def __func__(self):
        "py3 compatible alias"
        return self.im_func

def deprecated_function(msg=None, deprecated=None, removed=None, updoc=True):
    """decorator to deprecate a function.

    :arg msg: optional msg, default chosen if omitted
    :kwd deprecated: release where function was first deprecated
    :kwd removed: release where function will be removed
    :kwd updoc: add notice to docstring (default ``True``)
    """
    if msg is None:
        msg = "the function %(mod)s.%(name)s() is deprecated"
        if deprecated:
            msg += " as of Passlib %(deprecated)s"
        if removed:
            msg += ", and will be removed in Passlib %(removed)s"
        msg += "."
    def build(func):
        final = msg % dict(
            mod=func.__module__,
            name=func.__name__,
            deprecated=deprecated,
            removed=removed,
        )
        def wrapper(*args, **kwds):
            warn(final, DeprecationWarning, stacklevel=2)
            return func(*args, **kwds)
        update_wrapper(wrapper, func)
        if updoc and (deprecated or removed) and wrapper.__doc__:
            txt = "as of Passlib %s" % (deprecated,) if deprecated else ""
            if removed:
                if txt:
                    txt += ", and "
                txt += "will be removed in Passlib %s" % (removed,)
            wrapper.__doc__ += "\n.. deprecated:: %s\n" % (txt,)
        return wrapper
    return build

def relocated_function(target, msg=None, name=None, deprecated=None, mod=None,
                       removed=None, updoc=True):
    """constructor to create alias for relocated function.

    :arg target: import path to target
    :arg msg: optional msg, default chosen if omitted
    :kwd deprecated: release where function was first deprecated
    :kwd removed: release where function will be removed
    :kwd updoc: add notice to docstring (default ``True``)
    """
    target_mod, target_name = target.rsplit(".",1)
    if mod is None:
        import inspect
        mod = inspect.currentframe(1).f_globals["__name__"]
    if not name:
        name = target_name
    if msg is None:
        msg = ("the function %(mod)s.%(name)s() has been moved to "
               "%(target_mod)s.%(target_name)s(), the old location is deprecated")
        if deprecated:
            msg += " as of Passlib %(deprecated)s"
        if removed:
            msg += ", and will be removed in Passlib %(removed)s"
        msg += "."
    msg %= dict(
        mod=mod,
        name=name,
        target_mod=target_mod,
        target_name=target_name,
        deprecated=deprecated,
        removed=removed,
    )
    state = [None]
    def wrapper(*args, **kwds):
        warn(msg, DeprecationWarning, stacklevel=2)
        func = state[0]
        if func is None:
            module = __import__(target_mod, fromlist=[target_name], level=0)
            func = state[0] = getattr(module, target_name)
        return func(*args, **kwds)
    wrapper.__module__ = mod
    wrapper.__name__ = name
    wrapper.__doc__ = msg
    return wrapper

#works but not used
##class memoized_class_property(object):
##    """function decorator which calls function as classmethod, and replaces itself with result for current and all future invocations"""
##    def __init__(self, func):
##        self.im_func = func
##
##    def __get__(self, obj, cls):
##        func = self.im_func
##        value = func(cls)
##        setattr(cls, func.__name__, value)
##        return value
##
##    @property
##    def __func__(self):
##        "py3 compatible alias"

#works but not used...
##def abstractmethod(func):
##    """Method decorator which indicates this is a placeholder method which
##    should be overridden by subclass.
##
##    If called directly, this method will raise an :exc:`NotImplementedError`.
##    """
##    msg = "object %(self)r method %(name)r is abstract, and must be subclassed"
##    def wrapper(self, *args, **kwds):
##        text = msg % dict(self=self, name=wrapper.__name__)
##        raise NotImplementedError(text)
##    update_wrapper(wrapper, func)
##    return wrapper

#works but not used...
##def abstractclassmethod(func):
##    """Class Method decorator which indicates this is a placeholder method which
##    should be overridden by subclass, and must be a classmethod.
##
##    If called directly, this method will raise an :exc:`NotImplementedError`.
##    """
##    msg = "class %(cls)r method %(name)r is abstract, and must be subclassed"
##    def wrapper(cls, *args, **kwds):
##        text = msg % dict(cls=cls, name=wrapper.__name__)
##        raise NotImplementedError(text)
##    update_wrapper(wrapper, func)
##    return classmethod(wrapper)

#==========================================================
#protocol helpers
#==========================================================
def is_crypt_handler(obj):
    "check if object follows the :ref:`password-hash-api`"
    return all(hasattr(obj, name) for name in (
        "name",
        "setting_kwds", "context_kwds",
        "genconfig", "genhash",
        "verify", "encrypt", "identify",
        ))

def is_crypt_context(obj):
    "check if object appears to be a :class:`~passlib.context.CryptContext` instance"
    return all(hasattr(obj, name) for name in (
        "hash_needs_update",
        "genconfig", "genhash",
        "verify", "encrypt", "identify",
        ))

##def has_many_backends(handler):
##    "check if handler provides multiple baceknds"
##    #NOTE: should also provide get_backend(), .has_backend(), and .backends attr
##    return hasattr(handler, "set_backend")

def has_rounds_info(handler):
    "check if handler provides the optional :ref:`rounds information <optional-rounds-attributes>` attributes"
    return 'rounds' in handler.setting_kwds and getattr(handler, "min_rounds", None) is not None

def has_salt_info(handler):
    "check if handler provides the optional :ref:`salt information <optional-salt-attributes>` attributes"
    return 'salt' in handler.setting_kwds and getattr(handler, "min_salt_size", None) is not None

##def has_raw_salt(handler):
##    "check if handler takes in encoded salt as unicode (False), or decoded salt as bytes (True)"
##    sc = getattr(handler, "salt_chars", None)
##    if sc is None:
##        return None
##    elif isinstance(sc, unicode):
##        return False
##    elif isinstance(sc, bytes):
##        return True
##    else:
##        raise TypeError("handler.salt_chars must be None/unicode/bytes")

#==========================================================
#bytes <-> unicode conversion helpers
#==========================================================

def to_bytes(source, encoding="utf-8", source_encoding=None, errname="value"):
    """helper to encoding unicode -> bytes

    this function takes in a ``source`` string.
    if unicode, encodes it using the specified ``encoding``.
    if bytes, returns unchanged - unless ``source_encoding``
    is specified, in which case the bytes are transcoded
    if and only if the source encoding doesn't match
    the desired encoding.
    all other types result in a :exc:`TypeError`.

    :arg source: source bytes/unicode to process
    :arg encoding: target character encoding or ``None``.
    :param source_encoding: optional source encoding
    :param errname: optional name of variable/noun to reference when raising errors

    :raises TypeError: if unicode encountered but ``encoding=None`` specified;
                       or if source is not unicode or bytes.

    :returns: bytes object

    .. note::

        if ``encoding`` is set to ``None``, then unicode strings
        will be rejected, and only byte strings will be allowed through.
    """
    if isinstance(source, bytes):
        if source_encoding and encoding and \
                not is_same_codec(source_encoding, encoding):
            return source.decode(source_encoding).encode(encoding)
        else:
            return source
    elif not encoding:
        raise TypeError("%s must be bytes, not %s" % (errname, type(source)))
    elif isinstance(source, unicode):
        return source.encode(encoding)
    elif source_encoding:
        raise TypeError("%s must be unicode or %s-encoded bytes, not %s" %
                        (errname, source_encoding, type(source)))
    else:
        raise TypeError("%s must be unicode or bytes, not %s" % (errname, type(source)))

def to_unicode(source, source_encoding="utf-8", errname="value"):
    """take in unicode or bytes, return unicode

    if bytes provided, decodes using specified encoding.
    leaves unicode alone.

    :raises TypeError: if source is not unicode or bytes.

    :arg source: source bytes/unicode to process
    :arg source_encoding: encoding to use when decoding bytes instances
    :param errname: optional name of variable/noun to reference when raising errors

    :returns: unicode object
    """
    if isinstance(source, unicode):
        return source
    elif not source_encoding:
        raise TypeError("%s must be unicode, not %s" % (errname, type(source)))
    elif isinstance(source, bytes):
        return source.decode(source_encoding)
    else:
        raise TypeError("%s must be unicode or %s-encoded bytes, not %s" %
                        (errname, source_encoding, type(source)))

if PY3:
    def to_native_str(source, encoding="utf-8", errname="value"):
        if isinstance(source, bytes):
            return source.decode(encoding)
        elif isinstance(source, unicode):
            return source
        else:
            raise TypeError("%s must be unicode or bytes, not %s" %
                            (errname, type(source)))
else:
    def to_native_str(source, encoding="utf-8", errname="value"):
        if isinstance(source, bytes):
            return source
        elif isinstance(source, unicode):
            return source.encode(encoding)
        else:
            raise TypeError("%s must be unicode or bytes, not %s" %
                            (errname, type(source)))

_add_doc(to_native_str,
    """take in unicode or bytes, return native string

    python 2: encodes unicode using specified encoding, leaves bytes alone.
    python 3: decodes bytes using specified encoding, leaves unicode alone.

    :raises TypeError: if source is not unicode or bytes.

    :arg source:
        source unicode or bytes string.

    :arg encoding:
        encoding to use when encoding unicode or decoding bytes.
        this defaults to ``"utf-8"``.

    :param errname:
        optional name of variable/noun to reference when raising errors.

    :returns: :class:`str` instance
    """)

# DEPRECATED
def to_hash_str(source, encoding="ascii"):
    "deprecated, use to_native_str() instead"
    warn("to_hash_str() is deprecated, and will be removed in passlib 1.7",
         DeprecationWarning, stacklevel=2)
    return to_native_str(source, encoding, 'hash')

#--------------------------------------------------
#support utils
#--------------------------------------------------
def is_same_codec(left, right):
    "check if two codecs names are aliases for same codec"
    if left == right:
        return True
    if not (left and right):
        return False
    return _lookup_codec(left).name == _lookup_codec(right).name

_B80 = 128 if PY3 else b('\x80')
_U80 = u('\x80')
def is_ascii_safe(source):
    "check if source (bytes or unicode) contains only 7-bit ascii"
    r = _B80 if isinstance(source, bytes) else _U80
    return all(c < r for c in source)

#=================================================================================
#string helpers
#=================================================================================
UEMPTY = u("")
USPACE = u(" ")
ujoin = UEMPTY.join

def consteq(left, right):
    """check two strings/bytes for equality, taking constant time relative
    to the size of the righthand input.

    The purpose of this function is to aid in preventing timing attacks
    during digest comparisons (see the 1.6 changelog
    :ref:`entry <consteq-issue>` for more details).
    """
    # NOTE:
    # This function attempts to take an amount of time proportional
    # to ``THETA(len(right))``. The main loop is designed so that timing attacks
    # against this function should reveal nothing about how much (or which
    # parts) of the two inputs match.
    #
    # Why ``THETA(len(right))``?
    # Assuming the attacker controls one of the two inputs, padding to
    # the largest input or trimming to the smallest input both allow
    # a timing attack to reveal the length of the other input.
    # However, by fixing the runtime to be proportional to the right input:
    # * If the right value is attacker controlled, the runtime is proportional
    #   to their input, giving nothing away about the left value's size.
    # * If the left value is attacker controlled, the runtime is constant
    #   relative to their input, giving nothing away about the right value's size.

    # validate types
    if isinstance(left, unicode):
        if not isinstance(right, unicode):
            raise TypeError("inputs must be both unicode or bytes")
        is_py3_bytes = False
    elif isinstance(left, bytes):
        if not isinstance(right, bytes):
            raise TypeError("inputs must be both unicode or bytes")
        is_py3_bytes = PY3
    else:
        raise TypeError("inputs must be both unicode or bytes")

    # do size comparison.
    # NOTE: the double-if construction below is done deliberately, to ensure
    # the same number of operations (including branches) is performed regardless
    # of whether left & right are the same size.
    same = (len(left) == len(right))
    if same:
        # if sizes are the same, setup loop to perform actual check of contents.
        tmp = left
        result = 0
    if not same:
        # if sizes aren't the same, set 'result' so equality will fail regardless
        # of contents. then, to ensure we do exactly 'len(right)' iterations
        # of the loop, just compare 'right' against itself.
        tmp = right
        result = 1

    # run constant-time string comparision
    if is_py3_bytes:
        for l,r in zip(tmp, right):
            result |= l ^ r
    else:
        for l,r in zip(tmp, right):
            result |= ord(l) ^ ord(r)
    return result == 0

@deprecated_function(deprecated="1.6", removed="1.8")
def splitcomma(source, sep=","):
    """split comma-separated string into list of elements,
    stripping whitespace and discarding empty elements.
    """
    return [
        elem.strip()
        for elem in source.split(sep)
        if elem.strip()
    ]

def saslprep(source, errname="value"):
    """normalizes unicode string using SASLPrep stringprep profile.

    The SASLPrep profile is defined in :rfc:`4013`.
    It provides a uniform scheme for normalizing unicode usernames
    and passwords before performing byte-value sensitive operations
    such as hashing. Among other things, it normalizes diacritic
    representations, removes non-printing characters, and forbids
    invalid characters such as ``\n``.

    :arg source:
        unicode string to normalize & validate

    :param errname:
        optionally override noun used to refer to source in error messages,
        defaults to ``value``; mainly useful to make caller's error
        messages make more sense.

    :raises ValueError:
        if any characters forbidden by the SASLPrep profile are encountered.

    :returns:
        normalized unicode string
    """
    # saslprep - http://tools.ietf.org/html/rfc4013
    # stringprep - http://tools.ietf.org/html/rfc3454
    #              http://docs.python.org/library/stringprep.html

    # validate type
    if not isinstance(source, unicode):
        raise TypeError("input must be unicode string, not %s" %
                        (type(source),))

    # mapping stage
    #   - map non-ascii spaces to U+0020 (stringprep C.1.2)
    #   - strip 'commonly mapped to nothing' chars (stringprep B.1)
    in_table_c12 = stringprep.in_table_c12
    in_table_b1 = stringprep.in_table_b1
    data = ujoin(
        USPACE if in_table_c12(c) else c
        for c in source
        if not in_table_b1(c)
        )

    # normalize to KC form
    data = unicodedata.normalize('NFKC', data)
    if not data:
        return UEMPTY

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
            raise ValueError("malformed bidi sequence in " + errname)
        # forbid L chars within R/AL sequence.
        is_forbidden_bidi_char = stringprep.in_table_d2
    else:
        # forbid R/AL chars if start not setup correctly; L chars allowed.
        is_forbidden_bidi_char = is_ral_char

    # check for prohibited output - stringprep tables A.1, B.1, C.1.2, C.2 - C.9
    in_table_a1 = stringprep.in_table_a1
    in_table_c21_c22 = stringprep.in_table_c21_c22
    in_table_c3 = stringprep.in_table_c3
    in_table_c4 = stringprep.in_table_c4
    in_table_c5 = stringprep.in_table_c5
    in_table_c6 = stringprep.in_table_c6
    in_table_c7 = stringprep.in_table_c7
    in_table_c8 = stringprep.in_table_c8
    in_table_c9 = stringprep.in_table_c9
    for c in data:
        # check for this mapping stage should have removed
        assert not in_table_b1(c), "failed to strip B.1 in mapping stage"
        assert not in_table_c12(c), "failed to replace C.1.2 in mapping stage"

        # check for forbidden chars
        if in_table_a1(c):
            raise ValueError("unassigned code points forbidden in " + errname)
        if in_table_c21_c22(c):
            raise ValueError("control characters forbidden in " + errname)
        if in_table_c3(c):
            raise ValueError("private use characters forbidden in " + errname)
        if in_table_c4(c):
            raise ValueError("non-char code points forbidden in " + errname)
        if in_table_c5(c):
            raise ValueError("surrogate codes forbidden in " + errname)
        if in_table_c6(c):
            raise ValueError("non-plaintext chars forbidden in " + errname)
        if in_table_c7(c):
            # XXX: should these have been caught by normalize?
            # if so, should change this to an assert
            raise ValueError("non-canonical chars forbidden in " + errname)
        if in_table_c8(c):
            raise ValueError("display-modifying / deprecated chars "
                             "forbidden in" + errname)
        if in_table_c9(c):
            raise ValueError("tagged characters forbidden in " + errname)

        # do bidi constraint check chosen by bidi init, above
        if is_forbidden_bidi_char(c):
            raise ValueError("forbidden bidi character in " + errname)

    return data

#==========================================================
#bytes helpers
#==========================================================

#some common constants / aliases
BEMPTY = b('')

#helpers for joining / extracting elements
bjoin = BEMPTY.join

#def bjoin_elems(elems):
#    """takes series of bytes elements, returns bytes.
#
#    elem should be result of bytes[x].
#    this is another bytes instance under py2,
#    but it int under py3.
#
#    returns bytes.
#
#    this is bytes() constructor under py3,
#    but b"".join() under py2.
#    """
#    if PY3:
#        return bytes(elems)
#    else:
#        return bjoin(elems)
#
#for efficiency, don't bother with above wrapper...
if PY3:
    bjoin_elems = bytes
else:
    bjoin_elems = bjoin

#def bord(elem):
#    """takes bytes element, returns integer.
#
#    elem should be result of bytes[x].
#    this is another bytes instance under py2,
#    but it int under py3.
#
#    returns int in range(0,256).
#
#    this is ord() under py2, and noop under py3.
#    """
#    if PY3:
#        assert isinstance(elem, int)
#        return elem
#    else:
#        assert isinstance(elem, bytes)
#        return ord(elem)
#
#for efficiency, don't bother with above wrapper...
if PY3:
    def bord(elem):
        return elem
else:
    bord = ord

if PY3:
    bjoin_ints = bytes
else:
    def bjoin_ints(values):
        return bjoin(chr(v) for v in values)

def render_bytes(source, *args):
    """helper for using formatting operator with bytes.

    this function is motivated by the fact that
    :class:`bytes` instances do not support % or {} formatting under python 3.
    this function is an attempt to provide a replacement
    that will work uniformly under python 2 & 3.

    it converts everything to unicode (including bytes arguments),
    then encodes the result to latin-1.
    """
    if isinstance(source, bytes):
        source = source.decode("latin-1")
    def adapt(arg):
        if isinstance(arg, bytes):
            return arg.decode("latin-1")
        return arg
    result = source % tuple(adapt(arg) for arg in args)
    return result.encode("latin-1")

#=================================================================================
#numeric helpers
#=================================================================================

##def int_to_bytes(value, count=None, order="big"):
##    """encode a integer into a string of bytes
##
##    :arg value: the integer
##    :arg count: optional number of bytes to expose, uses minimum needed if count not specified
##    :param order: the byte ordering; "big" (the default), "little", or "native"
##
##    :raises ValueError:
##        * if count specified and integer too large to fit.
##        * if integer is negative
##
##    :returns:
##        bytes encoding integer
##    """
##
##
##def bytes_to_int(value, order="big"):
##    """decode a byte string into an integer representation of it's binary value.
##
##    :arg value: the string to decode.
##    :param order: the byte ordering; "big" (the default), "little", or "native"
##
##    :returns: the decoded positive integer.
##    """
##    if not value:
##        return 0
##    if order == "native":
##        order = sys.byteorder
##    if order == "little":
##        value = reversed(value)
##    out = 0
##    for v in value:
##        out = (out<<8) | ord(v)
##    return out

def bytes_to_int(value):
    "decode string of bytes as single big-endian integer"
    out = 0
    for v in value:
        out = (out<<8) | bord(v)
    return out

def int_to_bytes(value, count):
    "encodes integer into single big-endian byte string"
    assert value < (1<<(8*count)), "value too large for %d bytes: %d" % (count, value)
    return bjoin_ints(
        ((value>>s) & 0xff)
        for s in irange(8*count-8,-8,-8)
    )

if PY3:
    def xor_bytes(left, right):
        "perform bitwise-xor of two byte-strings"
        return bytes(l ^ r for l, r in zip(left, right))
else:
    def xor_bytes(left, right):
        "perform bitwise-xor of two byte-strings"
        return bjoin(chr(ord(l) ^ ord(r)) for l, r in zip(left, right))

#=================================================================================
# base64-variant encoding
#=================================================================================

class Base64Engine(object):
    """provides routines for encoding/decoding base64 data using
    arbitrary character mappings, selectable endianness, etc.

    Raw Bytes <-> Encoded Bytes
    ===========================
    .. automethod:: encode_bytes
    .. automethod:: decode_bytes
    .. automethod:: encode_transposed_bytes
    .. automethod:: decode_transposed_bytes

    Integers <-> Encoded Bytes
    ==========================
    .. automethod:: encode_int6
    .. automethod:: decode_int6

    .. automethod:: encode_int12
    .. automethod:: decode_int12

    .. automethod:: encode_int24
    .. automethod:: decode_int24

    .. automethod:: encode_int64
    .. automethod:: decode_int64

    Informational Attributes
    ========================
    .. attribute:: charmap
        unicode string containing list of characters used in encoding;
        position in string matches 6bit value of character.

    .. attribute:: bytemap
        bytes version of :attr:`charmap`

    .. attribute:: big
        boolean flag indicating this using big-endian encoding.
    """

    #=============================================================
    # instance attrs
    #=============================================================
    # public config
    bytemap = None # charmap as bytes
    big = None # little or big endian

    # filled in by init based on charmap.
    # encode: maps 6bit value -> byte_elem, decode: the reverse.
    # byte_elem is 1-byte under py2, and 0-255 int under py3.
    _encode64 = None
    _decode64 = None

    # helpers filled in by init based on endianness
    _encode_bytes = None # throws IndexError if bad value (shouldn't happen)
    _decode_bytes = None # throws KeyError if bad char.

    #=============================================================
    # init
    #=============================================================
    def __init__(self, charmap, big=False):
        # validate charmap, generate encode64/decode64 helper functions.
        if isinstance(charmap, unicode):
            charmap = charmap.encode("latin-1")
        elif not isinstance(charmap, bytes):
            raise TypeError("charmap must be unicode/bytes string")
        if len(charmap) != 64:
            raise ValueError("charmap must be 64 characters in length")
        if len(set(charmap)) != 64:
            raise ValueError("charmap must not contain duplicate characters")
        self.bytemap = charmap
        self._encode64 = charmap.__getitem__
        lookup = dict((value, idx) for idx, value in enumerate(charmap))
        self._decode64 = lookup.__getitem__

        # validate big, set appropriate helper functions.
        self.big = big
        if big:
            self._encode_bytes = self._encode_bytes_big
            self._decode_bytes = self._decode_bytes_big
        else:
            self._encode_bytes = self._encode_bytes_little
            self._decode_bytes = self._decode_bytes_little

        # TODO: support padding character
        ##if padding is not None:
        ##    if isinstance(padding, unicode):
        ##        padding = padding.encode("latin-1")
        ##    elif not isinstance(padding, bytes):
        ##        raise TypeError("padding char must be unicode or bytes")
        ##    if len(padding) != 1:
        ##        raise ValueError("padding must be single character")
        ##self.padding = padding

    @property
    def charmap(self):
        "charmap as unicode"
        return self.bytemap.decode("latin-1")

    #=============================================================
    # encoding byte strings
    #=============================================================
    def encode_bytes(self, source):
        """encode bytes to engine's specific base64 variant.
        :arg source: byte string to encode.
        :returns: byte string containing encoded data.
        """
        if not isinstance(source, bytes):
            raise TypeError("source must be bytes, not %s" % (type(source),))
        chunks, tail = divmod(len(source), 3)
        if PY3:
            next_value = iter(source).__next__
        else:
            next_value = (ord(elem) for elem in source).next
        gen = self._encode_bytes(next_value, chunks, tail)
        out = bjoin_elems(imap(self._encode64, gen))
        ##if tail:
        ##    padding = self.padding
        ##    if padding:
        ##        out += padding * (3-tail)
        return out

    def _encode_bytes_little(self, next_value, chunks, tail):
        "helper used by encode_bytes() to handle little-endian encoding"
        #
        # output bit layout:
        #
        # first byte:   v1 543210
        #
        # second byte:  v1 ....76
        #              +v2 3210..
        #
        # third byte:   v2 ..7654
        #              +v3 10....
        #
        # fourth byte:  v3 765432
        #
        idx = 0
        while idx < chunks:
            v1 = next_value()
            v2 = next_value()
            v3 = next_value()
            yield v1 & 0x3f
            yield ((v2 & 0x0f)<<2)|(v1>>6)
            yield ((v3 & 0x03)<<4)|(v2>>4)
            yield v3>>2
            idx += 1
        if tail:
            v1 = next_value()
            if tail == 1:
                # note: 4 msb of last byte are padding
                yield v1 & 0x3f
                yield v1>>6
            else:
                assert tail == 2
                # note: 2 msb of last byte are padding
                v2 = next_value()
                yield v1 & 0x3f
                yield ((v2 & 0x0f)<<2)|(v1>>6)
                yield v2>>4

    def _encode_bytes_big(self, next_value, chunks, tail):
        "helper used by encode_bytes() to handle big-endian encoding"
        #
        # output bit layout:
        #
        # first byte:   v1 765432
        #
        # second byte:  v1 10....
        #              +v2 ..7654
        #
        # third byte:   v2 3210..
        #              +v3 ....76
        #
        # fourth byte:  v3 543210
        #
        idx = 0
        while idx < chunks:
            v1 = next_value()
            v2 = next_value()
            v3 = next_value()
            yield v1>>2
            yield ((v1&0x03)<<4)|(v2>>4)
            yield ((v2&0x0f)<<2)|(v3>>6)
            yield v3 & 0x3f
            idx += 1
        if tail:
            v1 = next_value()
            if tail == 1:
                # note: 4 lsb of last byte are padding
                yield v1>>2
                yield (v1&0x03)<<4
            else:
                assert tail == 2
                # note: 2 lsb of last byte are padding
                v2 = next_value()
                yield v1>>2
                yield ((v1&0x03)<<4)|(v2>>4)
                yield ((v2&0x0f)<<2)

    #=============================================================
    # decoding byte strings
    #=============================================================

    def decode_bytes(self, source):
        """decode bytes from engine's specific base64 variant.
        :arg source: byte string to decode.
        :returns: byte string containing decoded data.
        """
        if not isinstance(source, bytes):
            raise TypeError("source must be bytes, not %s" % (type(source),))
        ##padding = self.padding
        ##if padding:
        ##    # TODO: add padding size check?
        ##    source = source.rstrip(padding)
        chunks, tail = divmod(len(source), 4)
        if tail == 1:
            #only 6 bits left, can't encode a whole byte!
            raise ValueError("input string length cannot be == 1 mod 4")
        if PY3:
            next_value = imap(self._decode64, source).__next__
        else:
            next_value = imap(self._decode64, source).next
        try:
            return bjoin_ints(self._decode_bytes(next_value, chunks, tail))
        except KeyError:
            err = exc_err()
            raise ValueError("invalid character: %r" % (err.args[0],))

    def _decode_bytes_little(self, next_value, chunks, tail):
        "helper used by decode_bytes() to handle little-endian encoding"
        #
        # input bit layout:
        #
        # first byte:   v1 ..543210
        #              +v2 10......
        #
        # second byte:  v2 ....5432
        #              +v3 3210....
        #
        # third byte:   v3 ......54
        #              +v4 543210..
        #
        idx = 0
        while idx < chunks:
            v1 = next_value()
            v2 = next_value()
            v3 = next_value()
            v4 = next_value()
            yield v1 | ((v2 & 0x3) << 6)
            yield (v2>>2) | ((v3 & 0xF) << 4)
            yield (v3>>4) | (v4<<2)
            idx += 1
        if tail:
            # tail is 2 or 3
            v1 = next_value()
            v2 = next_value()
            yield v1 | ((v2 & 0x3) << 6)
            #NOTE: if tail == 2, 4 msb of v2 are ignored (should be 0)
            if tail == 3:
                #NOTE: 2 msb of v3 are ignored (should be 0)
                v3 = next_value()
                yield (v2>>2) | ((v3 & 0xF) << 4)

    def _decode_bytes_big(self, next_value, chunks, tail):
        "helper used by decode_bytes() to handle big-endian encoding"
        #
        # input bit layout:
        #
        # first byte:   v1 543210..
        #              +v2 ......54
        #
        # second byte:  v2 3210....
        #              +v3 ....5432
        #
        # third byte:   v3 10......
        #              +v4 ..543210
        #
        idx = 0
        while idx < chunks:
            v1 = next_value()
            v2 = next_value()
            v3 = next_value()
            v4 = next_value()
            yield (v1<<2) | (v2>>4)
            yield ((v2&0xF)<<4) | (v3>>2)
            yield ((v3&0x3)<<6) | v4
            idx += 1
        if tail:
            # tail is 2 or 3
            v1 = next_value()
            v2 = next_value()
            yield (v1<<2) | (v2>>4)
            #NOTE: if tail == 2, 4 lsb of v2 are ignored (should be 0)
            if tail == 3:
                #NOTE: 2 lsb of v3 are ignored (should be 0)
                v3 = next_value()
                yield ((v2&0xF)<<4) | (v3>>2)

    #=============================================================
    # transposed encoding/decoding
    #=============================================================
    def encode_transposed_bytes(self, source, offsets):
        "encode byte string, first transposing source using offset list"
        if not isinstance(source, bytes):
            raise TypeError("source must be bytes, not %s" % (type(source),))
        tmp = bjoin_elems(source[off] for off in offsets)
        return self.encode_bytes(tmp)

    def decode_transposed_bytes(self, source, offsets):
        "decode byte string, then reverse transposition described by offset list"
        # NOTE: if transposition does not use all bytes of source,
        # the original can't be recovered... and bjoin_elems() will throw
        # an error because 1+ values in <buf> will be None.
        tmp = self.decode_bytes(source)
        buf = [None] * len(offsets)
        for off, char in zip(offsets, tmp):
            buf[off] = char
        return bjoin_elems(buf)

    #=============================================================
    # integer decoding helpers - mainly used by des_crypt family
    #=============================================================
    def _decode_int(self, source, bits):
        """decode hash64 string -> integer

        :arg source: base64 string to decode.
        :arg bits: number of bits in resulting integer.

        :raises ValueError:
            * if the string contains invalid base64 characters.
            * if the string is not long enough - it must be at least
              ``int(ceil(bits/6))`` in length.

        :returns:
            a integer in the range ``0 <= n < 2**bits``
        """
        if not isinstance(source, bytes):
            raise TypeError("source must be bytes, not %s" % (type(source),))
        big = self.big
        pad = -bits % 6
        chars = (bits+pad)/6
        if len(source) != chars:
            raise ValueError("source must be %d chars" % (chars,))
        decode = self._decode64
        out = 0
        try:
            for c in source if big else reversed(source):
                out = (out<<6) + decode(c)
        except KeyError:
            raise ValueError("invalid character in string: %r" % (c,))
        if pad:
            # strip padding bits
            if big:
                out >>= pad
            else:
                out &= (1<<bits)-1
        return out

    #---------------------------------------------
    # optimized versions for common integer sizes
    #---------------------------------------------

    def decode_int6(self, source):
        "decode single character -> 6 bit integer"
        if not isinstance(source, bytes):
            raise TypeError("source must be bytes, not %s" % (type(source),))
        if len(source) != 1:
            raise ValueError("source must be exactly 1 byte")
        try:
            return self._decode64(source)
        except KeyError:
            raise ValueError("invalid character")

    def decode_int12(self, source):
        "decodes 2 char string -> 12-bit integer (little-endian order)"
        if not isinstance(source, bytes):
            raise TypeError("source must be bytes, not %s" % (type(source),))
        if len(source) != 2:
            raise ValueError("source must be exactly 2 bytes")
        decode = self._decode64
        try:
            if self.big:
                return decode(source[1]) + (decode(source[0])<<6)
            else:
                return decode(source[0]) + (decode(source[1])<<6)
        except KeyError:
            raise ValueError("invalid character")

    def decode_int24(self, source):
        "decodes 4 char string -> 24-bit integer (little-endian order)"
        if not isinstance(source, bytes):
            raise TypeError("source must be bytes, not %s" % (type(source),))
        if len(source) != 4:
            raise ValueError("source must be exactly 4 bytes")
        decode = self._decode64
        try:
            if self.big:
                return decode(source[3]) + (decode(source[2])<<6)+ \
                       (decode(source[1])<<12) + (decode(source[0])<<18)
            else:
                return decode(source[0]) + (decode(source[1])<<6)+ \
                       (decode(source[2])<<12) + (decode(source[3])<<18)
        except KeyError:
            raise ValueError("invalid character")

    def decode_int64(self, source):
        """decode 11 char base64 string -> 64-bit integer

        this format is used primarily by des-crypt & variants to encode
        the DES output value used as a checksum.
        """
        return self._decode_int(source, 64)

    #=============================================================
    # integer encoding helpers - mainly used by des_crypt family
    #=============================================================
    def _encode_int(self, value, bits):
        """encode integer into base64 format

        :arg value: non-negative integer to encode
        :arg bits: number of bits to encode

        :returns:
            a string of length ``int(ceil(bits/6.0))``.
        """
        if value < 0:
            raise ValueError("value cannot be negative")
        pad = -bits % 6
        bits += pad
        if self.big:
            itr = irange(bits-6, -6, -6)
            # shift to add lsb padding.
            value <<= pad
        else:
            itr = irange(0, bits, 6)
            # padding is msb, so no change needed.
        return bjoin_elems(imap(self._encode64,
                                ((value>>off) & 0x3f for off in itr)))

    #---------------------------------------------
    # optimized versions for common integer sizes
    #---------------------------------------------

    def encode_int6(self, value):
        "encodes 6-bit integer -> single hash64 character"
        if value < 0 or value > 63:
            raise ValueError("value out of range")
        if PY3:
            return self.bytemap[value:value+1]
        else:
            return self._encode64(value)

    def encode_int12(self, value):
        "encodes 12-bit integer -> 2 char string"
        if value < 0 or value > 0xFFF:
            raise ValueError("value out of range")
        raw = [value & 0x3f, (value>>6) & 0x3f]
        if self.big:
            raw = reversed(raw)
        return bjoin_elems(imap(self._encode64, raw))

    def encode_int24(self, value):
        "encodes 24-bit integer -> 4 char string"
        if value < 0 or value > 0xFFFFFF:
            raise ValueError("value out of range")
        raw = [value & 0x3f, (value>>6) & 0x3f,
               (value>>12) & 0x3f, (value>>18) & 0x3f]
        if self.big:
            raw = reversed(raw)
        return bjoin_elems(imap(self._encode64, raw))

    def encode_int64(self, value):
        """encode 64-bit integer -> 11 char hash64 string

        this format is used primarily by des-crypt & variants to encode
        the DES output value used as a checksum.
        """
        if value < 0 or value > 0xffffffffffffffff:
            raise ValueError("value out of range")
        return self._encode_int(value, 64)

    #=============================================================
    # eof
    #=============================================================

# common charmaps
BASE64_CHARS = u("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")
AB64_CHARS =   u("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789./")
HASH64_CHARS = u("./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz")
BCRYPT_CHARS = u("./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")

# common variants
h64 = Base64Engine(HASH64_CHARS)
h64big = Base64Engine(HASH64_CHARS, big=True)

#=============================================================================
# adapted-base64 encoding
#=============================================================================
_A64_ALTCHARS = b("./")
_A64_STRIP = b("=\n")
_A64_PAD1 = b("=")
_A64_PAD2 = b("==")

def ab64_encode(data):
    """encode using variant of base64

    the output of this function is identical to b64_encode,
    except that it uses ``.`` instead of ``+``,
    and omits trailing padding ``=`` and whitepsace.

    it is primarily used by Passlib's custom pbkdf2 hashes.
    """
    return b64encode(data, _A64_ALTCHARS).strip(_A64_STRIP)

def ab64_decode(data):
    """decode using variant of base64

    the input of this function is identical to b64_decode,
    except that it uses ``.`` instead of ``+``,
    and should not include trailing padding ``=`` or whitespace.

    it is primarily used by Passlib's custom pbkdf2 hashes.
    """
    off = len(data) & 3
    if off == 0:
        return b64decode(data, _A64_ALTCHARS)
    elif off == 2:
        return b64decode(data + _A64_PAD2, _A64_ALTCHARS)
    elif off == 3:
        return b64decode(data + _A64_PAD1, _A64_ALTCHARS)
    else: # off == 1
        raise ValueError("invalid base64 input")

#=================================================================================
#randomness
#=================================================================================

# pick best timer function to expose as "tick" - lifted from timeit module.
if sys.platform == "win32":
    # On Windows, the best timer is time.clock()
    from time import clock as tick
else:
    # On most other platforms the best timer is time.time()
    from time import time as tick

# works but not used
##def _get_timer_resolution(timer=timer, repeat=3):
##    best = None
##    i = 0
##    while i < repeat:
##        start = end = timer()
##        while start == end:
##            end = timer()
##        delta = end-start
##        if delta < 0:
##            # probably NTP adjust or some such.
##            log.error("timer jumped backwards! (%r => %r)", start, end)
##            continue
##        if delta > 1:
##            # should have at least this resolution,
##            # so probably NTP adjust or some such.
##            log.error("timer jumped too far! (%r => %r)", start, end)
##            continue
##        if best is None or delta < best:
##            best = delta
##        i += 1
##    return best
##
##timer_resolution = _get_timer_resolution()

#-----------------------------------------------------------------------
# setup rng for generating salts
#-----------------------------------------------------------------------

#NOTE:
# generating salts (eg h64_gensalt, below) doesn't require cryptographically
# strong randomness. it just requires enough range of possible outputs
# that making a rainbow table is too costly.
# so python's builtin merseen twister prng is used, but seeded each time
# this module is imported, using a couple of minor entropy sources.

try:
    os.urandom(1)
    has_urandom = True
except NotImplementedError: #pragma: no cover
    has_urandom = False

def genseed(value=None):
    "generate prng seed value from system resources"
    #if value is rng, extract a bunch of bits from it's state
    if hasattr(value, "getrandbits"):
        value = value.getrandbits(256)
    text = u("%s %s %s %.15f %s") % (
        value,
            #if user specified a seed value (eg current rng state), mix it in

        os.getpid() if hasattr(os, "getpid") else None,
            #add current process id
            #NOTE: not available in some environments, eg GAE

        id(object()),
            #id of a freshly created object.
            #(at least 2 bytes of which should be hard to predict)

        time.time(),
            #the current time, to whatever precision os uses

        os.urandom(16).decode("latin-1") if has_urandom else 0,
            #if urandom available, might as well mix some bytes in.
        )
    #hash it all up and return it as int/long
    return int(sha256(text.encode("utf-8")).hexdigest(), 16)

if has_urandom:
    rng = random.SystemRandom()
else: #pragma: no cover
    #NOTE: to reseed - rng.seed(genseed(rng))
    rng = random.Random(genseed())

#-----------------------------------------------------------------------
# some rng helpers
#-----------------------------------------------------------------------
def getrandbytes(rng, count):
    """return byte-string containing *count* number of randomly generated bytes, using specified rng"""
    #NOTE: would be nice if this was present in stdlib Random class

    ###just in case rng provides this...
    ##meth = getattr(rng, "getrandbytes", None)
    ##if meth:
    ##    return meth(count)

    if not count:
        return BEMPTY
    def helper():
        #XXX: break into chunks for large number of bits?
        value = rng.getrandbits(count<<3)
        i = 0
        while i < count:
            yield value & 0xff
            value >>= 3
            i += 1
    return bjoin_ints(helper())

def getrandstr(rng, charset, count):
    """return string containing *count* number of chars/bytes, whose elements are drawn from specified charset, using specified rng"""
    #check alphabet & count
    if count < 0:
        raise ValueError("count must be >= 0")
    letters = len(charset)
    if letters == 0:
        raise ValueError("alphabet must not be empty")
    if letters == 1:
        return charset * count

    #get random value, and write out to buffer
    def helper():
        #XXX: break into chunks for large number of letters?
        value = rng.randrange(0, letters**count)
        i = 0
        while i < count:
            yield charset[value % letters]
            value //= letters
            i += 1

    if isinstance(charset, unicode):
        return ujoin(helper())
    else:
        return bjoin_elems(helper())

def generate_password(size=10, charset='2346789ABCDEFGHJKMNPQRTUVWXYZabcdefghjkmnpqrstuvwxyz'):
    """generate random password using given length & chars

    :param size:
        size of password.

    :param charset:
        optional string specified set of characters to draw from.

        the default charset contains all normal alphanumeric characters,
        except for the characters ``1IiLl0OoS5``, which were omitted
        due to their visual similarity.

    :returns: randomly generated password.
    """
    return getrandstr(rng, charset, size)

#=================================================================================
#eof
#=================================================================================
