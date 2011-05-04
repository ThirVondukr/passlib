"""passlib utility functions"""
#=================================================================================
#imports
#=================================================================================
#core
from base64 import b64encode, b64decode
from cStringIO import StringIO
from functools import update_wrapper
from hashlib import sha256
import logging; log = logging.getLogger(__name__)
from math import log as logb
import os
import sys
import random
import time
from warnings import warn
#site
#pkg
#local
__all__ = [
    #decorators
    "classproperty",
##    "memoized_class_property",
##    "abstractmethod",
##    "abstractclassmethod",

    #misc
    'os_crypt',

    #tests
    'is_crypt_handler',
    'is_crypt_context',

    #byte manipulation
    "bytes_to_list",
    "list_to_bytes",
    "xor_bytes",

    #random
    'rng',
    'getrandbytes',
    'getrandstr',

    #constants
    'sys_bits',
    'unix_crypt_schemes',
]

#=================================================================================
#constants
#=================================================================================

#: detect what we're running on
pypy_vm = hasattr(sys, "pypy_version_info")

#: number of bits in system architecture
sys_bits = int(logb(sys.maxint,2)+1.5)
assert sys_bits in (32,64), "unexpected sys_bits value: %r" % (sys_bits,)

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
ALL_BYTE_VALUES = ''.join(chr(x) for x in xrange(256))

#NOTE: Undef is only used in *one* place now, could just remove it
class UndefType(object):
    _undef = None

    def __new__(cls):
        if cls._undef is None:
            cls._undef = object.__new__(cls)
        return cls._undef

    def __repr__(self):
        return '<Undef>'

    def __eq__(self, other):
        return False

    def __ne__(self, other):
        return True

#: singleton used as default kwd value in some functions, indicating "NO VALUE"
Undef = UndefType()

#=================================================================================
#os crypt helpers
#=================================================================================
try:
    #NOTE: just doing this import once, for all the various hashes that need it.
    from crypt import crypt as os_crypt
except ImportError: #pragma: no cover
    os_crypt = None

#=================================================================================
#decorators and meta helpers
#=================================================================================
class classproperty(object):
    """Function decorator which acts like a combination of classmethod+property (limited to read-only properties)"""

    def __init__(self, func):
        self.im_func = func

    def __get__(self, obj, cls):
        return self.im_func(cls)

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
    "check if object follows :class:`CryptContext` interface"
    return all(hasattr(obj, name) for name in (
        "hash_needs_update",
        "genconfig", "genhash",
        "verify", "encrypt", "identify",
        ))

def has_rounds_info(handler):
    "check if handler provides the optional :ref:`rounds information <optional-rounds-attributes>` attributes"
    return 'rounds' in handler.setting_kwds and getattr(handler, "min_rounds", None) is not None

def has_salt_info(handler):
    "check if handler provides the optional :ref:`salt information <optional-salt-attributes>` attributes"
    return 'salt' in handler.setting_kwds and getattr(handler, "min_salt_size", None) is not None

#=================================================================================
#string helpers
#=================================================================================
def splitcomma(source, sep=","):
    "split comma-separated string into list of elements, stripping whitespace and discarding empty elements"
    return [
        elem.strip()
        for elem in source.split(sep)
        if elem.strip()
    ]

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
        out = (out<<8) | ord(v)
    return out

def int_to_bytes(value, count):
    "encodes integer into single big-endian byte string"
    assert value < (1<<(8*count)), "value too large for %d bytes: %d" % (count, value)
    return ''.join(
        chr((value>>s) & 0xff)
        for s in xrange(8*count-8,-8,-8)
    )

def list_to_bytes(value, count=None, order="big"):
    """Returns a multi-character string corresponding to a list of byte values.

    .. deprecated:: 1.4
        will be removed in 1.5

    This is similar to :func:`int_to_bytes`, except that this returns a list
    of integers, where each integer corresponds to a single byte of the input.

    :arg value:
        The list of integers to encode.
        It must be true that ``all(elem in range(0,256)) for elem in value``,
        or a ValueError will be raised.

    :param count:
        Optionally, the number of bytes to encode to.
        If specified, this will be the length of the returned string.

    :param order:
        Byte ordering: "big", "little", "native".
        The default is "big", since this the common network ordering,
        and "native" as the default would present poor cross-platform predictability.

    :returns:
        The number encoded into a string, according to the options.

    Usage Example::

        >>> from passlib.utils import list_to_bytes, bytes_to_list
        >>> list_to_bytes([4, 210], 4)
        '\\x00\\x00\\x04\\xd2'

        >>> list_to_bytes([4, 210], 4, order="little")
        '\\xd2\\x04\\x00\\x00'

        >>> bytes_to_list('\\x00\\x00\\x04\\xd2')
        [4, 210]
    """
    warn("list_to_bytes() is deprecated, and will be removed in passlib 1.5", DeprecationWarning)

    #make sure all elements have valid values
    if any( elem < 0 or elem > 255 for elem in value):
        raise ValueError("value must be list of integers in range(0,256): %r" % (value,))

    #validate bytes / upper
    if count is None:
        count = len(value)
        if count == 0:
            raise ValueError("empty list not allowed")
    else:
        if count < 1:
            raise ValueError("bytes must be None or >= 1: %r" % (count,))
        if len(value) > count:
            raise ValueError("list too large for number of bytes: bytes=%r len=%r" % (count, len(value)))

    #encode list in big endian mode
    out = ''.join( chr(elem) for elem in value )
    pad = count-len(out)

    #pad/reverse as needed for endianess
    if order == "native":
        order = sys.byteorder
    if order == "big":
        if pad:
            out = ('\x00' * pad) + out
    else:
        assert order == "little"
        if pad:
            out = out[::-1] + ('\x00' * pad)
        else:
            out = out[::-1]
    return out

def bytes_to_list(value, order="big"):
    """decode a string into a list of numeric values representing each of it's bytes.

    .. deprecated:: 1.4
        will be removed in 1.5

    This is similar to :func:`bytes_to_int`, the options and results
    are effectively the same, except that this function
    returns a list of numbers representing each byte in sequence,
    with most significant byte listed first.

    :arg value:
        The string to decode.
    :param order:
        The byte ordering, defaults to "big".
        See :func:`int_to_bytes` for more details.

    :returns:
        The decoded list of byte values.
    """
    warn("bytes_to_list() is deprecated, and will be removed in passlib 1.5", DeprecationWarning)
    if order == "native":
        order = sys.byteorder
    if order == "big":
        return [ ord(c) for c in value ]
    else:
        assert order == "little"
        return [ ord(c) for c in reversed(value) ]

_join = "".join
def xor_bytes(left, right):
    "perform bitwise-xor of two byte-strings"
    return _join(chr(ord(l) ^ ord(r)) for l, r in zip(left, right))

#=================================================================================
#alt base64 encoding
#=================================================================================

def adapted_b64_encode(data):
    """encode using variant of base64

    the output of this function is identical to b64_encode,
    except that it uses ``.`` instead of ``+``,
    and omits trailing padding ``=`` and whitepsace.

    it is primarily used for by passlib's custom pbkdf2 hashes.
    """
    return b64encode(data, "./").strip("=\n")

def adapted_b64_decode(data, sixthree="."):
    """decode using variant of base64

    the input of this function is identical to b64_decode,
    except that it uses ``.`` instead of ``+``,
    and should not include trailing padding ``=`` or whitespace.

    it is primarily used for by passlib's custom pbkdf2 hashes.
    """
    off = len(data) % 4
    if off == 0:
        return b64decode(data, "./")
    elif off == 1:
        raise ValueError("invalid bas64 input")
    elif off == 2:
        return b64decode(data + "==", "./")
    else:
        return b64decode(data + "=", "./")

#=================================================================================
#randomness
#=================================================================================

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
    text = "%s %s %s %.15f %s" % (
        value,
            #if user specified a seed value (eg current rng state), mix it in

        os.getpid(),
            #add current process id

        id(object()),
            #id of a freshly created object.
            #(at least 2 bytes of which should be hard to predict)

        time.time(),
            #the current time, to whatever precision os uses

        os.urandom(16) if has_urandom else 0,
            #if urandom available, might as well mix some bytes in.
        )
    #hash it all up and return it as int
    return long(sha256(text).hexdigest(), 16)

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

    #XXX: break into chunks for large number of bits?
    if not count:
        return ''
    value = rng.getrandbits(count<<3)
    buf = StringIO()
    for i in xrange(count):
        buf.write(chr(value & 0xff))
        value //= 0xff
    return buf.getvalue()

def getrandstr(rng, charset, count):
    """return character string containg *count* number of chars, whose elements are drawn from specified charset, using specified rng"""
    #check alphabet & count
    if count < 0:
        raise ValueError("count must be >= 0")
    letters = len(charset)
    if letters == 0:
        raise ValueError("alphabet must not be empty")
    if letters == 1:
        return charset * count

    #get random value, and write out to buffer
    #XXX: break into chunks for large number of letters?
    value = rng.randrange(0, letters**count)
    buf = StringIO()
    for i in xrange(count):
        buf.write(charset[value % letters])
        value //= letters
    assert value == 0
    return buf.getvalue()

def generate_password(size=10, charset=u'2346789ABCDEFGHJKMNPQRTUVWXYZabcdefghjkmnpqrstuvwxyz'):
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
