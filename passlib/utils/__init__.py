"""passlib utility functions"""
#=================================================================================
#imports
#=================================================================================
#core
from base64 import b64encode, b64decode
from codecs import lookup as _lookup_codec
from cStringIO import StringIO
##from functools import update_wrapper
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

    #byte compat aliases
    'bytes', 'native_str',

    #misc
    'os_crypt',

    #tests
    'is_crypt_handler',
    'is_crypt_context',

    #bytes<->unicode
    'to_bytes',
    'to_unicode',
    'to_native_str',
    'is_same_codec',

    #byte manipulation
    "xor_bytes",

    #random
    'rng',
    'getrandbytes',
    'getrandstr',

    #constants
    'pypy_vm', 'jython_vm',
    'py32_lang', 'py3k_lang',
    'sys_bits',
    'unix_crypt_schemes',
]

#=================================================================================
#constants
#=================================================================================

#: detect what we're running on
pypy_vm = hasattr(sys, "pypy_version_info")
jython_vm = sys.platform.startswith('java')
py3k_lang = sys.version_info >= (3,0)
py32_lang = sys.version_info >= (3,2)

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
# Py2k #
ALL_BYTE_VALUES = ''.join(chr(x) for x in xrange(256))
# Py3k #
#ALL_BYTE_VALUES = bytes(xrange(256))
# end Py3k #

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

NoneType = type(None)

class MissingBackendError(RuntimeError):
    """error raised if multi-backend handler has no available backends;
    or if specifically requested backend is not available.

    see :class:`~passlib.utils.handlers.HasManyBackends`.
    """

#==========================================================
#bytes compat aliases - bytes, native_str, b()
#==========================================================

# Py2k #
if sys.version_info < (2,6):
    #py25 doesn't define 'bytes', so we have to here -
    #and then import it everywhere bytes is needed,
    #just so we retain py25 compat - if that were sacrificed,
    #the need for this would go away
    bytes = str
else:
    bytes = bytes #just so it *can* be imported from this module
native_str = bytes
# Py3k #
#bytes = bytes #just so it *can* be imported from this module
#native_str = unicode
# end Py3k #

#NOTE: have to provide b() because we're supporting py25,
#      and py25 doesn't support the b'' notation.
#      if py25 compat were sacrificed, this func could be removed.
def b(source):
    "convert native str to bytes (noop under py2; uses latin-1 under py3)"
    #assert isinstance(source, native_str)
    # Py2k #
    return source
    # Py3k #
    #return source.encode("latin-1")
    # end Py3k #

#=================================================================================
#os crypt helpers
#=================================================================================

#expose crypt function as 'os_crypt', set to None if not available.
try:
    from crypt import crypt as os_crypt
except ImportError: #pragma: no cover
    safe_os_crypt = os_crypt = None
else:
    def safe_os_crypt(secret, hash):
        """wrapper around stdlib's crypt.

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
        """
        #XXX: source indicates crypt() may return None on some systems
        # if an error occurrs - could make this return False in that case.

        # Py2k #
        #NOTE: this guard logic is designed purely to match py3 behavior,
        #      with the exception that it accepts secret as bytes
        if isinstance(secret, unicode):
            secret = secret.encode("utf-8")
        if isinstance(hash, bytes):
            raise TypeError("hash must be unicode")
        else:
            hash = hash.encode("utf-8")
        return True, os_crypt(secret, hash).decode("ascii")

        # Py3k #
        #if isinstance(secret, bytes):
        #    #decode to utf-8. if successful, will be reencoded with os_crypt,
        #    #and we'll get back correct hash.
        #    #if not, we can't use os_crypt for this.
        #    orig = secret
        #    try:
        #        secret = secret.decode("utf-8")
        #    except UnicodeDecodeError:
        #        return False, None
        #    if secret.encode("utf-8") != orig:
        #        #just in case original encoding wouldn't be reproduced
        #        #during call to os_crypt.
        #        #not sure if/how this could happen, but being paranoid.
        #        warn("utf-8 password didn't re-encode correctly")
        #        return False, None
        #return True, os_crypt(secret, hash)
        # end Py3k #

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

def to_native_str(source, encoding="utf-8", errname="value"):
    """take in unicode or bytes, return native string

    python 2: encodes unicode using specified encoding, leaves bytes alone.
    python 3: decodes bytes using specified encoding, leaves unicode alone.

    :raises TypeError: if source is not unicode or bytes.

    :arg source: source bytes/unicode to process
    :arg encoding: encoding to use when encoding unicode / decoding bytes
    :param errname: optional name of variable/noun to reference when raising errors

    :returns: :class:`str` instance
    """
    assert encoding
    if isinstance(source, bytes):
        # Py2k #
        return source
        # Py3k #
        #return source.decode(encoding)
        # end Py3k #

    elif isinstance(source, unicode):
        # Py2k #
        return source.encode(encoding)
        # Py3k #
        #return source
        # end Py3k #

    else:
        raise TypeError("%s must be unicode or bytes, not %s" % (errname, type(source)))

def to_hash_str(hash, encoding="ascii", errname="hash"):
    "given hash string as bytes or unicode; normalize according to hash policy"
    #NOTE: for now, policy is ascii-bytes under py2, unicode under py3.
    #      but plan to make flag allowing apps to enable unicode behavior under py2.
    return to_native_str(hash, encoding, errname)

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

_U80 = u'\x80'
_B80 = b('\x80')

def is_ascii_safe(source):
    "check if source (bytes or unicode) contains only 7-bit ascii"
    if isinstance(source, bytes):
        # Py2k #
        return all(c < _B80 for c in source)
        # Py3k #
        #return all(c < 128 for c in source)
        # end Py3k #
    else:
        return all(c < _U80 for c in source)

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

#==========================================================
#bytes helpers
#==========================================================

#some common constants / aliases
BEMPTY = b('')

#helpers for joining / extracting elements
bjoin = BEMPTY.join
ujoin = u''.join

def belem_join(elems):
    """takes series of bytes elements, returns bytes.

    elem should be result of bytes[x].
    this is another bytes instance under py2,
    but it int under py3.

    returns bytes.

    this is bytes() constructor under py3,
    but b"".join() under py2.
    """
    # Py2k #
    return bjoin(elems)
    # Py3k #
    #return bytes(elems)
    # end Py3k #

#for efficiency, don't bother with above wrapper...
# Py2k #
belem_join = bjoin
# Py3k #
#belem_join = bytes
# end Py3k #

def bord(elem):
    """takes bytes element, returns integer.

    elem should be result of bytes[x].
    this is another bytes instance under py2,
    but it int under py3.

    returns int in range(0,256).

    this is ord() under py2, and noop under py3.
    """
    # Py2k #
    assert isinstance(elem, bytes)
    return ord(elem)
    # Py3k #
    ##assert isinstance(elem, int)
    #return elem
    # end Py3k #

#for efficiency, don't bother with wrapper
# Py2k #
bord = ord
# end Py2k #

def bchrs(*values):
    "takes series of ints, returns bytes; like chr() but for bytes, and w/ multi args"
    # Py2k #
    return bjoin(chr(v) for v in values)
    # Py3k #
    #return bytes(values)
    # end Py3k #

# Py2k #
def bjoin_ints(values):
    return bjoin(chr(v) for v in values)
# Py3k #
#bjoin_ints = bytes
# end Py3k #

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
        for s in xrange(8*count-8,-8,-8)
    )

def xor_bytes(left, right):
    "perform bitwise-xor of two byte-strings"
    #NOTE: this could use bjoin_ints(), but speed is *really* important here (c.f. PBKDF2)
    # Py2k #
    return bjoin(chr(ord(l) ^ ord(r)) for l, r in zip(left, right))
    # Py3k #
    #return bytes(l ^ r for l, r in zip(left, right))
    # end Py3k #

#=================================================================================
#alt base64 encoding
#=================================================================================
_A64_ALTCHARS = b("./")
_A64_STRIP = b("=\n")
_A64_PAD1 = b("=")
_A64_PAD2 = b("==")

def adapted_b64_encode(data):
    """encode using variant of base64

    the output of this function is identical to b64_encode,
    except that it uses ``.`` instead of ``+``,
    and omits trailing padding ``=`` and whitepsace.

    it is primarily used for by passlib's custom pbkdf2 hashes.
    """
    return b64encode(data, _A64_ALTCHARS).strip(_A64_STRIP)

def adapted_b64_decode(data, sixthree="."):
    """decode using variant of base64

    the input of this function is identical to b64_decode,
    except that it uses ``.`` instead of ``+``,
    and should not include trailing padding ``=`` or whitespace.

    it is primarily used for by passlib's custom pbkdf2 hashes.
    """
    off = len(data) % 4
    if off == 0:
        return b64decode(data, _A64_ALTCHARS)
    elif off == 1:
        raise ValueError("invalid bas64 input")
    elif off == 2:
        return b64decode(data + _A64_PAD2, _A64_ALTCHARS)
    else:
        return b64decode(data + _A64_PAD1, _A64_ALTCHARS)

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
    text = u"%s %s %s %.15f %s" % (
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
    #hash it all up and return it as int
    return long(sha256(text.encode("utf-8")).hexdigest(), 16)

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
            # Py2k #
            yield chr(value & 0xff)
            # Py3k #
            #yield value & 0xff
            # end Py3k #
            value >>= 3
            i += 1
    # Py2k #
    return bjoin(helper())
    # Py3k #
    #return bytes(helper())
    # end Py3k #

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
        # Py2k #
        return bjoin(helper())
        # Py3k #
        #return bytes(helper())
        # end Py3k #

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
