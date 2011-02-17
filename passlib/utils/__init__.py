"""passlib utility functions"""
#=================================================================================
#imports
#=================================================================================
#core
from cStringIO import StringIO
from functools import update_wrapper
from hashlib import sha256
import logging; log = logging.getLogger(__name__)
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
]

#=================================================================================
#os crypt helpers
#=================================================================================
try:
    #NOTE: just doing this import once, for all the various hashes that need it.
    from crypt import crypt as os_crypt
except ImportError:
    os_crypt = None

#=================================================================================
#decorators
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

Undef = object() #singleton used as default kwd value in some functions

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
        "lookup",
        "genconfig", "genhash",
        "verify", "encrypt", "identify",
        ))

#=================================================================================
#string helpers
#=================================================================================
def splitcomma(source):
    "split comma separated string into list elements, stripping whitespace and empty elements"
    return [
        elem.strip()
        for elem in source.split(",")
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

#TODO: rename 'bytes' kwd for py30 compat purposes
def list_to_bytes(value, bytes=None, order="big"):
    """Returns a multi-character string corresponding to a list of byte values.

    This is similar to :func:`int_to_bytes`, except that this returns a list
    of integers, where each integer corresponds to a single byte of the input.

    :arg value:
        The list of integers to encode.
        It must be true that ``all(elem in range(0,256)) for elem in value``,
        or a ValueError will be raised.

    :param bytes:
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
    #make sure all elements have valid values
    if any( elem < 0 or elem > 255 for elem in value):
        raise ValueError, "value must be list of integers in range(0,256): %r" % (value,)

    #validate bytes / upper
    if bytes is None:
        bytes = len(value)
        if bytes == 0:
            raise ValueError, "empty list not allowed"
    else:
        if bytes < 1:
            raise ValueError, "bytes must be None or >= 1: %r" % (bytes,)
        if len(value) > bytes:
            raise ValueError, "list too large for number of bytes: bytes=%r len=%r" % (bytes, len(value))

    #encode list in big endian mode
    out = ''.join( chr(elem) for elem in value )
    pad = bytes-len(out)

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
except NotImplementedError:
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
else:
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
        raise ValueError, "count must be >= 0"
    letters = len(charset)
    if letters == 0:
        raise ValueError, "alphabet must not be empty"
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

#=================================================================================
#misc helpers
#=================================================================================
class dict_proxy(object):
    def __init__(self, source):
        self.__source = source

    def __getattr__(self, key):
        try:
            return self.__source[key]
        except KeyError:
            raise AttributeError, "attribute not found: %r" % (key,)

def autodocument(scope, salt_charset="[./0-9A-Za-z]", settings_doc='', context_doc=''):
    """helper to auto-generate documentation for password hash handler

    :arg scope: dict containing encrypt/verify/etc functions (module scope or class dict)
    """
    #check for class
    if not hasattr(scope, "__dict__"):
        scope = dict_proxy(scope)

    #extract info
    name = scope.name

    setting_kwds = scope.setting_kwds
    has_salt = 'salt' in setting_kwds
    has_rounds = 'rounds' in setting_kwds
    has_other = any(c for c in setting_kwds if c not in ("salt", "rounds"))

    if has_salt:
        max_salt_chars = scope.max_salt_chars
        min_salt_chars = scope.min_salt_chars

    if has_rounds:
        default_rounds = scope.default_rounds
        min_rounds = scope.min_rounds
        max_rounds = scope.max_rounds
        rounds_cost = scope.rounds_cost
        assert rounds_cost in ("linear","log2")
        log_rounds = (rounds_cost == "log2")

    context_kwds = scope.context_kwds

    if context_doc:
        context_doc = context_doc.rstrip() + "\n"
    if settings_doc:
        settings_doc = settings_doc.rstrip() + "\n"

    def get_func(name):
        func = getattr(scope, name)
        if hasattr(func, "im_func"):
            func = func.im_func
        return func

    #--------------------------------------------------------------
    #generate genconfig docstring
    #--------------------------------------------------------------
    genconfig = get_func("genconfig")
    if not genconfig.__doc__:
        if setting_kwds:
            if has_other and not settings_doc:
                raise NotImplementedError, "can't auto generate genconfig docs w/ unknown setting_kwds"
            d = "generate %(name)s configuration string\n\n" % dict(name=name)

            if has_salt:
                d += """:param salt: optional salt string to use.\n\n    if omitted, one will be automatically generated (this is recommended for most cases).\n\n"""
                if max_salt_chars:
                    if min_salt_chars != max_salt_chars:
                        d += """    length must be between %d .. %d characters, inclusive.\n""" % (min_salt_chars, max_salt_chars)
                    else:
                        d += """    length must be %d characters\n""" % (max_salt_chars,)
                    if salt_charset:
                        d += """    characters must be in range ``%s``\n"""  % (salt_charset,)

            if has_rounds:
                d += """:param rounds:\n    optional number of rounds to apply (default is %d).\n    value must be between %d and %d, inclusive.\n"""  %(default_rounds, min_rounds, max_rounds)
                if log_rounds:
                    d += """    %(name)s's rounds value is logarithmic, the actual number of rounds used is ``2**rounds``.\n""" % dict(name=name)

            if settings_doc:
                d += settings_doc + "\n"

            d += """\n:raises ValueError: if invalid settings are passed in\n\n"""
            d += """:returns:\n    %(name)s configuration string\n""" % dict(name=name)
        else:
            d = """generate %(name)s configuration string

                :returns:
                    this hash has no configuration options, so genconfig always returns ``None``
            """ % dict(name=name)
        genconfig.__doc__ = d

    #--------------------------------------------------------------
    #generate genhash docstring
    #--------------------------------------------------------------
    genhash = get_func("genhash")
    if not genhash.__doc__:
        if context_kwds and not context_doc:
            raise NotImplementedError, "context_doc must be defined"
        if setting_kwds:
            d = """generate %(name)s hash from secret, using configuration string or existing hash.

:arg secret: string containing password to be encrypted
:arg config: a string containing an existing hash OR a configuration string as returned by :func:`genconfig`
%(context_doc)s
:raises TypeError: if the configuration string is not provided, or the secret is not a string

:raises ValueError: if the configuration string is not in a recognized format, or the secret contains a forbidden character.

:returns:
    encoded %(name)s hash of secret, using specified config string
        """ % dict(name=name, context_doc=context_doc)
        else:
            d = """generate %(name)s hash from secret.

:arg secret: string containing password to be encrypted
:arg config:
    a string containing an existing hash OR ``None`` (as returned by :func:`genconfig`).
    *This value is not used internally, as this algorithm has no configuration options.*
%(context_doc)s

:raises TypeError: if the secret is not a string

:raises ValueError: if the secret contains a forbidden character.

:returns:
    encoded %(name)s hash of secret
        """ % dict(name=name, context_doc=context_doc)

        genhash.__doc__ = d

    #--------------------------------------------------------------
    #generate encrypt docstring
    #--------------------------------------------------------------
    encrypt = get_func("encrypt")
    if not encrypt.__doc__:
        if context_kwds and not context_doc:
            raise NotImplementedError, "context_doc must be defined"
        encrypt.__doc__ = """encrypt secret, returning resulting %(name)s hash

this is a convience function,
it has the same effect as ``genhash(secret,genconfig(**settings))``

:arg secret: a string containing the secret to encode
%(context_doc)s

:param settings: all other keywords are used to configure the hash, see :func:`genconfig`.

:returns: %(name)s hash of secret, using specified settings
        """ % dict(name=name, context_doc=context_doc)

    #--------------------------------------------------------------
    #generate identify docstring
    #--------------------------------------------------------------
    identify = get_func("identify")
    if not identify.__doc__:
        if setting_kwds:
            cstr = " or configuration"
        else:
            cstr = ""
        identify.__doc__ = """identify this is a %(name)s hash.

:arg hash:
    the candidate hash string to check

:returns:
    ``True`` if input appears to be a %(name)s hash%(cstr)s string;
    otherwise, returns ``False``.
        """ % dict(name=name, cstr=cstr)
        #TODO: variant of this note, and also handle no settings
        ##.. note::
        ##    Some handlers may or may not return ``True`` for malformed hashes.
        ##    Those that do will raise a ValueError once the hash is passed to :func:`verify`.
        ##    Most handlers, however, will just return ``False``.

    #--------------------------------------------------------------
    #generate verify docstring
    #--------------------------------------------------------------
    verify = get_func("verify")
    if not verify.__doc__:
        if context_kwds and not context_doc:
            raise NotImplementedError, "context_doc must be defined"
        verify.__doc__ = """verify a secret against an existing %(name)s hash.

This checks if a secret matches against the one
encrypted in the specified %(name)s hash.

:param secret:
    A string containing the secret to check.
:param hash:
    A string containing the hash to check against.
%(context_doc)s

:raises TypeError:
    * if the secret is not a string.

:raises ValueError:
    * if the hash not specified
    * if the hash is not recognized as a %(name)s hash.
    * if the provided secret contains forbidden chars (see :func:`genhash`)

:returns:
    ``True`` if the secret matches, otherwise ``False``.
        """ % dict(name=name, context_doc=context_doc)

#=================================================================================
#eof
#=================================================================================
