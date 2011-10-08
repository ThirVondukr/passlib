"""passlib.handler - code for implementing handlers, and global registry for handlers"""
#=========================================================
#imports
#=========================================================
from __future__ import with_statement
#core
import inspect
import re
import hashlib
import logging; log = logging.getLogger(__name__)
import time
import os
from warnings import warn
#site
#libs
from passlib.registry import get_crypt_handler
from passlib.utils import to_hash_str, bytes, b, \
        classproperty, h64, getrandstr, getrandbytes, \
        rng, is_crypt_handler, ALL_BYTE_VALUES, MissingBackendError
#pkg
#local
__all__ = [

    #framework for implementing handlers
    'StaticHandler',
    'GenericHandler',
        'HasRawChecksum',
        'HasManyIdents',
        'HasSalt',
            'HasRawSalt',
        'HasRounds',
        'HasManyBackends',
    'PrefixWrapper',
]

#=========================================================
#constants
#=========================================================

#common salt_chars & checksum_chars values
H64_CHARS = h64.CHARS
B64_CHARS = u"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
PADDED_B64_CHARS = B64_CHARS + u"="
U64_CHARS = u"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
HEX_CHARS = u"0123456789abcdefABCDEF"
UC_HEX_CHARS = u"0123456789ABCDEF"
LC_HEX_CHARS = u"0123456789abcdef"

#=========================================================
#identify helpers
#=========================================================
def identify_regexp(hash, pat):
    "identify() helper for matching regexp"
    if not hash:
        return False
    if isinstance(hash, bytes):
        try:
            hash = hash.decode("ascii")
        except UnicodeDecodeError:
            return False
    return pat.match(hash) is not None

def identify_prefix(hash, prefix):
    "identify() helper for matching against prefixes"
    #NOTE: prefix may be a tuple of strings (since startswith supports that)
    if not hash:
        return False
    if isinstance(hash, bytes):
        try:
            hash = hash.decode("ascii")
        except UnicodeDecodeError:
            return False
    return hash.startswith(prefix)

#=========================================================
#parsing helpers
#=========================================================
def parse_mc2(hash, prefix, name="<unnamed>", sep=u"$"):
    "parse hash using 2-part modular crypt format"
    assert isinstance(prefix, unicode)
    assert isinstance(sep, unicode)
    #eg: MD5-Crypt: $1$salt[$checksum]
    if not hash:
        raise ValueError("no hash specified")
    if isinstance(hash, bytes):
        hash = hash.decode('ascii')
    if not hash.startswith(prefix):
        raise ValueError("not a valid %s hash (wrong prefix)" % (name,))
    parts = hash[len(prefix):].split(sep)
    if len(parts) == 2:
        salt, chk = parts
        return salt, chk or None
    elif len(parts) == 1:
        return parts[0], None
    else:
        raise ValueError("not a valid %s hash (malformed)" % (name,))

def parse_mc3(hash, prefix, name="<unnamed>", sep=u"$"):
    "parse hash using 3-part modular crypt format"
    assert isinstance(prefix, unicode)
    assert isinstance(sep, unicode)
    #eg: SHA1-Crypt: $sha1$rounds$salt[$checksum]
    if not hash:
        raise ValueError("no hash specified")
    if isinstance(hash, bytes):
        hash = hash.decode('ascii')
    if not hash.startswith(prefix):
        raise ValueError("not a valid %s hash" % (name,))
    parts = hash[len(prefix):].split(sep)
    if len(parts) == 3:
        rounds, salt, chk = parts
        return rounds, salt, chk or None
    elif len(parts) == 2:
        rounds, salt = parts
        return rounds, salt, None
    else:
        raise ValueError("not a valid %s hash" % (name,))

#=====================================================
#formatting helpers
#=====================================================
def render_mc2(ident, salt, checksum, sep=u"$"):
    "format hash using 2-part modular crypt format; inverse of parse_mc2"
    if checksum:
        hash = u"%s%s%s%s" % (ident, salt, sep, checksum)
    else:
        hash = u"%s%s" % (ident, salt)
    return to_hash_str(hash)

def render_mc3(ident, rounds, salt, checksum, sep=u"$"):
    "format hash using 3-part modular crypt format; inverse of parse_mc3"
    if checksum:
        hash = u"%s%s%s%s%s%s" % (ident, rounds, sep, salt, sep, checksum)
    else:
        hash = u"%s%s%s%s" % (ident, rounds, sep, salt)
    return to_hash_str(hash)

#=====================================================
#StaticHandler
#=====================================================
class StaticHandler(object):
    """helper class for implementing hashes which have no settings.

    This class is designed to help in writing hash handlers
    which have no settings whatsoever; that is to say: no salt, no rounds, etc.
    These hashes can typically be recognized by the fact that they
    will always hash a password to *exactly* the same hash string.

    Usage
    =====

    In order to use this class, just subclass it, and then do the following:

        * fill out the :attr:`name` attribute with the name of your hash.
        * provide an implementation of the :meth:`~PasswordHash.genhash` method.
        * provide an implementation of the :meth:`~PasswordHash.identify` method.
          (a default is provided, but it's inefficient).

    Based on the methods above, this class provides:

        * a :meth:`genconfig` method that returns ``None``.
        * a :meth:`encrypt` method that wraps :meth:`genhash`.
        * a :meth:`verify` method that wraps :meth:`genhash`.

    Implementation Details
    ======================

    The :meth:`genhash` method you implement must accept
    all valid hashes, *as well as* whatever value :meth:`genconfig` returns.
    This defaults to ``None``, but you may set the :attr:`_stub_config` attr
    to a random hash string, and :meth:`genconfig` will return this instead.

    The default :meth:`verify` method uses simple equality to compare hash strings.
    If your hash may have multiple encoding (eg case-insensitive), this
    method (or the private :meth:`_norm_hash` method)
    should be overridden on a per-handler basis.

    If your hash has options, such as multiple identifiers, salts,
    or variable rounds, this is not the right class to start with.
    You should use the :class:`GenericHandler` class, or implement the handler yourself.
    """

    #=====================================================
    #class attrs
    #=====================================================
    name = None #required - handler name
    setting_kwds = ()
    context_kwds = ()

    _stub_config = None

    #=====================================================
    #methods
    #=====================================================
    @classmethod
    def identify(cls, hash):
        #NOTE: this relys on genhash() throwing error for invalid hashes.
        # this approach is bad because genhash may take a long time on valid hashes,
        # so subclasses *really* should override this.
        try:
            cls.genhash('fakesecret', hash)
            return True
        except ValueError:
            return False

    @classmethod
    def genconfig(cls):
        return cls._stub_config

    @classmethod
    def genhash(cls, secret, config, **context):
        raise NotImplementedError("%s subclass must implement genhash()" % (cls,))

    @classmethod
    def encrypt(cls, secret, *cargs, **context):
        #NOTE: subclasses generally won't need to override this.
        config = cls.genconfig()
        return cls.genhash(secret, config, *cargs, **context)

    @classmethod
    def verify(cls, secret, hash, *cargs, **context):
        #NOTE: subclasses generally won't need to override this.
        if hash is None:
            raise ValueError("no hash specified")
        hash = cls._norm_hash(hash)
        result = cls.genhash(secret, hash, *cargs, **context)
        return cls._norm_hash(result) == hash

    @classmethod
    def _norm_hash(cls, hash):
        """[helper for verify] normalize hash for comparsion purposes"""
        #NOTE: this is mainly provided for case-insenstive subclasses to override.
        if isinstance(hash, bytes):
            hash = hash.decode("ascii")
        return hash

    #=====================================================
    #eoc
    #=====================================================

#=====================================================
#GenericHandler
#=====================================================
class GenericHandler(object):
    """helper class for implementing hash handlers.

    :param checksum:
        this should contain the digest portion of a
        parsed hash (mainly provided when the constructor is called
        by :meth:`from_string()`).
        defaults to ``None``.

    :param strict:
        If ``True``, this flag signals that :meth:`norm_checksum`
        (as well as the other :samp:`norm_{xxx}` methods provided by the mixins)
        should throw a :exc:`ValueError` if any errors are found
        in any of the provided parameters.

        If ``False`` (the default), the :exc:`ValueError` should only
        be throw if the error is not recoverable (eg: clipping salt string to max size).

        This is typically only set to ``True`` when the constructor
        is called by :meth:`from_string`, in order to perform validation
        on the hash string it's parsing; whereas :meth:`encrypt`
        does not set this flag, allowing user-provided values
        to be handled in a more permissive manner.

    Class Attributes
    ================

    .. attribute:: ident

        [optional]
        If this attribute is filled in, the default :meth:`identify` method will use
        it as a identifying prefix that can be used to recognize instances of this handler's
        hash. Filling this out is recommended for speed.

        This should be a unicode str.

    .. attribute:: checksum_size

        [optional]
        Specifies the number of characters that should be expected in the checksum string.
        If omitted, no check will be performed.

    .. attribute:: checksum_chars

        [optional]
        A string listing all the characters allowed in the checksum string.
        If omitted, no check will be performed.

        This should be a unicode str.

    Instance Attributes
    ===================
    .. attribute:: checksum

        The checksum string as provided by the constructor (after passing through :meth:`norm_checksum`).

    Required Class Methods
    ======================
    The following methods must be provided by handler subclass:

    .. automethod:: from_string
    .. automethod:: to_string
    .. automethod:: calc_checksum

    Default Class Methods
    =====================
    The following methods provide generally useful default behaviors,
    though they may be overridden if the hash subclass needs to:

    .. automethod:: norm_checksum

    .. automethod:: genconfig
    .. automethod:: genhash
    .. automethod:: identify
    .. automethod:: encrypt
    .. automethod:: verify
    """

    #=====================================================
    #class attr
    #=====================================================
    context_kwds = ()

    ident = None #identifier prefix if known

    checksum_size = None #if specified, norm_checksum will require this length
    checksum_chars = None #if specified, norm_checksum() will validate this

    #=====================================================
    #instance attrs
    #=====================================================
    checksum = None

    #=====================================================
    #init
    #=====================================================
    def __init__(self, checksum=None, strict=False, **kwds):
        self.checksum = self.norm_checksum(checksum, strict=strict)
        super(GenericHandler, self).__init__(**kwds)

    #XXX: support a subclass-specified _norm_checksum method
    #     to normalize for the purposes of verify()?
    #     currently the code cost seems smaller to just have classes override verify.

    @classmethod
    def norm_checksum(cls, checksum, strict=False):
        "validates checksum keyword against class requirements, returns normalized version of checksum"
        if checksum is None:
            if strict:
                raise ValueError("checksum not specified")
            return None
        if isinstance(checksum, bytes):
            checksum = checksum.decode('ascii')
        cc = cls.checksum_size
        if cc and len(checksum) != cc:
            raise ValueError("%s checksum must be %d characters" % (cls.name, cc))
        cs = cls.checksum_chars
        if cs and any(c not in cs for c in checksum):
            raise ValueError("invalid characters in %s checksum" % (cls.name,))
        return checksum

    #=====================================================
    #password hash api - formatting interface
    #=====================================================
    @classmethod
    def identify(cls, hash):
        #NOTE: subclasses may wish to use faster / simpler identify,
        # and raise value errors only when an invalid (but identifiable) string is parsed
        if not hash:
            return False
        ident = cls.ident
        if ident:
            #class specified a known prefix to look for
            assert isinstance(ident, unicode)
            if isinstance(hash, bytes):
                ident = ident.encode('ascii')
            return hash.startswith(ident)
        else:
            #don't have that, so fall back to trying to parse hash
            #(inefficient for these purposes)
            try:
                cls.from_string(hash)
                return True
            except ValueError:
                return False

    @classmethod
    def from_string(cls, hash): #pragma: no cover
        """return parsed instance from hash/configuration string

        :raises ValueError: if hash is incorrectly formatted

        :returns:
            hash parsed into components,
            for formatting / calculating checksum.
        """
        raise NotImplementedError("%s must implement from_string()" % (cls,))

    def to_string(self): #pragma: no cover
        """render instance to hash or configuration string

        :returns:
            if :attr:`checksum` is set, should return full hash string.
            if not, should either return abbreviated configuration string,
            or fill in a stub checksum.

            should return native string type (ascii-bytes under python 2,
            unicode under python 3)
        """
        #NOTE: documenting some non-standardized but common kwd flags
        #      that passlib to_string() method may have
        #
        #      native=True -- if false, return unicode under py2 -- ignored under py3
        #      withchk=True -- if false, omit checksum portion of hash
        #
        raise NotImplementedError("%s must implement from_string()" % (type(self),))

    ##def to_config_string(self):
    ##    "helper for generating configuration string (ignoring hash)"
    ##    chk = self.checksum
    ##    if chk:
    ##        try:
    ##            self.checksum = None
    ##            return self.to_string()
    ##        finally:
    ##            self.checksum = chk
    ##    else:
    ##        return self.to_string()

    #=========================================================
    #'crypt-style' interface (default implementation)
    #=========================================================
    @classmethod
    def genconfig(cls, **settings):
        return cls(**settings).to_string()

    @classmethod
    def genhash(cls, secret, config):
        self = cls.from_string(config)
        self.checksum = self.calc_checksum(secret)
        return self.to_string()

    def calc_checksum(self, secret): #pragma: no cover
        "given secret; calcuate and return encoded checksum portion of hash string, taking config from object state"
        raise NotImplementedError("%s must implement calc_checksum()" % (self.__class__,))

    #=========================================================
    #'application' interface (default implementation)
    #=========================================================
    @classmethod
    def encrypt(cls, secret, **settings):
        self = cls(**settings)
        self.checksum = self.calc_checksum(secret)
        return self.to_string()

    @classmethod
    def verify(cls, secret, hash):
        #NOTE: classes with multiple checksum encodings (rare)
        # may wish to either override this, or override norm_checksum
        # to normalize any checksums provided by from_string()
        self = cls.from_string(hash)
        return self.checksum == self.calc_checksum(secret)

    #=========================================================
    #eoc
    #=========================================================

#=====================================================
#GenericHandler mixin classes
#=====================================================

#XXX: add a HasContext helper to override GenericHandler's methods?

class HasRawChecksum(GenericHandler):
    """mixin for classes which work with decoded checksum bytes

    .. todo::

        document this class's usage
    """

    checksum_chars = None

    @classmethod
    def norm_checksum(cls, checksum, strict=False):
        if checksum is None:
            return None
        if isinstance(checksum, unicode):
            raise TypeError("checksum must be specified as bytes")
        cc = cls.checksum_size
        if cc and len(checksum) != cc:
            raise ValueError("%s checksum must be %d characters" % (cls.name, cc))
        return checksum

#NOTE: commented out because all use-cases work better with StaticHandler
##class HasNoSettings(GenericHandler):
##    """overrides some GenericHandler methods w/ versions more appropriate for hash w/no settings"""
##
##    setting_kwds = ()
##
##    _stub_checksum = None
##
##    @classmethod
##    def genconfig(cls):
##        if cls._stub_checksum:
##            return cls().to_string()
##        else:
##            return None
##
##    @classmethod
##    def genhash(cls, secret, config):
##        if config is None and not cls._stub_checksum:
##            self = cls()
##        else:
##            self = cls.from_string(config) #just to validate the input
##        self.checksum = self.calc_checksum(secret)
##        return self.to_string()
##
##    @classmethod
##    def encrypt(cls, secret):
##        self = cls()
##        self.checksum = self.calc_checksum(secret)
##        return self.to_string()

class HasManyIdents(GenericHandler):
    """mixin for hashes which use multiple prefix identifiers

    For the hashes which may use multiple identifier prefixes,
    this mixin adds an ``ident`` keyword to constructor.
    Any value provided is passed through the :meth:`norm_idents` method,
    which takes care of validating the identifier,
    as well as allowing aliases for easier specification
    of the identifiers by the user.

    .. todo::

        document this class's usage
    """

    #=========================================================
    #class attrs
    #=========================================================
    default_ident = None #: should be unicode
    ident_values = None #: should be list of unicode strings
    ident_aliases = None #: should be dict of unicode -> unicode
        #NOTE: any aliases provided to norm_ident() as bytes
        #      will have been converted to unicode before
        #      comparing against this dictionary.

        #NOTE: relying on test_06_HasManyIdents() to verify
        #      these are configured correctly.

    #=========================================================
    #instance attrs
    #=========================================================
    ident = None

    #=========================================================
    #init
    #=========================================================
    def __init__(self, ident=None, strict=False, **kwds):
        self.ident = self.norm_ident(ident, strict=strict)
        super(HasManyIdents, self).__init__(strict=strict, **kwds)

    @classmethod
    def norm_ident(cls, ident, strict=False):
        #fill in default identifier
        if not ident:
            if strict:
                raise ValueError("no ident specified")
            return cls.default_ident

        #handle unicode
        if isinstance(ident, bytes):
            ident = ident.decode('ascii')

        #check if identifier is valid
        iv = cls.ident_values
        if ident in iv:
            return ident

        #check if it's an alias
        ia = cls.ident_aliases
        if ia:
            try:
                value = ia[ident]
            except KeyError:
                pass
            else:
                if value in iv:
                    return value

        #failure!
        raise ValueError("invalid ident: %r" % (ident,))

    #=========================================================
    #password hash api
    #=========================================================
    @classmethod
    def identify(cls, hash):
        if not hash:
            return False
        if isinstance(hash, bytes):
            try:
                hash = hash.decode('ascii')
            except UnicodeDecodeError:
                return False
        return any(hash.startswith(ident) for ident in cls.ident_values)

    #=========================================================
    #eoc
    #=========================================================

class HasSalt(GenericHandler):
    """mixin for validating salts.

    This :class:`GenericHandler` mixin adds a ``salt`` keyword to the class constuctor;
    any value provided is passed through the :meth:`norm_salt` method,
    which takes care of validating salt length and content,
    as well as generating new salts if one it not provided.

    :param salt: optional salt string
    :param salt_size: optional size of salt (only used if no salt provided); defaults to :attr:`default_salt_size`.
    :param strict: if ``True``, requires a valid salt be provided; otherwise is tolerant of correctable errors (the default).

    Class Attributes
    ================
    In order for :meth:`!norm_salt` to do it's job, the following
    attributes must be provided by the handler subclass:

    .. attribute:: min_salt_size

        [required]
        The minimum number of characters allowed in a salt string.
        An :exc:`ValueError` will be throw if the salt is too small.

    .. attribute:: max_salt_size

        [required]
        The maximum number of characters allowed in a salt string.
        When ``strict=True`` (such as when parsing a hash),
        an :exc:`ValueError` will be throw if the salt is too large.
        WHen ``strict=False`` (such as when parsing user-provided values),
        the salt will be silently trimmed to this length if it's too long.

    .. attribute:: default_salt_size

        [optional]
        If no salt is provided, this should specify the size of the salt
        that will be generated by :meth:`generate_salt`.
        If this is not specified, it will default to :attr:`max_salt_size`.

    .. attribute:: salt_chars

        [required]
        A string containing all the characters which are allowed in the salt string.
        An :exc:`ValueError` will be throw if any other characters are encountered.
        May be set to ``None`` to skip this check (but see in :attr:`default_salt_chars`).

    .. attribute:: default_salt_chars

        [optional]
        This attribute controls the set of characters use to generate
        *new* salt strings. By default, it mirrors :attr:`salt_chars`.
        If :attr:`!salt_chars` is ``None``, this attribute must be specified
        in order to generate new salts. Aside from that purpose,
        the main use of this attribute is for hashes which wish to generate
        salts from a restricted subset of :attr:`!salt_chars`; such as accepting all characters,
        but only using a-z.

    Instance Attributes
    ===================
    .. attribute:: salt

        This instance attribute will be filled in with the salt provided
        to the constructor (as adapted by :meth:`norm_salt`)

    Class Methods
    =============
    .. automethod:: norm_salt
    .. automethod:: generate_salt
    """
    #TODO: split out "HasRawSalt" mixin for classes where salt should be provided as raw bytes.
    #       also might need a "HasRawChecksum" to accompany it.
    #XXX: allow providing raw salt to this class, and encoding it?

    #=========================================================
    #class attrs
    #=========================================================
    #NOTE: min/max/default_salt_chars is deprecated, use min/max/default_salt_size instead

    #: required - minimum size of salt (error if too small)
    min_salt_size = None

    #: required - maximum size of salt (truncated if too large)
    max_salt_size = None

    @classproperty
    def default_salt_size(cls):
        "default salt chars (defaults to max_salt_size if not specified by subclass)"
        return cls.max_salt_size

    #: optional - set of characters allowed in salt string.
    salt_chars = None

    @classproperty
    def default_salt_chars(cls):
        "required - set of characters used to generate *new* salt strings (defaults to salt_chars)"
        return cls.salt_chars

    #: helper for HasRawSalt, shouldn't be used publically
    _salt_is_bytes = False
    _salt_unit = "char"

    #=========================================================
    #instance attrs
    #=========================================================
    salt = None

    #=========================================================
    #init
    #=========================================================
    def __init__(self, salt=None, salt_size=None, strict=False, **kwds):
        self.salt = self.norm_salt(salt, salt_size=salt_size, strict=strict)
        super(HasSalt, self).__init__(strict=strict, **kwds)

    @classmethod
    def generate_salt(cls, salt_size=None, strict=False):
        """helper method for norm_salt(); generates a new random salt string.

        :param salt_size: optional salt size, falls back to :attr:`default_salt_size`.
        :param strict: if too-large salt should throw error, or merely be trimmed.
        """
        if salt_size is None:
            salt_size = cls.default_salt_size
        else:
            mn = cls.min_salt_size
            if mn and salt_size < mn:
                raise ValueError("%s salt string must be at least %d characters" % (cls.name, mn))
            mx = cls.max_salt_size
            if mx and salt_size > mx:
                if strict:
                    raise ValueError("%s salt string must be at most %d characters" % (cls.name, mx))
                salt_size = mx
        if cls._salt_is_bytes:
            if cls.salt_chars != ALL_BYTE_VALUES:
                raise NotImplementedError("raw salts w/ only certain bytes not supported")
            return getrandbytes(rng, salt_size)
        else:
            return getrandstr(rng, cls.default_salt_chars, salt_size)

    @classmethod
    def norm_salt(cls, salt, salt_size=None, strict=False):
        """helper to normalize & validate user-provided salt string

        :arg salt: salt string or ``None``
        :param strict: enable strict checking (see below); disabled by default

        :raises ValueError:

            * if ``strict=True`` and no salt is provided
            * if ``strict=True`` and salt contains greater than :attr:`max_salt_size` characters
            * if salt contains chars that aren't in :attr:`salt_chars`.
            * if salt contains less than :attr:`min_salt_size` characters.

        if no salt provided and ``strict=False``, a random salt is generated
        using :attr:`default_salt_size` and :attr:`default_salt_chars`.
        if the salt is longer than :attr:`max_salt_size` and ``strict=False``,
        the salt string is clipped to :attr:`max_salt_size`.

        :returns:
            normalized or generated salt
        """
        #generate new salt if none provided
        if salt is None:
            if strict:
                raise ValueError("no salt specified")
            return cls.generate_salt(salt_size=salt_size, strict=strict)

        #validate input charset
        if cls._salt_is_bytes:
            if isinstance(salt, unicode):
                raise TypeError("salt must be specified as bytes")
        else:
            if isinstance(salt, bytes):
                salt = salt.decode("ascii")
            sc = cls.salt_chars
            if sc is not None:
                for c in salt:
                    if c not in sc:
                        raise ValueError("invalid character in %s salt: %r"  % (cls.name, c))

        #check min size
        mn = cls.min_salt_size
        if mn and len(salt) < mn:
            raise ValueError("%s salt string must be at least %d %ss" % (cls.name, mn, cls._salt_unit))

        #check max size
        mx = cls.max_salt_size
        if mx is not None and len(salt) > mx:
            if strict:
                raise ValueError("%s salt string must be at most %d %ss" % (cls.name, mx, cls._salt_unit))
            salt = salt[:mx]

        return salt
    #=========================================================
    #eoc
    #=========================================================

class HasRawSalt(HasSalt):
    """mixin for classes which use decoded salt parameter

    A variant of :class:`!HasSalt` which takes in decoded bytes instead of an encoded string.

    .. todo::

        document this class's usage
    """

    salt_chars = ALL_BYTE_VALUES

    #NOTE: all HasRawSalt code is currently part of HasSalt,
    #      using private _salt_is_bytes flag.
    #      this arrangement may be changed in the future.
    _salt_is_bytes = True
    _salt_unit = "byte"

class HasRounds(GenericHandler):
    """mixin for validating rounds parameter

    This :class:`GenericHandler` mixin adds a ``rounds`` keyword to the class constuctor;
    any value provided is passed through the :meth:`norm_rounds` method,
    which takes care of validating the number of rounds.

    :param rounds: optional number of rounds hash should use
    :param strict: if ``True``, requires a valid rounds vlaue be provided; otherwise is tolerant of correctable errors (the default).

    Class Attributes
    ================
    In order for :meth:`!norm_rounds` to do it's job, the following
    attributes must be provided by the handler subclass:

    .. attribute:: min_rounds

        [optional]
        The minimum number of rounds allowed.
        An :exc:`ValueError` will be thrown if the rounds value is too small.
        When ``strict=True`` (such as when parsing a hash),
        an :exc:`ValueError` will be throw if the rounds value is too small.
        WHen ``strict=False`` (such as when parsing user-provided values),
        the rounds value will be silently clipped if it's too small.
        Defaults to ``0``.

    .. attribute:: max_rounds

        [required]
        The maximum number of rounds allowed.
        When ``strict=True`` (such as when parsing a hash),
        an :exc:`ValueError` will be throw if the rounds value is too large.
        WHen ``strict=False`` (such as when parsing user-provided values),
        the rounds value will be silently clipped if it's too large.

    .. attribute:: default_rounds

        [required]
        If no rounds value is provided to constructor, this value will be used.

    .. attribute:: rounds_cost

        [required]
        The ``rounds`` parameter typically encodes a cpu-time cost
        for calculating a hash. This should be set to ``"linear"``
        (the default) or ``"log2"``, depending on how the rounds value relates
        to the actual amount of time that will be required.

    .. attribute:: _strict_rounds_bounds

        [optional]
        If the handler subclass wishes to *always* throw an error if a rounds
        value is provided that's out of bounds (such as when it's provided by the user),
        set this private attribute to ``True``.
        The default policy in such cases is to silently clip the rounds value
        to within :attr:`min_rounds` and :attr:`max_rounds`;
        while issuing a :exc:`UserWarning`.

    Instance Attributes
    ===================
    .. attribute:: rounds

        This instance attribute will be filled in with the rounds value provided
        to the constructor (as adapted by :meth:`norm_rounds`)

    Class Methods
    =============
    .. automethod:: norm_rounds
    """
    #=========================================================
    #class attrs
    #=========================================================
    min_rounds = 0
    max_rounds = None #required by ExtendedHandler.norm_rounds()
    default_rounds = None #if not specified, ExtendedHandler.norm_rounds() will require explicit rounds value every time
    rounds_cost = "linear" #common case
    _strict_rounds_bounds = False #if true, always raises error if specified rounds values out of range - required by spec for some hashes

    #=========================================================
    #instance attrs
    #=========================================================
    rounds = None

    #=========================================================
    #init
    #=========================================================
    def __init__(self, rounds=None, strict=False, **kwds):
        self.rounds = self.norm_rounds(rounds, strict=strict)
        super(HasRounds, self).__init__(strict=strict, **kwds)

    @classmethod
    def norm_rounds(cls, rounds, strict=False):
        """helper routine for normalizing rounds

        :arg rounds: rounds integer or ``None``
        :param strict: enable strict checking (see below); disabled by default

        :raises ValueError:

            * if rounds is ``None`` and ``strict=True``
            * if rounds is ``None`` and no :attr:`default_rounds` are specified by class.
            * if rounds is outside bounds of :attr:`min_rounds` and :attr:`max_rounds`, and ``strict=True``.

        if rounds are not specified and ``strict=False``, uses :attr:`default_rounds`.
        if rounds are outside bounds and ``strict=False``, rounds are clipped as appropriate,
        but a warning is issued.

        :returns:
            normalized rounds value
        """
        #provide default if rounds not explicitly set
        if rounds is None:
            if strict:
                raise ValueError("no rounds specified")
            rounds = cls.default_rounds
            if rounds is None:
                raise ValueError("%s rounds value must be specified explicitly" % (cls.name,))

        #if class requests, always throw error instead of clipping
        if cls._strict_rounds_bounds:
            strict = True

        mn = cls.min_rounds
        if rounds < mn:
            if strict:
                raise ValueError("%s rounds must be >= %d" % (cls.name, mn))
            warn("%s does not allow less than %d rounds: %d" % (cls.name, mn, rounds))
            rounds = mn

        mx = cls.max_rounds
        if mx and rounds > mx:
            if strict:
                raise ValueError("%s rounds must be <= %d" % (cls.name, mx))
            warn("%s does not allow more than %d rounds: %d" % (cls.name, mx, rounds))
            rounds = mx

        return rounds
    #=========================================================
    #eoc
    #=========================================================

class HasManyBackends(GenericHandler):
    """GenericHandler mixin which provides selecting from multiple backends.

    .. todo::

        finish documenting this class's usage

    For hashes which need to select from multiple backends,
    depending on the host environment, this class
    offers a way to specify alternate :meth:`calc_checksum` methods,
    and will dynamically chose the best one at runtime.

    Backend Methods
    ---------------

    .. automethod:: get_backend
    .. automethod:: set_backend
    .. automethod:: has_backend

    Subclass Hooks
    --------------
    The following attributes and methods should be filled in by the subclass
    which is using :class:`HasManyBackends` as a mixin:

    .. attribute:: backends
    
        This attribute should be a tuple containing the names of the backends
        which are supported. Two common names are ``"os_crypt"`` (if backend
        uses :mod:`crypt`), and ``"builtin"`` (if the backend is a pure-python
        fallback). 

    .. attribute:: _has_backend_{name}

        private class attribute checked by :meth:`has_backend` to see if a
        specific backend is available, it should be either ``True``
        or ``False``. One of these should be provided by
        the subclass for each backend listed in :attr:`backends`.
        
    .. classmethod:: _calc_checksum_{name}
    
        private class method that should implement :meth:`calc_checksum`
        for a given backend. it will only be called if the backend has
        been selected by :meth:`set_backend`. One of these should be provided
        by the subclass for each backend listed in :attr:`backends`.
    """

    #NOTE: subclass must provide:
    #   * attr 'backends' containing list of known backends (top priority backend first)
    #   * attr '_has_backend_xxx' for each backend 'xxx', indicating if backend is available on system
    #   * attr '_calc_checksum_xxx' for each backend 'xxx', containing calc_checksum implementation using that backend

    backends = None #: list of backend names, provided by subclass.

    _backend = None #: holds currently loaded backend (if any) or None

    @classmethod
    def get_backend(cls):
        """return name of currently active backend.

        if no backend has been loaded,
        loads and returns name of default backend.

        :raises MissingBackendError: if no backends are available.

        :returns: name of active backend
        """
        name = cls._backend
        if not name:
            cls.set_backend()
            name = cls._backend
            assert name, "set_backend() didn't load any backends"
        return name

    @classmethod
    def has_backend(cls, name="any"):
        """check if support is currently available for specified backend.

        :arg name:
            name of backend to check for.
            defaults to ``"any"``,
            but can be any string accepted by :meth:`set_backend`.

        :raises ValueError: if backend name is unknown

        :returns:
            ``True`` if backend is currently supported, else ``False``.
        """
        if name in (None, "any", "default"):
            if name is None:
                warn("has_backend(None) is deprecated,"
                     " and support will be removed in Passlib 1.6;"
                     " use has_backend('any') instead.",
                    DeprecationWarning, stacklevel=2)
            try:
                cls.set_backend()
                return True
            except MissingBackendError:
                return False
        elif name in cls.backends:
            return getattr(cls, "_has_backend_" + name)
        else:
            raise ValueError("unknown backend: %r" % (name,))

    @classmethod
    def _no_backends_msg(cls):
        return "no %s backends available" % (cls.name,)

    @classmethod
    def set_backend(cls, name="any"):
        """load specified backend to be used for future calc_checksum() calls

        this method replaces :meth:`calc_checksum` with a method
        which uses the specified backend.

        :arg name:
            name of backend to load, defaults to ``"any"``.
            this can be any of the following values:

            * any string in :attr:`backends`,
              indicating the specific backend to use.

            * the special string ``"default"``, which means to use
              the preferred backend on the given host
              (this is generally the first backend in :attr:`backends`
              which can be loaded).

            * the special string ``"any"``, which means to use
              the current backend if one has been loaded,
              else acts like ``"default"``.

        :raises MissingBackendError:
            * if a specific backend was specified,
              but is not currently available.

            * if ``"any"`` or ``"default"`` was specified,
              and NO backends are currently available.
    
        return value should be ignored.
        
        .. note::

            :exc:`~passlib.utils.MissingBackendError` derives
            from :exc:`RuntimeError`, since this usually indicates
            lack of an external library or OS feature.
        """
        if name is None:
            warn("set_backend(None) is deprecated,"
                 " and support will be removed in Passlib 1.6;"
                 " use set_backend('any') instead.",
                DeprecationWarning, stacklevel=2)
            name = "any"
        if name == "any":
            name = cls._backend
            if name:
                return name
            name = "default"
        if name == "default":
            for name in cls.backends:
                if cls.has_backend(name):
                    break
            else:
                raise MissingBackendError(cls._no_backends_msg())
        elif not cls.has_backend(name):
            raise MissingBackendError("%s backend not available: %r" % (cls.name, name))
        cls.calc_checksum = getattr(cls, "_calc_checksum_" + name)
        cls._backend = name
        return name

    def calc_checksum(self, secret):
        "stub for calc_checksum(), default backend will be selected first time stub is called"
        #backend not loaded - run detection and call replacement
        assert not self._backend, "set_backend() failed to replace lazy loader"
        self.set_backend()
        assert self._backend, "set_backend() failed to load a default backend"
        #set_backend() should have replaced this method, so call it again.
        return self.calc_checksum(secret)

#=========================================================
#wrappers
#=========================================================
class PrefixWrapper(object):
    """wraps another handler, adding a constant prefix.

    instances of this class wrap another password hash handler,
    altering the constant prefix that's prepended to the wrapped
    handlers' hashes.

    this is used mainly by the :doc:`ldap crypt <passlib.hash.ldap_crypt>` handlers;
    such as :class:`~passlib.hash.ldap_md5_crypt` which wraps :class:`~passlib.hash.md5_crypt` and adds a ``{CRYPT}`` prefix.

    usage::

        myhandler = PrefixWrapper("myhandler", "md5_crypt", prefix="$mh$", orig_prefix="$1$")

    :param name: name to assign to handler
    :param wrapped: handler object or name of registered handler
    :param prefix: identifying prefix to prepend to all hashes
    :param orig_prefix: prefix to strip (defaults to '').
    :param lazy: if True and wrapped handler is specified by name, don't look it up until needed.
    """

    def __init__(self, name, wrapped, prefix=u'', orig_prefix=u'', lazy=False, doc=None):
        self.name = name
        if isinstance(prefix, bytes):
            prefix = prefix.decode("ascii")
        self.prefix = prefix
        if isinstance(orig_prefix, bytes):
            orig_prefix = orig_prefix.decode("ascii")
        self.orig_prefix = orig_prefix
        if doc:
            self.__doc__ = doc
        if hasattr(wrapped, "name"):
            self._check_handler(wrapped)
            self._wrapped_handler = wrapped
        else:
            self._wrapped_name = wrapped
            if not lazy:
                self._get_wrapped()

    _wrapped_name = None
    _wrapped_handler = None

    def _check_handler(self, handler):
        if 'ident' in handler.setting_kwds and self.orig_prefix:
            #TODO: look into way to fix the issues.
            warn("PrefixWrapper: 'orig_prefix' option may not work correctly for handlers which have multiple identifiers: %r" % (handler.name,))

    def _get_wrapped(self):
        handler = self._wrapped_handler
        if handler is None:
            handler = get_crypt_handler(self._wrapped_name)
            self._check_handler(handler)
            self._wrapped_handler = handler
        return handler

    wrapped = property(_get_wrapped)

    ##@property
    ##def ident(self):
    ##    return self._prefix

    #attrs that should be proxied
    _proxy_attrs = (
                    "setting_kwds", "context_kwds",
                    "default_rounds", "min_rounds", "max_rounds", "rounds_cost",
                    "backends", "has_backend", "get_backend", "set_backend",
                    )

    def __repr__(self):
        args = [ repr(self._wrapped_name or self._wrapped_handler) ]
        if self.prefix:
            args.append("prefix=%r" % self.prefix)
        if self.orig_prefix:
            args.append("orig_prefix=%r", self.orig_prefix)
        args = ", ".join(args)
        return 'PrefixWrapper(%r, %s)' % (self.name, args)

    def __getattr__(self, attr):
        "proxy most attributes from wrapped class (eg rounds, salt size, etc)"
        if attr in self._proxy_attrs:
            return getattr(self.wrapped, attr)
        raise AttributeError("missing attribute: %r" % (attr,))

    def _unwrap_hash(self, hash):
        "given hash belonging to wrapper, return orig version"
        if isinstance(hash, bytes):
            hash = hash.decode('ascii')
        prefix = self.prefix
        if not hash.startswith(prefix):
            raise ValueError("not a valid %s hash" % (self.name,))
        #NOTE: always passing to handler as unicode, to save reconversion
        return self.orig_prefix + hash[len(prefix):]

    def _wrap_hash(self, hash):
        "given orig hash; return one belonging to wrapper"
        #NOTE: should usually be native string.
        # (which does mean extra work under py2, but not py3)
        if isinstance(hash, bytes):
            hash = hash.decode('ascii')
        orig_prefix = self.orig_prefix
        if not hash.startswith(orig_prefix):
            raise ValueError("not a valid %s hash" % (self.wrapped.name,))
        wrapped = self.prefix + hash[len(orig_prefix):]
        return to_hash_str(wrapped)

    def identify(self, hash):
        if not hash:
            return False
        if isinstance(hash, bytes):
            hash = hash.decode('ascii')
        if not hash.startswith(self.prefix):
            return False
        hash = self._unwrap_hash(hash)
        return self.wrapped.identify(hash)

    def genconfig(self, **kwds):
        config = self.wrapped.genconfig(**kwds)
        if config:
            return self._wrap_hash(config)
        else:
            return config

    def genhash(self, secret, config, **kwds):
        if config:
            config = self._unwrap_hash(config)
        return self._wrap_hash(self.wrapped.genhash(secret, config, **kwds))

    def encrypt(self, secret, **kwds):
        return self._wrap_hash(self.wrapped.encrypt(secret, **kwds))

    def verify(self, secret, hash, **kwds):
        if not hash:
            raise ValueError("no %s hash specified" % (self.name,))
        hash = self._unwrap_hash(hash)
        return self.wrapped.verify(secret, hash, **kwds)

#=========================================================
# eof
#=========================================================
