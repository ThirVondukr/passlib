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
from passlib.exc import MissingBackendError, PasslibHandlerWarning, \
                        PasslibRuntimeWarning
from passlib.registry import get_crypt_handler
from passlib.utils import is_crypt_handler
from passlib.utils import classproperty, consteq, getrandstr, getrandbytes,\
                          BASE64_CHARS, HASH64_CHARS, rng, to_native_str
from passlib.utils.compat import b, bjoin_ints, bytes, irange, u, \
                                 uascii_to_str, ujoin, unicode
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

# common salt_chars & checksum_chars values
# (BASE64_CHARS, HASH64_CHARS imported above)
PADDED_BASE64_CHARS = BASE64_CHARS + u("=")
HEX_CHARS = u("0123456789abcdefABCDEF")
UPPER_HEX_CHARS = u("0123456789ABCDEF")
LOWER_HEX_CHARS = u("0123456789abcdef")

#: special byte string containing all possible byte values
# XXX: treated as singleton by some of the code for efficiency.
ALL_BYTE_VALUES = bjoin_ints(irange(256))

# deprecated aliases - will be removed after passlib 1.8
H64_CHARS = HASH64_CHARS
B64_CHARS = BASE64_CHARS
PADDED_B64_CHARS = PADDED_BASE64_CHARS
UC_HEX_CHARS = UPPER_HEX_CHARS
LC_HEX_CHARS = LOWER_HEX_CHARS

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
def parse_mc2(hash, prefix, name="<unnamed>", sep=u("$")):
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

def parse_mc3(hash, prefix, name="<unnamed>", sep=u("$")):
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
def render_mc2(ident, salt, checksum, sep=u("$")):
    "format hash using 2-part modular crypt format; inverse of parse_mc2"
    if checksum:
        hash = u("%s%s%s%s") % (ident, salt, sep, checksum)
    else:
        hash = u("%s%s") % (ident, salt)
    return uascii_to_str(hash)

def render_mc3(ident, rounds, salt, checksum, sep=u("$")):
    "format hash using 3-part modular crypt format; inverse of parse_mc3"
    if checksum:
        hash = u("%s%s%s%s%s%s") % (ident, rounds, sep, salt, sep, checksum)
    else:
        hash = u("%s%s%s%s") % (ident, rounds, sep, salt)
    return uascii_to_str(hash)

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

    # reserved value to be returned by default genconfig()
    # may be ``None`` if no such value; otherwise should be native ascii str.
    _stub_config = None

    #=====================================================
    #methods
    #=====================================================
    @classmethod
    def identify(cls, hash):
        #NOTE: this relys on genhash() throwing error for invalid hashes.
        # this approach is bad because genhash may take a long time on valid hashes,
        # so subclasses *really* should override this.
        if hash is None:
            return False
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
        if hash == cls._stub_config:
            raise ValueError("expected %s hash, got %s config string instead" %
                             (cls.name, cls.name))
        result = cls.genhash(secret, hash, *cargs, **context)
        return consteq(result, hash)

    @classmethod
    def _norm_hash(cls, hash):
        """[helper for verify] normalize hash for comparsion purposes.

        should return a native :class:`str` instance or raise a TypeError.
        """
        return to_native_str(hash, "ascii", errname="hash")

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

    :param use_defaults:
        If ``False`` (the default), a :exc:`TypeError` should be thrown
        if any settings required by the handler were not explicitly provided.

        If ``True``, the handler should attempt to provide a default for any
        missing values. This means generate missing salts, fill in default
        cost parameters, etc.

        This is typically only set to ``True`` when the constructor
        is called by :meth:`encrypt`, allowing user-provided values
        to be handled in a more permissive manner.

    :param relaxed:
        If ``False`` (the default), a :exc:`ValueError` should be thrown
        if any settings are out of bounds or otherwise invalid.

        If ``True``, they should be corrected if possible, and a warning
        issue. If not possible, only then should an error be raised.
        (e.g. under ``relaxed=True``, rounds values will be clamped
        to min/max rounds).

        This is mainly used when parsing the config strings of certain
        hashes, whose specifications implementations to be tolerant
        of incorrect values in salt strings.

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

        The checksum string as provided by the constructor (after passing it
        through :meth:`_norm_checksum`).

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

    .. automethod:: _norm_checksum

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

    checksum_size = None #if specified, _norm_checksum will require this length
    checksum_chars = None #if specified, _norm_checksum() will validate this

    #=====================================================
    #instance attrs
    #=====================================================
    checksum = None # stores checksum
#    relaxed = False # when norm_xxx() funcs should be strict about inputs
#    use_defaults = False # whether norm_xxx() funcs should fill in defaults.

    #=====================================================
    #init
    #=====================================================
    def __init__(self, checksum=None, use_defaults=False, relaxed=False,
                 **kwds):
        self.use_defaults = use_defaults
        self.relaxed = relaxed
        super(GenericHandler, self).__init__(**kwds)
        self.checksum = self._norm_checksum(checksum)

    def _norm_checksum(self, checksum):
        """validates checksum keyword against class requirements,
        returns normalized version of checksum.
        """
        # NOTE: this code assumes checksum should be a unicode string.
        # For classes where the checksum is raw bytes, the HasRawChecksum
        # mixin overrides this method with a more appropriate one.
        if checksum is None:
            return None

        # normalize to unicode
        if isinstance(checksum, bytes):
            checksum = checksum.decode('ascii')

        # check size
        cc = self.checksum_size
        if cc and len(checksum) != cc:
            raise ValueError("checksum wrong size (%s checksum must be "
                             "exactly %d characters" % (self.name, cc))

        # check charset
        cs = self.checksum_chars
        if cs:
            bad = set(checksum)
            bad.difference_update(cs)
            if bad:
                raise ValueError("invalid characters in %s checksum: %r" %
                                 (self.name, ujoin(sorted(bad))))

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
        return cls(use_defaults=True, **settings).to_string()

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
        self = cls(use_defaults=True, **settings)
        self.checksum = self.calc_checksum(secret)
        return self.to_string()

    @classmethod
    def verify(cls, secret, hash):
        #NOTE: classes with multiple checksum encodings (rare)
        # may wish to either override this, or override norm_checksum
        # to normalize any checksums provided by from_string()
        self = cls.from_string(hash)
        chk = self.checksum
        if chk is None:
            raise ValueError("expected %s hash, got %s config string instead" %
                             (cls.name, cls.name))
        return consteq(self.calc_checksum(secret), chk)

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

    def _norm_checksum(self, checksum):
        if checksum is None:
            return None
        if isinstance(checksum, unicode):
            raise TypeError("checksum must be specified as bytes")
        cc = self.checksum_size
        if cc and len(checksum) != cc:
            raise ValueError("checksum wrong size (%s checksum must be "
                             "exactly %d characters" % (self.name, cc))
        return checksum

class HasStubChecksum(GenericHandler):
    """modifies class to ignore placeholder checksum used by genconfig().

    this is mainly useful for hash formats which don't have a distinguishable
    configuration-only format; and genconfig() has to use a placeholder
    digest (usually all NULLs). this mixin causes that checksum to be
    treated as if there wasn't a checksum at all; preventing the (remote)
    chance of a configuration string 1) being stored as a hash, followed by
    2) an attacker finding and trying a password which correctly maps to that
    digest.
    """
    _stub_checksum = None

    def __init__(self, **kwds):
        super(HasStubChecksum, self).__init__(**kwds)
        chk = self.checksum
        if chk is not None and chk == self._stub_checksum:
            self.checksum = None

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
    def __init__(self, ident=None, **kwds):
        super(HasManyIdents, self).__init__(**kwds)
        self.ident = self._norm_ident(ident)

    def _norm_ident(self, ident):
        # fill in default identifier
        if ident is None:
            if not self.use_defaults:
                raise TypeError("no ident specified")
            ident = self.default_ident
            assert ident is not None, "class must define default_ident"

        # handle unicode
        if isinstance(ident, bytes):
            ident = ident.decode('ascii')

        # check if identifier is valid
        iv = self.ident_values
        if ident in iv:
            return ident

        # resolve aliases, and recheck against ident_values
        ia = self.ident_aliases
        if ia:
            try:
                value = ia[ident]
            except KeyError:
                pass
            else:
                if value in iv:
                    return value

        # failure!
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
    #XXX: allow providing raw salt to this class, and encoding it?

    #=========================================================
    #class attrs
    #=========================================================

    min_salt_size = None
    max_salt_size = None
    salt_chars = None

    @classproperty
    def default_salt_size(cls):
        "default salt chars (defaults to max_salt_size if not specified by subclass)"
        return cls.max_salt_size

    @classproperty
    def default_salt_chars(cls):
        "required - set of characters used to generate *new* salt strings (defaults to salt_chars)"
        return cls.salt_chars

    # private helpers for HasRawSalt, shouldn't be used by subclasses
    _salt_is_bytes = False
    _salt_unit = "chars"

    #=========================================================
    #instance attrs
    #=========================================================
    salt = None

    #=========================================================
    #init
    #=========================================================
    def __init__(self, salt=None, salt_size=None, **kwds):
        super(HasSalt, self).__init__(**kwds)
        self.salt = self._norm_salt(salt, salt_size=salt_size)

    def _norm_salt(self, salt, salt_size=None):
        """helper to normalize & validate user-provided salt string

        If no salt provided, a random salt is generated
        using :attr:`default_salt_size` and :attr:`default_salt_chars`.

        :arg salt: salt string or ``None``
        :param salt_size: optionally specified size of autogenerated salt

        :raises TypeError:
            If salt not provided and ``use_defaults=False``.

        :raises ValueError:

            * if salt contains chars that aren't in :attr:`salt_chars`.
            * if salt contains less than :attr:`min_salt_size` characters.
            * if ``relaxed=False`` and salt has more than :attr:`max_salt_size`
              characters (if ``relaxed=True``, the salt is truncated
              and a warning is issued instead).

        :returns:
            normalized or generated salt
        """
        # generate new salt if none provided
        if salt is None:
            if not self.use_defaults:
                raise TypeError("no salt specified")
            if salt_size is None:
                salt_size = self.default_salt_size
            salt = self._generate_salt(salt_size)

        # check type
        if self._salt_is_bytes:
            if not isinstance(salt, bytes):
                raise TypeError("salt must be specified as bytes")
        else:
            if not isinstance(salt, unicode):
                if isinstance(salt, bytes):
                    salt = salt.decode("ascii")
                else:
                    raise TypeError("salt must be specified as unicode")

            # check charset
            sc = self.salt_chars
            if sc is not None:
                bad = set(salt)
                bad.difference_update(sc)
                if bad:
                    raise ValueError("invalid characters in %s salt: %r" %
                                     (self.name, ujoin(sorted(bad))))

        # check min size
        mn = self.min_salt_size
        if mn and len(salt) < mn:
            msg = "salt too small (%s requires %s %d %s)" % (self.name,
                        "exactly" if mn == self.max_salt_size else ">=", mn,
                        self._salt_unit)
            raise ValueError(msg)

        # check max size
        mx = self.max_salt_size
        if mx and len(salt) > mx:
            msg = "salt too large (%s requires %s %d %s)" % (self.name,
                        "exactly" if mx == mn else "<=", mx, self._salt_unit)
            if self.relaxed:
                warn(msg, PasslibHandlerWarning)
                salt = self._truncate_salt(salt, mx)
            else:
                raise ValueError(msg)

        return salt

    @staticmethod
    def _truncate_salt(salt, mx):
        # NOTE: some hashes (e.g. bcrypt) has structure within their
        # salt string. this provides a method to overide to perform
        # the truncation properly
        return salt[:mx]

    def _generate_salt(self, salt_size):
        """helper method for _norm_salt(); generates a new random salt string.
        :arg salt_size: salt size to generate
        """
        return getrandstr(rng, self.default_salt_chars, salt_size)

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
    _salt_unit = "bytes"

    def _generate_salt(self, salt_size):
        assert self.salt_chars in [None, ALL_BYTE_VALUES]
        return getrandbytes(rng, salt_size)

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
    max_rounds = None
    defaults_rounds = None
    rounds_cost = "linear" # default to the common case

    #=========================================================
    #instance attrs
    #=========================================================
    rounds = None

    #=========================================================
    #init
    #=========================================================
    def __init__(self, rounds=None, **kwds):
        super(HasRounds, self).__init__(**kwds)
        self.rounds = self._norm_rounds(rounds)

    def _norm_rounds(self, rounds):
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
        # fill in default
        if rounds is None:
            if not self.use_defaults:
                raise TypeError("no rounds specified")
            rounds = self.default_rounds
            if rounds is None:
                raise TypeError("%s rounds value must be specified explicitly"
                                 % (self.name,))

        # check type
        if not isinstance(rounds, int):
            raise TypeError("rounds must be an integer")

        # check bounds
        mn = self.min_rounds
        if rounds < mn:
            msg = "rounds too low (%s requires >= %d rounds)"  % (self.name, mn)
            if self.relaxed:
                warn(msg, PasslibHandlerWarning)
                rounds = mn
            else:
                raise ValueError(msg)

        mx = self.max_rounds
        if mx and rounds > mx:
            msg = "rounds too high (%s requires <= %d rounds)"  % (self.name, mx)
            if self.relaxed:
                warn(msg, PasslibHandlerWarning)
                rounds = mx
            else:
                raise ValueError(msg)

        return rounds

    #=========================================================
    #eoc
    #=========================================================

def _clear_backend(cls):
    "restore HasManyBackend subclass to unloaded state - used by unittests"
    assert issubclass(cls, HasManyBackends) and cls is not HasManyBackends
    if cls._backend:
        del cls._backend
        del cls.calc_checksum

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

        :raises passlib.exc.MissingBackendError: if no backends are available.

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
        if name in ("any", "default"):
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

        :raises passlib.exc.MissingBackendError:
            * ... if a specific backend was requested,
              but is not currently available.

            * ... if ``"any"`` or ``"default"`` was specified,
              and *no* backends are currently available.

        :returns:

            The return value of this function should be ignored.
        """
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

    def __init__(self, name, wrapped, prefix=u(''), orig_prefix=u(''), lazy=False,
                 doc=None, ident=None):
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

        if ident is not None:
            if isinstance(ident, bytes):
                ident = ident.decode("ascii")
            if ident[:len(prefix)] != prefix[:len(ident)]:
                raise ValueError("ident agree with prefix")
            self._ident = ident

    _wrapped_name = None
    _wrapped_handler = None

    def _check_handler(self, handler):
        if 'ident' in handler.setting_kwds and self.orig_prefix:
            #TODO: look into way to fix the issues.
            warn("PrefixWrapper: 'orig_prefix' option may not work correctly "
                 "for handlers which have multiple identifiers: %r" %
                 (handler.name,), PasslibRuntimeWarning)

    def _get_wrapped(self):
        handler = self._wrapped_handler
        if handler is None:
            handler = get_crypt_handler(self._wrapped_name)
            self._check_handler(handler)
            self._wrapped_handler = handler
        return handler

    wrapped = property(_get_wrapped)

    _ident = False

    @property
    def ident(self):
        value = self._ident
        if value is False:
            value = None
            # XXX: how will this interact with orig_prefix ?
            #      not exposing attrs for now if orig_prefix is set.
            if not self.orig_prefix:
                wrapped = self.wrapped
                ident = getattr(wrapped, "ident", None)
                if ident is not None:
                    value = self._wrap_hash(ident)
            self._ident = value
        return value

    _ident_values = False

    @property
    def ident_values(self):
        value = self._ident_values
        if value is False:
            value = None
            # XXX: how will this interact with orig_prefix ?
            #      not exposing attrs for now if orig_prefix is set.
            if not self.orig_prefix:
                wrapped = self.wrapped
                idents = getattr(wrapped, "ident_values", None)
                if idents:
                    value = [ self._wrap_hash(ident) for ident in idents ]
                ##else:
                ##    ident = self.ident
                ##    if ident is not None:
                ##        value = [ident]
            self._ident_values = value
        return value

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
            args.append("orig_prefix=%r" % self.orig_prefix)
        args = ", ".join(args)
        return 'PrefixWrapper(%r, %s)' % (self.name, args)

    def __dir__(self):
        attrs = set(dir(self.__class__))
        attrs.update(self.__dict__)
        wrapped = self.wrapped
        attrs.update(
            attr for attr in self._proxy_attrs
            if hasattr(wrapped, attr)
        )
        return list(attrs)

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
        return uascii_to_str(wrapped)

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
