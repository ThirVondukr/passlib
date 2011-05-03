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
from passlib.utils import classproperty, h64, getrandstr, getrandbytes, \
        rng, is_crypt_handler, ALL_BYTE_VALUES
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
B64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
HEX_CHARS = "0123456789abcdefABCDEF"
UC_HEX_CHARS = "0123456789ABCDEF"
LC_HEX_CHARS = "0123456789abcdef"

#=========================================================
#parsing helpers
#=========================================================
def parse_mc2(hash, prefix, name="<unnamed>", sep="$"):
    "parse hash using 2-part modular crypt format"
    #eg: MD5-Crypt: $1$salt[$checksum]
    if not hash:
        raise ValueError("no hash specified")
    if isinstance(hash, unicode):
        hash = hash.encode("ascii")
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

def parse_mc3(hash, prefix, name="<unnamed>", sep="$"):
    "parse hash using 3-part modular crypt format"
    #eg: SHA1-Crypt: $sha1$rounds$salt[$checksum]
    if not hash:
        raise ValueError("no hash specified")
    if isinstance(hash, unicode):
        hash = hash.encode("ascii")
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

#=========================================================
#base handler
#=========================================================
class SimpleHandler(object):
    """helper for implementing password hash handler with minimal methods

    .. warning::

        this class is deprecated, and will be removed in Passlib 1.5

    hash implementations should fill out the following:

        * all required class attributes: name, setting_kwds
        * classmethods genconfig() and genhash()

    many implementations will want to override the following:

        * classmethod identify() can usually be done more efficiently

    most implementations can use defaults for the following:

        * encrypt(), verify()

    note this class does not support context kwds of any type,
    since that is a rare enough requirement inside passlib.

    implemented subclasses may call cls.validate_class() to check attribute consistency
    (usually only required in unittests, etc)
    """

    #=====================================================
    #required attributes
    #=====================================================
    name = None #required by subclass
    setting_kwds = None #required by subclass
    context_kwds = ()

    #=====================================================
    #init helpers
    #=====================================================
    @classmethod
    def _warndep(cls):
        alt = "GenericHandler" if cls._has_settings else "StaticHandler"
        msg = "SimpleHandler is deprecated, and will be removed in Passlib 1.5; %s should derived from %s instead" % (cls, alt)
        warn(msg, DeprecationWarning)

    @classproperty
    def _has_settings(cls):
        "attr for checking if class has ANY settings, memoizes itself on first use"
        if cls.name is None:
            #otherwise this would optimize itself away prematurely
            raise RuntimeError("_has_settings must only be called on subclass: %r" % (cls,))
        value = cls._has_settings = bool(cls.setting_kwds)
        return value

    #=====================================================
    #formatting (usually subclassed)
    #=====================================================
    @classmethod
    def identify(cls, hash):
        cls._warndep()
        #NOTE: this relys on genhash throwing error for invalid hashes.
        # this approach is bad because genhash may take a long time on valid hashes,
        # so subclasses *really* should override this.
        try:
            cls.genhash('stub', hash)
            return True
        except ValueError:
            return False

    #=====================================================
    #primary interface (must be subclassed)
    #=====================================================
    @classmethod
    def genconfig(cls, **settings):
        cls._warndep()
        if cls._has_settings:
            raise NotImplementedError("%s subclass must implement genconfig()" % (cls,))
        else:
            if settings:
                raise TypeError("%s genconfig takes no kwds" % (cls.name,))
            return None

    @classmethod
    def genhash(cls, secret, config):
        raise NotImplementedError("%s subclass must implement genhash()" % (cls,))

    #=====================================================
    #secondary interface (rarely subclassed)
    #=====================================================
    @classmethod
    def encrypt(cls, secret, **settings):
        cls._warndep()
        config = cls.genconfig(**settings)
        return cls.genhash(secret, config)

    @classmethod
    def verify(cls, secret, hash):
        cls._warndep()
        if not hash:
            raise ValueError("no hash specified")
        return hash == cls.genhash(secret, hash)

    #=====================================================
    #eoc
    #=====================================================

#=========================================================
# ExtendedHandler
#   rounds+salt+xtra    phpass, sha256_crypt, sha512_crypt
#   rounds+salt         bcrypt, ext_des_crypt, sha1_crypt, sun_md5_crypt
#   salt                apr_md5_crypt, des_crypt, md5_crypt
#   nothing             mysql_323, mysql_41, nthash, postgres_md5
#=========================================================
class ExtendedHandler(SimpleHandler):
    """helper class for implementing hash schemes

    .. warning::

        this class is deprecated, and will be removed in Passlib 1.5

    hash implementations should fill out the following:
        * all required class attributes:
            - name, setting_kwds
            - max_salt_chars, min_salt_chars - only if salt is used
            - max_rounds, min_rounds, default_rounds - only if rounds are used
        * classmethod from_string()
        * instancemethod to_string()
        * instancemethod calc_checksum()

    many implementations will want to override the following:
        * classmethod identify() can usually be done more efficiently
        * checksum_charset, checksum_chars attributes may prove helpful for validation

    most implementations can use defaults for the following:
        * genconfig(), genhash(), encrypt(), verify(), etc
        * norm_checksum() usually only needs overriding if checksum has multiple encodings
        * salt_charset, default_salt_charset, default_salt_chars - if does not match common case

    note this class does not support context kwds of any type,
    since that is a rare enough requirement inside passlib.

    implemented subclasses may call cls.validate_class() to check attribute consistency
    (usually only required in unittests, etc)
    """

    #=========================================================
    #class attributes
    #=========================================================

    #----------------------------------------------
    #password hash api - required attributes
    #----------------------------------------------
    name = None #required by ExtendedHandler
    setting_kwds = None #required by ExtendedHandler
    context_kwds = ()

    #----------------------------------------------
    #checksum information
    #----------------------------------------------
    checksum_charset = None #if specified, norm_checksum() will validate this
    checksum_chars = None #if specified, norm_checksum will require this length

    #----------------------------------------------
    #salt information
    #----------------------------------------------
    max_salt_chars = None #required by ExtendedHandler.norm_salt()

    @classproperty
    def min_salt_chars(cls):
        "min salt chars (defaults to max_salt_chars if not specified by subclass)"
        return cls.max_salt_chars

    @classproperty
    def default_salt_chars(cls):
        "default salt chars (defaults to max_salt_chars if not specified by subclass)"
        return cls.max_salt_chars

    salt_charset = h64.CHARS

    @classproperty
    def default_salt_charset(cls):
        return cls.salt_charset

    #----------------------------------------------
    #rounds information
    #----------------------------------------------
    min_rounds = 0
    max_rounds = None #required by ExtendedHandler.norm_rounds()
    default_rounds = None #if not specified, ExtendedHandler.norm_rounds() will require explicit rounds value every time
    rounds_cost = "linear" #common case

    #----------------------------------------------
    #misc ExtendedHandler configuration
    #----------------------------------------------
    _strict_rounds_bounds = False #if true, always raises error if specified rounds values out of range - required by spec for some hashes
    _extra_init_settings = () #settings that ExtendedHandler.__init__ should handle by calling norm_<key>()

    #=========================================================
    #instance attributes
    #=========================================================
    checksum = None
    salt = None
    rounds = None

    #=========================================================
    #init
    #=========================================================
    @classmethod
    def _warndep(cls):
        msg = "ExtendedHandler is deprecated, and will be removed in Passlib 1.5; %s should use GenericHandler instead" % (cls,)
        warn(msg, DeprecationWarning)

    #XXX: rename strict kwd to _strict ?
    #XXX: for from_string() purposes, a strict_salt kwd to override strict, might also be useful
    def __init__(self, checksum=None, salt=None, rounds=None, strict=False, **kwds):
        self._warndep()
        self.checksum = self.norm_checksum(checksum, strict=strict)
        self.salt = self.norm_salt(salt, strict=strict)
        self.rounds = self.norm_rounds(rounds, strict=strict)
        extra = self._extra_init_settings
        if extra:
            for key in extra:
                value = kwds.pop(key, None)
                norm = getattr(self, "norm_" + key)
                value = norm(value, strict=strict)
                setattr(self, key, value)
        super(ExtendedHandler, self).__init__(**kwds)

    #=========================================================
    #init helpers
    #=========================================================

    #---------------------------------------------------------
    #internal tests for features
    #---------------------------------------------------------

    @classproperty
    def _has_salt(cls):
        "attr for checking if salts are supported, memoizes itself on first use"
        cls._warndep()
        if cls is ExtendedHandler:
            raise RuntimeError("not allowed for ExtendedHandler directly")
        value = cls._has_salt = 'salt' in cls.setting_kwds
        return value

    @classproperty
    def _has_rounds(cls):
        "attr for checking if variable are supported, memoizes itself on first use"
        cls._warndep()
        if cls is ExtendedHandler:
            raise RuntimeError("not allowed for ExtendedHandler directly")
        value = cls._has_rounds = 'rounds' in cls.setting_kwds
        return value

    @classproperty
    def _salt_is_bytes(cls):
        "helper for detecting if salt kwd uses unencoded bytes string instead of encoding set of specified letters"
        cls._warndep()
        #FIXME: how we're handling unencoded salts vs encoded salts between diff handlers is a serious mess.
        # need to clean it all up. for now, there's this property,
        # to begin sweeping things under the rug.
        if cls is ExtendedHandler:
            raise RuntimeError("not allowed for ExtendedHandler directly")
        value = cls._salt_is_bytes = cls._has_salt and cls.salt_charset == ALL_BYTE_VALUES
        return value

    #---------------------------------------------------------
    #normalization/validation helpers
    #---------------------------------------------------------
    @classmethod
    def norm_checksum(cls, checksum, strict=False):
        cls._warndep()
        if checksum is None:
            return None
        cc = cls.checksum_chars
        if cc and len(checksum) != cc:
            raise ValueError("%s checksum must be %d characters" % (cls.name, cc))
        cs = cls.checksum_charset
        if cs and any(c not in cs for c in checksum):
            raise ValueError("invalid characters in %s checksum" % (cls.name,))
        return checksum

    @classmethod
    def norm_salt(cls, salt, strict=False):
        """helper to normalize & validate user-provided salt string

        :arg salt: salt string or ``None``
        :param strict: enable strict checking (see below); disabled by default

        :raises ValueError:

            * if ``strict=True`` and no salt is provided
            * if ``strict=True`` and salt contains greater than :attr:`max_salt_chars` characters
            * if salt contains chars that aren't in :attr:`salt_charset`.
            * if salt contains less than :attr:`min_salt_chars` characters.

        if no salt provided and ``strict=False``, a random salt is generated
        using :attr:`default_salt_chars` and :attr:`default_salt_charset`.
        if the salt is longer than :attr:`max_salt_chars` and ``strict=False``,
        the salt string is clipped to :attr:`max_salt_chars`.

        :returns:
            normalized or generated salt
        """
        cls._warndep()
        if not cls._has_salt:
            #NOTE: special casing schemes which have no salt...
            if salt is not None:
                raise TypeError("%s does not support ``salt`` parameter" % (cls.name,))
            return None

        if salt is None:
            if strict:
                raise ValueError("no salt specified")
            if cls._salt_is_bytes:
                return getrandbytes(rng, cls.default_salt_chars)
            else:
                return getrandstr(rng, cls.default_salt_charset, cls.default_salt_chars)

        if cls._salt_is_bytes:
            if isinstance(salt, unicode):
                salt = salt.encode("utf-8")
        else:
            sc = cls.salt_charset
            for c in salt:
                if c not in sc:
                    raise ValueError("invalid character in %s salt: %r"  % (cls.name, c))

        mn = cls.min_salt_chars
        if mn and len(salt) < mn:
            raise ValueError("%s salt string must be at least %d characters" % (cls.name, mn))

        mx = cls.max_salt_chars
        if len(salt) > mx:
            if strict:
                raise ValueError("%s salt string must be at most %d characters" % (cls.name, mx))
            salt = salt[:mx]

        return salt

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
        cls._warndep()
        #XXX: for speed, could optimize this by replacing method at class level
        # when cls._has_rounds check is first called.
        # could make same optimization for norm_salt()

        if not cls._has_rounds:
            #NOTE: special casing schemes which don't have rounds
            if rounds is not None:
                raise TypeError("%s does not support ``rounds``" % (cls.name,))
            return None

        if rounds is None:
            if strict:
                raise ValueError("no rounds specified")
            rounds = cls.default_rounds
            if rounds is None:
                raise ValueError("%s rounds value must be specified explicitly" % (cls.name,))
            return rounds

        if cls._strict_rounds_bounds:
            strict = True

        mn = cls.min_rounds
        if rounds < mn:
            if strict:
                raise ValueError("%s rounds must be >= %d" % (cls.name, mn))
            warn("%s does not allow less than %d rounds: %d" % (cls.name, mn, rounds))
            rounds = mn

        mx = cls.max_rounds
        if rounds > mx:
            if strict:
                raise ValueError("%s rounds must be <= %d" % (cls.name, mx))
            warn("%s does not allow more than %d rounds: %d" % (cls.name, mx, rounds))
            rounds = mx

        return rounds

    #=========================================================
    #password hash api - formatting interface
    #=========================================================
    @classmethod
    def identify(cls, hash):
        cls._warndep()
        #NOTE: subclasses may wish to use faster / simpler identify,
        # and raise value errors only when an invalid (but identifiable) string is parsed
        if not hash:
            return False
        try:
            cls.from_string(hash)
            return True
        except ValueError:
            return False

    @classmethod
    def from_string(cls, hash): #pragma: no cover
        "return parsed instance from hash/configuration string; raising ValueError on invalid inputs"
        raise NotImplementedError("%s must implement from_string()" % (cls,))

    def to_string(self): #pragma: no cover
        "render instance to hash or configuration string (depending on if checksum attr is set)"
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
        cls._warndep()
        if cls._has_settings:
            return cls(**settings).to_string()
        elif settings:
            raise TypeError("%s.genconfig() takes no arguments" % (cls.name,))
        else:
            return None

    @classmethod
    def genhash(cls, secret, config):
        cls._warndep()
        if cls._has_settings or config is not None:
            self = cls.from_string(config)
        else:
            self = cls()
        self.checksum = self.calc_checksum(secret)
        return self.to_string()

    def calc_checksum(self, secret): #pragma: no cover
        "given secret; calcuate and return encoded checksum portion of hash string, taking config from object state"
        raise NotImplementedError("%s must implement calc_checksum()" % (cls,))

    #=========================================================
    #'application' interface (default implementation)
    #=========================================================
    @classmethod
    def encrypt(cls, secret, **settings):
        cls._warndep()
        self = cls(**settings)
        self.checksum = self.calc_checksum(secret)
        return self.to_string()

    @classmethod
    def verify(cls, secret, hash):
        cls._warndep()
        #NOTE: classes with multiple checksum encodings (rare)
        # may wish to either override this, or override norm_checksum
        # to normalize any checksums provided by from_string()
        self = cls.from_string(hash)
        return self.checksum == self.calc_checksum(secret)

    #=========================================================
    #eoc
    #=========================================================

#=========================================================
#helpful mixin which provides lazy-loading of different backends
#to be used for calc_checksum
#=========================================================
class MultiBackendHandler(ExtendedHandler):
    """subclass of ExtendedHandler which provides selecting from multiple backends
    for checksum calculation.

    .. warning::

        this class is deprecated, and will be removed in Passlib 1.5
    """

    #NOTE: subclass must provide:
    #   * attr 'backends' containing list of known backends (top priority backend first)
    #   * attr '_has_backend_xxx' for each backend 'xxx', indicating if backend is available on system
    #   * attr '_calc_checksum_xxx' for each backend 'xxx', containing calc_checksum implementation using that backend

    _backend = None

    @classmethod
    def _warndep(cls):
        msg = "MultiBackendHandler is deprecated, and will be removed in Passlib 1.5; %s should use GenericHandler+HasManyBackends instead" % (cls,)
        warn(msg, DeprecationWarning)

    @classmethod
    def get_backend(cls):
        "return name of active backend"
        cls._warndep()
        return cls._backend or cls.set_backend()

    @classmethod
    def has_backend(cls, name=None):
        "check if specified backend is currently available"
        cls._warndep()
        if name is None:
            try:
                cls.set_backend()
                return True
            except EnvironmentError:
                return False
        return getattr(cls, "_has_backend_" + name)

    @classmethod
    def _no_backends_msg(cls):
        return "no %s backends available" % (cls.name,)

    @classmethod
    def set_backend(cls, name=None):
        "change class to use specified backend"
        cls._warndep()
        if not name:
            name = cls._backend
            if name:
                return name
        if not name or name == "default":
            for name in cls.backends:
                if cls.has_backend(name):
                    break
            else:
                raise EnvironmentError(cls._no_backends_msg())
        elif not cls.has_backend(name):
            raise ValueError("%s backend not available: %r" % (cls.name, name))
        cls.calc_checksum = getattr(cls, "_calc_checksum_" + name)
        cls._backend = name
        return name

    def calc_checksum(self, secret):
        "stub for calc_checksum(), default backend will be selected first time stub is called"
        cls._warndep()
        #backend not loaded - run detection and call replacement
        assert not self._backend, "set_backend() failed to replace lazy loader"
        self.set_backend()
        assert self._backend, "set_backend() failed to load a default backend"
        #set_backend() should have replaced this method, so call it again.
        return self.calc_checksum(secret)

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
    method should be overridden on a per-handler basis.

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
            cls.genhash('stub', hash)
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
    def encrypt(cls, secret, **context):
        config = cls.genconfig()
        return cls.genhash(secret, config, **context)

    @classmethod
    def verify(cls, secret, hash, **context):
        if hash is None:
            raise ValueError("no hash specified")
        return cls.genhash(secret, hash, **context) == hash

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

    .. attribute:: checksum_size

        [optional]
        Specifies the number of characters that should be expected in the checksum string.
        If omitted, no check will be performed.

    .. attribute:: checksum_chars

        [optional]
        A string listing all the characters allowed in the checksum string.
        If omitted, no check will be performed.

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
    checksum_chars = H64_CHARS #if specified, norm_checksum() will validate this

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
        if cls.ident:
            #class specified a known prefix to look for
            return hash.startswith(cls.ident)
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
        "return parsed instance from hash/configuration string; raising ValueError on invalid inputs"
        raise NotImplementedError("%s must implement from_string()" % (cls,))

    def to_string(self): #pragma: no cover
        "render instance to hash or configuration string (depending on if checksum attr is set)"
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
            raise TypeError, "checksum must be specified as bytes"
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
    default_ident = None
    ident_values = None
    ident_aliases = None

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
        return bool(hash) and any(hash.startswith(ident) for ident in cls.ident_values)

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

    #--------------------------------------------------------
    #deprecated attrs
    #--------------------------------------------------------
    @classproperty
    def min_salt_chars(cls):
        warn(".min_salt_chars is deprecated, use .min_salt_size instead; .min_salt_chars will be removed in passlib 1.5", DeprecationWarning)
        return cls.min_salt_size

    @classproperty
    def max_salt_chars(cls):
        warn(".max_salt_chars is deprecated, use .max_salt_size instead; .max_salt_chars will be removed in passlib 1.5", DeprecationWarning)
        return cls.max_salt_size

    @classproperty
    def salt_charset(cls):
        warn(".salt_charset is deprecated, use .salt_chars instead; .salt_charset will be removed in passlib 1.5", DeprecationWarning)
        return cls.salt_chars

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
                salt = salt.encode("utf-8")
        else:
            sc = cls.salt_chars
            if sc is not None:
                for c in salt:
                    if c not in sc:
                        raise ValueError("invalid character in %s salt: %r"  % (cls.name, c))

        #check min size
        mn = cls.min_salt_size
        if mn and len(salt) < mn:
            raise ValueError("%s salt string must be at least %d characters" % (cls.name, mn))

        #check max size
        mx = cls.max_salt_size
        if mx is not None and len(salt) > mx:
            if strict:
                raise ValueError("%s salt string must be at most %d characters" % (cls.name, mx))
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

    For hashes which need to select from multiple backends,
    depending on the host environment, this class
    offers a way to specify alternate :meth:`calc_checksum` methods,
    will dynamically chose the best one at runtime.

    .. todo::

        document this class's usage
    """

    #NOTE: subclass must provide:
    #   * attr 'backends' containing list of known backends (top priority backend first)
    #   * attr '_has_backend_xxx' for each backend 'xxx', indicating if backend is available on system
    #   * attr '_calc_checksum_xxx' for each backend 'xxx', containing calc_checksum implementation using that backend

    backends = None #: list of backend names, provided by subclass.

    _backend = None

    @classmethod
    def get_backend(cls):
        "return name of active backend"
        return cls._backend or cls.set_backend()

    @classmethod
    def has_backend(cls, name=None):
        "check if specified backend is currently available"
        if name is None:
            try:
                cls.set_backend()
                return True
            except EnvironmentError:
                return False
        return getattr(cls, "_has_backend_" + name)

    @classmethod
    def _no_backends_msg(cls):
        return "no %s backends available" % (cls.name,)

    @classmethod
    def set_backend(cls, name=None):
        "change class to use specified backend"
        if not name:
            name = cls._backend
            if name:
                return name
        if not name or name == "default":
            for name in cls.backends:
                if cls.has_backend(name):
                    break
            else:
                raise EnvironmentError(cls._no_backends_msg())
        elif not cls.has_backend(name):
            raise ValueError("%s backend not available: %r" % (cls.name, name))
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

    def __init__(self, name, wrapped, prefix='', orig_prefix='', lazy=False, doc=None):
        self.name = name
        self.prefix = prefix
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
        prefix = self.prefix
        if not hash.startswith(prefix):
            raise ValueError("not a valid %s hash" % (self.name,))
        return self.orig_prefix + hash[len(prefix):]

    def _wrap_hash(self, hash):
        "given orig hash; return one belonging to wrapper"
        prefix = self.orig_prefix
        if not hash.startswith(prefix):
            raise ValueError("not a valid %s hash" % (self.wrapped.name,))
        return self.prefix + hash[len(prefix):]

    def identify(self, hash):
        if not hash or not hash.startswith(self.prefix):
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
