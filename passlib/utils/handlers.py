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
from passlib.utils import classproperty, h64, getrandstr, rng, is_crypt_handler
#pkg
#local
__all__ = [

    #framework for implementing handlers
    'SimpleHandler',
    'ExtendedHandler',
    'MultiBackendHandler',
]

#=========================================================
#base handler
#=========================================================
class SimpleHandler(object):
    """helper for implementing password hash handler with minimal methods

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
    @classproperty
    def _has_settings(cls):
        "attr for checking if class has ANY settings, memoizes itself on first use"
        if cls.name is None:
            #otherwise this would optimize itself away prematurely
            raise RuntimeError, "_has_settings must only be called on subclass: %r" % (cls,)
        value = cls._has_settings = bool(cls.setting_kwds)
        return value

    #=====================================================
    #formatting (usually subclassed)
    #=====================================================
    @classmethod
    def identify(cls, hash):
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
        if cls._has_settings:
            raise NotImplementedError, "%s subclass must implement genconfig()" % (cls,)
        else:
            if settings:
                raise TypeError, "%s genconfig takes no kwds" % (cls.name,)
            return None

    @classmethod
    def genhash(cls, secret, config):
        raise NotImplementedError, "%s subclass must implement genhash()" % (cls,)

    #=====================================================
    #secondary interface (rarely subclassed)
    #=====================================================
    @classmethod
    def encrypt(cls, secret, **settings):
        config = cls.genconfig(**settings)
        return cls.genhash(secret, config)

    @classmethod
    def verify(cls, secret, hash):
        if not hash:
            raise ValueError, "no hash specified"
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
    #XXX: rename strict kwd to _strict ?
    #XXX: for from_string() purposes, a strict_salt kwd to override strict, might also be useful
    def __init__(self, checksum=None, salt=None, rounds=None, strict=False, **kwds):
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
        if cls is ExtendedHandler:
            raise RuntimeError, "not allowed for ExtendedHandler directly"
        value = cls._has_salt = 'salt' in cls.setting_kwds
        return value

    @classproperty
    def _has_rounds(cls):
        "attr for checking if variable are supported, memoizes itself on first use"
        if cls is ExtendedHandler:
            raise RuntimeError, "not allowed for ExtendedHandler directly"
        value = cls._has_rounds = 'rounds' in cls.setting_kwds
        return value

    #---------------------------------------------------------
    #normalization/validation helpers
    #---------------------------------------------------------
    @classmethod
    def norm_checksum(cls, checksum, strict=False):
        if checksum is None:
            return None
        cc = cls.checksum_chars
        if cc and len(checksum) != cc:
            raise ValueError, "%s checksum must be %d characters" % (cls.name, cc)
        cs = cls.checksum_charset
        if cs and any(c not in cs for c in checksum):
            raise ValueError, "invalid characters in %s checksum" % (cls.name,)
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
        if not cls._has_salt:
            #NOTE: special casing schemes which have no salt...
            if salt is not None:
                raise TypeError, "%s does not support ``salt`` parameter" % (cls.name,)
            return None

        if salt is None:
            if strict:
                raise ValueError, "no salt specified"
            return getrandstr(rng, cls.default_salt_charset, cls.default_salt_chars)

        #TODO: run salt_charset tests
        sc = cls.salt_charset
        if sc:
            for c in salt:
                if c not in sc:
                    raise ValueError, "invalid character in %s salt: %r"  % (cls.name, c)

        mn = cls.min_salt_chars
        if mn and len(salt) < mn:
            raise ValueError, "%s salt string must be at least %d characters" % (cls.name, mn)

        mx = cls.max_salt_chars
        if len(salt) > mx:
            if strict:
                raise ValueError, "%s salt string must be at most %d characters" % (cls.name, mx)
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
        #XXX: for speed, could optimize this by replacing method at class level
        # when cls._has_rounds check is first called.
        # could make same optimization for norm_salt()

        if not cls._has_rounds:
            #NOTE: special casing schemes which don't have rounds
            if rounds is not None:
                raise TypeError, "%s does not support ``rounds``" % (cls.name,)
            return None

        if rounds is None:
            if strict:
                raise ValueError, "no rounds specified"
            rounds = cls.default_rounds
            if rounds is None:
                raise ValueError, "%s rounds value must be specified explicitly" % (cls.name,)
            return rounds

        if cls._strict_rounds_bounds:
            strict = True

        mn = cls.min_rounds
        if rounds < mn:
            if strict:
                raise ValueError, "%s rounds must be >= %d" % (cls.name, mn)
            warn("%s does not allow less than %d rounds: %d" % (cls.name, mn, rounds))
            rounds = mn

        mx = cls.max_rounds
        if rounds > mx:
            if strict:
                raise ValueError, "%s rounds must be <= %d" % (cls.name, mx)
            warn("%s does not allow more than %d rounds: %d" % (cls.name, mx, rounds))
            rounds = mx

        return rounds

    #=========================================================
    #password hash api - formatting interface
    #=========================================================
    @classmethod
    def identify(cls, hash):
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
        raise NotImplementedError, "%s must implement from_string()" % (cls,)

    def to_string(self): #pragma: no cover
        "render instance to hash or configuration string (depending on if checksum attr is set)"
        raise NotImplementedError, "%s must implement from_string()" % (type(self),)

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
        if cls._has_settings:
            return cls(**settings).to_string()
        elif settings:
            raise TypeError, "%s.genconfig() takes no arguments" % (cls.name,)
        else:
            return None

    @classmethod
    def genhash(cls, secret, config):
        if cls._has_settings or config is not None:
            self = cls.from_string(config)
        else:
            self = cls()
        self.checksum = self.calc_checksum(secret)
        return self.to_string()

    def calc_checksum(self, secret): #pragma: no cover
        "given secret; calcuate and return encoded checksum portion of hash string, taking config from object state"
        raise NotImplementedError, "%s must implement calc_checksum()" % (cls,)

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

#=========================================================
#helpful mixin which provides lazy-loading of different backends
#to be used for calc_checksum
#=========================================================
class MultiBackendHandler(ExtendedHandler):
    "subclass of ExtendedHandler which provides selecting from multiple backends for checksum calculation"

    #NOTE: subclass must provide:
    #   * attr 'backends' containing list of known backends (top priority backend first)
    #   * attr '_has_backend_xxx' for each backend 'xxx', indicating if backend is available on system
    #   * attr '_calc_checksum_xxx' for each backend 'xxx', containing calc_checksum implementation using that backend

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
                raise EnvironmentError, cls._no_backends_msg()
        elif not cls.has_backend(name):
            raise ValueError, "%s backend not available: %r" % (cls.name, name)
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
# eof
#=========================================================
