"""passlib.handlers.django- Django password hash support"""
#=========================================================
#imports
#=========================================================
#core
from hashlib import md5, sha1
import re
import logging; log = logging.getLogger(__name__)
from warnings import warn
#site
#libs
from passlib.utils import h64, handlers as uh, b, bytes, to_unicode, to_hash_str
#pkg
#local
__all__ = [
    "django_salted_sha1",
    "django_salted_md5",
    "django_des_crypt",
    "django_disabled",
]

#=========================================================
#salted hashes
#=========================================================
class DjangoSaltedHash(uh.HasSalt, uh.GenericHandler):
    """base class providing common code for django hashes"""
    #must be specified by subclass - along w/ calc_checksum
    setting_kwds = ("salt", "salt_size")
    ident = None #must have "$" suffix
    _stub_checksum = None

    #common to most subclasses
    min_salt_size = 0
    default_salt_size = 5
    max_salt_size = None
    salt_chars = checksum_chars = uh.LC_HEX_CHARS

    @classmethod
    def identify(cls, hash):
        return uh.identify_prefix(hash, cls.ident)

    @classmethod
    def from_string(cls, hash):
        if not hash:
            raise ValueError("no hash specified")
        if isinstance(hash, bytes):
            hash = hash.decode("ascii")
        ident = cls.ident
        assert ident.endswith(u"$")
        if not hash.startswith(ident):
            raise ValueError("invalid %s hash" % (cls.name,))
        _, salt, chk = hash.split(u"$")
        return cls(salt=salt, checksum=chk, strict=True)

    def to_string(self):
        chk = self.checksum or self._stub_checksum
        out = u"%s%s$%s" % (self.ident, self.salt, chk)
        return to_hash_str(out)

class django_salted_sha1(DjangoSaltedHash):
    """This class implements Django's Salted SHA1 hash"""
    name = "django_salted_sha1"
    ident = u"sha1$"
    checksum_size = 40
    _stub_checksum = u'0' * 40

    def calc_checksum(self, secret):
        if isinstance(secret, unicode):
            secret = secret.encode("utf-8")
        return to_unicode(sha1(self.salt.encode("ascii") + secret).hexdigest(), "ascii")

class django_salted_md5(DjangoSaltedHash):
    """This class implements Django's Salted MD5 hash"""
    name = "django_salted_md5"
    ident = u"md5$"
    checksum_size = 32
    _stub_checksum = u'0' * 32

    def calc_checksum(self, secret):
        if isinstance(secret, unicode):
            secret = secret.encode("utf-8")
        return to_unicode(md5(self.salt.encode("ascii") + secret).hexdigest(), "ascii")

#=========================================================
#other
#=========================================================
class django_des_crypt(DjangoSaltedHash):
    """This class implements Django's des_crypt wrapper"""
    #NOTE: under django this only available on unix systems.

    name = "django_des_crypt"
    ident = "crypt$"
    checksum_chars = uh.H64_CHARS
    checksum_size = 13 #NOTE: includes dup copy of salt chars
    _stub_checksum = u'.' * 13

    #NOTE: django generates des_crypt hashes w/ 5 char salt,
    #      but last 3 are just ignored by crypt()

    #XXX: we *could* check if OS des_crypt support present,
    #     but not really worth bother.

    _raw_crypt = None #lazy imported

    def calc_checksum(self, secret):
        if isinstance(secret, unicode):
            secret = secret.encode("utf-8")
        #lazy import raw_crypt from des_crypt only if needed,
        #since most django deploys won't need this.
        raw_crypt = self._raw_crypt
        if raw_crypt is None:
            from passlib.handlers.des_crypt import raw_crypt
            self._raw_crypt = raw_crypt
        salt = self.salt[:2]
        return salt + raw_crypt(secret, salt.encode("ascii")).decode("ascii")

class django_disabled(uh.StaticHandler):
    """special handler for detecting django disabled accounts"""
    name = "django_disabled"

    @classmethod
    def identify(cls, hash):
        if not hash:
            return False
        if isinstance(hash, bytes):
            return hash == b("!")
        else:
            return hash == u"!"

    @classmethod
    def genhash(cls, secret, config):
        if secret is None:
            raise TypeError("no secret provided")
        return to_hash_str(u"!")

    @classmethod
    def verify(cls, secret, hash):
        if not cls.identify(hash):
            raise ValueError("invalid django-disabled hash")
        return False

#=========================================================
#eof
#=========================================================
