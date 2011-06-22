"""passlib.handlers.django- Django password hash support

.. warning::

	the code in this module is unfinished, untested, and undocumented.

django hashes have the basic format "{alg}${salt}${hash}"
where alg is "sha1" "md5" or "crypt".

salt is typically 5 hex digits,
hash is typically alg-digest-size hex digits

    sha1/md5 use alg HASH(salt+passwd)

'crypt' is only available on unix systems (for django) - seems to only be des_crypt
    only uses first 2 chars of salt
    crypt version duplicates 2 chars of salt in hash section (just raw output of crypt)
    
old versions of django (eg .90) uses raw hex md5,
these should be upgraded - detected (by them) via "$" not in password

sha1$54123$893cf12e134c3c215f3a76bd50d13f92404a54d3 <- MyPassword

also has UNUSABLE_PASSWORD for disabled accounts - "!"

"""
#=========================================================
#imports
#=========================================================
#core
from hashlib import md5
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

    "set_django_context",
]

#=========================================================
#salted hashes
#=========================================================
class DjangoSaltedHash(uh.HasSalt, uh.GenericHandler):
    """base class providing common code for django hashes"""
    #must be specified by subclass - along w/ calc_checksum
    ident = None #must have "$" suffix
    _stub_checksum = None 
   
    #common to most subclasses
    min_salt_size = 0
    default_salt_size = 5
    max_salt_size = None
    
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
        if hash.startswith(ident):
            raise ValueError("invalid %s hash" % (cls.name,))
        _, salt, chk = hash.split(u"$")
        return cls(salt=salt, checksum=checksum, strict=True)
        
    def to_string(self):
        chk = self.checksum or self._stub_checksum
        out = u"%s%s$%s" % (self.ident, self.salt, chk)
        return to_hash_str(out)
    
class django_salted_sha1(DjangoSaltedHash):
    """This class implements Django's Salted SHA1 hash"""
    name = "django_salted_sha1"
    ident = u"sha1$"
    _stub_checksum = u'0' * 32    
    
    def calc_checksum(self, secret):
        return to_unicode(hashlib.sha1(self.salt + secret).hexdigest(), "ascii")
    
class django_salted_md5(DjangoSaltedHash):
    """This class implements Django's Salted MD5 hash"""
    name = "django_salted_md5"
    ident = u"md5$"
    _stub_checksum = u'0' * 16

    def calc_checksum(self, secret):
        return to_unicode(hashlib.sha1(self.salt + secret).hexdigest(), "ascii")
    
#=========================================================
#other
#=========================================================
class django_des_crypt(DjangoSaltedHash):
    """This class implements Django's des_crypt wrapper"""
    name = "django_des_crypt"
    ident = "crypt$"
    min_salt_size = default_salt_size = max_salt_size = 2
    
    #NOTE: django generates des_crypt hashes w/ 5 char salt,
    #      but last 3 are just ignored by crypt()

    #XXX: we *could* check if OS des_crypt support present,
    #     but not really worth bother. 

    _raw_crypt = None #lazy imported

    def calc_checksum(self, secret):
        if isinstance(secret, unicode):
            secret = secret.encode("utf-8")            
        raw_crypt = self._raw_crypt
        if raw_crypt is None:
            from passlib.handlers.des_crypt import raw_crypt
            self._raw_crypt = raw_crypt
        return raw_crypt(secret, self.salt.encode("ascii")).decode("ascii")           
            
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
        return to_hash_str(u"!")
        
    @classmethod
    def verify(cls, secret, hash):
        if not cls.identify(hash):
            raise ValueError("invalid django-disabled hash")
        return False

#=========================================================
#django context
#=========================================================
djano_context = CryptContext(
    schemes=[
        "django_salted_sha1", "django_salted_md5", "django_des_crypt",
        "hex_md5",
    ],
    deprecated=["django_salted_md5", "django_des_crypt", "hex_md5"],
)

#=========================================================
#monkeypatching django
#=========================================================
_orig_django_state = None

def set_django_password_context(context=None):
    "monkeypatches django.contrib.auth to use specified password context"
    global _orig_django_state
    from django.contrib.auth import models
    
    if context is None:
        #restore original state if needed
        if _orig_django_state is not None:
            models.User.set_password = _orig_django_state['set_password']
            models.User.migrate_password = lambda secret: False
            models.check_password = _orig_django_state['check_password']
            _orig_django_state = None
    else:
        #store original state if needed
        if _orig_django_state is None:
            _orig_django_state = dict(
                check_password = models.check_password,
                set_password = models.User.set_password,
            )
        
        #override with new context
        def set_password(user, raw_password):
            if raw_password is None:
                user.set_unusable_password()
            user.password = context.encrypt(raw_password)
            
        def migrate_password(user, raw_password):
            if context.hash_needs_update(user.password):
                user.password = context.encrypt(raw_password)
                user.save()
                return True
            else:
                return False
            
        def check_password(raw_password, hash):
            return context.verify(raw_password, hash)
            
        models.User.set_password = set_password
        models.User.migrate_password = migrate_password
        models.check_password = check_password
        
#=========================================================
#eof
#=========================================================
