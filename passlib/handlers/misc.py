"""passlib.handlers.misc - misc generic handlers
"""
#=========================================================
#imports
#=========================================================
#core
import logging; log = logging.getLogger(__name__)
from warnings import warn
#site
#libs
from passlib.utils import to_native_str, consteq
from passlib.utils.compat import bytes, unicode, u
import passlib.utils.handlers as uh
#pkg
#local
__all__ = [
    "unix_fallback",
    "plaintext",
]

#=========================================================
#handler
#=========================================================
class unix_fallback(uh.StaticHandler):
    """This class provides the fallback behavior for unix shadow files, and follows the :ref:`password-hash-api`.

    This class does not implement a hash, but instead provides fallback
    behavior as found in /etc/shadow on most unix variants.
    If used, should be the last scheme in the context.

    * this class will positive identify all hash strings.
    * for security, newly encrypted passwords will hash to ``!``.
    * it rejects all passwords if the hash is NOT an empty string (``!`` or ``*`` are frequently used).
    * by default it rejects all passwords if the hash is an empty string,
      but if ``enable_wildcard=True`` is passed to verify(),
      all passwords will be allowed through if the hash is an empty string.
    """
    name = "unix_fallback"
    context_kwds = ("enable_wildcard",)

    @classmethod
    def identify(cls, hash):
        return hash is not None

    def __init__(self, enable_wildcard=False, **kwds):
        super(unix_fallback, self).__init__(**kwds)
        self.enable_wildcard = enable_wildcard

    def _calc_checksum(self, secret):
        if secret is None:
            raise TypeError("secret must be string")
        if self.checksum:
            # NOTE: hash will generally be "!", but we want to preserve
            # it in case it's something else, like "*".
            return self.checksum
        else:
            return u("!")

    @classmethod
    def verify(cls, secret, hash, enable_wildcard=False):
        if secret is None:
            raise TypeError("secret must be string")
        elif hash is None:
            raise ValueError("no hash provided")
        elif hash:
            return False
        else:
            return enable_wildcard

class plaintext(object):
    """This class stores passwords in plaintext, and follows the :ref:`password-hash-api`.

    Unicode passwords will be encoded using utf-8.

    Under Python 3, existing 'hashes' must decode as utf-8.
    """
    # NOTE: this tries to avoid decoding bytes under py2,
    # for applications that are using latin-1 or some other encoding.
    # they'll just have to stop using plaintext under py3 :)
    # (or re-encode as utf-8)

    # NOTE: this is subclassed by ldap_plaintext

    name = "plaintext"
    setting_kwds = ()
    context_kwds = ()
    _hash_encoding = "utf-8"

    @classmethod
    def identify(cls, hash):
        # by default, identify ALL strings
        return hash is not None

    @classmethod
    def encrypt(cls, secret):
        return to_native_str(secret, cls._hash_encoding, "secret")

    @classmethod
    def verify(cls, secret, hash):
        if hash is None:
            raise TypeError("no hash specified")
        elif not cls.identify(hash):
            raise ValueError("not a %s hash" % (cls.name,))
        hash = to_native_str(hash, cls._hash_encoding, "hash")
        return consteq(cls.encrypt(secret), hash)

    @classmethod
    def genconfig(cls):
        return None

    @classmethod
    def genhash(cls, secret, hash):
        if hash is not None and not cls.identify(hash):
            raise ValueError("not a %s hash" % (cls.name,))
        return cls.encrypt(secret)

#=========================================================
#eof
#=========================================================
