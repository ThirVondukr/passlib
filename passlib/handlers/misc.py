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
from passlib.utils.handlers import SimpleHandler
#pkg
#local
__all__ = [
    "unix_fallback",
    "plaintext",
]

#=========================================================
#handler
#=========================================================
class unix_fallback(SimpleHandler):
    """This class fallback behavior for unix shadow files, and follows the :ref:`password-hash-api`.

    This class does not implement a hash, but instead provides fallback
    behavior as found in /etc/shadow on most unix variants.
    If used, should be the last scheme in the context.

    * this class recognizes all hash strings.
    * it accepts all passwords if the hash is an empty string.
    * it rejects all passwords if the hash is NOT an empty string (``!`` or ``*`` are frequently used).
    * for security, newly encrypted passwords will hash to ``!``.
    """
    name = "unix_fallback"
    setting_kwds = ()
    context_kwds = ()

    @classmethod
    def identify(cls, hash):
        return hash is not None

    @classmethod
    def genconfig(cls):
        return "!"

    @classmethod
    def genhash(cls, secret, hash):
        if secret is None:
            raise TypeError, "secret must be string"
        if hash is None:
            raise ValueError, "no hash provided"
        return hash

    @classmethod
    def verify(cls, secret, hash):
        if hash is None:
            raise ValueError, "no hash provided"
        return not hash

class plaintext(SimpleHandler):
    """This class stores passwords in plaintext, and follows the :ref:`password-hash-api`.

    Unicode passwords will be encoded using utf-8.
    """
    name = "plaintext"
    setting_kwds = ()
    context_kwds = ()

    @classmethod
    def identify(cls, hash):
        return hash is not None

    @classmethod
    def genhash(cls, secret, hash):
        if secret is None:
            raise TypeError, "secret must be string"
        if isinstance(secret, unicode):
            secret = secret.encode("utf-8")
        return secret

    @classmethod
    def verify(cls, secret, hash):
        if hash is None:
            raise ValueError, "no hash specified"
        return hash == cls.genhash(secret, hash)

#=========================================================
#eof
#=========================================================
