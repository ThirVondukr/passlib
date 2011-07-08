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
from passlib.utils import to_hash_str, handlers as uh, bytes
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
    _stub_config = "!"

    @classmethod
    def identify(cls, hash):
        return hash is not None

    @classmethod
    def genhash(cls, secret, hash, enable_wildcard=False):
        if secret is None:
            raise TypeError("secret must be string")
        if hash is None:
            raise ValueError("no hash provided")
        return to_hash_str(hash)

    @classmethod
    def verify(cls, secret, hash, enable_wildcard=False):
        if hash is None:
            raise ValueError("no hash provided")
        return enable_wildcard and not hash

class plaintext(uh.StaticHandler):
    """This class stores passwords in plaintext, and follows the :ref:`password-hash-api`.

    Unicode passwords will be encoded using utf-8.
    """
    name = "plaintext"

    @classmethod
    def identify(cls, hash):
        return hash is not None

    @classmethod
    def genhash(cls, secret, hash):
        if secret is None:
            raise TypeError("secret must be string")
        return to_hash_str(secret, "utf-8")

    @classmethod
    def _norm_hash(cls, hash):
        if isinstance(hash, bytes):
            #XXX: current code uses utf-8
            #     if existing hashes use something else,
            #     probably have to modify this code to allow hash_encoding
            #     to be specified as an option.
            hash = hash.decode("utf-8")
        return hash

#=========================================================
#eof
#=========================================================
