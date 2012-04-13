"""passlib.handlers.misc - misc generic handlers
"""
#=========================================================
#imports
#=========================================================
#core
import sys
import logging; log = logging.getLogger(__name__)
from warnings import warn
#site
#libs
from passlib.utils import to_native_str, consteq
from passlib.utils.compat import bytes, unicode, u, base_string_types
import passlib.utils.handlers as uh
#pkg
#local
__all__ = [
    "unix_disabled",
    "unix_fallback",
    "plaintext",
]

#=========================================================
#handler
#=========================================================
class unix_fallback(uh.StaticHandler):
    """This class provides the fallback behavior for unix shadow files, and follows the :ref:`password-hash-api`.

    .. note::

        This class has been deprecated as of Passlib 1.6,
        and will be removed in Passlib 1.8.
        Use 'unix_disabled' instead.

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
        if isinstance(hash, base_string_types):
            return True
        else:
            raise uh.exc.ExpectedStringError(hash, "hash")

    def __init__(self, enable_wildcard=False, **kwds):
        warn("'unix_fallback' is deprecated, "
             "and will be removed in Passlib 1.8; "
             "please use 'unix_disabled' instead.",
             DeprecationWarning)
        super(unix_fallback, self).__init__(**kwds)
        self.enable_wildcard = enable_wildcard

    def _calc_checksum(self, secret):
        if self.checksum:
            # NOTE: hash will generally be "!", but we want to preserve
            # it in case it's something else, like "*".
            return self.checksum
        else:
            return u("!")

    @classmethod
    def verify(cls, secret, hash, enable_wildcard=False):
        uh.validate_secret(secret)
        if not isinstance(hash, base_string_types):
            raise uh.exc.ExpectedStringError(hash, "hash")
        elif hash:
            return False
        else:
            return enable_wildcard

class unix_disabled(object):
    """This class provides disabled password behavior for unix shadow files,
    and follows the :ref:`password-hash-api`. This class does not implement a
    hash, but instead provides disabled account behavior as found in
    ``/etc/shadow`` on most unix variants.

    * this class will positively identify all hash strings.
      because of this it should be checked last.
    * "encrypting" a password will simply return the disabled account marker.
    * it will reject all passwords, no matter the hash.

    The :meth:`encrypt` method supports one optional keyword:

    :param marker:
        Optional marker string which overrides the platform default
        used to indicate a disabled account.

        If not specified, this will default to ``*`` on BSD systems,
        and use the Linux default ``!`` for all other platforms.
        (:attr:`!unix_disabled.marker` will contain the default value)
    """
    name = "unix_disabled"
    setting_kwds = ("marker",)
    context_kwds = ()

    if 'bsd' in sys.platform:
        marker = u("*")
    else:
        # use the linux default for other systems
        # (glibc also supports adding old hash after the marker
        # so it can be restored later).
        marker = u("!")

    @classmethod
    def identify(cls, hash):
        if isinstance(hash, base_string_types):
            return True
        else:
            raise uh.exc.ExpectedStringError(hash, "hash")

    @classmethod
    def encrypt(cls, secret, marker=None):
        return cls.genhash(secret, None, marker)

    @classmethod
    def verify(cls, secret, hash):
        uh.validate_secret(secret)
        if not isinstance(hash, base_string_types):
            raise uh.exc.ExpectedStringError(hash, "hash")
        return False

    @classmethod
    def genconfig(cls):
        return None

    @classmethod
    def genhash(cls, secret, config, marker=None):
        uh.validate_secret(secret)
        if config is not None:
            # NOTE: config/hash will generally be "!" or "*",
            # but we want to preserve it in case it has some other content,
            # such as ``"!"  + original hash``, which glibc uses.
            # XXX: should this detect mcf header, or other things re:
            # local system policy?
            return to_native_str(config, errname="config")
        else:
            return to_native_str(marker or cls.marker, errname="marker")

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
        if isinstance(hash, base_string_types):
            return True
        else:
            raise uh.exc.ExpectedStringError(hash, "hash")

    @classmethod
    def encrypt(cls, secret):
        uh.validate_secret(secret)
        return to_native_str(secret, cls._hash_encoding, "secret")

    @classmethod
    def verify(cls, secret, hash):
        hash = to_native_str(hash, cls._hash_encoding, "hash")
        if not cls.identify(hash):
            raise uh.exc.InvalidHashError(cls)
        return consteq(cls.encrypt(secret), hash)

    @classmethod
    def genconfig(cls):
        return None

    @classmethod
    def genhash(cls, secret, hash):
        if hash is not None and not cls.identify(hash):
            raise uh.exc.InvalidHashError(cls)
        return cls.encrypt(secret)

#=========================================================
#eof
#=========================================================
