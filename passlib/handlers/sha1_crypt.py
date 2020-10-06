"""passlib.handlers.sha1_crypt
"""

#=============================================================================
# imports
#=============================================================================

# core
import logging; log = logging.getLogger(__name__)
# site
# pkg
from passlib.utils import safe_crypt, test_crypt
from passlib.utils.binary import h64
from passlib.utils.compat import unicode
from passlib.crypto.digest import compile_hmac
import passlib.utils.handlers as uh
# local
__all__ = [
]
#=============================================================================
# sha1-crypt
#=============================================================================
_BNULL = b'\x00'

class sha1_crypt(uh.HasManyBackends, uh.HasRounds, uh.HasSalt, uh.GenericHandler):
    """This class implements the SHA1-Crypt password hash, and follows the :ref:`password-hash-api`.

    It supports a variable-length salt, and a variable number of rounds.

    The :meth:`~passlib.ifc.PasswordHash.using` method accepts the following optional keywords:

    :type salt: str
    :param salt:
        Optional salt string.
        If not specified, an 8 character one will be autogenerated (this is recommended).
        If specified, it must be 0-64 characters, drawn from the regexp range ``[./0-9A-Za-z]``.

    :type salt_size: int
    :param salt_size:
        Optional number of bytes to use when autogenerating new salts.
        Defaults to 8 bytes, but can be any value between 0 and 64.

    :type rounds: int
    :param rounds:
        Optional number of rounds to use.
        Defaults to 480000, must be between 1 and 4294967295, inclusive.

    :type relaxed: bool
    :param relaxed:
        By default, providing an invalid value for one of the other
        keywords will result in a :exc:`ValueError`. If ``relaxed=True``,
        and the error can be corrected, a :exc:`~passlib.exc.PasslibHashWarning`
        will be issued instead. Correctable errors include ``rounds``
        that are too small or too large, and ``salt`` strings that are too long.

        .. versionadded:: 1.6
    """

    #===================================================================
    # class attrs
    #===================================================================
    #--GenericHandler--
    name = "sha1_crypt"
    setting_kwds = ("salt", "salt_size", "rounds")
    ident = u"$sha1$"
    checksum_size = 28
    checksum_chars = uh.HASH64_CHARS

    #--HasSalt--
    default_salt_size = 8
    max_salt_size = 64
    salt_chars = uh.HASH64_CHARS

    #--HasRounds--
    default_rounds = 480000 # current passlib default
    min_rounds = 1 # really, this should be higher.
    max_rounds = 4294967295 # 32-bit integer limit
    rounds_cost = "linear"

    #===================================================================
    # formatting
    #===================================================================
    @classmethod
    def from_string(cls, hash):
        rounds, salt, chk = uh.parse_mc3(hash, cls.ident, handler=cls)
        return cls(rounds=rounds, salt=salt, checksum=chk)

    def to_string(self, config=False):
        chk = None if config else self.checksum
        return uh.render_mc3(self.ident, self.rounds, self.salt, chk)

    #===================================================================
    # backend
    #===================================================================
    backends = ("os_crypt", "builtin")

    #---------------------------------------------------------------
    # os_crypt backend
    #---------------------------------------------------------------
    @classmethod
    def _load_backend_os_crypt(cls):
        if test_crypt("test", '$sha1$1$Wq3GL2Vp$C8U25GvfHS8qGHim'
                              'ExLaiSFlGkAe'):
            cls._set_calc_checksum_backend(cls._calc_checksum_os_crypt)
            return True
        else:
            return False

    def _calc_checksum_os_crypt(self, secret):
        config = self.to_string(config=True)
        hash = safe_crypt(secret, config)
        if hash is None:
            # py3's crypt.crypt() can't handle non-utf8 bytes.
            # fallback to builtin alg, which is always available.
            return self._calc_checksum_builtin(secret)
        if not hash.startswith(config) or len(hash) != len(config) + 29:
            raise uh.exc.CryptBackendError(self, config, hash)
        return hash[-28:]

    #---------------------------------------------------------------
    # builtin backend
    #---------------------------------------------------------------
    @classmethod
    def _load_backend_builtin(cls):
        cls._set_calc_checksum_backend(cls._calc_checksum_builtin)
        return True

    def _calc_checksum_builtin(self, secret):
        if isinstance(secret, unicode):
            secret = secret.encode("utf-8")
        if _BNULL in secret:
            raise uh.exc.NullPasswordError(self)
        rounds = self.rounds
        # NOTE: this seed value is NOT the same as the config string
        result = (u"%s$sha1$%s" % (self.salt, rounds)).encode("ascii")
        # NOTE: this algorithm is essentially PBKDF1, modified to use HMAC.
        keyed_hmac = compile_hmac("sha1", secret)
        for _ in range(rounds):
            result = keyed_hmac(result)
        return h64.encode_transposed_bytes(result, self._chk_offsets).decode("ascii")

    _chk_offsets = [
        2,1,0,
        5,4,3,
        8,7,6,
        11,10,9,
        14,13,12,
        17,16,15,
        0,19,18,
    ]

    #===================================================================
    # eoc
    #===================================================================

#=============================================================================
# eof
#=============================================================================
