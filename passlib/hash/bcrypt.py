"""passlib.bcrypt

Implementation of OpenBSD's BCrypt algorithm.

Passlib will use the py-bcrypt package if it is available,
otherwise it will fall back to a slower builtin pure-python implementation.

Note that rounds must be >= 10 or an error will be returned.
"""
#=========================================================
#imports
#=========================================================
from __future__ import with_statement, absolute_import
#core
import re
import logging; log = logging.getLogger(__name__)
from warnings import warn
#site
try:
    from bcrypt import hashpw as pybcrypt_hashpw
except ImportError:
    pybcrypt_hashpw = None
#libs
from passlib.base import register_crypt_handler
from passlib.utils import autodocument, os_crypt
from passlib.utils.handlers import BackendExtHandler

#TODO: make this a lazy import, generally don't want to load it.
from passlib.utils._slow_bcrypt import raw_bcrypt as slow_raw_bcrypt

#pkg
#local
__all__ = [
    "BCrypt",
]

#=========================================================
#handler
#=========================================================
class BCrypt(BackendExtHandler):
    #=========================================================
    #class attrs
    #=========================================================
    name = "bcrypt"
    setting_kwds = ("salt", "rounds", "ident")

    min_salt_chars = max_salt_chars = 22

    default_rounds = 12 #current passlib default
    min_rounds = 4 # bcrypt spec specified minimum
    max_rounds = 31 # 32-bit integer limit (real_rounds=1<<rounds)
    rounds_cost = "log2"

    checksum_chars = 31

    #=========================================================
    #init
    #=========================================================
    _extra_init_settings = ("ident",)

    @classmethod
    def norm_ident(cls, ident, strict=False):
        if not ident:
            if strict:
                raise ValueError, "no ident specified"
            ident = "2a"
        if ident not in ("2", "2a"):
            raise ValueError, "invalid ident: %r" % (ident,)
        return ident

    #=========================================================
    #formatting
    #=========================================================
    @classmethod
    def identify(cls, hash):
        return bool(hash) and (hash.startswith("$2$") or hash.startswith("$2a$"))

    _pat = re.compile(r"""
        ^
        \$(?P<ident>2a?)
        \$(?P<rounds>\d{2})
        \$(?P<salt>[A-Za-z0-9./]{22})
        (?P<chk>[A-Za-z0-9./]{31})?
        $
        """, re.X)

    @classmethod
    def from_string(cls, hash):
        if not hash:
            raise ValueError, "no hash specified"
        m = cls._pat.match(hash)
        if not m:
            raise ValueError, "invalid bcrypt hash"
        ident, rounds, salt, chk = m.group("ident", "rounds", "salt", "chk")
        return cls(
            rounds=int(rounds),
            salt=salt,
            checksum=chk,
            ident=ident,
            strict=bool(chk),
        )

    def to_string(self):
        return "$%s$%02d$%s%s" % (self.ident, self.rounds, self.salt, self.checksum or '')

    #=========================================================
    #primary interface
    #=========================================================
    backends = ("pybcrypt", "os_crypt", "builtin")

    _has_backend_builtin = True

    @classmethod
    def _has_backend_pybcrypt(cls):
        return pybcrypt_hashpw is not None

    @classmethod
    def _has_backend_os_crypt(cls):
        return (
            os_crypt
            and
            os_crypt("test", "$2a$04$......................") ==
                '$2a$04$......................qiOQjkB8hxU8OzRhS.GhRMa4VUnkPty'
            and
            os_crypt("test", "$2$04$......................") ==
                '$2$04$......................1O4gOrCYaqBG3o/4LnT2ykQUt1wbyju'
        )

    @classmethod
    def set_backend(cls, name=None):
        result = super(BCrypt, cls).set_backend(name)
        #issue warning if builtin is ever chosen by default
        # (but if they explicitly ask for it, let it happen)
        if name != "builtin" and result == "builtin":
            warn("PassLib's builtin bcrypt is too slow for production use; PLEASE INSTALL pybcrypt")
        return result

    def _calc_checksum_builtin(self, secret):
        return slow_raw_bcrypt(secret, self.ident, self.salt, self.rounds)

    def _calc_checksum_os_crypt(self, secret):
        if isinstance(secret, unicode):
            secret = secret.encode("utf-8")
        return os_crypt(secret, self.to_string())[-31:]

    def _calc_checksum_pybcrypt(self, secret):
        return pybcrypt_hashpw(secret, self.to_string())[-31:]

    #=========================================================
    #eoc
    #=========================================================

autodocument(BCrypt, settings_doc="""
:param ident:
    selects specific version of BCrypt hash that will be used.
    Typically you want to leave this alone, and let it default to ``2a``,
    but it can be set to ``2`` to use the older version of BCrypt.
""")
register_crypt_handler(BCrypt)
#=========================================================
#eof
#=========================================================
