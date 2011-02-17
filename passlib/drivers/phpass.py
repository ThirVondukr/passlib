"""passlib.drivers.phpass - PHPass Portable Crypt

phppass located - http://www.openwall.com/phpass/
algorithm described - http://www.openwall.com/articles/PHP-Users-Passwords

phpass context - blowfish, ext_des_crypt, phpass
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
from passlib.utils import h64, autodocument
from passlib.utils.drivers import ExtHash
#pkg
#local
__all__ = [
    "phpass",
]

#=========================================================
#phpass
#=========================================================
class phpass(ExtHash):

    #=========================================================
    #class attrs
    #=========================================================
    name = "phpass"
    setting_kwds = ("salt", "rounds", "ident")

    min_salt_chars = max_salt_chars = 8

    default_rounds = 9
    min_rounds = 7
    max_rounds = 30
    rounds_cost = "log2"

    _strict_rounds_bounds = True
    _extra_init_settings = ("ident",)

    #=========================================================
    #instance attrs
    #=========================================================
    ident = None

    #=========================================================
    #init
    #=========================================================
    @classmethod
    def norm_ident(cls, ident, strict=False):
        if not ident:
            if strict:
                raise ValueError, "no ident specified"
            ident = "P"
        if ident not in ("P", "H"):
            raise ValueError, "invalid ident: %r" % (ident,)
        return ident

    #=========================================================
    #formatting
    #=========================================================

    @classmethod
    def identify(cls, hash):
        return bool(hash) and (hash.startswith("$P$") or hash.startswith("$H$"))

    #$P$9IQRaTwmfeRo7ud9Fh4E2PdI0S3r.L0
    # $P$
    # 9
    # IQRaTwmf
    # eRo7ud9Fh4E2PdI0S3r.L0
    _pat = re.compile(r"""
        ^
        \$
        (?P<ident>[PH])
        \$
        (?P<rounds>[A-Za-z0-9./])
        (?P<salt>[A-Za-z0-9./]{8})
        (?P<chk>[A-Za-z0-9./]{22})?
        $
        """, re.X)

    @classmethod
    def from_string(cls, hash):
        if not hash:
            raise ValueError, "no hash specified"
        m = cls._pat.match(hash)
        if not m:
            raise ValueError, "invalid phpass portable hash"
        ident, rounds, salt, chk = m.group("ident", "rounds", "salt", "chk")
        return cls(
            ident=ident,
            rounds=h64.decode_6bit(rounds),
            salt=salt,
            checksum=chk,
            strict=bool(chk),
        )

    def to_string(self):
        return "$%s$%s%s%s" % (self.ident, h64.encode_6bit(self.rounds), self.salt, self.checksum or '')

    #=========================================================
    #backend
    #=========================================================
    def calc_checksum(self, secret):
        #FIXME: can't find definitive policy on how phpass handles non-ascii.
        if isinstance(secret, unicode):
            secret = secret.encode("utf-8")
        real_rounds = 1<<self.rounds
        result = md5(self.salt + secret).digest()
        r = 0
        while r < real_rounds:
            result = md5(result + secret).digest()
            r += 1
        return h64.encode_bytes(result)

    #=========================================================
    #eoc
    #=========================================================

autodocument(phpass, settings_doc="""
:param ident:
    phpBB3 uses ``H`` instead of ``P`` for it's identifier,
    this may be set to ``H`` in order to generate phpBB3 compatible hashes.
    it defaults to ``P``.
""")
#=========================================================
#eof
#=========================================================
