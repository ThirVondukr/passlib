"""passlib.handlers.nthash - unix-crypt compatible nthash passwords"""
#=========================================================
#imports
#=========================================================
#core
import re
import logging; log = logging.getLogger(__name__)
from warnings import warn
#site
#libs
from passlib.utils.md4 import md4
from passlib.utils.handlers import ExtendedHandler
#pkg
#local
__all__ = [
    "NTHash",
]

#=========================================================
#handler
#=========================================================
class nthash(ExtendedHandler):
    """This class implements the NT Password hash in a manner compatible with the :ref:`modular-crypt-format`, and follows the :ref:`password-hash-api`.

    It has no salt and a single fixed round.

    The :meth:`encrypt()` and :meth:`genconfig` methods accept no optional keywords.
    """

    #TODO: verify where $NT$ is being used.
    ##:param ident:
    ##This handler supports two different :ref:`modular-crypt-format` identifiers.
    ##It defaults to ``3``, but users may specify the alternate ``NT`` identifier
    ##which is used in some contexts.

    #=========================================================
    #class attrs
    #=========================================================
    name = "nthash"
    setting_kwds = ("ident",)

    #=========================================================
    #init
    #=========================================================
    _extra_init_settings = ("ident",)

    @classmethod
    def norm_ident(cls, value, strict=False):
        if value is None:
            if strict:
                raise ValueError, "no ident specified"
            return "3"
        if value not in ("3", "NT"):
            raise ValueError, "invalid ident"
        return value

    #=========================================================
    #formatting
    #=========================================================
    @classmethod
    def identify(cls, hash):
        return bool(hash) and (hash.startswith("$3$") or hash.startswith("$NT$"))

    _pat = re.compile(r"""
        ^
        \$(?P<ident>3\$\$|NT\$)
        (?P<chk>[a-f0-9]{32})
        $
        """, re.X)

    @classmethod
    def from_string(cls, hash):
        if not hash:
            raise ValueError, "no hash specified"
        m = cls._pat.match(hash)
        if not m:
            raise ValueError, "invalid nthash"
        ident, chk = m.group("ident", "chk")
        return cls(ident=ident.strip("$"), checksum=chk, strict=True)

    def to_string(self):
        ident = self.ident
        if ident == "3":
            return "$3$$" + self.checksum
        else:
            assert ident == "NT"
            return "$NT$" + self.checksum

    #=========================================================
    #primary interface
    #=========================================================
    _stub_checksum = "0" * 32

    @classmethod
    def genconfig(cls, ident=None):
        return cls(ident=ident, checksum=cls._stub_checksum).to_string()

    def calc_checksum(self, secret):
        if secret is None:
            raise TypeError, "secret must be a string"
        return self.raw_nthash(secret, hex=True)

    @staticmethod
    def raw_nthash(secret, hex=False):
        "encode password using md4-based NTHASH algorithm; returns string of raw bytes"
        hash = md4(secret.encode("utf-16le"))
        return hash.hexdigest() if hex else hash.digest()

    #=========================================================
    #eoc
    #=========================================================

#=========================================================
#eof
#=========================================================
