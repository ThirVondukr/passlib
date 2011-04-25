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
from passlib.utils import handlers as uh
from passlib.utils.md4 import md4
#pkg
#local
__all__ = [
    "NTHash",
]

#=========================================================
#handler
#=========================================================
class nthash(uh.HasManyIdents, uh.GenericHandler):
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
    #--GenericHandler--
    name = "nthash"
    setting_kwds = ("ident",)
    checksum_chars = uh.LC_HEX_CHARS

    _stub_checksum = "0" * 32

    #--HasManyIdents--
    default_ident = "$3$$"
    ident_values = ("$3$$", "$NT$")
    ident_aliases = {"3": "$3$$", "NT": "$NT$"}

    #=========================================================
    #formatting
    #=========================================================

    @classmethod
    def from_string(cls, hash):
        if not hash:
            raise ValueError("no hash specified")
        if isinstance(hash, unicode):
            hash = hash.encode("ascii")
        for ident in cls.ident_values:
            if hash.startswith(ident):
                break
        else:
            raise ValueError("invalid nthash")
        chk = hash[len(ident):]
        return cls(ident=ident, checksum=chk, strict=True)

    def to_string(self):
        return self.ident + (self.checksum or self._stub_checksum)

    #=========================================================
    #primary interface
    #=========================================================

    def calc_checksum(self, secret):
        if secret is None:
            raise TypeError("secret must be a string")
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
