"""passlib.handlers.nthash - unix-crypt compatible nthash passwords"""
#=========================================================
#imports
#=========================================================
#core
from binascii import hexlify
import re
import logging; log = logging.getLogger(__name__)
from warnings import warn
#site
#libs
from passlib.utils import to_unicode, to_bytes
from passlib.utils.compat import b, bytes, str_to_uascii, u, uascii_to_str
from passlib.utils.md4 import md4
import passlib.utils.handlers as uh
#pkg
#local
__all__ = [
    "lmhash",
    "nthash",
]

#=========================================================
# lanman hash
#=========================================================

class _HasEncodingContext(uh.GenericHandler):
    # NOTE: consider moving this to helpers if other classes could use it.
    context_kwds = ("encoding",)
    _default_encoding = "utf-8"

    def __init__(self, encoding=None, **kwds):
        super(_HasEncodingContext, self).__init__(**kwds)
        self.encoding = encoding or self._default_encoding

class lmhash(_HasEncodingContext, uh.StaticHandler):
    """This class implements the Lan Manager Password hash, and follows the :ref:`password-hash-api`.

    It has no salt and a single fixed round.

    The :meth:`encrypt()` and :meth:`verify` methods accept a single
    optional keyword:

    :param encoding:

        This specifies what character encoding LMHASH should use when
        calculating digest. It defaults to ``cp437``, the most
        common encoding encountered.

    Note that while this class outputs digests in lower-case hexidecimal,
    it will accept upper-case as well.
    """
    #=========================================================
    # class attrs
    #=========================================================
    name = "lmhash"
    checksum_chars = uh.HEX_CHARS
    checksum_size = 32
    _default_encoding = "cp437"

    #=========================================================
    # methods
    #=========================================================
    @classmethod
    def _norm_hash(cls, hash):
        return hash.lower()

    def _calc_checksum(self, secret):
        return hexlify(self.raw(secret, self.encoding)).decode("ascii")

    # magic constant used by LMHASH
    _magic = b("KGS!@#$%")

    @classmethod
    def raw(cls, secret, encoding="cp437"):
        """encode password using LANMAN hash algorithm.

        :arg secret: secret as unicode or utf-8 encoded bytes
        :arg encoding:
            optional encoding to use for unicode inputs.
            this defaults to ``cp437``, which is the
            common case for most situations.

        :returns: returns string of raw bytes
        """
        # some nice empircal data re: different encodings is at...
        # http://www.openwall.com/lists/john-dev/2011/08/01/2
        # http://www.freerainbowtables.com/phpBB3/viewtopic.php?t=387&p=12163
        from passlib.utils.des import des_encrypt_block
        MAGIC = cls._magic
        if isinstance(secret, unicode):
            # perform uppercasing while we're still unicode,
            # to give a better shot at getting non-ascii chars right.
            # (though some codepages do NOT upper-case the same as unicode).
            secret = secret.upper().encode(encoding)
        elif isinstance(secret, bytes):
            # FIXME: just trusting ascii upper will work?
            # and if not, how to do codepage specific case conversion?
            # we could decode first using <encoding>,
            # but *that* might not always be right.
            secret = secret.upper()
        else:
            raise TypeError("secret must be unicode or bytes")
        if len(secret) < 14:
            secret += b("\x00") * (14-len(secret))
        return des_encrypt_block(secret[0:7], MAGIC) + \
               des_encrypt_block(secret[7:14], MAGIC)

    #=========================================================
    # eoc
    #=========================================================

#=========================================================
# ntlm hash
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
    checksum_chars = uh.LOWER_HEX_CHARS

    _stub_checksum = u("0") * 32

    #--HasManyIdents--
    default_ident = u("$3$$")
    ident_values = (u("$3$$"), u("$NT$"))
    ident_aliases = {u("3"): u("$3$$"), u("NT"): u("$NT$")}

    #=========================================================
    #formatting
    #=========================================================

    @classmethod
    def from_string(cls, hash):
        ident, chk = cls._parse_ident(hash)
        return cls(ident=ident, checksum=chk)

    def to_string(self):
        hash = self.ident + (self.checksum or self._stub_checksum)
        return uascii_to_str(hash)

    #=========================================================
    #primary interface
    #=========================================================

    def _calc_checksum(self, secret):
        return self.raw_nthash(secret, hex=True)

    @staticmethod
    def raw_nthash(secret, hex=False):
        """encode password using md4-based NTHASH algorithm

        :returns:
            returns string of raw bytes if ``hex=False``,
            returns digest as hexidecimal unicode if ``hex=True``.
        """
        secret = to_unicode(secret, "utf-8", errname="secret")
        hash = md4(secret.encode("utf-16le"))
        if hex:
            return str_to_uascii(hash.hexdigest())
        else:
            return hash.digest()

    #=========================================================
    #eoc
    #=========================================================

#=========================================================
#eof
#=========================================================
