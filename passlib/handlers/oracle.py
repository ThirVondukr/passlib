"""passlib.handlers.oracle - Oracle DB Password Hashes"""
#=========================================================
#imports
#=========================================================
#core
from binascii import hexlify, unhexlify
from hashlib import sha1
import re
import logging; log = logging.getLogger(__name__)
from warnings import warn
#site
#libs
#pkg
from passlib.utils import xor_bytes
from passlib.utils.des import des_encrypt_block
from passlib.utils.handlers import ExtendedHandler
#local
__all__ = [
    "oracle10g",
    "oracle11g"
]

#=========================================================
#oracle10
#=========================================================
def des_cbc_encrypt(key, value, iv='\x00' * 8, pad='\x00'):
    """performs des-cbc encryption, returns only last block.

    this performs a specific DES-CBC encryption implementation
    as needed by the Oracle10 hash. it probably won't be useful for
    other purposes as-is.

    input value is null-padded to multiple of 8 bytes.

    :arg key: des key as bytes
    :arg value: value to encrypt, as bytes.
    :param iv: optional IV
    :param pad: optional pad byte

    :returns: last block of DES-CBC encryption of all ``value``'s byte blocks.
    """
    value += pad * (-len(value) % 8) #null pad to multiple of 8
    hash = iv #start things off
    for offset in xrange(0,len(value),8):
        chunk = xor_bytes(hash, value[offset:offset+8])
        hash = des_encrypt_block(key, chunk)
    return hash

class oracle10(object):
    """This class implements the password hash used by Oracle up to version 10g, and follows the :ref:`password-hash-api`.

    It has no salt and a single fixed round.

    The :meth:`encrypt()` and :meth:`genconfig` methods accept no optional keywords.

    The :meth:`encrypt()`, :meth:`genhash()`, and :meth:`verify()` methods all require the
    following additional contextual keywords:

    :param user: string containing name of oracle user account this password is associated with.
    """
    #=========================================================
    #algorithm information
    #=========================================================
    name = "oracle10"
    setting_kwds = ()
    context_kwds = ("user",)

    #=========================================================
    #formatting
    #=========================================================
    _pat = re.compile(r"^[0-9a-fA-F]{16}$")

    @classmethod
    def identify(cls, hash):
        return bool(hash and cls._pat.match(hash))

    #=========================================================
    #primary interface
    #=========================================================
    @classmethod
    def genconfig(cls):
        return None

    @classmethod
    def genhash(cls, secret, config, user):
        if config and not cls.identify(config):
            raise ValueError, "not a oracle10g hash"
        return cls.encrypt(secret, user)

    #=========================================================
    #secondary interface
    #=========================================================
    @classmethod
    def encrypt(cls, secret, user):
        if secret is None:
            raise TypeError, "secret must be specified"
        if not user:
            raise ValueError, "user keyword must be specified for this algorithm"

        #FIXME: not sure how oracle handles unicode.
        # online docs about 10g hash indicate it puts ascii chars
        # in a 2-byte encoding w/ the high bytenull.
        # they don't say how it handles other chars,
        # or what encoding.
        #
        # so for now, encoding secret & user to utf-16-be,
        # since that fits,
        # and if secret/user is bytes, inserting artificial
        # null bytes in between.
        #
        # this whole mess really needs someone w/ an oracle system,
        # and some answers :)

        def encode(value):
            "encode according to guess at how oracle encodes strings (see note above)"
            if not isinstance(value, unicode):
                value = value.decode("ascii")
            return value.upper().encode("utf-16-be")

        input = encode(user) + encode(secret)
        hash = des_cbc_encrypt("\x01\x23\x45\x67\x89\xAB\xCD\xEF", input)
        hash = des_cbc_encrypt(hash, input)
        return hexlify(hash).upper()

    @classmethod
    def verify(cls, secret, hash, user):
        if not hash:
            raise ValueError, "no hash specified"
        return cls.genhash(secret, hash, user) == hash.upper()

    #=========================================================
    #eoc
    #=========================================================

#=========================================================
#oracle11
#=========================================================
class oracle11(ExtendedHandler):
    """This class implements the Oracle11g password hash, and follows the :ref:`password-hash-api`.

    It supports a fixed-length salt.

    The :meth:`encrypt()` and :meth:`genconfig` methods accept the following optional keywords:

    :param salt:
        Optional salt string.
        If not specified, one will be autogenerated (this is recommended).
        If specified, it must be 20 hexidecimal characters.
    """

    name = "oracle11"
    setting_kwds = ("salt",)

    min_salt_chars = max_salt_chars = 20
    salt_charset = checksum_charset = "0123456789ABCDEF"
    checksum_chars = 40

    _pat = re.compile("^S:(?P<chk>[0-9a-f]{40})(?P<salt>[0-9a-f]{20})$", re.I)

    @classmethod
    def identify(cls, hash):
        return bool(hash and cls._pat.match(hash))

    @classmethod
    def from_string(cls, hash):
        if not hash:
            raise ValueError, "no hash provided"
        m = cls._pat.match(hash)
        if not m:
            raise ValueError, "invalid oracle11g hash"
        salt, chk = m.group("salt", "chk")
        return cls(salt=salt, checksum=chk.upper(), strict=True)

    _stub_checksum = '0' * 40

    def to_string(self):
        return "S:%s%s" % ((self.checksum or self._stub_checksum).upper(), self.salt.upper())

    def calc_checksum(self, secret):
        if isinstance(secret, unicode):
            secret = secret.encode("utf-8")
        return sha1(secret + unhexlify(self.salt)).hexdigest().upper()

#=========================================================
#eof
#=========================================================
