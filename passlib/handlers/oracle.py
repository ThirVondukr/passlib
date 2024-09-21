"""Oracle DB Password Hashes"""

import re
from binascii import hexlify, unhexlify
from hashlib import sha1

import passlib.utils.handlers as uh
from passlib.crypto.des import des_encrypt_block
from passlib.utils import to_unicode, xor_bytes

__all__ = ["oracle10", "oracle11"]


def des_cbc_encrypt(key, value, iv=b"\x00" * 8, pad=b"\x00"):
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
    value += pad * (-len(value) % 8)  # null pad to multiple of 8
    hash = iv  # start things off
    for offset in range(0, len(value), 8):
        chunk = xor_bytes(hash, value[offset : offset + 8])
        hash = des_encrypt_block(key, chunk)
    return hash


# magic string used as initial des key by oracle10
ORACLE10_MAGIC = b"\x01\x23\x45\x67\x89\xab\xcd\xef"


class oracle10(uh.HasUserContext, uh.StaticHandler):
    """This class implements the password hash used by Oracle up to version 10g, and follows the :ref:`password-hash-api`.

    It does a single round of hashing, and relies on the username as the salt.

    The :meth:`~passlib.ifc.PasswordHash.hash`, :meth:`~passlib.ifc.PasswordHash.genhash`, and :meth:`~passlib.ifc.PasswordHash.verify` methods all require the
    following additional contextual keywords:

    :type user: str
    :param user: name of oracle user account this password is associated with.
    """

    name = "oracle10"
    checksum_chars = uh.HEX_CHARS
    checksum_size = 16

    @classmethod
    def _norm_hash(cls, hash):
        return hash.upper()

    def _calc_checksum(self, secret):
        # FIXME: not sure how oracle handles unicode.
        #        online docs about 10g hash indicate it puts ascii chars
        #        in a 2-byte encoding w/ the high byte set to null.
        #        they don't say how it handles other chars, or what encoding.
        #
        #        so for now, encoding secret & user to utf-16-be,
        #        since that fits, and if secret/user is bytes,
        #        we assume utf-8, and decode first.
        #
        #        this whole mess really needs someone w/ an oracle system,
        #        and some answers :)
        if isinstance(secret, bytes):
            secret = secret.decode("utf-8")
        user = to_unicode(self.user, "utf-8", param="user")
        input = (user + secret).upper().encode("utf-16-be")
        hash = des_cbc_encrypt(ORACLE10_MAGIC, input)
        hash = des_cbc_encrypt(hash, input)
        return hexlify(hash).decode("ascii").upper()


class oracle11(uh.HasSalt, uh.GenericHandler):
    """This class implements the Oracle11g password hash, and follows the :ref:`password-hash-api`.

    It supports a fixed-length salt.

    The :meth:`~passlib.ifc.PasswordHash.using` method accepts the following optional keywords:

    :type salt: str
    :param salt:
        Optional salt string.
        If not specified, one will be autogenerated (this is recommended).
        If specified, it must be 20 hexadecimal characters.

    :type relaxed: bool
    :param relaxed:
        By default, providing an invalid value for one of the other
        keywords will result in a :exc:`ValueError`. If ``relaxed=True``,
        and the error can be corrected, a :exc:`~passlib.exc.PasslibHashWarning`
        will be issued instead. Correctable errors include
        ``salt`` strings that are too long.

        .. versionadded:: 1.6
    """

    # --GenericHandler--
    name = "oracle11"
    setting_kwds = ("salt",)
    checksum_size = 40
    checksum_chars = uh.UPPER_HEX_CHARS

    # --HasSalt--
    min_salt_size = max_salt_size = 20
    salt_chars = uh.UPPER_HEX_CHARS
    _hash_regex = re.compile(
        "^S:(?P<chk>[0-9a-f]{40})(?P<salt>[0-9a-f]{20})$", re.IGNORECASE
    )

    @classmethod
    def from_string(cls, hash):
        hash = to_unicode(hash, "ascii", "hash")
        m = cls._hash_regex.match(hash)
        if not m:
            raise uh.exc.InvalidHashError(cls)
        salt, chk = m.group("salt", "chk")
        return cls(salt=salt, checksum=chk.upper())

    def to_string(self):
        chk = self.checksum
        return f"S:{chk.upper()}{self.salt.upper()}"

    def _calc_checksum(self, secret):
        if isinstance(secret, str):
            secret = secret.encode("utf-8")
        chk = sha1(secret + unhexlify(self.salt.encode("ascii"))).hexdigest()
        return chk.upper()
