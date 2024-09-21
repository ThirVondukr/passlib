"""passlib.handlers.mysql

MySQL 3.2.3 / OLD_PASSWORD()

    This implements Mysql's OLD_PASSWORD algorithm, introduced in version 3.2.3, deprecated in version 4.1.

    See :mod:`passlib.handlers.mysql_41` for the new algorithm was put in place in version 4.1

    This algorithm is known to be very insecure, and should only be used to verify existing password hashes.

    http://djangosnippets.org/snippets/1508/

MySQL 4.1.1 / NEW PASSWORD
    This implements Mysql new PASSWORD algorithm, introduced in version 4.1.

    This function is unsalted, and therefore not very secure against rainbow attacks.
    It should only be used when dealing with mysql passwords,
    for all other purposes, you should use a salted hash function.

    Description taken from http://dev.mysql.com/doc/refman/6.0/en/password-hashing.html
"""

from hashlib import sha1

import passlib.utils.handlers as uh

__all__ = [
    "mysql323",
    "mysql41",
]


class mysql323(uh.StaticHandler):
    """This class implements the MySQL 3.2.3 password hash, and follows the :ref:`password-hash-api`.

    It has no salt and a single fixed round.

    The :meth:`~passlib.ifc.PasswordHash.hash` and :meth:`~passlib.ifc.PasswordHash.genconfig` methods accept no optional keywords.
    """

    name = "mysql323"
    checksum_size = 16
    checksum_chars = uh.HEX_CHARS

    @classmethod
    def _norm_hash(cls, hash):
        return hash.lower()

    def _calc_checksum(self, secret):
        # FIXME: no idea if mysql has a policy about handling unicode passwords
        if isinstance(secret, str):
            secret = secret.encode("utf-8")

        MASK_32 = 0xFFFFFFFF
        MASK_31 = 0x7FFFFFFF
        WHITE = b" \t"

        nr1 = 0x50305735
        nr2 = 0x12345671
        add = 7
        for c in secret:
            if c in WHITE:
                continue
            tmp = c
            nr1 ^= ((((nr1 & 63) + add) * tmp) + (nr1 << 8)) & MASK_32
            nr2 = (nr2 + ((nr2 << 8) ^ nr1)) & MASK_32
            add = (add + tmp) & MASK_32
        return f"{nr1 & MASK_31:08x}{nr2 & MASK_31:08x}"


class mysql41(uh.StaticHandler):
    """This class implements the MySQL 4.1 password hash, and follows the :ref:`password-hash-api`.

    It has no salt and a single fixed round.

    The :meth:`~passlib.ifc.PasswordHash.hash` and :meth:`~passlib.ifc.PasswordHash.genconfig` methods accept no optional keywords.
    """

    name = "mysql41"
    _hash_prefix = "*"
    checksum_chars = uh.HEX_CHARS
    checksum_size = 40

    @classmethod
    def _norm_hash(cls, hash):
        return hash.upper()

    def _calc_checksum(self, secret):
        # FIXME: no idea if mysql has a policy about handling unicode passwords
        if isinstance(secret, str):
            secret = secret.encode("utf-8")
        return sha1(sha1(secret).digest()).hexdigest().upper()
