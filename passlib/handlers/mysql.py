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
#=========================================================
#imports
#=========================================================
#core
from hashlib import sha1
import re
import logging; log = logging.getLogger(__name__)
from warnings import warn
#site
#libs
#pkg
from passlib.utils import handlers as uh, to_hash_str, b, bord, bytes
#local
__all__ = [
    'mysql323',
    'mysq41',
]

#=========================================================
#backend
#=========================================================
class mysql323(uh.StaticHandler):
    """This class implements the MySQL 3.2.3 password hash, and follows the :ref:`password-hash-api`.

    It has no salt and a single fixed round.

    The :meth:`encrypt()` and :meth:`genconfig` methods accept no optional keywords.
    """
    #=========================================================
    #class attrs
    #=========================================================
    name = "mysql323"
    checksum_chars = uh.HEX_CHARS

    _pat = re.compile(ur"^[0-9a-f]{16}$", re.I)

    #=========================================================
    #methods
    #=========================================================

    @classmethod
    def identify(cls, hash):
        return uh.identify_regexp(hash, cls._pat)

    @classmethod
    def genhash(cls, secret, config):
        if config is not None and not cls.identify(config):
            raise ValueError("not a mysql-3.2.3 hash")

        #FIXME: no idea if mysql has a policy about handling unicode passwords
        if isinstance(secret, unicode):
            secret = secret.encode("utf-8")

        MASK_32 = 0xffffffff
        MASK_31 = 0x7fffffff

        nr1 = 0x50305735
        nr2 = 0x12345671
        add = 7
        for c in secret:
            if c in b(' \t'):
                continue
            tmp = bord(c)
            nr1 ^= ((((nr1 & 63)+add)*tmp) + (nr1 << 8)) & MASK_32
            nr2 = (nr2+((nr2 << 8) ^ nr1)) & MASK_32
            add = (add+tmp) & MASK_32
        hash = u"%08x%08x" % (nr1 & MASK_31, nr2 & MASK_31)
        return to_hash_str(hash)

    @classmethod
    def _norm_hash(cls, hash):
        if isinstance(hash, bytes):
            hash = hash.decode("ascii")
        return hash.lower()

    #=========================================================
    #eoc
    #=========================================================

#=========================================================
#handler
#=========================================================
class mysql41(uh.StaticHandler):
    """This class implements the MySQL 4.1 password hash, and follows the :ref:`password-hash-api`.

    It has no salt and a single fixed round.

    The :meth:`encrypt()` and :meth:`genconfig` methods accept no optional keywords.
    """
    #=========================================================
    #class attrs
    #=========================================================
    name = "mysql41"
    _pat = re.compile(r"^\*[0-9A-F]{40}$", re.I)

    #=========================================================
    #methods
    #=========================================================

    @classmethod
    def identify(cls, hash):
        return uh.identify_regexp(hash, cls._pat)

    @classmethod
    def genhash(cls, secret, config):
        if config is not None and not cls.identify(config):
            raise ValueError("not a mysql-4.1 hash")
        #FIXME: no idea if mysql has a policy about handling unicode passwords
        if isinstance(secret, unicode):
            secret = secret.encode("utf-8")
        return '*' + sha1(sha1(secret).digest()).hexdigest().upper()

    @classmethod
    def _norm_hash(cls, hash):
        if isinstance(hash, bytes):
            hash = hash.decode("ascii")
        return hash.upper()

    #=========================================================
    #eoc
    #=========================================================

#=========================================================
#eof
#=========================================================
