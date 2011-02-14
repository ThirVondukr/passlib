"""passlib.hash.ext_des_crypt - extended BSDi unix (DES) crypt"""
#=========================================================
#imports
#=========================================================
#core
import re
import logging; log = logging.getLogger(__name__)
from warnings import warn
#site
#libs
from passlib.base import register_crypt_handler
from passlib.utils.handlers import ExtHandler
from passlib.utils import h64, autodocument
from passlib.utils.des import mdes_encrypt_int_block
from passlib.hash.des_crypt import _crypt_secret_to_key
#pkg
#local
__all__ = [
    "ExtDesCrypt",
]

#TODO: rename this to BSDiCrypt

#=========================================================
#backend
#=========================================================
def raw_ext_crypt(secret, rounds, salt):
    "ext_crypt() helper which returns checksum only"

    #decode salt
    try:
        salt_value = h64.decode_int24(salt)
    except ValueError:
        raise ValueError, "invalid salt"

    #validate secret
    if '\x00' in secret:
        #builtin linux crypt doesn't like this, so we don't either
        #XXX: would make more sense to raise ValueError, but want to be compatible w/ stdlib crypt
        raise ValueError, "secret must be string without null bytes"

    #convert secret string into an integer
    key_value = _crypt_secret_to_key(secret)
    idx = 8
    end = len(secret)
    while idx < end:
        next = idx+8
        key_value = mdes_encrypt_int_block(key_value, key_value) ^ _crypt_secret_to_key(secret[idx:next])
        idx = next

    #run data through des using input of 0
    result = mdes_encrypt_int_block(key_value, 0, salt_value, rounds)

    #run h64 encode on result
    return h64.encode_dc_int64(result)

#=========================================================
#handler
#=========================================================
class ExtDesCrypt(ExtHandler):
    #=========================================================
    #class attrs
    #=========================================================
    name = "ext_des_crypt"
    setting_kwds = ("salt", "rounds")

    min_salt_chars = max_salt_chars = 4

    default_rounds = 1000
    min_rounds = 0
    max_rounds = 16777215 # (1<<24)-1
    rounds_cost = "linear"

    checksum_chars = 11
    checksum_charset = h64.CHARS

    # NOTE: OpenBSD login.conf reports 7250 as minimum allowed rounds,
    # but that seems to be an OS policy, not a algorithm limitation.

    #=========================================================
    #internal helpers
    #=========================================================
    _pat = re.compile(r"""
        ^
        _
        (?P<rounds>[./a-z0-9]{4})
        (?P<salt>[./a-z0-9]{4})
        (?P<chk>[./a-z0-9]{11})?
        $""", re.X|re.I)

    @classmethod
    def identify(cls, hash):
        return bool(hash and cls._pat.match(hash))

    @classmethod
    def from_string(cls, hash):
        if not hash:
            raise ValueError, "no hash specified"
        m = cls._pat.match(hash)
        if not m:
            raise ValueError, "invalid ext-des-crypt hash"
        rounds, salt, chk = m.group("rounds", "salt", "chk")
        return cls(
            rounds=h64.decode_int24(rounds),
            salt=salt,
            checksum=chk,
            strict=bool(chk),
        )

    def to_string(self):
        return "_%s%s%s" % (h64.encode_int24(self.rounds), self.salt, self.checksum or '')

    #=========================================================
    #backend
    #=========================================================
    #TODO: check if os_crypt supports ext-des-crypt.

    def calc_checksum(self, secret):
        if isinstance(secret, unicode):
            secret = secret.encode("utf-8")
        return raw_ext_crypt(secret, self.rounds, self.salt)

    #=========================================================
    #eoc
    #=========================================================

autodocument(ExtDesCrypt)
register_crypt_handler(ExtDesCrypt)
#=========================================================
#eof
#=========================================================
