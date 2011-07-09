"""passlib.handlers.des_crypt - traditional unix (DES) crypt and variants

.. note::

    for des-crypt, passlib restricts salt characters to just the hash64 charset,
    and salt string size to >= 2 chars; since implementations of des-crypt
    vary in how they handle other characters / sizes...

    linux

        linux crypt() accepts salt characters outside the hash64 charset,
        and maps them using the following formula (determined by examining crypt's output):
            chr 0..64:      v = (c-(1-19)) & 63 = (c+18) & 63
            chr 65..96:     v = (c-(65-12)) & 63 = (c+11) & 63
            chr 97..127:    v = (c-(97-38)) & 63 = (c+5) & 63
            chr 128..255:   same as c-128

        invalid salt chars are mirrored back in the resulting hash.

        if the salt is too small, it uses a NUL char for the remaining
        character (which is treated the same as the char ``G``)
        when decoding the 12 bit salt. however, it outputs
        a hash string containing the single salt char twice,
        resulting in a corrupted hash.

    netbsd

        netbsd crypt() uses a 128-byte lookup table,
        which is only initialized for the hash64 values.
        the remaining values < 128 are implicitly zeroed,
        and values > 128 access past the array bounds
        (but seem to return 0).

        if the salt string is too small, it reads
        the NULL char (and continues past the end for bsdi crypt,
        though the buffer is usually large enough and NULLed).
        salt strings are output as provided,
        except for any NULs, which are converted to ``.``.

    openbsd, freebsd

        openbsd crypt() strictly defines the hash64 values as normal,
        and all other char values as 0. salt chars are reported as provided.

        if the salt or rounds string is too small,
        it'll read past the end, resulting in unpredictable
        values, though it'll terminate it's encoding
        of the output at the first null.
        this will generally result in a corrupted hash.
"""

#=========================================================
#imports
#=========================================================
#core
import re
import logging; log = logging.getLogger(__name__)
from warnings import warn
#site
#libs
from passlib.utils import h64, classproperty, safe_os_crypt, b, bytes, \
            to_hash_str, handlers as uh, bord
from passlib.utils.des import mdes_encrypt_int_block
#pkg
#local
__all__ = [
    "des_crypt",
    "bsdi_crypt",
    "bigcrypt",
    "crypt16",
]

#=========================================================
#pure-python backend
#=========================================================
def _crypt_secret_to_key(secret):
    "crypt helper which converts lower 7 bits of first 8 chars of secret -> 56-bit des key, padded to 64 bits"
    return sum(
        (bord(c) & 0x7f) << (57-8*i)
        for i, c in enumerate(secret[:8])
    )

def raw_crypt(secret, salt):
    "pure-python fallback if stdlib support not present"
    assert len(salt) == 2

    #NOTE: technically could accept non-standard salts & single char salt,
    #but no official spec.
    try:
        salt_value = h64.decode_int12(salt)
    except ValueError: #pragma: no cover - always caught by class
        raise ValueError("invalid chars in salt")
    #FIXME: ^ this will throws error if bad salt chars are used
    # whereas linux crypt does something (inexplicable) with it

    #convert first 8 bytes of secret string into an integer
    key_value = _crypt_secret_to_key(secret)

    #run data through des using input of 0
    result = mdes_encrypt_int_block(key_value, 0, salt_value, 25)

    #run h64 encode on result
    return h64.encode_dc_int64(result)

def raw_ext_crypt(secret, rounds, salt):
    "ext_crypt() helper which returns checksum only"

    #decode salt
    try:
        salt_value = h64.decode_int24(salt)
    except ValueError: #pragma: no cover - always caught by class
        raise ValueError("invalid salt")

    #validate secret
    if b('\x00') in secret: #pragma: no cover - always caught by class
        #builtin linux crypt doesn't like this, so we don't either
        #XXX: would make more sense to raise ValueError, but want to be compatible w/ stdlib crypt
        raise ValueError("secret must be string without null bytes")

    #convert secret string into an integer
    key_value = _crypt_secret_to_key(secret)
    idx = 8
    end = len(secret)
    while idx < end:
        next = idx+8
        key_value = mdes_encrypt_int_block(key_value, key_value) ^ \
                                        _crypt_secret_to_key(secret[idx:next])
        idx = next

    #run data through des using input of 0
    result = mdes_encrypt_int_block(key_value, 0, salt_value, rounds)

    #run h64 encode on result
    return h64.encode_dc_int64(result)

#=========================================================
#handler
#=========================================================
class des_crypt(uh.HasManyBackends, uh.HasSalt, uh.GenericHandler):
    """This class implements the des-crypt password hash, and follows the :ref:`password-hash-api`.

    It supports a fixed-length salt.

    The :meth:`encrypt()` and :meth:`genconfig` methods accept the following optional keywords:

    :param salt:
        Optional salt string.
        If not specified, one will be autogenerated (this is recommended).
        If specified, it must be 2 characters, drawn from the regexp range ``[./0-9A-Za-z]``.

    It will use the first available of two possible backends:

    * stdlib :func:`crypt()`, if the host OS supports des-crypt (most unix systems).
    * a pure python implementation of des-crypt

    You can see which backend is in use by calling the :meth:`get_backend()` method.
    """

    #=========================================================
    #class attrs
    #=========================================================
    #--GenericHandler--
    name = "des_crypt"
    setting_kwds = ("salt",)
    checksum_chars = uh.H64_CHARS

    #--HasSalt--
    min_salt_size = max_salt_size = 2
    salt_chars = uh.H64_CHARS

    #=========================================================
    #formatting
    #=========================================================
    #FORMAT: 2 chars of H64-encoded salt + 11 chars of H64-encoded checksum

    _pat = re.compile(ur"""
        ^
        (?P<salt>[./a-z0-9]{2})
        (?P<chk>[./a-z0-9]{11})?
        $""", re.X|re.I)

    @classmethod
    def identify(cls, hash):
        return uh.identify_regexp(hash, cls._pat)

    @classmethod
    def from_string(cls, hash):
        if not hash:
            raise ValueError("no hash specified")
        if isinstance(hash, bytes):
            hash = hash.decode("ascii")
        salt, chk = hash[:2], hash[2:]
        return cls(salt=salt, checksum=chk, strict=bool(chk))

    def to_string(self, native=True):
        hash = u"%s%s" % (self.salt, self.checksum or u'')
        return to_hash_str(hash) if native else hash

    #=========================================================
    #backend
    #=========================================================
    backends = ("os_crypt", "builtin")

    _has_backend_builtin = True

    @classproperty
    def _has_backend_os_crypt(cls):
        h = u'abgOeLfPimXQo'
        return bool(safe_os_crypt and safe_os_crypt(u"test",h)[1]==h)

    def _calc_checksum_builtin(self, secret):
        #gotta do something - no official policy since des-crypt predates unicode
        if isinstance(secret, unicode):
            secret = secret.encode("utf-8")
        #forbidding nul chars because linux crypt (and most C implementations) won't accept it either.
        if b('\x00') in secret:
            raise ValueError("null char in secret")
        return raw_crypt(secret, self.salt.encode("ascii")).decode("ascii")

    def _calc_checksum_os_crypt(self, secret):
        #os_crypt() would raise less useful error
        null = u'\x00' if isinstance(secret, unicode) else b('\x00')
        if null in secret:
            raise ValueError("null char in secret")

        #NOTE: safe_os_crypt encodes unicode secret -> utf8
        #no official policy since des-crypt predates unicode
        ok, hash = safe_os_crypt(secret, self.salt)
        if ok:
            return hash[2:]
        else:
            return self._calc_checksum_builtin(secret)

    #=========================================================
    #eoc
    #=========================================================

#=========================================================
#handler
#=========================================================

#FIXME: phpass code notes that even rounds values should be avoided for BSDI-Crypt,
# so as not to reveal weak des keys. given the random salt, this shouldn't be
# a very likely issue anyways, but should do something about default rounds generation anyways.

class bsdi_crypt(uh.HasManyBackends, uh.HasRounds, uh.HasSalt, uh.GenericHandler):
    """This class implements the BSDi-Crypt password hash, and follows the :ref:`password-hash-api`.

    It supports a fixed-length salt, and a variable number of rounds.

    The :meth:`encrypt()` and :meth:`genconfig` methods accept the following optional keywords:

    :param salt:
        Optional salt string.
        If not specified, one will be autogenerated (this is recommended).
        If specified, it must be 4 characters, drawn from the regexp range ``[./0-9A-Za-z]``.

    :param rounds:
        Optional number of rounds to use.
        Defaults to 5000, must be between 0 and 16777215, inclusive.

    It will use the first available of two possible backends:

    * stdlib :func:`crypt()`, if the host OS supports bsdi-crypt (most BSD systems).
    * a pure python implementation of bsdi-crypt

    You can see which backend is in use by calling the :meth:`get_backend()` method.
    """
    #=========================================================
    #class attrs
    #=========================================================
    #--GenericHandler--
    name = "bsdi_crypt"
    setting_kwds = ("salt", "rounds")
    checksum_size = 11
    checksum_chars = uh.H64_CHARS

    #--HasSalt--
    min_salt_size = max_salt_size = 4
    salt_chars = uh.H64_CHARS

    #--HasRounds--
    default_rounds = 5001
    min_rounds = 0
    max_rounds = 16777215 # (1<<24)-1
    rounds_cost = "linear"

    # NOTE: OpenBSD login.conf reports 7250 as minimum allowed rounds,
    # but that seems to be an OS policy, not a algorithm limitation.

    #=========================================================
    #internal helpers
    #=========================================================
    _pat = re.compile(ur"""
        ^
        _
        (?P<rounds>[./a-z0-9]{4})
        (?P<salt>[./a-z0-9]{4})
        (?P<chk>[./a-z0-9]{11})?
        $""", re.X|re.I)

    @classmethod
    def identify(cls, hash):
        return uh.identify_regexp(hash, cls._pat)

    @classmethod
    def from_string(cls, hash):
        if not hash:
            raise ValueError("no hash specified")
        if isinstance(hash, bytes):
            hash = hash.decode("ascii")
        m = cls._pat.match(hash)
        if not m:
            raise ValueError("invalid ext-des-crypt hash")
        rounds, salt, chk = m.group("rounds", "salt", "chk")
        return cls(
            rounds=h64.decode_int24(rounds.encode("ascii")),
            salt=salt,
            checksum=chk,
            strict=bool(chk),
        )

    def to_string(self, native=True):
        hash = u"_%s%s%s" % (h64.encode_int24(self.rounds).decode("ascii"),
                             self.salt, self.checksum or u'')
        return to_hash_str(hash) if native else hash

    #=========================================================
    #backend
    #=========================================================
    backends = ("os_crypt", "builtin")

    _has_backend_builtin = True

    @classproperty
    def _has_backend_os_crypt(cls):
        h = u'_/...lLDAxARksGCHin.'
        return bool(safe_os_crypt and safe_os_crypt(u"test",h)[1]==h)
        
    def _calc_checksum_builtin(self, secret):
        if isinstance(secret, unicode):
            secret = secret.encode("utf-8")
        return raw_ext_crypt(secret, self.rounds, self.salt.encode("ascii")).decode("ascii")

    def _calc_checksum_os_crypt(self, secret):
        ok, hash = safe_os_crypt(secret, self.to_string(native=False))
        if ok:
            return hash[9:]
        else:
            return self._calc_checksum_builtin(secret)

    #=========================================================
    #eoc
    #=========================================================

#=========================================================
#
#=========================================================
class bigcrypt(uh.HasSalt, uh.GenericHandler):
    """This class implements the BigCrypt password hash, and follows the :ref:`password-hash-api`.

    It supports a fixed-length salt.

    The :meth:`encrypt()` and :meth:`genconfig` methods accept the following optional keywords:

    :param salt:
        Optional salt string.
        If not specified, one will be autogenerated (this is recommended).
        If specified, it must be 22 characters, drawn from the regexp range ``[./0-9A-Za-z]``.
    """
    #=========================================================
    #class attrs
    #=========================================================
    #--GenericHandler--
    name = "bigcrypt"
    setting_kwds = ("salt",)
    checksum_chars = uh.H64_CHARS
    #NOTE: checksum chars must be multiple of 11

    #--HasSalt--
    min_salt_size = max_salt_size = 2
    salt_chars = uh.H64_CHARS

    #=========================================================
    #internal helpers
    #=========================================================
    _pat = re.compile(ur"""
        ^
        (?P<salt>[./a-z0-9]{2})
        (?P<chk>[./a-z0-9]{11,})?
        $""", re.X|re.I)

    @classmethod
    def identify(cls, hash):
        if not hash:
            return False
        if isinstance(hash, bytes):
            try:
                hash = hash.decode("ascii")
            except UnicodeDecodeError:
                return False
        return bool(cls._pat.match(hash)) and (len(hash)-2) % 11 == 0

    @classmethod
    def from_string(cls, hash):
        if not hash:
            raise ValueError("no hash specified")
        if isinstance(hash, bytes):
            hash = hash.decode("ascii")
        m = cls._pat.match(hash)
        if not m:
            raise ValueError("invalid bigcrypt hash")
        salt, chk = m.group("salt", "chk")
        return cls(salt=salt, checksum=chk, strict=bool(chk))

    def to_string(self, native=True):
        hash = u"%s%s" % (self.salt, self.checksum or u'')
        return to_hash_str(hash) if native else hash

    @classmethod
    def norm_checksum(cls, value, strict=False):
        value = super(bigcrypt, cls).norm_checksum(value, strict=strict)
        if value and len(value) % 11:
            raise ValueError("invalid bigcrypt hash")
        return value

    #=========================================================
    #backend
    #=========================================================
    #TODO: check if os_crypt supports ext-des-crypt.

    def calc_checksum(self, secret):
        if isinstance(secret, unicode):
            secret = secret.encode("utf-8")
        chk = raw_crypt(secret, self.salt.encode("ascii"))
        idx = 8
        end = len(secret)
        while idx < end:
            next = idx + 8
            chk += raw_crypt(secret[idx:next], chk[-11:-9])
            idx = next
        return chk.decode("ascii")

    #=========================================================
    #eoc
    #=========================================================

#=========================================================
#
#=========================================================
class crypt16(uh.HasSalt, uh.GenericHandler):
    """This class implements the crypt16 password hash, and follows the :ref:`password-hash-api`.

    It supports a fixed-length salt.

    The :meth:`encrypt()` and :meth:`genconfig` methods accept the following optional keywords:

    :param salt:
        Optional salt string.
        If not specified, one will be autogenerated (this is recommended).
        If specified, it must be 2 characters, drawn from the regexp range ``[./0-9A-Za-z]``.
    """
    #=========================================================
    #class attrs
    #=========================================================
    #--GenericHandler--
    name = "crypt16"
    setting_kwds = ("salt",)
    checksum_size = 22
    checksum_chars = uh.H64_CHARS

    #--HasSalt--
    min_salt_size = max_salt_size = 2
    salt_chars = uh.H64_CHARS

    #=========================================================
    #internal helpers
    #=========================================================
    _pat = re.compile(ur"""
        ^
        (?P<salt>[./a-z0-9]{2})
        (?P<chk>[./a-z0-9]{22})?
        $""", re.X|re.I)

    @classmethod
    def identify(cls, hash):
        return uh.identify_regexp(hash, cls._pat)

    @classmethod
    def from_string(cls, hash):
        if not hash:
            raise ValueError("no hash specified")
        if isinstance(hash, bytes):
            hash = hash.decode("ascii")
        m = cls._pat.match(hash)
        if not m:
            raise ValueError("invalid crypt16 hash")
        salt, chk = m.group("salt", "chk")
        return cls(salt=salt, checksum=chk, strict=bool(chk))

    def to_string(self, native=True):
        hash = u"%s%s" % (self.salt, self.checksum or u'')
        return to_hash_str(hash) if native else hash

    #=========================================================
    #backend
    #=========================================================
    #TODO: check if os_crypt supports ext-des-crypt.

    def calc_checksum(self, secret):
        if isinstance(secret, unicode):
            secret = secret.encode("utf-8")

        #parse salt value
        try:
            salt_value = h64.decode_int12(self.salt.encode("ascii"))
        except ValueError: #pragma: no cover - caught by class
            raise ValueError("invalid chars in salt")

        #convert first 8 byts of secret string into an integer,
        key1 = _crypt_secret_to_key(secret)

        #run data through des using input of 0
        result1 = mdes_encrypt_int_block(key1, 0, salt_value, 20)

        #convert next 8 bytes of secret string into integer (key=0 if secret < 8 chars)
        key2 = _crypt_secret_to_key(secret[8:])

        #run data through des using input of 0
        result2 = mdes_encrypt_int_block(key2, 0, salt_value, 5)

        #done
        chk = h64.encode_dc_int64(result1) + h64.encode_dc_int64(result2)
        return chk.decode("ascii")

    #=========================================================
    #eoc
    #=========================================================

#=========================================================
#eof
#=========================================================
