"""passlib.handlers.sha2_crypt - SHA256/512-CRYPT"""
#=========================================================
#imports
#=========================================================
#core
from hashlib import sha256, sha512
import re
import logging; log = logging.getLogger(__name__)
from warnings import warn
#site
#libs
from passlib.utils import h64, os_crypt, classproperty
from passlib.utils.handlers import MultiBackendHandler
#pkg
#local
__all__ = [
    "SHA256Crypt",
    "SHA512Crypt",
]

#=========================================================
#pure-python backend (shared between sha256-crypt & sha512-crypt)
#=========================================================
def raw_sha_crypt(secret, salt, rounds, hash):
    """perform raw sha crypt

    :arg secret: password to encode (if unicode, encoded to utf-8)
    :arg salt: salt string to use (required)
    :arg rounds: int rounds
    :arg hash: hash constructor function for 256/512 variant

    :returns:
        Returns tuple of ``(unencoded checksum, normalized salt, normalized rounds)``.

    """
    #validate secret
    if isinstance(secret, unicode):
        secret = secret.encode("utf-8")

    #validate rounds
    if rounds < 1000:
        rounds = 1000
    if rounds > 999999999: #pragma: no cover
        rounds = 999999999

    #validate salt
    if any(c in salt for c in '\x00$'):
        raise ValueError, "invalid chars in salt"
    if len(salt) > 16:
        salt = salt[:16]

    #init helpers
    def extend(source, size_ref):
        "helper which repeats <source> digest string until it's the same length as <size_ref> string"
        assert len(source) == chunk_size
        size = len(size_ref)
        return source * int(size/chunk_size) + source[:size % chunk_size]

    #calc digest B
    b = hash(secret)
    chunk_size = b.digest_size #grab this once hash is created
    b.update(salt)
    a = b.copy() #make a copy to save a little time later
    b.update(secret)
    b_result = b.digest()
    b_extend = extend(b_result, secret)

    #begin digest A
    #a = hash(secret) <- performed above
    #a.update(salt) <- performed above
    a.update(b_extend)

    #for each bit in slen, add B or SECRET
    value = len(secret)
    while value > 0:
        if value % 2:
            a.update(b_result)
        else:
            a.update(secret)
        value >>= 1

    #finish A
    a_result = a.digest()

    #calc DP - hash of password, extended to size of password
    dp = hash(secret * len(secret))
    dp_result = extend(dp.digest(), secret)

    #calc DS - hash of salt, extended to size of salt
    ds = hash(salt * (16+ord(a_result[0])))
    ds_result = extend(ds.digest(), salt) #aka 'S'

    #
    #calc digest C
    #NOTE: this has been contorted a little to allow pre-computing
    #some of the hashes. the original algorithm was that
    #each round generates digest composed of:
    #   if round%2>0 => dp else lr
    #   if round%3>0 => ds
    #   if round%7>0 => dp
    #   if round%2>0 => lr else dp
    #where lr is digest of the last round's hash (initially = a_result)
    #

    #pre-calculate some digests to speed up odd rounds
    dp_hash = hash(dp_result).copy
    dp_ds_hash = hash(dp_result + ds_result).copy
    dp_dp_hash = hash(dp_result * 2).copy
    dp_ds_dp_hash = hash(dp_result + ds_result + dp_result).copy

    #pre-calculate some strings to speed up even rounds
    ds_dp_result = ds_result + dp_result
    dp_dp_result = dp_result * 2
    ds_dp_dp_result = ds_result + dp_dp_result

    #run through rounds
    last_result = a_result
    i = 0
    while i < rounds:
        if i % 2:
            if i % 3:
                if i % 7:
                    c = dp_ds_dp_hash()
                else:
                    c = dp_ds_hash()
            elif i % 7:
                c = dp_dp_hash()
            else:
                c = dp_hash()
            c.update(last_result)
        else:
            c = hash(last_result)
            if i % 3:
                if i % 7:
                    c.update(ds_dp_dp_result)
                else:
                    c.update(ds_dp_result)
            elif i % 7:
                c.update(dp_dp_result)
            else:
                c.update(dp_result)
        last_result = c.digest()
        i += 1

    #return unencoded result, along w/ normalized config values
    return last_result, salt, rounds

def raw_sha256_crypt(secret, salt, rounds):
    "perform raw sha256-crypt; returns encoded checksum, normalized salt & rounds"
    #run common crypt routine
    result, salt, rounds = raw_sha_crypt(secret, salt, rounds, sha256)
    out = h64.encode_transposed_bytes(result, _256_offsets)
    assert len(out) == 43, "wrong length: %r" % (out,)
    return out, salt, rounds

_256_offsets = (
    20, 10, 0,
    11, 1,  21,
    2,  22, 12,
    23, 13, 3,
    14, 4,  24,
    5,  25, 15,
    26, 16, 6,
    17, 7,  27,
    8,  28, 18,
    29, 19, 9,
    30, 31,
)

def raw_sha512_crypt(secret, salt, rounds):
    "perform raw sha512-crypt; returns encoded checksum, normalized salt & rounds"
    #run common crypt routine
    result, salt, rounds = raw_sha_crypt(secret, salt, rounds, sha512)

    ###encode result
    out = h64.encode_transposed_bytes(result, _512_offsets)
    assert len(out) == 86, "wrong length: %r" % (out,)
    return out, salt, rounds

_512_offsets = (
    42, 21, 0,
    1,  43, 22,
    23, 2,  44,
    45, 24, 3,
    4,  46, 25,
    26, 5,  47,
    48, 27, 6,
    7,  49, 28,
    29, 8,  50,
    51, 30, 9,
    10, 52, 31,
    32, 11, 53,
    54, 33, 12,
    13, 55, 34,
    35, 14, 56,
    57, 36, 15,
    16, 58, 37,
    38, 17, 59,
    60, 39, 18,
    19, 61, 40,
    41, 20, 62,
    63,
)

#=========================================================
#handler
#=========================================================
class sha256_crypt(MultiBackendHandler):
    """This class implements the SHA256-Crypt password hash, and follows the :ref:`password-hash-api`.

    It supports a variable-length salt, and a variable number of rounds.

    The :meth:`encrypt()` and :meth:`genconfig` methods accept the following optional keywords:

    :param salt:
        Optional salt string.
        If not specified, one will be autogenerated (this is recommended).
        If specified, it must be 0-16 characters, drawn from the regexp range ``[./0-9A-Za-z]``.

    :param rounds:
        Optional number of rounds to use.
        Defaults to 40000, must be between 1000 and 999999999, inclusive.

    :param implicit_rounds:
        this is an internal option which generally doesn't need to be touched.

        this flag determines whether the hash should omit the rounds parameter
        when encoding it to a string; this is only permitted by the spec for rounds=5000,
        and the flag is ignored otherwise. the spec requires the two different
        encodings be preserved as they are, instead of normalizing them.

    It will use the first available of two possible backends:

    * stdlib :func:`crypt()`, if the host OS supports SHA256-Crypt.
    * a pure python implementation of SHA256-Crypt built into passlib.

    You can see which backend is in use by calling the :meth:`get_backend()` method.
    """

    #=========================================================
    #algorithm information
    #=========================================================
    name = "sha256_crypt"

    setting_kwds = ("salt", "rounds", "implicit_rounds")

    min_salt_chars = 0
    max_salt_chars = 16
    #TODO: allow salt charset 0-255 except for "\x00\n:$"

    default_rounds = 40000 #current passlib default
    min_rounds = 1000
    max_rounds = 999999999
    rounds_cost = "linear"

    #=========================================================
    #init
    #=========================================================
    def __init__(self, implicit_rounds=None, **kwds):
        if implicit_rounds is None:
            implicit_rounds = True
        self.implicit_rounds = implicit_rounds
        super(sha256_crypt, self).__init__(**kwds)

    #=========================================================
    #parsing
    #=========================================================
    @classmethod
    def identify(cls, hash):
        return bool(hash) and hash.startswith("$5$")

    #: regexp used to parse hashes
    _pat = re.compile(r"""
        ^
        \$5
        (\$rounds=(?P<rounds>\d+))?
        \$
        (
            (?P<salt1>[^:$]*)
            |
            (?P<salt2>[^:$]{0,16})
            \$
            (?P<chk>[A-Za-z0-9./]{43})?
        )
        $
        """, re.X)

    @classmethod
    def from_string(cls, hash):
        if not hash:
            raise ValueError, "no hash specified"
        #TODO: write non-regexp based parser,
        # and rely on norm_salt etc to handle more of the validation.
        m = cls._pat.match(hash)
        if not m:
            raise ValueError, "invalid sha256-crypt hash"
        rounds, salt1, salt2, chk = m.group("rounds", "salt1", "salt2", "chk")
        if rounds and rounds.startswith("0"):
            raise ValueError, "invalid sha256-crypt hash (zero-padded rounds)"
        return cls(
            implicit_rounds = not rounds,
            rounds=int(rounds) if rounds else 5000,
            salt=salt1 or salt2,
            checksum=chk,
            strict=bool(chk),
        )

    def to_string(self):
        if self.rounds == 5000 and self.implicit_rounds:
            return "$5$%s$%s" % (self.salt, self.checksum or '')
        else:
            return "$5$rounds=%d$%s$%s" % (self.rounds, self.salt, self.checksum or '')

    #=========================================================
    #backend
    #=========================================================
    backends = ("os_crypt", "builtin")

    _has_backend_builtin = True

    @classproperty
    def _has_backend_os_crypt(cls):
        return bool(
            os_crypt is not None and
            os_crypt("test", "$5$rounds=1000$test") ==
            "$5$rounds=1000$test$QmQADEXMG8POI5WDsaeho0P36yK3Tcrgboabng6bkb/"
            )

    def _calc_checksum_builtin(self, secret):
        checksum, salt, rounds = raw_sha256_crypt(secret, self.salt, self.rounds)
        assert salt == self.salt, "class doesn't agree w/ builtin backend"
        assert rounds == self.rounds, "class doesn't agree w/ builtin backend"
        return checksum

    def _calc_checksum_os_crypt(self, secret):
        if isinstance(secret, unicode):
            secret = secret.encode("utf-8")
        #NOTE: avoiding full parsing routine via from_string().checksum,
        # and just extracting the bit we need.
        result = os_crypt(secret, self.to_string())
        assert result.startswith("$5$")
        chk = result[-43:]
        assert '$' not in chk
        return chk

    #=========================================================
    #eoc
    #=========================================================

#=========================================================
#sha 512 crypt
#=========================================================
class sha512_crypt(MultiBackendHandler):
    """This class implements the SHA512-Crypt password hash, and follows the :ref:`password-hash-api`.

    It supports a variable-length salt, and a variable number of rounds.

    The :meth:`encrypt()` and :meth:`genconfig` methods accept the following optional keywords:

    :param salt:
        Optional salt string.
        If not specified, one will be autogenerated (this is recommended).
        If specified, it must be 0-16 characters, drawn from the regexp range ``[./0-9A-Za-z]``.

    :param rounds:
        Optional number of rounds to use.
        Defaults to 40000, must be between 1000 and 999999999, inclusive.

    :param implicit_rounds:
        this is an internal option which generally doesn't need to be touched.

        this flag determines whether the hash should omit the rounds parameter
        when encoding it to a string; this is only permitted by the spec for rounds=5000,
        and the flag is ignored otherwise. the spec requires the two different
        encodings be preserved as they are, instead of normalizing them.

    It will use the first available of two possible backends:

    * stdlib :func:`crypt()`, if the host OS supports SHA512-Crypt.
    * a pure python implementation of SHA512-Crypt built into passlib.

    You can see which backend is in use by calling the :meth:`get_backend()` method.
    """

    #=========================================================
    #algorithm information
    #=========================================================
    name = "sha512_crypt"

    setting_kwds = ("salt", "rounds", "implicit_rounds")

    min_salt_chars = 0
    max_salt_chars = 16
    #TODO: allow salt charset 0-255 except for "\x00\n:$"

    default_rounds = 40000 #current passlib default
    min_rounds = 1000
    max_rounds = 999999999
    rounds_cost = "linear"

    #=========================================================
    #init
    #=========================================================
    def __init__(self, implicit_rounds=None, **kwds):
        if implicit_rounds is None:
            implicit_rounds = True
        self.implicit_rounds = implicit_rounds
        super(sha512_crypt, self).__init__(**kwds)

    #=========================================================
    #parsing
    #=========================================================
    @classmethod
    def identify(cls, hash):
        return bool(hash) and hash.startswith("$6$")

    #: regexp used to parse hashes
    _pat = re.compile(r"""
        ^
        \$6
        (\$rounds=(?P<rounds>\d+))?
        \$
        (
            (?P<salt1>[^:$\n]*)
            |
            (?P<salt2>[^:$\n]{0,16})
            (
                \$
                (?P<chk>[A-Za-z0-9./]{86})?
            )?
        )
        $
        """, re.X)

    @classmethod
    def from_string(cls, hash):
        if not hash:
            raise ValueError, "no hash specified"
        #TODO: write non-regexp based parser,
        # and rely on norm_salt etc to handle more of the validation.
        m = cls._pat.match(hash)
        if not m:
            raise ValueError, "invalid sha512-crypt hash"
        rounds, salt1, salt2, chk = m.group("rounds", "salt1", "salt2", "chk")
        if rounds and rounds.startswith("0"):
            raise ValueError, "invalid sha512-crypt hash (zero-padded rounds)"
        return cls(
            implicit_rounds = not rounds,
            rounds=int(rounds) if rounds else 5000,
            salt=salt1 or salt2,
            checksum=chk,
            strict=bool(chk),
        )

    def to_string(self):
        if self.rounds == 5000 and self.implicit_rounds:
            return "$6$%s$%s" % (self.salt, self.checksum or '')
        else:
            return "$6$rounds=%d$%s$%s" % (self.rounds, self.salt, self.checksum or '')

    #=========================================================
    #backend
    #=========================================================
    backends = ("os_crypt", "builtin")

    _has_backend_builtin = True

    @classproperty
    def _has_backend_os_crypt(cls):
        return bool(
            os_crypt is not None and
            os_crypt("test", "$6$rounds=1000$test") ==
            "$6$rounds=1000$test$2M/Lx6MtobqjLjobw0Wmo4Q5OFx5nVLJvmgseatA6oMnyWeBdRDx4DU.1H3eGmse6pgsOgDisWBGI5c7TZauS0"
            )

    #NOTE: testing w/ HashTimer shows 64-bit linux's crypt to be ~2.6x faster than builtin (627253 vs 238152 rounds/sec)

    def _calc_checksum_builtin(self, secret):
        checksum, salt, rounds = raw_sha512_crypt(secret, self.salt, self.rounds)
        assert salt == self.salt, "class doesn't agree w/ builtin backend"
        assert rounds == self.rounds, "class doesn't agree w/ builtin backend"
        return checksum

    def _calc_checksum_os_crypt(self, secret):
        if isinstance(secret, unicode):
            secret = secret.encode("utf-8")
        #NOTE: avoiding full parsing routine via from_string().checksum,
        # and just extracting the bit we need.
        result = os_crypt(secret, self.to_string())
        assert result.startswith("$6$")
        chk = result[-86:]
        assert '$' not in chk
        return chk

    #=========================================================
    #eoc
    #=========================================================

#=========================================================
#eof
#=========================================================
