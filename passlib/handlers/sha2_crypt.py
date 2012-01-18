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
from passlib.utils import classproperty, h64, safe_os_crypt
from passlib.utils.compat import b, bytes, belem_ord, irange, u, \
                                 uascii_to_str, unicode
import passlib.utils.handlers as uh
#pkg
#local
__all__ = [
    "SHA256Crypt",
    "SHA512Crypt",
]

#=========================================================
#pure-python backend (shared between sha256-crypt & sha512-crypt)
#=========================================================
INVALID_SALT_VALUES = b("\x00$")

##_OFFSETS = [((i       % 3 > 0) + (i       % 7 > 0)*2,
##             ((i + 1) % 3 > 0) + ((i + 1) % 7 > 0)*2)
##            for i in irange(0, 42, 2) ]
_OFFSETS = [
    (0, 3), (3, 2), (3, 3), (2, 1), (3, 2), (3, 3), (2, 3),
    (1, 2), (3, 3), (2, 3), (3, 0), (3, 3), (2, 3), (3, 2),
    (1, 3), (2, 3), (3, 2), (3, 1), (2, 3), (3, 2), (3, 3),
    ]

def extend(source, size_ref):
    "helper which repeats <source> so it's the same length as <size_ref>"
    m,d = divmod(len(size_ref), len(source))
    if d:
        return source*m + source[:d]
    else:
        return source*m

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
    if not isinstance(secret, bytes):
        raise TypeError("secret must be encoded as bytes")

    #validate rounds
    if rounds < 1000:
        rounds = 1000
    if rounds > 999999999: #pragma: no cover
        rounds = 999999999

    #validate salt
    if not isinstance(salt, bytes):
        raise TypeError("salt must be encoded as bytes")
    if any(c in salt for c in INVALID_SALT_VALUES):
        raise ValueError("invalid chars in salt")
    if len(salt) > 16:
        salt = salt[:16]

    #calc digest B
    b = hash(secret + salt + secret).digest()

    #begin digest A
    a_hash = hash(secret + salt + extend(b, secret))

    #for each bit in slen, add B or SECRET
    i = len(secret)
    while i > 0:
        if i & 1:
            a_hash.update(b)
        else:
            a_hash.update(secret)
        i >>= 1

    #finish A
    a = a_hash.digest()

    #calc DP - hash of password, extended to size of password
    tmp = hash(secret * len(secret))
    dp = extend(tmp.digest(), secret)

    #calc DS - hash of salt, extended to size of salt
    tmp = hash(salt * (16+belem_ord(a[0])))
    ds = extend(tmp.digest(), salt)

    #
    # calc digest C
    #
    # NOTE: The code below is quite different in appearance from how the
    # specification performs this step. the original algorithm was that:
    # C should start out set to A
    # for i in [0,rounds)... the next value of C is calculated as the digest of:
    #       if i%2>0 then DP else C
    #       +
    #       if i%3>0 then DS else ""
    #       +
    #       if i%7>0 then DP else ""
    #       +
    #       if i%2>0 then C else DP
    #
    # The algorithm can be see as a series of paired even/odd rounds,
    # with each pair performing 'C = md5(odd_data + md5(C + even_data))',
    # where even_data & odd_data cycle through a fixed series of
    # combinations of DP & DS, repeating every 42 rounds (since lcm(2,3,7)==42)
    #
    # This code takes advantage of these facts: it precalculates all possible
    # combinations, and then orders them into 21 pairs of even,odd values.
    # this allows the brunt of C stage to be performed in 42-round blocks,
    # with minimal overhead.

    # build array containing 42-round pattern as pairs of even & odd data.
    dp_dp = dp*2
    ds_dp = ds+dp
    evens = [dp, ds_dp, dp_dp, ds_dp+dp]
    odds =  [dp, dp+ds, dp_dp, dp+ds_dp]
    data = [(evens[e], odds[o]) for e,o in _OFFSETS]

    # perform as many full 42-round blocks as possible
    c = a
    blocks, tail = divmod(rounds, 42)
    i = 0
    while i < blocks:
        for even, odd in data:
            c = hash(odd + hash(c + even).digest()).digest()
        i += 1

    # perform any leftover rounds
    if tail:
        # perform any pairs of rounds
        half = tail>>1
        for even, odd in data[:half]:
            c = hash(odd + hash(c + even).digest()).digest()
        # if rounds was odd, do one last round
        if tail & 1:
            c = hash(c + data[half][0]).digest()

    #return unencoded result, along w/ normalized config values
    return c, salt, rounds

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
class sha256_crypt(uh.HasManyBackends, uh.HasRounds, uh.HasSalt, uh.GenericHandler):
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
    #--GenericHandler--
    name = "sha256_crypt"
    setting_kwds = ("salt", "rounds", "implicit_rounds", "salt_size")
    ident = u("$5$")
    checksum_chars = uh.HASH64_CHARS

    #--HasSalt--
    min_salt_size = 0
    max_salt_size = 16
    #TODO: allow salt charset 0-255 except for "\x00\n:$"
    salt_chars = uh.HASH64_CHARS

    #--HasRounds--
    default_rounds = 40000 #current passlib default
    min_rounds = 1000 #other bounds set by spec
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

    #: regexp used to parse hashes
    _pat = re.compile(u(r"""
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
        """), re.X)

    @classmethod
    def from_string(cls, hash):
        if not hash:
            raise ValueError("no hash specified")
        if isinstance(hash, bytes):
            hash = hash.decode("ascii")
        m = cls._pat.match(hash)
        if not m:
            raise ValueError("invalid sha256-crypt hash")
        rounds, salt1, salt2, chk = m.group("rounds", "salt1", "salt2", "chk")
        if rounds and rounds.startswith(u("0")):
            raise ValueError("invalid sha256-crypt hash (zero-padded rounds)")
        return cls(
            implicit_rounds = not rounds,
            rounds=int(rounds) if rounds else 5000,
            salt=salt1 or salt2,
            checksum=chk,
            strict=bool(chk),
        )

    def to_string(self, native=True):
        if self.rounds == 5000 and self.implicit_rounds:
            hash = u("$5$%s$%s") % (self.salt, self.checksum or u(''))
        else:
            hash = u("$5$rounds=%d$%s$%s") % (self.rounds, self.salt, self.checksum or u(''))
        return uascii_to_str(hash) if native else hash

    #=========================================================
    #backend
    #=========================================================
    backends = ("os_crypt", "builtin")

    _has_backend_builtin = True

    @classproperty
    def _has_backend_os_crypt(cls):
        h = u("$5$rounds=1000$test$QmQADEXMG8POI5WDsaeho0P36yK3Tcrgboabng6bkb/")
        return bool(safe_os_crypt and safe_os_crypt(u("test"),h)[1]==h)

    def _calc_checksum_builtin(self, secret):
        if isinstance(secret, unicode):
            secret = secret.encode("utf-8")
        checksum, salt, rounds = raw_sha256_crypt(secret,
                                                  self.salt.encode("ascii"),
                                                  self.rounds)
        assert salt == self.salt.encode("ascii"), \
            "class doesn't agree w/ builtin backend: salt %r != %r" % (salt, self.salt.encode("ascii"))
        assert rounds == self.rounds, \
            "class doesn't agree w/ builtin backend: rounds %r != %r" % (rounds, self.rounds)
        return checksum.decode("ascii")

    def _calc_checksum_os_crypt(self, secret):
        ok, result = safe_os_crypt(secret, self.to_string(native=False))
        if ok:
            #NOTE: avoiding full parsing routine via from_string().checksum,
            # and just extracting the bit we need.
            assert result.startswith(u("$5$"))
            chk = result[-43:]
            assert u('$') not in chk
            return chk
        else:
            return self._calc_checksum_builtin(secret)

    #=========================================================
    #eoc
    #=========================================================

#=========================================================
#sha 512 crypt
#=========================================================
class sha512_crypt(uh.HasManyBackends, uh.HasRounds, uh.HasSalt, uh.GenericHandler):
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
    ident = u("$6$")
    checksum_chars = uh.HASH64_CHARS

    setting_kwds = ("salt", "rounds", "implicit_rounds", "salt_size")

    min_salt_size = 0
    max_salt_size = 16
    #TODO: allow salt charset 0-255 except for "\x00\n:$"
    salt_chars = uh.HASH64_CHARS

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

    #: regexp used to parse hashes
    _pat = re.compile(u(r"""
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
        """), re.X)

    @classmethod
    def from_string(cls, hash):
        if not hash:
            raise ValueError("no hash specified")
        if isinstance(hash, bytes):
            hash = hash.decode("ascii")
        m = cls._pat.match(hash)
        if not m:
            raise ValueError("invalid sha512-crypt hash")
        rounds, salt1, salt2, chk = m.group("rounds", "salt1", "salt2", "chk")
        if rounds and rounds.startswith("0"):
            raise ValueError("invalid sha512-crypt hash (zero-padded rounds)")
        return cls(
            implicit_rounds = not rounds,
            rounds=int(rounds) if rounds else 5000,
            salt=salt1 or salt2,
            checksum=chk,
            strict=bool(chk),
        )

    def to_string(self, native=True):
        if self.rounds == 5000 and self.implicit_rounds:
            hash = u("$6$%s$%s") % (self.salt, self.checksum or u(''))
        else:
            hash = u("$6$rounds=%d$%s$%s") % (self.rounds, self.salt, self.checksum or u(''))
        return uascii_to_str(hash) if native else hash

    #=========================================================
    #backend
    #=========================================================
    backends = ("os_crypt", "builtin")

    _has_backend_builtin = True

    @classproperty
    def _has_backend_os_crypt(cls):
        h = u("$6$rounds=1000$test$2M/Lx6MtobqjLjobw0Wmo4Q5OFx5nVLJvmgseatA6oMnyWeBdRDx4DU.1H3eGmse6pgsOgDisWBGI5c7TZauS0")
        return bool(safe_os_crypt and safe_os_crypt(u("test"),h)[1]==h)

    #NOTE: testing w/ HashTimer shows 64-bit linux's crypt to be ~2.6x faster than builtin (627253 vs 238152 rounds/sec)

    def _calc_checksum_builtin(self, secret):
        if isinstance(secret, unicode):
            secret = secret.encode("utf-8")
        checksum, salt, rounds = raw_sha512_crypt(secret,
                                                  self.salt.encode("ascii"),
                                                  self.rounds)
        assert salt == self.salt.encode("ascii"), \
            "class doesn't agree w/ builtin backend: salt %r != %r" % (salt, self.salt.encode("ascii"))
        assert rounds == self.rounds, \
            "class doesn't agree w/ builtin backend: rounds %r != %r" % (rounds, self.rounds)
        return checksum.decode("ascii")

    def _calc_checksum_os_crypt(self, secret):
        ok, result = safe_os_crypt(secret, self.to_string(native=False))
        if ok:
            #NOTE: avoiding full parsing routine via from_string().checksum,
            # and just extracting the bit we need.
            assert result.startswith(u("$6$"))
            chk = result[-86:]
            assert u('$') not in chk
            return chk
        else:
            return self._calc_checksum_builtin(secret)

    #=========================================================
    #eoc
    #=========================================================

#=========================================================
#eof
#=========================================================
