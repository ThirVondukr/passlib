from hashlib import md5

import passlib.utils.handlers as uh
from passlib.utils import to_unicode
from passlib.utils.binary import h64
from passlib.utils.compat import str_to_bascii

__all__ = [
    "sun_md5_crypt",
]

# constant data used by alg - Hamlet act 3 scene 1 + null char
# exact bytes as in http://www.ibiblio.org/pub/docs/books/gutenberg/etext98/2ws2610.txt
# from Project Gutenberg.

MAGIC_HAMLET = (
    b"To be, or not to be,--that is the question:--\n"
    b"Whether 'tis nobler in the mind to suffer\n"
    b"The slings and arrows of outrageous fortune\n"
    b"Or to take arms against a sea of troubles,\n"
    b"And by opposing end them?--To die,--to sleep,--\n"
    b"No more; and by a sleep to say we end\n"
    b"The heartache, and the thousand natural shocks\n"
    b"That flesh is heir to,--'tis a consummation\n"
    b"Devoutly to be wish'd. To die,--to sleep;--\n"
    b"To sleep! perchance to dream:--ay, there's the rub;\n"
    b"For in that sleep of death what dreams may come,\n"
    b"When we have shuffled off this mortal coil,\n"
    b"Must give us pause: there's the respect\n"
    b"That makes calamity of so long life;\n"
    b"For who would bear the whips and scorns of time,\n"
    b"The oppressor's wrong, the proud man's contumely,\n"
    b"The pangs of despis'd love, the law's delay,\n"
    b"The insolence of office, and the spurns\n"
    b"That patient merit of the unworthy takes,\n"
    b"When he himself might his quietus make\n"
    b"With a bare bodkin? who would these fardels bear,\n"
    b"To grunt and sweat under a weary life,\n"
    b"But that the dread of something after death,--\n"
    b"The undiscover'd country, from whose bourn\n"
    b"No traveller returns,--puzzles the will,\n"
    b"And makes us rather bear those ills we have\n"
    b"Than fly to others that we know not of?\n"
    b"Thus conscience does make cowards of us all;\n"
    b"And thus the native hue of resolution\n"
    b"Is sicklied o'er with the pale cast of thought;\n"
    b"And enterprises of great pith and moment,\n"
    b"With this regard, their currents turn awry,\n"
    b"And lose the name of action.--Soft you now!\n"
    b"The fair Ophelia!--Nymph, in thy orisons\n"
    b"Be all my sins remember'd.\n\x00"
    # <- apparently null at end of C string is included (test vector won't pass otherwise)
)

# NOTE: these sequences are pre-calculated iteration ranges used by X & Y loops w/in rounds function below
xr = range(7)
_XY_ROUNDS = [
    tuple((i, i, i + 3) for i in xr),  # xrounds 0
    tuple((i, i + 1, i + 4) for i in xr),  # xrounds 1
    tuple((i, i + 8, (i + 11) & 15) for i in xr),  # yrounds 0
    tuple((i, (i + 9) & 15, (i + 12) & 15) for i in xr),  # yrounds 1
]
del xr


def raw_sun_md5_crypt(secret, rounds, salt):
    """given secret & salt, return encoded sun-md5-crypt checksum"""
    assert isinstance(secret, bytes)
    assert isinstance(salt, bytes)

    # validate rounds
    rounds = max(0, rounds)
    real_rounds = 4096 + rounds
    # NOTE: spec seems to imply max 'rounds' is 2**32-1

    # generate initial digest to start off round 0.
    # NOTE: algorithm 'salt' includes full config string w/ trailing "$"
    result = md5(secret + salt).digest()
    assert len(result) == 16

    # NOTE: many things in this function have been inlined (to speed up the loop
    #       as much as possible), to the point that this code barely resembles
    #       the algorithm as described in the docs. in particular:
    #
    #       * all accesses to a given bit have been inlined using the formula
    #         rbitval(bit) = (rval((bit>>3) & 15) >> (bit & 7)) & 1
    #
    #       * the calculation of coinflip value R has been inlined
    #
    #       * the conditional division of coinflip value V has been inlined as
    #         a shift right of 0 or 1.
    #
    #       * the i, i+3, etc iterations are precalculated in lists.
    #
    #       * the round-based conditional division of x & y is now performed
    #         by choosing an appropriate precalculated list, so that it only
    #         calculates the 7 bits which will actually be used.
    #
    X_ROUNDS_0, X_ROUNDS_1, Y_ROUNDS_0, Y_ROUNDS_1 = _XY_ROUNDS

    # NOTE: % appears to be *slightly* slower than &, so we prefer & if possible

    round = 0
    while round < real_rounds:
        # convert last result byte string to list of byte-ints for easy access
        rval = [c for c in result].__getitem__

        # build up X bit by bit
        x = 0
        xrounds = (
            X_ROUNDS_1 if (rval((round >> 3) & 15) >> (round & 7)) & 1 else X_ROUNDS_0
        )
        for i, ia, ib in xrounds:
            a = rval(ia)
            b = rval(ib)
            v = rval((a >> (b % 5)) & 15) >> ((b >> (a & 7)) & 1)
            x |= ((rval((v >> 3) & 15) >> (v & 7)) & 1) << i

        # build up Y bit by bit
        y = 0
        yrounds = (
            Y_ROUNDS_1
            if (rval(((round + 64) >> 3) & 15) >> (round & 7)) & 1
            else Y_ROUNDS_0
        )
        for i, ia, ib in yrounds:
            a = rval(ia)
            b = rval(ib)
            v = rval((a >> (b % 5)) & 15) >> ((b >> (a & 7)) & 1)
            y |= ((rval((v >> 3) & 15) >> (v & 7)) & 1) << i

        # extract x'th and y'th bit, xoring them together to yeild "coin flip"
        coin = ((rval(x >> 3) >> (x & 7)) ^ (rval(y >> 3) >> (y & 7))) & 1

        # construct hash for this round
        h = md5(result)
        if coin:
            h.update(MAGIC_HAMLET)
        h.update(str(round).encode("ascii"))
        result = h.digest()

        round += 1

    # encode output
    return h64.encode_transposed_bytes(result, _chk_offsets)


# NOTE: same offsets as md5_crypt
_chk_offsets = (
    12,
    6,
    0,
    13,
    7,
    1,
    14,
    8,
    2,
    15,
    9,
    3,
    5,
    10,
    4,
    11,
)


class sun_md5_crypt(uh.HasRounds, uh.HasSalt, uh.GenericHandler):  # type: ignore[misc]
    """This class implements the Sun-MD5-Crypt password hash, and follows the :ref:`password-hash-api`.

    It supports a variable-length salt, and a variable number of rounds.

    The :meth:`~passlib.ifc.PasswordHash.using` method accepts the following optional keywords:

    :type salt: str
    :param salt:
        Optional salt string.
        If not specified, a salt will be autogenerated (this is recommended).
        If specified, it must be drawn from the regexp range ``[./0-9A-Za-z]``.

    :type salt_size: int
    :param salt_size:
        If no salt is specified, this parameter can be used to specify
        the size (in characters) of the autogenerated salt.
        It currently defaults to 8.

    :type rounds: int
    :param rounds:
        Optional number of rounds to use.
        Defaults to 34000, must be between 0 and 4294963199, inclusive.

    :type bare_salt: bool
    :param bare_salt:
        Optional flag used to enable an alternate salt digest behavior
        used by some hash strings in this scheme.
        This flag can be ignored by most users.
        Defaults to ``False``.
        (see :ref:`smc-bare-salt` for details).

    :type relaxed: bool
    :param relaxed:
        By default, providing an invalid value for one of the other
        keywords will result in a :exc:`ValueError`. If ``relaxed=True``,
        and the error can be corrected, a :exc:`~passlib.exc.PasslibHashWarning`
        will be issued instead. Correctable errors include ``rounds``
        that are too small or too large, and ``salt`` strings that are too long.

        .. versionadded:: 1.6
    """

    name = "sun_md5_crypt"
    setting_kwds = ("salt", "rounds", "bare_salt", "salt_size")
    checksum_chars = uh.HASH64_CHARS
    checksum_size = 22

    # NOTE: docs say max password length is 255.
    # release 9u2

    # NOTE: not sure if original crypt has a salt size limit,
    # all instances that have been seen use 8 chars.
    default_salt_size = 8
    max_salt_size = None
    salt_chars = uh.HASH64_CHARS

    default_rounds = 34000  # current passlib default
    min_rounds = 0
    max_rounds = 4294963199  ##2**32-1-4096
    # XXX: ^ not sure what it does if past this bound... does 32 int roll over?
    rounds_cost = "linear"

    ident_values = ("$md5$", "$md5,")
    bare_salt = False  # flag to indicate legacy hashes that lack "$$" suffix

    def __init__(self, bare_salt=False, **kwds):
        self.bare_salt = bare_salt
        super().__init__(**kwds)

    @classmethod
    def identify(cls, hash):
        hash = uh.to_unicode_for_identify(hash)
        return hash.startswith(cls.ident_values)

    @classmethod
    def from_string(cls, hash):
        hash = to_unicode(hash, "ascii", "hash")

        #
        # detect if hash specifies rounds value.
        # if so, parse and validate it.
        # by end, set 'rounds' to int value, and 'tail' containing salt+chk
        #
        if hash.startswith("$md5$"):
            rounds = 0
            salt_idx = 5
        elif hash.startswith("$md5,rounds="):
            idx = hash.find("$", 12)
            if idx == -1:
                raise uh.exc.MalformedHashError(cls, "unexpected end of rounds")
            rstr = hash[12:idx]
            try:
                rounds = int(rstr)
            except ValueError:
                raise uh.exc.MalformedHashError(cls, "bad rounds")
            if rstr != str(rounds):
                raise uh.exc.ZeroPaddedRoundsError(cls)
            if rounds == 0:
                # NOTE: not sure if this is forbidden by spec or not;
                #      but allowing it would complicate things,
                #      and it should never occur anyways.
                raise uh.exc.MalformedHashError(cls, "explicit zero rounds")
            salt_idx = idx + 1
        else:
            raise uh.exc.InvalidHashError(cls)

        #
        # salt/checksum separation is kinda weird,
        # to deal cleanly with some backward-compatible workarounds
        # implemented by original implementation.
        #
        chk_idx = hash.rfind("$", salt_idx)
        if chk_idx == -1:
            # ''-config for $-hash
            salt = hash[salt_idx:]
            chk = None
            bare_salt = True
        elif chk_idx == len(hash) - 1:
            if chk_idx > salt_idx and hash[-2] == "$":
                raise uh.exc.MalformedHashError(cls, "too many '$' separators")
            # $-config for $$-hash
            salt = hash[salt_idx:-1]
            chk = None
            bare_salt = False
        elif chk_idx > 0 and hash[chk_idx - 1] == "$":
            # $$-hash
            salt = hash[salt_idx : chk_idx - 1]
            chk = hash[chk_idx + 1 :]
            bare_salt = False
        else:
            # $-hash
            salt = hash[salt_idx:chk_idx]
            chk = hash[chk_idx + 1 :]
            bare_salt = True

        return cls(
            rounds=rounds,
            salt=salt,
            checksum=chk,
            bare_salt=bare_salt,
        )

    def to_string(self, _withchk=True):
        ss = "" if self.bare_salt else "$"
        rounds = self.rounds
        if rounds > 0:
            hash = "$md5,rounds=%d$%s%s" % (rounds, self.salt, ss)
        else:
            hash = f"$md5${self.salt}{ss}"
        if _withchk:
            chk = self.checksum
            hash = f"{hash}${chk}"
        return hash

    # TODO: if we're on solaris, check for native crypt() support.
    #       this will require extra testing, to make sure native crypt
    #       actually behaves correctly. of particular importance:
    #       when using ""-config, make sure to append "$x" to string.

    def _calc_checksum(self, secret):
        # NOTE: no reference for how sun_md5_crypt handles unicode
        if isinstance(secret, str):
            secret = secret.encode("utf-8")
        config = str_to_bascii(self.to_string(_withchk=False))
        return raw_sun_md5_crypt(secret, self.rounds, config).decode("ascii")
