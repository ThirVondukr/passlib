"""passlib.handlers.sun_md5_crypt - Sun's Md5 Crypt, used on Solaris

.. warning::

    This implementation has not been fully tested
    (particularly on an actual Solaris system)
    and so may not match the real implementation.
    it still needs work, and in particular,
    test cases to run against.

This code was written based on the algorithm
described in the passlib documentation,
combined with trial and error based on a
small number of known password/hash pairs.
It may have some border case issues.
"""

#=========================================================
#imports
#=========================================================
#core
from hashlib import md5
import re
import logging; log = logging.getLogger(__name__)
from warnings import warn
#site
#libs
from passlib.utils import h64
from passlib.utils.handlers import ExtendedHandler
#pkg
#local
__all__ = [
    "sun_md5_crypt",
]

#=========================================================
#backend
#=========================================================
#=========================================================
#backend
#=========================================================
#constant data used by alg - Hamlet act 3 scene 1 + null char
# exact bytes as in http://www.ibiblio.org/pub/docs/books/gutenberg/etext98/2ws2610.txt
# from Project Gutenberg.

MAGIC_HAMLET = (
    "To be, or not to be,--that is the question:--\n"
    "Whether 'tis nobler in the mind to suffer\n"
    "The slings and arrows of outrageous fortune\n"
    "Or to take arms against a sea of troubles,\n"
    "And by opposing end them?--To die,--to sleep,--\n"
    "No more; and by a sleep to say we end\n"
    "The heartache, and the thousand natural shocks\n"
    "That flesh is heir to,--'tis a consummation\n"
    "Devoutly to be wish'd. To die,--to sleep;--\n"
    "To sleep! perchance to dream:--ay, there's the rub;\n"
    "For in that sleep of death what dreams may come,\n"
    "When we have shuffled off this mortal coil,\n"
    "Must give us pause: there's the respect\n"
    "That makes calamity of so long life;\n"
    "For who would bear the whips and scorns of time,\n"
    "The oppressor's wrong, the proud man's contumely,\n"
    "The pangs of despis'd love, the law's delay,\n"
    "The insolence of office, and the spurns\n"
    "That patient merit of the unworthy takes,\n"
    "When he himself might his quietus make\n"
    "With a bare bodkin? who would these fardels bear,\n"
    "To grunt and sweat under a weary life,\n"
    "But that the dread of something after death,--\n"
    "The undiscover'd country, from whose bourn\n"
    "No traveller returns,--puzzles the will,\n"
    "And makes us rather bear those ills we have\n"
    "Than fly to others that we know not of?\n"
    "Thus conscience does make cowards of us all;\n"
    "And thus the native hue of resolution\n"
    "Is sicklied o'er with the pale cast of thought;\n"
    "And enterprises of great pith and moment,\n"
    "With this regard, their currents turn awry,\n"
    "And lose the name of action.--Soft you now!\n"
    "The fair Ophelia!--Nymph, in thy orisons\n"
    "Be all my sins remember'd.\n\x00" #<- apparently null at end of C string is included (test vector won't pass otherwise)
)

#NOTE: these sequences are pre-calculated iteration ranges used by X & Y loops w/in rounds function below
xr = range(7)
_XY_ROUNDS = [
    tuple((i,i,i+3) for i in xr), #xrounds 0
    tuple((i,i+1,i+4) for i in xr), #xrounds 1
    tuple((i,i+8,(i+11)&15) for i in xr), #yrounds 0
    tuple((i,(i+9)&15, (i+12)&15) for i in xr), #yrounds 1
]
del xr

def raw_sun_md5_crypt(secret, rounds, salt):
    "given secret & salt, return encoded sun-md5-crypt checksum"
    global MAGIC_HAMLET

    #validate secret
    #FIXME: no definitive information about how it handles unicode,
    # so using this as a fallback...
    if isinstance(secret, unicode):
        secret = secret.encode("utf-8")

    #validate salt
    if len(salt) > 8:
        salt = salt[:8]

    #validate rounds
    if rounds <= 0:
        rounds = 0
    real_rounds = 4096 + rounds
    #NOTE: spec seems to imply max 'rounds' is 2**32-1

    #generate initial digest to start off round 0.
    #NOTE: algorithm includes prefix & rounds in salt as well.
    #FIXME: seen in various forms around web, some of which
    # have "$" instead of "," as md5/rounds separator.
    # code will currently normalize that away,
    # but that might be in opposition to spec behavior.
    # lacking a real spec for this algorithm, not sure.
    if rounds:
        prefix = "$md5,rounds=%d$" % (rounds,)
    else:
        prefix = "$md5$"
    result = md5(secret + prefix + salt).digest()
    assert len(result) == 16

    #NOTE: many things have been inlined to speed up the loop as much as possible,
    # so that this only barely resembles the algorithm as described in the docs.
    # * all accesses to a given bit have been inlined using the formula
    #       rbitval(bit) = (rval((bit>>3) & 15) >> (bit & 7)) & 1
    # * the calculation of coinflip value R has been inlined
    # * the conditional division of coinflip value V has been inlined as a shift right of 0 or 1.
    # * the i, i+3, etc iterations are precalculated in lists.
    # * the round-based conditional division of x & y is now performed
    #   by choosing an appropriate precalculated list, so only the 7 used bits
    #   are actually calculated
    X_ROUNDS_0, X_ROUNDS_1, Y_ROUNDS_0, Y_ROUNDS_1 = _XY_ROUNDS

    #NOTE: % appears to be *slightly* slower than &, so we prefer & if possible

    round = 0
    while round < real_rounds:
        #convert last result byte string to list of byte-ints for easy access
        rval = [ ord(c) for c in result ].__getitem__

        #build up X bit by bit
        x = 0
        xrounds = X_ROUNDS_1 if (rval((round>>3) & 15)>>(round & 7)) & 1 else X_ROUNDS_0
        for i, ia, ib in xrounds:
            a = rval(ia)
            b = rval(ib)
            v = rval((a >> (b % 5)) & 15) >> ((b>>(a&7)) & 1)
            x |= ((rval((v>>3)&15)>>(v&7))&1) << i

        #build up Y bit by bit
        y = 0
        yrounds = Y_ROUNDS_1 if (rval(((round+64)>>3) & 15)>>(round & 7)) & 1 else Y_ROUNDS_0
        for i, ia, ib in yrounds:
            a = rval(ia)
            b = rval(ib)
            v = rval((a >> (b % 5)) & 15) >> ((b>>(a&7)) & 1)
            y |= ((rval((v>>3)&15)>>(v&7))&1) << i

        #extract x'th and y'th bit, xoring them together to yeild "coin flip"
        coin = ((rval(x>>3) >> (x&7)) ^ (rval(y>>3) >> (y&7))) & 1

        #construct hash for this round
        h = md5(result)
        if coin:
            h.update(MAGIC_HAMLET)
        h.update(str(round))
        result = h.digest()

        round += 1

    #encode output
    return h64.encode_transposed_bytes(result, _chk_offsets)

#NOTE: same offsets as md5_crypt
_chk_offsets = (
    12,6,0,
    13,7,1,
    14,8,2,
    15,9,3,
    5,10,4,
    11,
)

#=========================================================
#handler
#=========================================================
class sun_md5_crypt(ExtendedHandler):
    """This class implements the Sun-MD5-Crypt password hash, and follows the :ref:`password-hash-api`.

    It supports a variable-length salt, and a variable number of rounds.

    The :meth:`encrypt()` and :meth:`genconfig` methods accept the following optional keywords:

    :param salt:
        Optional salt string.
        If not specified, one will be autogenerated (this is recommended).
        If specified, it must be 0-8 characters, drawn from the regexp range ``[./0-9A-Za-z]``.

    :param rounds:
        Optional number of rounds to use.
        Defaults to 5000, must be between 0 and 4294963199, inclusive.
    """
    #=========================================================
    #class attrs
    #=========================================================
    name = "sun_md5_crypt"
    setting_kwds = ("salt", "rounds")

    min_salt_chars = 0
    max_salt_chars = 8

    default_rounds = 5000 #current passlib default
    min_rounds = 0
    max_rounds = 4294963199 ##2**32-1-4096
        #XXX: ^ not sure what it does if past this bound... does 32 int roll over?
    rounds_cost = "linear"

    #=========================================================
    #internal helpers
    #=========================================================
    @classmethod
    def identify(cls, hash):
        return bool(hash) and (hash.startswith("$md5$") or hash.startswith("$md5,"))

    _pat = re.compile(r"""
        ^
        \$md5
        ([$,]rounds=(?P<rounds>\d+))?
        \$(?P<salt>[A-Za-z0-9./]{0,8})
        (\$(?P<chk>[A-Za-z0-9./]{22})?)?
        $
        """, re.X)

    #NOTE: trailing "$" is supposed to be part of config string,
    # supposed to take both, but render with "$"
    #NOTE: seen examples with both "," or "$" as md5/rounds separator,
    # not sure what official format is.
    # taking both, rendering ","

    @classmethod
    def from_string(cls, hash):
        if not hash:
            raise ValueError, "no hash specified"
        m = cls._pat.match(hash)
        if not m:
            raise ValueError, "invalid sun-md5-crypt hash"
        rounds, salt, chk = m.group("rounds", "salt", "chk")
        #NOTE: this is *additional* rounds added to base 4096 specified by spec.
        #XXX: should we note whether "$" or "," was used as rounds separator?
        # not sure if that affects anything
        return cls(
            rounds=int(rounds) if rounds else 0,
            salt=salt,
            checksum=chk,
            strict=bool(chk)
        )

    def to_string(self):
        rounds = self.rounds
        if rounds > 0:
            out = "$md5,rounds=%d$%s" % (rounds, self.salt)
        else:
            out = "$md5$%s" % (self.salt,)
        chk = self.checksum
        if chk:
            out = "%s$%s" % (out, chk)
        return out

    #=========================================================
    #primary interface
    #=========================================================
    #TODO: if we're on solaris, check for native crypt() support

    def calc_checksum(self, secret):
        return raw_sun_md5_crypt(secret, self.rounds, self.salt)

    #=========================================================
    #eoc
    #=========================================================

#=========================================================
#eof
#=========================================================
