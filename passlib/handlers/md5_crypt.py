"""md5-crypt algorithm"""

from hashlib import md5

import passlib.utils.handlers as uh
from passlib.utils import repeat_string
from passlib.utils.binary import h64

__all__ = [
    "md5_crypt",
    "apr_md5_crypt",
]


_BNULL = b"\x00"
_MD5_MAGIC = b"$1$"
_APR_MAGIC = b"$apr1$"

# pre-calculated offsets used to speed up C digest stage (see notes below).
# sequence generated using the following:
##perms_order = "p,pp,ps,psp,sp,spp".split(",")
##def offset(i):
##    key = (("p" if i % 2 else "") + ("s" if i % 3 else "") +
##        ("p" if i % 7 else "") + ("" if i % 2 else "p"))
##    return perms_order.index(key)
##_c_digest_offsets = [(offset(i), offset(i+1)) for i in range(0,42,2)]
_c_digest_offsets = (
    (0, 3),
    (5, 1),
    (5, 3),
    (1, 2),
    (5, 1),
    (5, 3),
    (1, 3),
    (4, 1),
    (5, 3),
    (1, 3),
    (5, 0),
    (5, 3),
    (1, 3),
    (5, 1),
    (4, 3),
    (1, 3),
    (5, 1),
    (5, 2),
    (1, 3),
    (5, 1),
    (5, 3),
)

# map used to transpose bytes when encoding final digest
_transpose_map = (12, 6, 0, 13, 7, 1, 14, 8, 2, 15, 9, 3, 5, 10, 4, 11)


def _raw_md5_crypt(pwd, salt, use_apr=False):
    """perform raw md5-crypt calculation

    this function provides a pure-python implementation of the internals
    for the MD5-Crypt algorithms; it doesn't handle any of the
    parsing/validation of the hash strings themselves.

    :arg pwd: password chars/bytes to hash
    :arg salt: salt chars to use
    :arg use_apr: use apache variant

    :returns:
        encoded checksum chars
    """
    # NOTE: regarding 'apr' format:
    # really, apache? you had to invent a whole new "$apr1$" format,
    # when all you did was change the ident incorporated into the hash?
    # would love to find webpage explaining why just using a portable
    # implementation of $1$ wasn't sufficient. *nothing else* was changed.

    # validate secret
    # XXX: not sure what official unicode policy is, using this as default
    if isinstance(pwd, str):
        pwd = pwd.encode("utf-8")
    assert isinstance(pwd, bytes), "pwd not str or bytes"
    if _BNULL in pwd:
        raise uh.exc.NullPasswordError(md5_crypt)
    pwd_len = len(pwd)

    # validate salt - should have been taken care of by caller
    assert isinstance(salt, str), "salt not str"
    salt = salt.encode("ascii")
    assert len(salt) < 9, "salt too large"
    # NOTE: spec says salts larger than 8 bytes should be truncated,
    # instead of causing an error. this function assumes that's been
    # taken care of by the handler class.

    # load APR specific constants
    if use_apr:  # noqa: SIM108
        magic = _APR_MAGIC
    else:
        magic = _MD5_MAGIC
    db = md5(pwd + salt + pwd).digest()
    # start out with pwd + magic + salt
    a_ctx = md5(pwd + magic + salt)
    a_ctx_update = a_ctx.update

    # add pwd_len bytes of b, repeating b as many times as needed.
    a_ctx_update(repeat_string(db, pwd_len))

    # add null chars & first char of password
    # NOTE: this may have historically been a bug,
    # where they meant to use db[0] instead of B_NULL,
    # but the original code memclear'ed db,
    # and now all implementations have to use this.
    i = pwd_len
    evenchar = pwd[:1]
    while i:
        a_ctx_update(_BNULL if i & 1 else evenchar)
        i >>= 1

    # finish A
    da = a_ctx.digest()

    # ===================================================================
    # digest C - for a 1000 rounds, combine A, S, and P
    #            digests in various ways; in order to burn CPU time.
    # ===================================================================

    # NOTE: the original MD5-Crypt implementation performs the C digest
    # calculation using the following loop:
    #
    ##dc = da
    ##i = 0
    ##while i < rounds:
    ##    tmp_ctx = md5(pwd if i & 1 else dc)
    ##    if i % 3:
    ##        tmp_ctx.update(salt)
    ##    if i % 7:
    ##        tmp_ctx.update(pwd)
    ##    tmp_ctx.update(dc if i & 1 else pwd)
    ##    dc = tmp_ctx.digest()
    ##    i += 1
    #
    # The code Passlib uses (below) implements an equivalent algorithm,
    # it's just been heavily optimized to pre-calculate a large number
    # of things beforehand. It works off of a couple of observations
    # about the original algorithm:
    #
    # 1. each round is a combination of 'dc', 'salt', and 'pwd'; and the exact
    #    combination is determined by whether 'i' a multiple of 2,3, and/or 7.
    # 2. since lcm(2,3,7)==42, the series of combinations will repeat
    #    every 42 rounds.
    # 3. even rounds 0-40 consist of 'hash(dc + round-specific-constant)';
    #    while odd rounds 1-41 consist of hash(round-specific-constant + dc)
    #
    # Using these observations, the following code...
    # * calculates the round-specific combination of salt & pwd for each round 0-41
    # * runs through as many 42-round blocks as possible (23)
    # * runs through as many pairs of rounds as needed for remaining rounds (17)
    # * this results in the required 42*23+2*17=1000 rounds required by md5_crypt.
    #
    # this cuts out a lot of the control overhead incurred when running the
    # original loop 1000 times in python, resulting in ~20% increase in
    # speed under CPython (though still 2x slower than glibc crypt)

    # prepare the 6 combinations of pwd & salt which are needed
    # (order of 'perms' must match how _c_digest_offsets was generated)
    pwd_pwd = pwd + pwd
    pwd_salt = pwd + salt
    perms = [pwd, pwd_pwd, pwd_salt, pwd_salt + pwd, salt + pwd, salt + pwd_pwd]

    # build up list of even-round & odd-round constants,
    # and store in 21-element list as (even,odd) pairs.
    data = [(perms[even], perms[odd]) for even, odd in _c_digest_offsets]

    # perform 23 blocks of 42 rounds each (for a total of 966 rounds)
    dc = da
    blocks = 23
    while blocks:
        for even, odd in data:
            dc = md5(odd + md5(dc + even).digest()).digest()
        blocks -= 1

    # perform 17 more pairs of rounds (34 more rounds, for a total of 1000)
    for even, odd in data[:17]:
        dc = md5(odd + md5(dc + even).digest()).digest()
    return h64.encode_transposed_bytes(dc, _transpose_map).decode("ascii")


class _MD5_Common(uh.HasSalt, uh.GenericHandler):
    """common code for md5_crypt and apr_md5_crypt"""

    # name - set in subclass
    setting_kwds = ("salt", "salt_size")
    # ident - set in subclass
    checksum_size = 22
    checksum_chars = uh.HASH64_CHARS

    max_salt_size = 8
    salt_chars = uh.HASH64_CHARS

    @classmethod
    def from_string(cls, hash):
        salt, chk = uh.parse_mc2(hash, cls.ident, handler=cls)
        return cls(salt=salt, checksum=chk)

    def to_string(self):
        return uh.render_mc2(self.ident, self.salt, self.checksum)

    # _calc_checksum() - provided by subclass


class md5_crypt(uh.HasManyBackends, _MD5_Common):
    """This class implements the MD5-Crypt password hash, and follows the :ref:`password-hash-api`.

    It supports a variable-length salt.

    The :meth:`~passlib.ifc.PasswordHash.using` method accepts the following optional keywords:

    :type salt: str
    :param salt:
        Optional salt string.
        If not specified, one will be autogenerated (this is recommended).
        If specified, it must be 0-8 characters, drawn from the regexp range ``[./0-9A-Za-z]``.

    :type salt_size: int
    :param salt_size:
        Optional number of characters to use when autogenerating new salts.
        Defaults to 8, but can be any value between 0 and 8.
        (This is mainly needed when generating Cisco-compatible hashes,
        which require ``salt_size=4``).

    :type relaxed: bool
    :param relaxed:
        By default, providing an invalid value for one of the other
        keywords will result in a :exc:`ValueError`. If ``relaxed=True``,
        and the error can be corrected, a :exc:`~passlib.exc.PasslibHashWarning`
        will be issued instead. Correctable errors include
        ``salt`` strings that are too long.

        .. versionadded:: 1.6
    """

    name = "md5_crypt"
    ident = "$1$"
    # FIXME: can't find definitive policy on how md5-crypt handles non-ascii.
    #        all backends currently coerce -> utf-8

    backends = ("builtin",)

    # ---------------------------------------------------------------
    # builtin backend
    # ---------------------------------------------------------------
    @classmethod
    def _load_backend_builtin(cls):
        cls._set_calc_checksum_backend(cls._calc_checksum_builtin)
        return True

    def _calc_checksum_builtin(self, secret):
        return _raw_md5_crypt(secret, self.salt)


class apr_md5_crypt(_MD5_Common):
    """This class implements the Apr-MD5-Crypt password hash, and follows the :ref:`password-hash-api`.

    It supports a variable-length salt.

    The :meth:`~passlib.ifc.PasswordHash.using` method accepts the following optional keywords:

    :type salt: str
    :param salt:
        Optional salt string.
        If not specified, one will be autogenerated (this is recommended).
        If specified, it must be 0-8 characters, drawn from the regexp range ``[./0-9A-Za-z]``.

    :type relaxed: bool
    :param relaxed:
        By default, providing an invalid value for one of the other
        keywords will result in a :exc:`ValueError`. If ``relaxed=True``,
        and the error can be corrected, a :exc:`~passlib.exc.PasslibHashWarning`
        will be issued instead. Correctable errors include
        ``salt`` strings that are too long.

        .. versionadded:: 1.6
    """

    name = "apr_md5_crypt"
    ident = "$apr1$"

    def _calc_checksum(self, secret):
        return _raw_md5_crypt(secret, self.salt, use_apr=True)
