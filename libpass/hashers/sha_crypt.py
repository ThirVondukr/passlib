from __future__ import annotations

import hashlib
import secrets
from typing import TYPE_CHECKING, Callable

from libpass._utils.bytes import StrOrBytes, as_bytes, as_str
from libpass._utils.str import repeat_string
from libpass._utils.validation import validate_rounds
from libpass.binary import B64_CHARS, h64_engine
from libpass.hashers.abc import PasswordHasher
from libpass.inspect.sha_crypt import SHA256CryptInfo, inspect_sha_crypt

if TYPE_CHECKING:
    from libpass._utils.protocols import HashLike


def _gen_salt(size: int) -> str:
    return "".join(secrets.choice(B64_CHARS) for _ in range(size))


# map used to transpose bytes when encoding final sha256_crypt digest
_256_transpose_map = (
    20,
    10,
    0,
    11,
    1,
    21,
    2,
    22,
    12,
    23,
    13,
    3,
    14,
    4,
    24,
    5,
    25,
    15,
    26,
    16,
    6,
    17,
    7,
    27,
    8,
    28,
    18,
    29,
    19,
    9,
    30,
    31,
)

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


def _sha_crypt(
    secret: bytes, salt: bytes, rounds: int, hash_method: Callable[[bytes], HashLike]
) -> str:
    """perform raw sha256-crypt / sha512-crypt

    this function provides a pure-python implementation of the internals
    for the SHA256-Crypt and SHA512-Crypt algorithms; it doesn't
    handle any of the parsing/validation of the hash strings themselves.
    """

    # NOTE: the setup portion of this algorithm scales ~linearly in time
    #       with the size of the password, making it vulnerable to a DOS from
    #       unreasonably large inputs. the following code has some optimizations
    #       which would make things even worse, using O(pwd_len**2) memory
    #       when calculating digest P.
    #
    #       to mitigate these two issues: 1) this code switches to a
    #       O(pwd_len)-memory algorithm for passwords that are much larger
    #       than average, and 2) Passlib enforces a library-wide max limit on
    #       the size of passwords it will allow, to prevent this algorithm and
    #       others from being DOSed in this way (see passlib.exc.PasswordSizeError
    #       for details).

    secret_len = len(secret)
    initial = hash_method(secret + salt + secret).digest()

    # start out with pwd + salt
    sha = hash_method(secret + salt)
    sha.update(repeat_string(initial, secret_len))

    i = secret_len
    while i:
        sha.update(initial if i & 1 else secret)
        i >>= 1

    da = sha.digest()
    # Finish A

    if secret_len < 96:
        # this method is faster under python, but uses O(pwd_len**2) memory;
        # so we don't use it for larger passwords to avoid a potential DOS.
        dp = repeat_string(hash_method(secret * secret_len).digest(), secret_len)
    else:
        # this method is slower under python, but uses a fixed amount of memory.
        tmp_ctx = hash_method(secret)
        i = secret_len - 1
        while i:
            tmp_ctx.update(secret)
            i -= 1
        dp = repeat_string(tmp_ctx.digest(), secret_len)

    ds = hash_method(salt * (16 + da[0])).digest()[: len(salt)]

    # ===================================================================
    # digest C - for a variable number of rounds, combine A, S, and P
    #            digests in various ways; in order to burn CPU time.
    # ===================================================================

    # NOTE: the original SHA256/512-Crypt specification performs the C digest
    # calculation using the following loop:
    #
    ##dc = da
    ##i = 0
    ##while i < rounds:
    ##    tmp_ctx = hash_const(dp if i & 1 else dc)
    ##    if i % 3:
    ##        tmp_ctx.update(ds)
    ##    if i % 7:
    ##        tmp_ctx.update(dp)
    ##    tmp_ctx.update(dc if i & 1 else dp)
    ##    dc = tmp_ctx.digest()
    ##    i += 1
    #
    # The code Passlib uses (below) implements an equivalent algorithm,
    # it's just been heavily optimized to pre-calculate a large number
    # of things beforehand. It works off of a couple of observations
    # about the original algorithm:
    #
    # 1. each round is a combination of 'dc', 'ds', and 'dp'; determined
    #    by the whether 'i' a multiple of 2,3, and/or 7.
    # 2. since lcm(2,3,7)==42, the series of combinations will repeat
    #    every 42 rounds.
    # 3. even rounds 0-40 consist of 'hash(dc + round-specific-constant)';
    #    while odd rounds 1-41 consist of hash(round-specific-constant + dc)
    #
    # Using these observations, the following code...
    # * calculates the round-specific combination of ds & dp for each round 0-41
    # * runs through as many 42-round blocks as possible
    # * runs through as many pairs of rounds as possible for remaining rounds
    # * performs once last round if the total rounds should be odd.
    #
    # this cuts out a lot of the control overhead incurred when running the
    # original loop 40,000+ times in python, resulting in ~20% increase in
    # speed under CPython (though still 2x slower than glibc crypt)

    # prepare the 6 combinations of ds & dp which are needed
    # (order of 'perms' must match how _c_digest_offsets was generated)
    perms = [dp, dp + dp, dp + ds, dp + ds + dp, ds + dp, ds + dp + dp]

    # build up list of even-round & odd-round constants,
    # and store in 21-element list as (even,odd) pairs.
    data = [(perms[even], perms[odd]) for even, odd in _c_digest_offsets]

    # perform as many full 42-round blocks as possible
    dc = da
    blocks, tail = divmod(rounds, 42)
    while blocks:
        for even, odd in data:
            dc = hash_method(odd + hash_method(dc + even).digest()).digest()
        blocks -= 1

    # perform any leftover rounds
    if tail:
        # perform any pairs of rounds
        pairs = tail >> 1
        for even, odd in data[:pairs]:
            dc = hash_method(odd + hash_method(dc + even).digest()).digest()

        # if rounds was odd, do one last round (since we started at 0,
        # last round will be an even-numbered round)
        if tail & 1:
            dc = hash_method(dc + data[pairs][0]).digest()
    return h64_engine.encode_transposed_bytes(dc, _256_transpose_map).decode("ascii")


class SHA256Hasher(PasswordHasher):
    def __init__(self, rounds: int = 535_000) -> None:
        self._rounds = rounds
        validate_rounds(self._rounds, 1000, 999_999_999)

    def hash(self, secret: StrOrBytes, *, salt: StrOrBytes | None = None) -> str:
        salt = as_str(salt) if salt is not None else _gen_salt(16)

        sha = _sha_crypt(
            secret=as_bytes(secret),
            salt=as_bytes(salt),
            rounds=self._rounds,
            hash_method=hashlib.sha256,
        )
        return SHA256CryptInfo(
            rounds=self._rounds,
            salt=salt,
            hash=as_str(sha),
        ).as_str()

    def verify(self, hash: StrOrBytes, secret: StrOrBytes) -> bool:
        info = inspect_sha_crypt(as_str(hash))
        if info is None:
            return False

        hashed = _sha_crypt(
            as_bytes(secret),
            as_bytes(info.salt),
            info.rounds,
            hashlib.sha256,
        )
        return hashed == info.hash

    def identify(self, hash: StrOrBytes) -> bool:
        return inspect_sha_crypt(as_str(hash)) is not None
