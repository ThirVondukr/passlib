"""traditional unix (DES) crypt and variants"""

import re
from warnings import warn

import passlib.utils.handlers as uh
from passlib.crypto.des import des_encrypt_int_block
from passlib.utils import to_unicode
from passlib.utils.binary import h64, h64big

# local
__all__ = [
    "des_crypt",
    "bsdi_crypt",
    "bigcrypt",
    "crypt16",
]

_BNULL = b"\x00"


def _crypt_secret_to_key(secret):
    """convert secret to 64-bit DES key.

    this only uses the first 8 bytes of the secret,
    and discards the high 8th bit of each byte at that.
    a null parity bit is inserted after every 7th bit of the output.
    """
    # NOTE: this would set the parity bits correctly,
    #       but des_encrypt_int_block() would just ignore them...
    ##return sum(expand_7bit(byte_elem_value(c) & 0x7f) << (56-i*8)
    ##           for i, c in enumerate(secret[:8]))
    return sum((c & 0x7F) << (57 - i * 8) for i, c in enumerate(secret[:8]))


def _raw_des_crypt(secret, salt):
    """pure-python backed for des_crypt"""
    assert len(salt) == 2

    # NOTE: some OSes will accept non-HASH64 characters in the salt,
    #       but what value they assign these characters varies wildy,
    #       so just rejecting them outright.
    #       the same goes for single-character salts...
    #       some OSes duplicate the char, some insert a '.' char,
    #       and openbsd does (something) which creates an invalid hash.
    salt_value = h64.decode_int12(salt)

    # gotta do something - no official policy since this predates unicode
    if isinstance(secret, str):
        secret = secret.encode("utf-8")
    assert isinstance(secret, bytes)

    # forbidding NULL char because underlying crypt() rejects them too.
    if _BNULL in secret:
        raise uh.exc.NullPasswordError(des_crypt)

    # convert first 8 bytes of secret string into an integer
    key_value = _crypt_secret_to_key(secret)

    # run data through des using input of 0
    result = des_encrypt_int_block(key_value, 0, salt_value, 25)

    # run h64 encode on result
    return h64big.encode_int64(result)


def _bsdi_secret_to_key(secret):
    """convert secret to DES key used by bsdi_crypt"""
    key_value = _crypt_secret_to_key(secret)
    idx = 8
    end = len(secret)
    while idx < end:
        next = idx + 8
        tmp_value = _crypt_secret_to_key(secret[idx:next])
        key_value = des_encrypt_int_block(key_value, key_value) ^ tmp_value
        idx = next
    return key_value


def _raw_bsdi_crypt(secret, rounds, salt):
    """pure-python backend for bsdi_crypt"""

    # decode salt
    salt_value = h64.decode_int24(salt)

    # gotta do something - no official policy since this predates unicode
    if isinstance(secret, str):
        secret = secret.encode("utf-8")
    assert isinstance(secret, bytes)

    # forbidding NULL char because underlying crypt() rejects them too.
    if _BNULL in secret:
        raise uh.exc.NullPasswordError(bsdi_crypt)

    # convert secret string into an integer
    key_value = _bsdi_secret_to_key(secret)

    # run data through des using input of 0
    result = des_encrypt_int_block(key_value, 0, salt_value, rounds)

    # run h64 encode on result
    return h64big.encode_int64(result)


class des_crypt(uh.TruncateMixin, uh.HasManyBackends, uh.HasSalt, uh.GenericHandler):  # type: ignore[misc]
    """This class implements the des-crypt password hash, and follows the :ref:`password-hash-api`.

    It supports a fixed-length salt.

    The :meth:`~passlib.ifc.PasswordHash.using` method accepts the following optional keywords:

    :type salt: str
    :param salt:
        Optional salt string.
        If not specified, one will be autogenerated (this is recommended).
        If specified, it must be 2 characters, drawn from the regexp range ``[./0-9A-Za-z]``.

    :param bool truncate_error:
        By default, des_crypt will silently truncate passwords larger than 8 bytes.
        Setting ``truncate_error=True`` will cause :meth:`~passlib.ifc.PasswordHash.hash`
        to raise a :exc:`~passlib.exc.PasswordTruncateError` instead.

        .. versionadded:: 1.7

    :type relaxed: bool
    :param relaxed:
        By default, providing an invalid value for one of the other
        keywords will result in a :exc:`ValueError`. If ``relaxed=True``,
        and the error can be corrected, a :exc:`~passlib.exc.PasslibHashWarning`
        will be issued instead. Correctable errors include
        ``salt`` strings that are too long.

        .. versionadded:: 1.6
    """

    # --------------------
    # PasswordHash
    # --------------------
    name = "des_crypt"
    setting_kwds = ("salt", "truncate_error")

    # --------------------
    # GenericHandler
    # --------------------
    checksum_chars = uh.HASH64_CHARS
    checksum_size = 11

    # --------------------
    # HasSalt
    # --------------------
    min_salt_size = max_salt_size = 2
    salt_chars = uh.HASH64_CHARS

    # --------------------
    # TruncateMixin
    # --------------------
    truncate_size = 8
    # FORMAT: 2 chars of H64-encoded salt + 11 chars of H64-encoded checksum

    _hash_regex = re.compile(
        r"""
        ^
        (?P<salt>[./a-z0-9]{2})
        (?P<chk>[./a-z0-9]{11})?
        $""",
        re.VERBOSE | re.IGNORECASE,
    )

    @classmethod
    def from_string(cls, hash):
        hash = to_unicode(hash, "ascii", "hash")
        salt, chk = hash[:2], hash[2:]
        return cls(salt=salt, checksum=chk or None)

    def to_string(self):
        return f"{self.salt}{self.checksum}"

    def _calc_checksum(self, secret):
        # check for truncation (during .hash() calls only)
        if self.use_defaults:
            self._check_truncate_policy(secret)

        return self._calc_checksum_backend(secret)

    backends = ("builtin",)

    # ---------------------------------------------------------------
    # builtin backend
    # ---------------------------------------------------------------
    @classmethod
    def _load_backend_builtin(cls):
        cls._set_calc_checksum_backend(cls._calc_checksum_builtin)
        return True

    def _calc_checksum_builtin(self, secret):
        return _raw_des_crypt(secret, self.salt.encode("ascii")).decode("ascii")


class bsdi_crypt(uh.HasManyBackends, uh.HasRounds, uh.HasSalt, uh.GenericHandler):  # type: ignore[misc]
    """This class implements the BSDi-Crypt password hash, and follows the :ref:`password-hash-api`.

    It supports a fixed-length salt, and a variable number of rounds.

    The :meth:`~passlib.ifc.PasswordHash.using` method accepts the following optional keywords:

    :type salt: str
    :param salt:
        Optional salt string.
        If not specified, one will be autogenerated (this is recommended).
        If specified, it must be 4 characters, drawn from the regexp range ``[./0-9A-Za-z]``.

    :type rounds: int
    :param rounds:
        Optional number of rounds to use.
        Defaults to 5001, must be between 1 and 16777215, inclusive.

    :type relaxed: bool
    :param relaxed:
        By default, providing an invalid value for one of the other
        keywords will result in a :exc:`ValueError`. If ``relaxed=True``,
        and the error can be corrected, a :exc:`~passlib.exc.PasslibHashWarning`
        will be issued instead. Correctable errors include ``rounds``
        that are too small or too large, and ``salt`` strings that are too long.

        .. versionadded:: 1.6

    .. versionchanged:: 1.6
        :meth:`hash` will now issue a warning if an even number of rounds is used
        (see :ref:`bsdi-crypt-security-issues` regarding weak DES keys).
    """

    # --GenericHandler--
    name = "bsdi_crypt"
    setting_kwds = ("salt", "rounds")
    checksum_size = 11
    checksum_chars = uh.HASH64_CHARS

    # --HasSalt--
    min_salt_size = max_salt_size = 4
    salt_chars = uh.HASH64_CHARS

    # --HasRounds--
    default_rounds = 5001
    min_rounds = 1
    max_rounds = 16777215  # (1<<24)-1
    rounds_cost = "linear"

    # NOTE: OpenBSD login.conf reports 7250 as minimum allowed rounds,
    # but that seems to be an OS policy, not a algorithm limitation.
    _hash_regex = re.compile(
        r"""
        ^
        _
        (?P<rounds>[./a-z0-9]{4})
        (?P<salt>[./a-z0-9]{4})
        (?P<chk>[./a-z0-9]{11})?
        $""",
        re.VERBOSE | re.IGNORECASE,
    )

    @classmethod
    def from_string(cls, hash):
        hash = to_unicode(hash, "ascii", "hash")
        m = cls._hash_regex.match(hash)
        if not m:
            raise uh.exc.InvalidHashError(cls)
        rounds, salt, chk = m.group("rounds", "salt", "chk")
        return cls(
            rounds=h64.decode_int24(rounds.encode("ascii")),
            salt=salt,
            checksum=chk,
        )

    def to_string(self):
        return "_{}{}{}".format(
            h64.encode_int24(self.rounds).decode("ascii"),
            self.salt,
            self.checksum,
        )

    # NOTE: keeping this flag for admin/choose_rounds.py script.
    #       want to eventually expose rounds logic to that script in better way.
    _avoid_even_rounds = True

    @classmethod
    def using(cls, **kwds):
        subcls = super().using(**kwds)
        if not subcls.default_rounds & 1:
            # issue warning if caller set an even 'rounds' value.
            warn(
                "bsdi_crypt rounds should be odd, as even rounds may reveal weak DES keys",
                uh.exc.PasslibSecurityWarning,
            )
        return subcls

    @classmethod
    def _generate_rounds(cls):
        rounds = super()._generate_rounds()
        # ensure autogenerated rounds are always odd
        # NOTE: doing this even for default_rounds so needs_update() doesn't get
        #       caught in a loop.
        # FIXME: this technically might generate a rounds value 1 larger
        # than the requested upper bound - but better to err on side of safety.
        return rounds | 1

    def _calc_needs_update(self, **kwds):
        # mark bsdi_crypt hashes as deprecated if they have even rounds.
        if not self.rounds & 1:
            return True
        # hand off to base implementation
        return super()._calc_needs_update(**kwds)

    backends = ("builtin",)

    # ---------------------------------------------------------------
    # builtin backend
    # ---------------------------------------------------------------
    @classmethod
    def _load_backend_builtin(cls):
        cls._set_calc_checksum_backend(cls._calc_checksum_builtin)
        return True

    def _calc_checksum_builtin(self, secret):
        return _raw_bsdi_crypt(secret, self.rounds, self.salt.encode("ascii")).decode(
            "ascii"
        )


class bigcrypt(uh.HasSalt, uh.GenericHandler):
    """This class implements the BigCrypt password hash, and follows the :ref:`password-hash-api`.

    It supports a fixed-length salt.

    The :meth:`~passlib.ifc.PasswordHash.using` method accepts the following optional keywords:

    :type salt: str
    :param salt:
        Optional salt string.
        If not specified, one will be autogenerated (this is recommended).
        If specified, it must be 22 characters, drawn from the regexp range ``[./0-9A-Za-z]``.

    :type relaxed: bool
    :param relaxed:
        By default, providing an invalid value for one of the other
        keywords will result in a :exc:`ValueError`. If ``relaxed=True``,
        and the error can be corrected, a :exc:`~passlib.exc.PasslibHashWarning`
        will be issued instead. Correctable errors include
        ``salt`` strings that are too long.

        .. versionadded:: 1.6
    """

    # --GenericHandler--
    name = "bigcrypt"
    setting_kwds = ("salt",)
    checksum_chars = uh.HASH64_CHARS
    # NOTE: checksum chars must be multiple of 11

    # --HasSalt--
    min_salt_size = max_salt_size = 2
    salt_chars = uh.HASH64_CHARS
    _hash_regex = re.compile(
        r"""
        ^
        (?P<salt>[./a-z0-9]{2})
        (?P<chk>([./a-z0-9]{11})+)?
        $""",
        re.VERBOSE | re.IGNORECASE,
    )

    @classmethod
    def from_string(cls, hash):
        hash = to_unicode(hash, "ascii", "hash")
        m = cls._hash_regex.match(hash)
        if not m:
            raise uh.exc.InvalidHashError(cls)
        salt, chk = m.group("salt", "chk")
        return cls(salt=salt, checksum=chk)

    def to_string(self):
        return f"{self.salt}{self.checksum}"

    def _norm_checksum(self, checksum, relaxed=False):
        checksum = super()._norm_checksum(checksum, relaxed=relaxed)
        if len(checksum) % 11:
            raise uh.exc.InvalidHashError(self)
        return checksum

    def _calc_checksum(self, secret):
        if isinstance(secret, str):
            secret = secret.encode("utf-8")
        chk = _raw_des_crypt(secret, self.salt.encode("ascii"))
        idx = 8
        end = len(secret)
        while idx < end:
            next = idx + 8
            chk += _raw_des_crypt(secret[idx:next], chk[-11:-9])
            idx = next
        return chk.decode("ascii")


class crypt16(uh.TruncateMixin, uh.HasSalt, uh.GenericHandler):  # type: ignore[misc]
    """This class implements the crypt16 password hash, and follows the :ref:`password-hash-api`.

    It supports a fixed-length salt.

    The :meth:`~passlib.ifc.PasswordHash.using` method accepts the following optional keywords:

    :type salt: str
    :param salt:
        Optional salt string.
        If not specified, one will be autogenerated (this is recommended).
        If specified, it must be 2 characters, drawn from the regexp range ``[./0-9A-Za-z]``.

    :param bool truncate_error:
        By default, crypt16 will silently truncate passwords larger than 16 bytes.
        Setting ``truncate_error=True`` will cause :meth:`~passlib.ifc.PasswordHash.hash`
        to raise a :exc:`~passlib.exc.PasswordTruncateError` instead.

        .. versionadded:: 1.7

    :type relaxed: bool
    :param relaxed:
        By default, providing an invalid value for one of the other
        keywords will result in a :exc:`ValueError`. If ``relaxed=True``,
        and the error can be corrected, a :exc:`~passlib.exc.PasslibHashWarning`
        will be issued instead. Correctable errors include
        ``salt`` strings that are too long.

        .. versionadded:: 1.6
    """

    # --------------------
    # PasswordHash
    # --------------------
    name = "crypt16"
    setting_kwds = ("salt", "truncate_error")

    # --------------------
    # GenericHandler
    # --------------------
    checksum_size = 22
    checksum_chars = uh.HASH64_CHARS

    # --------------------
    # HasSalt
    # --------------------
    min_salt_size = max_salt_size = 2
    salt_chars = uh.HASH64_CHARS

    # --------------------
    # TruncateMixin
    # --------------------
    truncate_size = 16
    _hash_regex = re.compile(
        r"""
        ^
        (?P<salt>[./a-z0-9]{2})
        (?P<chk>[./a-z0-9]{22})?
        $""",
        re.VERBOSE | re.IGNORECASE,
    )

    @classmethod
    def from_string(cls, hash):
        hash = to_unicode(hash, "ascii", "hash")
        m = cls._hash_regex.match(hash)
        if not m:
            raise uh.exc.InvalidHashError(cls)
        salt, chk = m.group("salt", "chk")
        return cls(salt=salt, checksum=chk)

    def to_string(self):
        return f"{self.salt}{self.checksum}"

    def _calc_checksum(self, secret):
        if isinstance(secret, str):
            secret = secret.encode("utf-8")

        # check for truncation (during .hash() calls only)
        if self.use_defaults:
            self._check_truncate_policy(secret)

        # parse salt value
        try:
            salt_value = h64.decode_int12(self.salt.encode("ascii"))
        except ValueError:  # pragma: no cover - caught by class
            raise ValueError("invalid chars in salt") from None

        # convert first 8 byts of secret string into an integer,
        key1 = _crypt_secret_to_key(secret)

        # run data through des using input of 0
        result1 = des_encrypt_int_block(key1, 0, salt_value, 20)

        # convert next 8 bytes of secret string into integer (key=0 if secret < 8 chars)
        key2 = _crypt_secret_to_key(secret[8:16])

        # run data through des using input of 0
        result2 = des_encrypt_int_block(key2, 0, salt_value, 5)

        # done
        chk = h64big.encode_int64(result1) + h64big.encode_int64(result2)
        return chk.decode("ascii")
