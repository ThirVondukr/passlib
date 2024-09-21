import re
from base64 import b64decode, b64encode

import passlib.utils.handlers as uh
from passlib.crypto.digest import pbkdf1
from passlib.utils import to_unicode
from passlib.utils.compat import bascii_to_str

__all__ = [
    "fshp",
]


class fshp(uh.HasRounds, uh.HasRawSalt, uh.HasRawChecksum, uh.GenericHandler):
    """This class implements the FSHP password hash, and follows the :ref:`password-hash-api`.

    It supports a variable-length salt, and a variable number of rounds.

    The :meth:`~passlib.ifc.PasswordHash.using` method accepts the following optional keywords:

    :param salt:
        Optional raw salt string.
        If not specified, one will be autogenerated (this is recommended).

    :param salt_size:
        Optional number of bytes to use when autogenerating new salts.
        Defaults to 16 bytes, but can be any non-negative value.

    :param rounds:
        Optional number of rounds to use.
        Defaults to 480000, must be between 1 and 4294967295, inclusive.

    :param variant:
        Optionally specifies variant of FSHP to use.

        * ``0`` - uses SHA-1 digest (deprecated).
        * ``1`` - uses SHA-2/256 digest (default).
        * ``2`` - uses SHA-2/384 digest.
        * ``3`` - uses SHA-2/512 digest.

    :type relaxed: bool
    :param relaxed:
        By default, providing an invalid value for one of the other
        keywords will result in a :exc:`ValueError`. If ``relaxed=True``,
        and the error can be corrected, a :exc:`~passlib.exc.PasslibHashWarning`
        will be issued instead. Correctable errors include ``rounds``
        that are too small or too large, and ``salt`` strings that are too long.

        .. versionadded:: 1.6
    """

    # --GenericHandler--
    name = "fshp"
    setting_kwds = ("salt", "salt_size", "rounds", "variant")
    checksum_chars = uh.PADDED_BASE64_CHARS
    ident = "{FSHP"
    # checksum_size is property() that depends on variant

    # --HasRawSalt--
    default_salt_size = 16  # current passlib default, FSHP uses 8
    max_salt_size = None

    # --HasRounds--
    # FIXME: should probably use different default rounds
    # based on the variant. setting for default variant (sha256) for now.
    default_rounds = 480000  # current passlib default, FSHP uses 4096
    min_rounds = 1  # set by FSHP
    max_rounds = 4294967295  # 32-bit integer limit - not set by FSHP
    rounds_cost = "linear"

    # --variants--
    default_variant = 1
    _variant_info = {
        # variant: (hash name, digest size)
        0: ("sha1", 20),
        1: ("sha256", 32),
        2: ("sha384", 48),
        3: ("sha512", 64),
    }
    _variant_aliases = dict(
        [(str(k), k) for k in _variant_info]
        + [(v[0], k) for k, v in _variant_info.items()]
    )

    @classmethod
    def using(cls, variant=None, **kwds):
        subcls = super().using(**kwds)
        if variant is not None:
            subcls.default_variant = cls._norm_variant(variant)
        return subcls

    variant = None

    def __init__(self, variant=None, **kwds):
        # NOTE: variant must be set first, since it controls checksum size, etc.
        self.use_defaults = kwds.get("use_defaults")  # load this early
        if variant is not None:
            variant = self._norm_variant(variant)
        elif self.use_defaults:
            variant = self.default_variant
            assert (
                self._norm_variant(variant) == variant
            ), f"invalid default variant: {variant!r}"
        else:
            raise TypeError("no variant specified")
        self.variant = variant
        super().__init__(**kwds)

    @classmethod
    def _norm_variant(cls, variant):
        if isinstance(variant, bytes):
            variant = variant.decode("ascii")
        if isinstance(variant, str):
            try:
                variant = cls._variant_aliases[variant]
            except KeyError:
                raise ValueError("invalid fshp variant")
        if not isinstance(variant, int):
            raise TypeError("fshp variant must be int or known alias")
        if variant not in cls._variant_info:
            raise ValueError("invalid fshp variant")
        return variant

    @property
    def checksum_alg(self):
        return self._variant_info[self.variant][0]

    @property
    def checksum_size(self):
        return self._variant_info[self.variant][1]

    _hash_regex = re.compile(
        r"""
            ^
            \{FSHP
            (\d+)\| # variant
            (\d+)\| # salt size
            (\d+)\} # rounds
            ([a-zA-Z0-9+/]+={0,3}) # digest
            $""",
        re.VERBOSE,
    )

    @classmethod
    def from_string(cls, hash):
        hash = to_unicode(hash, "ascii", "hash")
        m = cls._hash_regex.match(hash)
        if not m:
            raise uh.exc.InvalidHashError(cls)
        variant, salt_size, rounds, data = m.group(1, 2, 3, 4)
        variant = int(variant)
        salt_size = int(salt_size)
        rounds = int(rounds)
        try:
            data = b64decode(data.encode("ascii"))
        except TypeError:
            raise uh.exc.MalformedHashError(cls)
        salt = data[:salt_size]
        chk = data[salt_size:]
        return cls(salt=salt, checksum=chk, rounds=rounds, variant=variant)

    def to_string(self):
        chk = self.checksum
        salt = self.salt
        data = bascii_to_str(b64encode(salt + chk))
        return "{FSHP%d|%d|%d}%s" % (self.variant, len(salt), self.rounds, data)

    def _calc_checksum(self, secret):
        if isinstance(secret, str):
            secret = secret.encode("utf-8")
        # NOTE: for some reason, FSHP uses pbkdf1 with password & salt reversed.
        #       this has only a minimal impact on security,
        #       but it is worth noting this deviation.
        return pbkdf1(
            digest=self.checksum_alg,
            secret=self.salt,
            salt=secret,
            rounds=self.rounds,
            keylen=self.checksum_size,
        )
