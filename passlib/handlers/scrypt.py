"""passlib.handlers.scrypt -- scrypt password hash"""
#=============================================================================
# imports
#=============================================================================
from __future__ import with_statement, absolute_import
# core
import logging; log = logging.getLogger(__name__)
from warnings import warn
# site
# pkg
from passlib.crypto import scrypt as _scrypt
from passlib.utils import ab64_decode, ab64_encode, to_bytes, classproperty
from passlib.utils.compat import int_types, u, uascii_to_str, suppress_cause
import passlib.utils.handlers as uh
# local
__all__ = [
    "scrypt",
]

#=============================================================================
# handler
#=============================================================================
class scrypt(uh.ParallelismMixin, uh.HasRounds, uh.HasRawChecksum, uh.HasRawSalt,
             uh.GenericHandler):
    """This class implements an SCrypt-based password [#scrypt-home]_ hash, and follows the :ref:`password-hash-api`.

    It supports a variable-length salt, a variable number of rounds,
    as well as some custom tuning parameters unique to scrypt (see below).

    The :meth:`~passlib.ifc.PasswordHash.using` method accepts the following optional keywords:

    :type salt: str
    :param salt:
        Optional salt string.
        If specified, the length must be between 0-1024 bytes.
        If not specified, one will be auto-generated (this is recommended).

    :type salt_size: int
    :param salt_size:
        Optional number of bytes to use when autogenerating new salts.
        Defaults to 16 bytes, but can be any value between 0 and 1024.

    :type rounds: int
    :param rounds:
        Optional number of rounds to use.
        Defaults to 16, but must be within ``range(1,32)``.

        .. warning::

            Unlike many hash algorithms, increasing the rounds value
            will increase both the time *and memory* required to hash a password.

    :type block_size: int
    :param block_size:
        Optional block size to pass to scrypt hash function (the ``r`` parameter).
        Useful for tuning scrypt to optimal performance for your CPU architecture.
        Defaults to 8.

    :type parallelism: int
    :param parallelism:
        Optional parallelism to pass to scrypt hash function (the ``p`` parameter).
        Defaults to 1.

    :type relaxed: bool
    :param relaxed:
        By default, providing an invalid value for one of the other
        keywords will result in a :exc:`ValueError`. If ``relaxed=True``,
        and the error can be corrected, a :exc:`~passlib.exc.PasslibHashWarning`
        will be issued instead. Correctable errors include ``rounds``
        that are too small or too large, and ``salt`` strings that are too long.

    .. note::

        The underlying scrypt hash function has a number of limitations
        on it's parameter values, which forbids certain combinations of settings.
        The requirements are:

        * ``linear_rounds = 2**<some positive integer>``
        * ``linear_rounds < 2**(16 * block_size)``
        * ``block_size * parallelism <= 2**30-1``

    .. todo::

        This class currently does not support configuring default values
        for ``block_size`` or ``parallelism`` via a :class:`~passlib.context.CryptContext`
        configuration.
    """

    #===================================================================
    # class attrs
    #===================================================================
    #--GenericHandler--
    name = "scrypt"
    ident = u("$scrypt$")

    # NOTE: scrypt supports arbitrary output sizes. since it's output runs through
    #       pbkdf2-hmac-sha256 before returning, and this could be raised eventually...
    #       but a 256-bit digest is more than sufficient for password hashing.
    checksum_size = 32
    setting_kwds = ("salt", "salt_size", "rounds", "block_size", "parallelism")

    #--HasSalt--
    default_salt_size = 16
    min_salt_size = 0
    max_salt_size = 1024

    #--HasRounds--
    # TODO: would like to dynamically pick this based on system
    default_rounds = 16
    min_rounds = 1
    max_rounds = 31  # limited by scrypt alg
    rounds_cost = "log2"

    # TODO: make default block size & parallel count configurable via using(),
    #       and deprecatable via .needs_update()

    #===================================================================
    # instance attrs
    #===================================================================

    #: default parallelism setting (min=1 currently hardcoded in mixin)
    parallelism = 1

    #: default block size setting
    block_size = 8

    #===================================================================
    # variant constructor
    #===================================================================

    @classmethod
    def using(cls, block_size=None, **kwds):
        subcls = super(scrypt, cls).using(**kwds)
        if block_size is not None:
            if isinstance(block_size, uh.native_string_types):
                block_size = int(block_size)
            subcls.block_size = subcls._norm_block_size(block_size, relaxed=kwds.get("relaxed"))

        # make sure param combination is valid for scrypt()
        try:
            _scrypt.validate(1 << cls.default_rounds, cls.block_size, cls.parallelism)
        except ValueError as err:
            raise suppress_cause(ValueError("scrypt: invalid settings combination: " + str(err)))

        return subcls

    #===================================================================
    # formatting
    #===================================================================

    # format:
    #   $scrypt$<nExp>,<r>,<p>$<salt>[$<checksum>]
    #   nExp, r, p -- decimal-encoded positive integer, no zero-padding
    #   nExp -- log cost setting
    #   r -- block size setting (usually 8)
    #   p -- parallelism setting (usually 1)
    #   salt, checksum -- ab64 encoded

    @classmethod
    def from_string(cls, hash):
        settings, salt, chk = uh.parse_mc3_long(hash, cls.ident, handler=cls)
        parts = settings.split(",")
        if len(parts) == 3:
            nexp, r, p = parts
        else:
            raise uh.exc.MalformedHashError(cls, "malformed settings field")
        salt = ab64_decode(salt.encode("ascii"))
        if chk:
            chk = ab64_decode(chk.encode("ascii"))
        return cls(rounds=uh.parse_int(nexp, param="rounds", handler=cls),
                   block_size=uh.parse_int(r, param="block_size", handler=cls),
                   parallelism=uh.parse_int(p, param="parallelism", handler=cls),
                   salt=salt,
                   checksum=chk)

    def to_string(self):
        hash = u("%s%d,%d,%d$%s$%s") % (self.ident, self.rounds,
                                        self.block_size, self.parallelism,
                                        ab64_encode(self.salt).decode("ascii"),
                                        ab64_encode(self.checksum).decode("ascii"))
        return uascii_to_str(hash)

    #===================================================================
    # init
    #===================================================================
    def __init__(self, block_size=None, **kwds):
        super(scrypt, self).__init__(**kwds)

        # init block size
        if block_size is None:
            assert uh.validate_default_value(self, self.block_size, self._norm_block_size,
                                             param="block_size")
        else:
            self.block_size = self._norm_block_size(block_size)

        # NOTE: if hash contains invalid complex constraint, relying on error
        #       being raised by scrypt call in _calc_checksum()

    @classmethod
    def _norm_block_size(cls, block_size, relaxed=False):
        return uh.norm_integer(cls, block_size, min=1, param="block_size", relaxed=relaxed)

    #===================================================================
    # backend configuration
    # NOTE: this following HasManyBackends' API, but provides it's own implementation,
    #       which actually switches the backend that 'passlib.crypto.scrypt.scrypt()' uses.
    #===================================================================

    @classproperty
    def backends(cls):
        return _scrypt.backend_values

    @classmethod
    def get_backend(cls):
        return _scrypt.backend

    @classmethod
    def has_backend(cls, name="any"):
        try:
            cls.set_backend(name, dryrun=True)
            return True
        except uh.exc.MissingBackendError:
            return False

    @classmethod
    def set_backend(cls, name="any", dryrun=False):
        _scrypt._set_backend(name, dryrun=dryrun)

    #===================================================================
    # digest calculation
    #===================================================================
    def _calc_checksum(self, secret):
        secret = to_bytes(secret, param="secret")
        return _scrypt.scrypt(secret, self.salt, n=(1 << self.rounds), r=self.block_size,
                              p=self.parallelism, keylen=self.checksum_size)

    #===================================================================
    # hash migration
    #===================================================================

    def _calc_needs_update(self, **kwds):
        """
        mark hash as needing update if rounds is outside desired bounds.
        """
        # XXX: for now, marking all hashes which don't have matching block_size setting
        if self.block_size != type(self).block_size:
            return True
        return super(scrypt, self)._calc_needs_update(**kwds)

    #===================================================================
    # eoc
    #===================================================================

#=============================================================================
# eof
#=============================================================================
