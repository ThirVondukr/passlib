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
from passlib.utils.compat import int_types, u, uascii_to_str
import passlib.utils.handlers as uh
# local
__all__ = [
    "scrypt",
]

#=============================================================================
# handler
#=============================================================================
class scrypt(uh.HasRounds, uh.HasRawChecksum, uh.HasRawSalt, uh.GenericHandler):
    """This class implements an SCrypt-based password [#scrypt-home]_ hash, and follows the :ref:`password-hash-api`.

    It supports a variable-length salt, a variable number of rounds,
    as well as some custom tuning parameters unique to scrypt (see below).

    The :meth:`~passlib.ifc.PasswordHash.hash` and :meth:`~passlib.ifc.PasswordHash.genconfig` methods accept the following optional keywords:

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

    :type parallel_count: int
    :param parallel_count:
        Optional parallel_count to pass to scrypt hash function (the ``p`` parameter).
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
        * ``block_size * parallel_count <= 2**30-1``

    .. todo::

        This class currently does not support configuring default values
        for ``block_size`` or ``parallel_count`` via a :class:`~passlib.context.CryptContext`
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
    setting_kwds = ("salt", "salt_size", "rounds")

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

    # TODO: make default block size & parallel count configurable via replace(),
    #       and deprecatable via .needs_update()

    #===================================================================
    # instance attrs
    #===================================================================

    block_size = 8

    parallel_count = 1

    #===================================================================
    # formatting
    #===================================================================

    # format:
    #   $scrypt$<nExp>,<r>,<p>$<salt>[$<checksum>]
    #   nExp, r, p -- decimal-encoded positive integer, no zero-padding
    #   nExp -- log cost setting
    #   r -- block size setting (usually 8)
    #   p -- parallel_count setting (usually 1)
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
                   parallel_count=uh.parse_int(p, param="parallel_count", handler=cls),
                   salt=salt,
                   checksum=chk)

    def to_string(self):
        hash = u("%s%d,%d,%d$%s$%s") % (self.ident, self.rounds,
                                        self.block_size, self.parallel_count,
                                        ab64_encode(self.salt).decode("ascii"),
                                        ab64_encode(self.checksum).decode("ascii"))
        return uascii_to_str(hash)

    #===================================================================
    # init
    #===================================================================
    def __init__(self, block_size=None, parallel_count=None, **kwds):
        super(scrypt, self).__init__(**kwds)
        self.block_size = self._norm_block_size(block_size)
        self.parallel_count = self._norm_parallel_count(parallel_count)
        _scrypt.validate(self.linear_rounds, self.block_size, self.parallel_count)

    @property
    def linear_rounds(self):
        return 1 << self.rounds

    def _norm_block_size(self, block_size):
        return self._norm_integer(block_size, self.block_size, "block_size")

    def _norm_parallel_count(self, parallel_count):
        return self._norm_integer(parallel_count, self.parallel_count, "parallel_count")

    # XXX: this might be generally useful, could move to utils.handlers...
    def _norm_integer(self, value, default, param, min=1, max=None):
        """
        helper to normalize and validate an integer value

        :arg value: value provided to constructor
        :arg default: default value if none provided. if set to ``None``, value is required.
        :arg param: name of parameter (xxx: move to first arg?)
        :param min: minimum value (defaults to 1)
        :param max: maximum value (default ``None`` means no maximum)
        :returns: validated value
        """
        # fill in default
        if value is None:
            if not self.use_defaults:
                raise TypeError("no %s specified" % param)
            if default is None:
                raise TypeError("%s %s value must be specified explicitly" % (self.name, param))
            value = default

        # check type
        if not isinstance(value, int_types):
            raise uh.exc.ExpectedTypeError(value, "integer", param)

        # check min bound
        if value < min:
            msg = "%s too low (%s requires %s >= %d)" % (param, self.name, param, min)
            if self.relaxed:
                warn(msg, uh.exc.PasslibHashWarning)
                value = min
            else:
                raise ValueError(msg)

        # check max bound
        if max and value > max:
            msg = "%s too high (%s requires  %s <= %d)" % (param, self.name, param, max)
            if self.relaxed:
                warn(msg, uh.exc.PasslibHashWarning)
                value = max
            else:
                raise ValueError(msg)

        return value

    #===================================================================
    # backend configuration
    # NOTE: this following HasManyBackends' API, but provides it's own implementation,
    #       which actually switches the backend that 'passlib.crypto.scrypt.scrypt()' uses.
    #===================================================================

    @classproperty
    def backends(cls):
        return _scrypt.backend_values

    @classproperty
    def backend(cls):
        return _scrypt.backend

    @classmethod
    def get_backend(cls):
        return cls.backend

    @classmethod
    def has_backend(cls, name="any"):
        if name == "any" or name == "default":
            return True
        else:
            return _scrypt._load_backend(name) is not None

    @classmethod
    def set_backend(cls, name="any"):
        if name != "any":
            _scrypt._set_backend(name)

    #===================================================================
    # calc checksum
    #===================================================================
    def _calc_checksum(self, secret):
        secret = to_bytes(secret, param="secret")
        return _scrypt.scrypt(secret, self.salt, n=self.linear_rounds, r=self.block_size,
                              p=self.parallel_count, keylen=self.checksum_size)

    #===================================================================
    # eoc
    #===================================================================

#=============================================================================
# eof
#=============================================================================
