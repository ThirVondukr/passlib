"""passlib.handlers.cisco - Cisco password hashes"""
#=========================================================
#imports
#=========================================================
#core
from binascii import hexlify, unhexlify
from hashlib import md5
import logging; log = logging.getLogger(__name__)
from warnings import warn
#site
#libs
#pkg
from passlib.utils import h64, to_bytes
from passlib.utils.compat import b, bascii_to_str, unicode, u, bjoin_ints, \
             bjoin_elems, belem_ord, biter_ints, uascii_to_str, str_to_uascii
import passlib.utils.handlers as uh
#local
__all__ = [
    "cisco_pix",
    "cisco_type7",
]

#=========================================================
# cisco pix firewall hash
#=========================================================
class cisco_pix(uh.HasUserContext, uh.StaticHandler):
    """This class implements the password hash used by Cisco PIX firewalls,
    and follows the :ref:`password-hash-api`.
    It has a single round, and relies on the username
    as the salt.

    The :meth:`encrypt()`, :meth:`genhash()`, and :meth:`verify()` methods
    have the following extra keyword:

    :param user:
        String containing name of user account this password is associated with.

        This is *required* in order to correctly hash passwords associated
        with a user account on the Cisco device, as it is used to salt
        the hash.

        Conversely, this *must* be omitted or set to ``""`` in order to correctly
        hash passwords which don't have an associated user account
        (such as the "enable" password).
    """
    #=========================================================
    # class attrs
    #=========================================================
    name = "cisco_pix"
    checksum_size = 16
    checksum_chars = uh.HASH64_CHARS

    #=========================================================
    # methods
    #=========================================================
    def _calc_checksum(self, secret):
        if isinstance(secret, unicode):
            # XXX: no idea what unicode policy is, but all examples are
            # 7-bit ascii compatible, so using UTF-8
            secret = secret.encode("utf-8")

        user = self.user
        if user:
            # NOTE: not *positive* about this, but it looks like per-user
            # accounts use first 4 chars of user as salt, whereas global
            # "enable" passwords don't have any salt at all.
            if isinstance(user, unicode):
                user = user.encode("utf-8")
            secret += user[:4]

        # pad/truncate to 16
        secret = secret[:16] + b("\x00") * (16 - len(secret))

        # md5 digest
        hash = md5(secret).digest()

        # drop every 4th byte
        hash = bjoin_elems(c for i,c in enumerate(hash) if i & 3 < 3)

        # encode using Hash64
        return h64.encode_bytes(hash).decode("ascii")

    #=========================================================
    # eoc
    #=========================================================

#=========================================================
# type 7
#=========================================================
class cisco_type7(uh.GenericHandler):
    """This class implements the Type 7 password encoding used by Cisco IOS,
    and follows the :ref:`password-hash-api`.
    It has a simple 4-5 bit salt, but is nonetheless a reversible encoding
    instead of a real hash.

    The :meth:`encrypt` and :meth:`genhash` methods
    have the following optional keyword:

    :param salt:
        This may be an optional salt integer drawn from ``range(0,16)``.
        If omitted, one will be chosen at random.

    Note that while this class outputs digests in upper-case hexidecimal,
    it will accept lower-case as well.
    """
    #=========================================================
    # class attrs
    #=========================================================
    name = "cisco_type7"
    setting_kwds = ("salt",)
    checksum_chars = uh.UPPER_HEX_CHARS
    _stub_checksum = u("00")

    max_salt_value = 52

    #=========================================================
    # methods
    #=========================================================
    @classmethod
    def from_string(cls, hash):
        if not hash:
            raise ValueError("no hash provided")
        if len(hash) < 2:
            raise ValueError("invalid cisco_type7 hash")
        if isinstance(hash, bytes):
            hash = hash.decode("latin-1")
        salt = int(hash[:2]) # may throw ValueError
        return cls(salt=salt, checksum=hash[2:].upper())

    def __init__(self, salt=None, **kwds):
        super(cisco_type7, self).__init__(**kwds)
        self.salt = self._norm_salt(salt)

    def _norm_salt(self, salt):
        # NOTE: the "salt" for this algorithm is a small integer.
        # XXX: not entirely sure that values >15 are valid, so for
        # compatibility we don't output those values but we do accept them.
        if salt is None:
            if self.use_defaults:
                salt = self._generate_salt()
            else:
                raise TypeError("no salt specified")
        if not isinstance(salt, int):
            raise TypeError("salt must be an integer")
        if salt < 0 or salt > self.max_salt_value:
            msg = "salt/offset must be in 0..52 range"
            if self.relaxed:
                warn(msg, uh.PasslibHashWarning)
                salt = 0 if salt < 0 else self.max_salt_value
            else:
                raise ValueError(msg)
        return salt

    def _generate_salt(self):
        return uh.rng.randint(0, 15)

    def to_string(self):
        return "%02d%s" % (self.salt, uascii_to_str(self.checksum or
                                                    self._stub_checksum))

    def _calc_checksum(self, secret):
        # XXX: no idea what unicode policy is, but all examples are
        # 7-bit ascii compatible, so using UTF-8
        secret = to_bytes(secret, "utf-8", errname="secret")
        return str_to_uascii(hexlify(self._cipher(secret, self.salt))).upper()

    @classmethod
    def decode(cls, hash, encoding="utf-8"):
        """decode hash, returning original password.

        :arg hash: encoded password
        :param encoding: optional encoding to use (defaults to ``UTF-8``).
        :returns: password as unicode
        """
        self = cls.from_string(hash)
        tmp = unhexlify(self.checksum.encode("ascii"))
        raw = self._cipher(tmp, self.salt)
        return raw.decode(encoding) if encoding else raw

    # type7 uses a xor-based vingere variant, using the following secret key:
    _key = u("dsfd;kfoA,.iyewrkldJKDHSUBsgvca69834ncxv9873254k;fg87")

    @classmethod
    def _cipher(cls, data, salt):
        "xor static key against data - encrypts & decrypts"
        key = cls._key
        key_size = len(key)
        return bjoin_ints(
            value ^ ord(key[(salt + idx) % key_size])
            for idx, value in enumerate(biter_ints(data))
        )

#=========================================================
#eof
#=========================================================
