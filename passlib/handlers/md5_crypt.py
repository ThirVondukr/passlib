"""passlib.handlers.md5_crypt - md5-crypt algorithm"""
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
from passlib.utils import b, bytes, to_bytes, h64, safe_os_crypt, \
                          classproperty, handlers as uh
#pkg
#local
__all__ = [
    "md5_crypt",
    "apr_md5_crypt",
]

#=========================================================
#pure-python backend
#=========================================================
B_NULL = b("\x00")
B_MD5_MAGIC = b("$1$")
B_APR_MAGIC = b("$apr1$")

def raw_md5_crypt(secret, salt, apr=False):
    """perform raw md5-crypt calculation

    :arg secret:
        password, bytes or unicode (encoded to utf-8)

    :arg salt:
        salt portion of hash, bytes or unicode (encoded to ascii),
        clipped to max 8 bytes.

    :param apr:
        flag to use apache variant

    :returns:
        encoded checksum as unicode
    """
    #NOTE: regarding 'apr' format:
    # really, apache? you had to invent a whole new "$apr1$" format,
    # when all you did was change the ident incorporated into the hash?
    # would love to find webpage explaining why just using a portable
    # implementation of $1$ wasn't sufficient. *nothing* else was changed.

    #validate secret
    #FIXME: can't find definitive policy on how md5-crypt handles non-ascii.
    if isinstance(secret, unicode):
        secret = secret.encode("utf-8")

    #validate salt
    if isinstance(salt, unicode):
        salt = salt.encode("ascii")
    if len(salt) > 8:
        salt = salt[:8]

    #primary hash = secret+id+salt+...
    h = md5(secret)
    h.update(B_APR_MAGIC if apr else B_MD5_MAGIC)
    h.update(salt)

    # primary hash - add len(secret) chars of tmp hash,
    # where temp hash is md5(secret+salt+secret)
    tmp = md5(secret + salt + secret).digest()
    assert len(tmp) == 16
    slen = len(secret)
    h.update(tmp * (slen//16) + tmp[:slen % 16])

    # primary hash - add null chars & first char of secret !?!
    #
    # this may have historically been a bug,
    # where they meant to use tmp[0] instead of '\x00',
    # but the code memclear'ed the buffer,
    # and now all implementations have to use this.
    #
    # sha-crypt replaced this step with
    # something more useful, anyways
    idx = len(secret)
    evenchar = secret[:1]
    while idx > 0:
        h.update(B_NULL if idx & 1 else evenchar)
        idx >>= 1
    result = h.digest()

    #next:
    # do 1000 rounds of md5 to make things harder.
    # each round we do digest of round-specific content,
    # where content is formed from concatenation of...
    #   secret if round % 2 else result
    #   salt if round % 3
    #   secret if round % 7
    #   result if round % 2 else secret
    #
    #NOTE:
    # instead of doing this directly, this implementation
    # pre-computes all the combinations of strings & md5 hash objects
    # that will be needed, in order to perform round operations as fast as possible
    # (so that each round consists of one hash create/copy + 1 update + 1 digest)
    #
    #TODO: might be able to optimize even further by removing need for tests, since
    # if/then pattern is easily predicatble -
    # pattern is 7-0-1-0-3-0 (where 1 bit = mult 2, 2 bit = mult 3, 3 bit = mult 7)
    secret_secret = secret*2
    salt_secret = salt+secret
    salt_secret_secret = salt + secret*2
    secret_hash = md5(secret).copy
    secret_secret_hash = md5(secret_secret).copy
    secret_salt_hash = md5(secret+salt).copy
    secret_salt_secret_hash = md5(secret+salt_secret).copy
    for idx in xrange(1000):
        if idx & 1:
            if idx % 3:
                if idx % 7:
                    h = secret_salt_secret_hash()
                else:
                    h = secret_salt_hash()
            elif idx % 7:
                h = secret_secret_hash()
            else:
                h = secret_hash()
            h.update(result)
        else:
            h = md5(result)
            if idx % 3:
                if idx % 7:
                    h.update(salt_secret_secret)
                else:
                    h.update(salt_secret)
            elif idx % 7:
                h.update(secret_secret)
            else:
                h.update(secret)
        result = h.digest()

    #encode resulting hash
    return h64.encode_transposed_bytes(result, _chk_offsets).decode("ascii")

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
class _Md5Common(uh.HasSalt, uh.GenericHandler):
    "common code for md5_crypt and apr_md5_crypt"
    #=========================================================
    #algorithm information
    #=========================================================
    #--GenericHandler--
    #name in subclass
    setting_kwds = ("salt", "salt_size")
    #ident in subclass
    checksum_size = 22
    checksum_chars = uh.H64_CHARS

    #--HasSalt--
    min_salt_size = 0
    max_salt_size = 8
    salt_chars = uh.H64_CHARS

    #=========================================================
    #internal helpers
    #=========================================================

    @classmethod
    def from_string(cls, hash):
        salt, chk = uh.parse_mc2(hash, cls.ident, cls.name)
        return cls(salt=salt, checksum=chk, strict=bool(chk))

    def to_string(self):
        return uh.render_mc2(self.ident, self.salt, self.checksum)

    #=========================================================
    #primary interface
    #=========================================================
    #calc_checksum in subclass

    #=========================================================
    #eoc
    #=========================================================

#=========================================================
#handler
#=========================================================
class md5_crypt(uh.HasManyBackends, _Md5Common):
    """This class implements the MD5-Crypt password hash, and follows the :ref:`password-hash-api`.

    It supports a variable-length salt.

    The :meth:`encrypt()` and :meth:`genconfig` methods accept the following optional keywords:

    :param salt:
        Optional salt string.
        If not specified, one will be autogenerated (this is recommended).
        If specified, it must be 0-8 characters, drawn from the regexp range ``[./0-9A-Za-z]``.

    It will use the first available of two possible backends:

    * stdlib :func:`crypt()`, if the host OS supports MD5-Crypt.
    * a pure python implementation of MD5-Crypt built into passlib.

    You can see which backend is in use by calling the :meth:`get_backend()` method.
    """
    #=========================================================
    #algorithm information
    #=========================================================
    name = "md5_crypt"
    ident = u"$1$"

    #=========================================================
    #primary interface
    #=========================================================
    #FIXME: can't find definitive policy on how md5-crypt handles non-ascii.
    # all backends currently coerce -> utf-8

    backends = ("os_crypt", "builtin")

    _has_backend_builtin = True

    @classproperty
    def _has_backend_os_crypt(cls):
        h = u'$1$test$pi/xDtU5WFVRqYS6BMU8X/'
        return bool(safe_os_crypt and safe_os_crypt(u"test",h)[1]==h)

    def _calc_checksum_builtin(self, secret):
        return raw_md5_crypt(secret, self.salt)

    def _calc_checksum_os_crypt(self, secret):
        ok, hash = safe_os_crypt(secret, self.ident + self.salt)
        if ok:
            return hash[-22:]
        else:
            return self._calc_checksum_builtin(secret)

    #=========================================================
    #eoc
    #=========================================================

#=========================================================
#apache variant of md5-crypt
#=========================================================
class apr_md5_crypt(_Md5Common):
    """This class implements the Apr-MD5-Crypt password hash, and follows the :ref:`password-hash-api`.

    It supports a variable-length salt.

    The :meth:`encrypt()` and :meth:`genconfig` methods accept the following optional keywords:

    :param salt:
        Optional salt string.
        If not specified, one will be autogenerated (this is recommended).
        If specified, it must be 0-8 characters, drawn from the regexp range ``[./0-9A-Za-z]``.
    """
    #=========================================================
    #algorithm information
    #=========================================================
    name = "apr_md5_crypt"
    ident = u"$apr1$"

    #=========================================================
    #primary interface
    #=========================================================
    def calc_checksum(self, secret):
        return raw_md5_crypt(secret, self.salt, apr=True)

    #=========================================================
    #eoc
    #=========================================================

#=========================================================
#eof
#=========================================================
