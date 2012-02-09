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
from passlib.utils import classproperty, h64, safe_crypt, test_crypt
from passlib.utils.compat import b, bytes, irange, unicode, u
import passlib.utils.handlers as uh
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

_OFFSETS = [
    (0, 3), (3, 2), (3, 3), (2, 1), (3, 2), (3, 3), (2, 3),
    (1, 2), (3, 3), (2, 3), (3, 0), (3, 3), (2, 3), (3, 2),
    (1, 3), (2, 3), (3, 2), (3, 1), (2, 3), (3, 2), (3, 3),
    ]

def extend(source, size_ref):
    "helper which repeats <source> so it's the same length as <size_ref>"
    m,d = divmod(len(size_ref), len(source))
    if d:
        return source*m + source[:d]
    else:
        return source*m

def raw_md5_crypt(password, salt, apr=False):
    """perform raw md5-crypt calculation

    :arg password:
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

    #validate password
    #FIXME: can't find definitive policy on how md5-crypt handles non-ascii.
    if isinstance(password, unicode):
        password = password.encode("utf-8")

    #validate salt
    if isinstance(salt, unicode):
        salt = salt.encode("ascii")
    if len(salt) > 8:
        salt = salt[:8]

    #primary hash = password+id+salt+...
    if apr:
        magic = B_APR_MAGIC
    else:
        magic = B_MD5_MAGIC
    a_hash = md5(password + magic + salt)

    # primary hash - add len(password) chars of tmp hash,
    # where temp hash is md5(password+salt+password)
    b = md5(password + salt + password).digest()
    a_hash.update(extend(b, password))

    # primary hash - add null chars & first char of password !?!
    #
    # this may have historically been a bug,
    # where they meant to use tmp[0] instead of '\x00',
    # but the code memclear'ed the buffer,
    # and now all implementations have to use this.
    #
    # sha-crypt replaced this step with
    # something more useful, anyways
    idx = len(password)
    evenchar = password[:1]
    while idx > 0:
        a_hash.update(B_NULL if idx & 1 else evenchar)
        idx >>= 1
    a = a_hash.digest()

    #next:
    # do 1000 rounds of md5 to make things harder.
    # each round we do digest of round-specific content,
    # where content is formed from concatenation of...
    #   secret if round % 2 else result
    #   salt if round % 3
    #   secret if round % 7
    #   result if round % 2 else secret
    #
    # NOTE: instead of doing this directly, this implementation precomputes
    # most of the data ahead of time. (see sha2_crypt for details, it
    # uses the same alg & optimization).
    #
    p = password
    s = salt
    p_p = p*2
    s_p = s+p
    evens = [p, s_p, p_p, s_p+p]
    odds =  [p, p+s, p_p, p+s_p]
    data = [(evens[e], odds[o]) for e,o in _OFFSETS]

    # perform 23 blocks of 42 rounds each
    c = a
    i = 0
    while i < 23:
        for even, odd in data:
            c = md5(odd + md5(c + even).digest()).digest()
        i += 1

    # perform 34 additional rounds, 2 at a time; for a total of 1000 rounds.
    for even, odd in data[:17]:
        c = md5(odd + md5(c + even).digest()).digest()

    #encode resulting hash
    return h64.encode_transposed_bytes(c, _chk_offsets).decode("ascii")

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
    checksum_chars = uh.HASH64_CHARS

    #--HasSalt--
    min_salt_size = 0
    max_salt_size = 8
    salt_chars = uh.HASH64_CHARS

    #=========================================================
    #internal helpers
    #=========================================================

    @classmethod
    def from_string(cls, hash):
        salt, chk = uh.parse_mc2(hash, cls.ident, cls.name)
        return cls(salt=salt, checksum=chk)

    def to_string(self):
        return uh.render_mc2(self.ident, self.salt, self.checksum)

    #=========================================================
    #primary interface
    #=========================================================
    # calc_checksum defined in subclass

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
    ident = u("$1$")

    #=========================================================
    #primary interface
    #=========================================================
    #FIXME: can't find definitive policy on how md5-crypt handles non-ascii.
    # all backends currently coerce -> utf-8

    backends = ("os_crypt", "builtin")

    _has_backend_builtin = True

    @classproperty
    def _has_backend_os_crypt(cls):
        return test_crypt("test", '$1$test$pi/xDtU5WFVRqYS6BMU8X/')

    def _calc_checksum_builtin(self, secret):
        return raw_md5_crypt(secret, self.salt)

    def _calc_checksum_os_crypt(self, secret):
        hash = safe_crypt(secret, self.ident + self.salt)
        if hash:
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
    ident = u("$apr1$")

    #=========================================================
    #primary interface
    #=========================================================
    def _calc_checksum(self, secret):
        return raw_md5_crypt(secret, self.salt, apr=True)

    #=========================================================
    #eoc
    #=========================================================

#=========================================================
#eof
#=========================================================
