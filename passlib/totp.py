"""passlib.totp -- TOTP / RFC6238 / Google Authenticator utilities."""
#=============================================================================
# imports
#=============================================================================
from __future__ import division
from passlib.utils.compat import PY3
# core
import base64
import calendar
import json
import logging; log = logging.getLogger(__name__)
import struct
import time as _time
import re
if PY3:
    from urllib.parse import urlparse, parse_qsl, quote, unquote
else:
    from urllib import quote, unquote
    from urlparse import urlparse, parse_qsl
from warnings import warn
# pkg
from passlib import exc
from passlib.utils import (to_unicode, to_bytes, consteq, memoized_property,
                           getrandbytes, rng, xor_bytes)
from passlib.utils.compat import (u, unicode, bascii_to_str, int_types, num_types,
                                  irange, byte_elem_value, UnicodeIO, PY26)
from passlib.utils.pbkdf2 import get_prf, norm_hash_name, pbkdf2
# local
__all__ = [
    # frontend classes
    "TOTP",
    "HOTP",

    # deserialization
    "from_uri",
    "from_string",

    # internal helpers
    "BaseOTP",
]

#=============================================================================
# HACK: python2.6's urlparse() won't parse query strings unless the url scheme
#       is one of the schemes in the urlparse.uses_query list. 2.7 abandoned
#       this, and parses query if present, regardless of the scheme.
#       as a workaround for py2.6, we add "otpauth" to the known list.
#=============================================================================
if PY26:
    from urlparse import uses_query
    if "otpauth" not in uses_query:
        uses_query.append("otpauth")
        log.debug("registered 'otpauth' scheme with urlparse.uses_query")
    del uses_query

#=============================================================================
# internal helpers
#=============================================================================
class _SequenceMixin(object):
    """
    helper which lets result object act like a fixed-length sequence.
    subclass just needs to provide :meth:`_as_tuple()`.
    """
    def _as_tuple(self):
        raise NotImplemented("implement in subclass")

    def __repr__(self):
        return repr(self._as_tuple())

    def __getitem__(self, idx):
        return self._as_tuple()[idx]

    def __iter__(self):
        return iter(self._as_tuple())

    def __len__(self):
        return len(self._as_tuple())

    def __eq__(self, other):
        return self._as_tuple() == other

    def __ne__(self, other):
        return not self.__eq__(other)

#-----------------------------------------------------------------------------
# token parsing / rendering helpers
#-----------------------------------------------------------------------------

#: regex used to clean whitespace from tokens & keys
_clean_re = re.compile(u("\s|[-=]"), re.U)

_chunk_sizes = [4,6,5]

def _get_group_size(klen):
    """
    helper for group_string() --
    calculates optimal size of group for given string size.
    """
    # look for exact divisor
    for size in _chunk_sizes:
        if not klen % size:
            return size
    # fallback to divisor with largest remainder
    # (so chunks are as close to even as possible)
    best = _chunk_sizes[0]
    rem = 0
    for size in _chunk_sizes:
        if klen % size > rem:
            best = size
            rem = klen % size
    return best

def group_string(value, sep="-"):
    """
    reformat string into (roughly) evenly-sized groups, separated by **sep**.
    useful for making tokens & keys easier to read by humans.
    """
    klen = len(value)
    size = _get_group_size(klen)
    return sep.join(value[o:o+size] for o in irange(0, klen, size))

#-----------------------------------------------------------------------------
# encoding helpers
#-----------------------------------------------------------------------------

def b32encode(key):
    """
    wrapper around :func:`base64.b32encode` which strips padding,
    and returns a native string.
    """
    # NOTE: using upper case by default here, since base32 has less ambiguity
    #       in that case ('i & l' are visually more similar than 'I & L')
    return bascii_to_str(base64.b32encode(key).rstrip(b"="))

def b32decode(key):
    """
    wrapper around :func:`base64.b32decode`
    which handles common mistyped chars, and inserts padding.
    """
    if isinstance(key, unicode):
        key = key.encode("ascii")
    # XXX: could correct '1' -> 'I', but could be a mistyped lower-case 'l', so leaving it alone.
    key = key.replace(b"8", b"B") # replace commonly mistyped char
    key = key.replace(b"0", b"O") # ditto
    pad = -len(key) % 8 # pad things so final string is multiple of 8
    return base64.b32decode(key + b"=" * pad, True)

def _decode_bytes(key, format):
    """
    internal _BaseOTP() helper --
    decodes key according to specified format.
    """
    if format == "raw":
        if not isinstance(key, bytes):
            raise exc.ExpectedTypeError(key, "bytes", "key")
        return key
    # for encoded data, key must be either unicode or ascii-encoded bytes,
    # and must contain a hex or base32 string.
    key = to_unicode(key, param="key")
    key = _clean_re.sub("", key).encode("utf-8") # strip whitespace & hypens
    if format == "hex" or format == "base16":
        return base64.b16decode(key.upper())
    elif format == "base32":
        return b32decode(key)
    else:
        raise ValueError("unknown byte-encoding format: %r" % (format,))

#-----------------------------------------------------------------------------
# encryption helpers -- used by to_json() / from_json() methods
#-----------------------------------------------------------------------------

#: default salt size for encrypt_key() output
ENCRYPT_SALT_SIZE = 12

#: default cost (log2 of pbkdf2 rounds) for encrypt_key() output
ENCRYPT_COST = 13

def _raw_encrypt_key(key, password, salt, cost):
    """
    internal helper for encrypt_key() & decrypt_key() --
    runs password through pbkdf2-hmac-sha256,
    and XORs key with the resulting bytes.
    """
    # NOTE: have to have a unique salt here, otherwise attacker can use known plaintext attack
    #       to figure out 'data', and trivially decrypt other keys in the database,
    #       (all without needing 'password')
    assert isinstance(key, bytes)
    password = to_bytes(password, param="password")
    data = pbkdf2(password, salt=salt, rounds=(1<<cost),
                  keylen=len(key), prf="hmac-sha256")
    return xor_bytes(key, data)

def encrypt_key(key, password, cost=None):
    """
    Helper used to encrypt TOTP keys for storage.

    Since keys will typically be small (<= 32 bytes), this just runs the password
    through PBKDF2-HMAC-SHA256, and XORs the result with the key (rather than using AES).
    A version number and the cost parameter value is prepended.

    :arg key: raw key as bytes
    :arg password: password for encryption, as bytes
    :param cost: encryption will use ``2**cost`` pbkdf2 rounds.
    :returns:
        encrypted key, using format :samp:`{version}-{cost}-{salt}-{data}`.
        ``version`` and ``cost`` are hex integers, ``salt`` and ``data`` are base32 encoded bytes.
    """
    if not key:
        raise ValueError("no key provided")
    if cost is None:
        cost = ENCRYPT_COST
    salt = getrandbytes(rng, ENCRYPT_SALT_SIZE)
    rawenckey = _raw_encrypt_key(key, password, salt, cost)
    # NOTE: * no checksum, to save space and to make things harder on attacker
    #       * considered storing as binary string, and then encoding, but no real space savings,
    #         and this is more transparent about it's structure.
    #       * since this is internal, could use base64 here, but keeping w/ base32 to be
    #         consistent w/ OTP, and that would only save ~4 bytes anyways.
    return "%X-%X-%s-%s" % (1, cost, b32encode(salt), b32encode(rawenckey))

def decrypt_key(enckey, password):
    """
    decrypt key format generated by :func:`encrypt_key`.
    """
    def _malformed_error():
        return ValueError("malformed encrypt_key() data")
    enckey = to_unicode(enckey, param="enckey")
    try:
        ver, tail = enckey.split("-", 1)
    except ValueError:
        raise _malformed_error()
    if ver != "1":
        raise ValueError("unknown encrypt_key() version")
    try:
        cost, salt, enckey = tail.split("-")
    except ValueError:
        raise _malformed_error()
    cost = int(cost, 16)
    try:
        salt = b32decode(salt)
        rawenckey = b32decode(enckey)
    except (ValueError, TypeError) as err:
        if str(err).lower() in ["incorrect padding", "non-base32 digit found"]:
             raise _malformed_error()
        raise
    return _raw_encrypt_key(rawenckey, password, salt, cost)

#-----------------------------------------------------------------------------
# offset / clock drift helpers
#-----------------------------------------------------------------------------

#: default offset preferred by suggest_offset()
#: attempts to account for time taken for user to enter token + transmission delay.
#: value is avg of 'history1' sample in the unittests.
DEFAULT_OFFSET = 0

def suggest_offset(history, period=30, target=None, default=None):
    """
    Given a history of previous verification offsets,
    calculate offset that should be used for specified timestamp.
    This is used by :meth:`verify` and :meth:`verify_next`.

    :param history:
        List of 0+ ``(timestamp, counter_offset)`` entries.

    :param period:
        Counter period in seconds (defaults to 30).

    :param target:
        Timestamp that resulting offset should target (defaults to the current time).

    :param default:
        Default offset if there are no history entries;
        also used as starting seed. for calculations.

    :returns:
        Suggested offset to use when verifying at specified time.
    """
    # NOTE: ``target`` param currently unused, reserved for future algorithm
    #       which might attempt to utilize timestamp data to account for client clock drift.

    # XXX: This function could use a lot of improvement.
    #
    # The Problem
    # -----------
    # The problem this function is trying to solve is to find an estimate for the client
    # offset at time <target>, given a list of known (time, counter_offset) values from previously
    # successful authentications.  An ideal solution would use some method (e.g. linear regression)
    # to estimate the client clock drift and skew, and correctly predict the offset
    # we need for the target timestamp.
    #
    # However, all we know for each (time, counter_offset) pair is that the actual offset at that
    # point in time lies somewhere in the half-closed interval:
    #                   ``[counter_start - time, counter_end - time)``
    # ... which can be reduced to:
    #                   ``[min_offset, min_offset + period)``
    # .. where min_offset is:
    #                   ``counter = time // period``,
    #                   ``min_offset = (counter + counter_offset) * period - time``
    #
    # Further complicating things, the actual offset is not just a function of the client clock skew,
    # but also includes a random amount of transmission delay (including time taken by the user
    # to enter the token).
    #
    # Thus any proper solution would need to predict a best fit line across a set of intervals,
    # not just datapoints, minimizing drift, while ignoring outliers.
    #
    # Current Algorithm
    # -----------------
    # For now, mostly punting on this problem.
    # Current code just takes the average & stddev of the intervals,
    # and returns value in interval ``avg +- sigma`` which is nearest ``default``.

    # use default offset
    if default is None:
        default = DEFAULT_OFFSET

    # fallback for empty list
    if not history:
        return default

    # helpers
    def calc_min_offset(time, counter_offset):
        return counter_offset * period - divmod(int(time), period)[1]

    # convert to list of min_offset values -- more useful for current algorithm
    half_period = period // 2
    min_offsets = [calc_min_offset(time, diff) for time, diff in history]
    ##log.debug("suggest_offsets(): midpoints=%r",
    ##          [min_offset+half_period for min_offset in min_offsets])

    # calc average & stddev of min_offset values
    hsize = len(history)
    avg = sum(min_offsets) // hsize
    if hsize > 2:
        _total = sum((min_offset - avg) ** 2 for min_offset in min_offsets)
        sigma = int((_total // (hsize - 1)) ** 0.5)
    else:
        # too few samples for stddev to be reliable
        # (*need* at least 2, but < 3 seems to fluctuate too much for this purpose)
        sigma = half_period

    # add half period so that avg of min_offset is now
    # avg midpoint of the [min_offset, max_offset) intervals
    avg += half_period

    # keep result within 1/2 of sigma or interval size, whichever is smaller.
    # using full sigma or interval size seems to add too much variability in output.
    bounds = min(sigma, half_period)//2

    # use default if within bounds of avg,
    # otherwise use whichever of ``avg +- bounds`` is closest to default.
    ##log.debug("suggest_offsets(): avg=%r, radius=%r, sigma=%r, bound=%r",
    ##          avg, half_period, sigma, bounds)
    if abs(default - avg) <= bounds:
        return default
    elif avg < default:
        return avg + bounds
    else:
        return avg - bounds

# def _debug_suggested_offset(data, default=None):
#     """dev helper for debugging suggested_offset() behavior"""
#     from crowbar.math import analyze_values
#     for window in range(1, len(data)+1):
#         result = []
#         offset = default # simulate offset being carried through a rolling window
#         for idx in range(len(data)-window+1):
#             offset = suggest_offset(data[idx:idx+window], default=offset)
#             result.append(offset)
#         stats = analyze_values(result)
#         print "{:2d} {:2.0f} {:2.2f} {!r}".format(window, stats.mean, stats.stdev, result)

#=============================================================================
# common code shared by TOTP & HOTP
#=============================================================================
class BaseOTP(object):
    """
    Base class for generating and verifying OTP codes.

    .. rst-class:: inline-title

    .. note::

        **This class shouldn't be used directly.**
        It's here to provide & document common functionality
        shared by the :class:`TOTP` and :class:`HOTP` classes.
        See those classes for usage instructions.

    .. _baseotp-constructor-options:

    Constructor Options
    ===================
    Both the :class:`TOTP` and :class:`HOTP` classes accept the following common options
    (only **key** and **format** may be specified as positional arguments).

    :arg str key:
        The secret key to use. By default, should be encoded as
        a base32 string (see **format** for other encodings).
        (Exactly one of **key** or ``new=True`` must be specified)

    :arg str format:
        The encoding used by the **key** parameter. May be one of:
        ``"base32"`` (base32-encoded string),
        ``"hex"`` (hexadecimal string), or ``"raw"`` (raw bytes).
        Defaults to ``"base32"``.

    :param bool new:
        If ``True``, a new key will be generated using :class:`random.SystemRandom`.
        By default, the generated key will match the digest size of the selected **alg**.
        (Exactly one ``new=True`` or **key** must be specified)

    :param str label:
        Label to associate with this token when generating a URI.
        Displayed to user by most OTP client applications (e.g. Google Authenticator),
        and typically has format such as ``"John Smith"`` or ``"jsmith@webservice.example.org"``.
        Defaults to ``None``.
        See :meth:`to_uri` for details.

    :param str issuer:
        String identifying the token issuer (e.g. the domain name of your service).
        Used internally by some OTP client applications (e.g. Google Authenticator) to distinguish entries
        which otherwise have the same label.
        Optional but strongly recommended if you're rendering to a URI.
        Defaults to ``None``.
        See :meth:`to_uri` for details.

    :param int size:
        Number of bytes when generating new keys. Defaults to size of hash algorithm (e.g. 20 for SHA1).

        .. warning::

            Overriding the default values for ``digits`` or ``alg`` (below) may
            cause problems with some OTP client programs (such as Google Authenticator),
            which may have these defaults hardcoded.

    :param int digits:
        The number of digits in the generated / accepted tokens. Defaults to ``6``.
        Must be in range [6 .. 10].

        .. rst-class:: inline-title
        .. caution::
           Due to a limitation of the HOTP algorithm, the 10th digit can only take on values 0 .. 2,
           and thus offers very little extra security.

    :param str alg:
        Name of hash algorithm to use. Defaults to ``"sha1"``.
        ``"sha256"`` and ``"sha512"`` are also accepted, per :rfc:`6238`.

    .. _baseotp-configuration-attributes:

    Configuration Attributes
    ========================
    All the OTP objects offer the following attributes,
    which correspond to the constructor options (above).
    Most of this information will be serialized by :meth:`to_uri` and :meth:`to_string`:

    .. autoattribute:: key
    .. autoattribute:: hex_key
    .. autoattribute:: base32_key
    .. autoattribute:: label
    .. autoattribute:: issuer
    .. autoattribute:: digits
    .. autoattribute:: alg

    .. _baseotp-client-provisioning:

    Client Provisioning (URIs & QRCodes)
    ====================================
    The configuration of any OTP object can be encoded into a URI [#uriformat]_,
    suitable for configuring an OTP client such as Google Authenticator.

    .. automethod:: to_uri
    .. automethod:: from_uri
    .. automethod:: pretty_key

    .. _baseotp-serialization:

    Serialization
    =============
    While :class:`TOTP` and :class:`HOTP` instances can be used statelessly
    to calculate token values, they can also be used in a persistent
    manner, to handle tracking of previously used tokens, etc.  In this case,
    they will need to be serialized to / from external storage, which
    can be performed with the following methods:

    .. automethod:: to_string
    .. automethod:: from_string

    .. attribute:: dirty

        boolean flag set by all BaseOTP subclass methods which modify the internal state.
        if true, then something has changed in the object since it was created / loaded
        via :meth:`from_string`, and needs re-persisting via :meth:`to_string`.
        After which, your application may clear the flag, or discard the object, as appropriate.

    ..
        Undocumented Helper Methods
        ===========================

        .. automethod:: normalize_token
    """
    #=============================================================================
    # class attrs
    #=============================================================================

    #: otpauth uri type that subclass implements ('totp' or 'hotp')
    #: (used by uri & serialization code)
    type = None

    #: minimum number of bytes to allow in key, enforced by passlib.
    # XXX: see if spec says anything relevant to this.
    _min_key_size = 10

    #: dict used by from_uri() to lookup subclass based on otpauth type
    _type_map = {}

    #: minimum & current serialization version (may be set independently by subclasses)
    min_json_version = json_version = 1

    #=============================================================================
    # instance attrs
    #=============================================================================

    #: secret key as raw :class:`!bytes`
    key = None

    #: copy of original encrypted key,
    #: used by to_string() to re-serialize w/ original password.
    _enckey = None

    #: number of digits in the generated tokens.
    digits = 6

    #: name of hash algorithm in use (e.g. ``"sha1"``)
    alg = "sha1"

    #: default label for :meth:`to_uri`
    label = None

    #: default issuer for :meth:`to_uri`
    issuer = None

    #---------------------------------------------------------------------------
    # state attrs
    #---------------------------------------------------------------------------

    #: flag set if internal state is modified
    dirty = False

    #=============================================================================
    # init
    #=============================================================================
    def __init__(self, key=None, format="base32",
                 # keyword only...
                 new=False, digits=None, alg=None, size=None,
                 label=None, issuer=None, dirty=False, password=None,
                 rng=rng, # mainly for unittesting
                 **kwds):
        if type(self) is BaseOTP:
            raise RuntimeError("BaseOTP() shouldn't be invoked directly -- use TOTP() or HOTP() instead")
        super(BaseOTP, self).__init__(**kwds)
        self.dirty = dirty

        # validate & normalize alg
        self.alg = norm_hash_name(alg or self.alg)
        # XXX: could use get_keyed_prf() instead
        digest_size = get_prf("hmac-" + self.alg)[1]
        if digest_size < 4:
            raise RuntimeError("%r hash digest too small" % alg)

        # parse or generate new key
        if new:
            # generate new key
            if key:
                raise TypeError("'key' and 'new' are mutually exclusive")
            if size is None:
                # default to digest size, per RFC 6238 Section 5.1
                size = digest_size
            elif size > digest_size:
                # not forbidden by spec, but would just be wasted bytes. maybe just warn about this?
                raise ValueError("'size' should be less than digest size (%d)" % digest_size)
            self.key = getrandbytes(rng, size)
        elif not key:
            raise TypeError("must specify either an existing 'key', or 'new=True'")
        elif format == "encrypted":
            # use existing-but-encrypted key, and store copy for to_string()
            if not password:
                raise ValueError("cannot load encrypted key without password")
            self._enckey = key
            self.key = decrypt_key(key, password)
        else:
            # use existing plain key
            self.key = _decode_bytes(key, format)
        if password and not self._enckey:
            # pre-encrypt copy for to_string().
            # alternately, we could keep password hanging around instead.
            self._enckey = encrypt_key(self.key, password)
        if len(self.key) < self._min_key_size:
            # only making this fatal for new=True,
            # so that existing (but ridiculously small) keys can still be used.
            msg = "for security purposes, secret key must be >= %d bytes" % self._min_key_size
            if new:
                raise ValueError(msg)
            else:
                warn(msg, exc.PasslibSecurityWarning, stacklevel=1)

        # validate digits
        if digits is None:
            digits = self.digits
        if not isinstance(digits, int_types):
            raise TypeError("digits must be an integer, not a %r" % type(digits))
        if digits < 6 or digits > 10:
            raise ValueError("digits must in range(6,11)")
        self.digits = digits

        # validate label
        if label:
            self._check_label(label)
            self.label = label

        # validate issuer
        if issuer:
            self._check_issuer(issuer)
            self.issuer = issuer

    def _check_serial(self, value, param, minval=0):
        """
        check that serial value (e.g. 'counter') is non-negative integer
        """
        if not isinstance(value, int_types):
            raise exc.ExpectedTypeError(value, "int", param)
        if value < minval:
            raise ValueError("%s must be >= %d" % (param, minval))

    def _check_label(self, label):
        """
        check that label doesn't contain chars forbidden by KeyURI spec
        """
        if label and ":" in label:
            raise ValueError("label may not contain ':'")

    def _check_issuer(self, issuer):
        """
        check that issuer doesn't contain chars forbidden by KeyURI spec
        """
        if issuer and ":" in issuer:
            raise ValueError("issuer may not contain ':'")

    #=============================================================================
    # key helpers
    #=============================================================================
    @property
    def hex_key(self):
        """
        secret key encoded as hexadecimal string
        """
        return bascii_to_str(base64.b16encode(self.key)).lower()

    @property
    def base32_key(self):
        """
        secret key encoded as base32 string
        """
        return b32encode(self.key)

    def pretty_key(self, format="base32", sep="-"):
        """
        pretty-print the secret key.

        This is mainly useful for situations where the user cannot get the qrcode to work,
        and must enter the key manually into their TOTP client. It tries to format
        the key in a manner that is easier for humans to read.

        :param format:
            format to output secret key. ``"hex"`` and ``"base32"`` are both accepted.

        :param sep:
            separator to insert to break up key visually.
            can be any of ``"-"`` (the default), ``" "``, or ``False`` (no separator).

        :return:
            key as native string.

        Usage example::

            >>> t = TOTP('s3jdvb7qd2r7jpxx')
            >>> t.pretty_key()
            'S3JD-VB7Q-D2R7-JPXX'
        """
        if format == "hex" or format == "base16":
            key = self.hex_key
        elif format == "base32":
            key = self.base32_key
        else:
            raise ValueError("unknown byte-encoding format: %r" % (format,))
        if sep:
            key = group_string(key, sep)
        return key

    #=============================================================================
    # token helpers
    #=============================================================================

    @memoized_property
    def _prf_info(self):
        return get_prf("hmac-" + self.alg)

    def _generate(self, counter):
        """
        implementation of lowlevel HOTP generation algorithm,
        shared by both TOTP and HOTP classes.

        :arg counter: HOTP counter, as non-negative integer
        :returns: token as unicode string
        """
        # generate digest
        prf, digest_size = self._prf_info
        assert isinstance(counter, int_types), "counter must be integer"
        digest = prf(self.key, struct.pack(">Q", counter))
        assert len(digest) == digest_size, "digest_size: sanity check failed"

        # derive 31-bit token value
        assert digest_size >= 20, "digest_size: sanity check 2 failed" # otherwise 0xF+4 will run off end of hash.
        offset = byte_elem_value(digest[-1]) & 0xF
        value = struct.unpack(">I", digest[offset:offset+4])[0] & 0x7fffffff

        # render to decimal string, return last <digits> chars
        # NOTE: the 10'th digit is not as secure, as it can only take on values 0-2, not 0-9,
        #       due to 31-bit mask on int ">I". But some servers / clients use it :|
        #       if 31-bit mask removed (which breaks spec), would only get values 0-4.
        digits = self.digits
        assert 0 < digits < 11, "digits: sanity check failed"
        return (u("%0*d") % (digits, value))[-digits:]

    def normalize_token(self, token):
        """
        normalize OTP token representation:
        strips whitespace, converts integers to zero-padded string,
        validates token content & number of digits.

        :arg token:
            token as ascii bytes, unicode, or an integer.

        :returns:
            token as unicode string containing only digits 0-9.

        :raises ValueError:
            if token has wrong number of digits, or contains non-numeric characters.
        """
        digits = self.digits
        if isinstance(token, int_types):
            token = u("%0*d") % (digits, token)
        else:
            token = to_unicode(token, param="token")
            token = _clean_re.sub(u(""), token)
            if not token.isdigit():
                raise ValueError("Invalid token: must contain only the digits 0-9")
        if len(token) != digits:
            raise ValueError("Invalid token: expected %d digits, got %d" %
                             (digits, len(token)))
        return token

    def _find_match(self, token, start, end, expected=None):
        """
        helper for verify() implementations --
        returns counter value within specified range that matches token.

        :arg token:
            token value to match (will be normalized internally)

        :arg start:
            starting counter value to check

        :arg end:
            check up to (but not including) this counter value

        :arg expected:
            optional expected value where search should start,
            to help speed up searches.

        :returns:
            ``(valid, match)`` where ``match`` is non-negative counter value that matched
            (or ``0`` if no match).
        """
        token = self.normalize_token(token)
        if start < 0:
            start = 0
        if end <= start:
            return False, 0
        generate = self._generate
        if not (expected is None or expected < start) and consteq(token, generate(expected)):
            return True, expected
        # XXX: if (end - start) is very large (e.g. for resync purposes),
        #      could start with expected value, and work outward from there,
        #      alternately checking before & after it until match is found.
        for counter in irange(start, end):
            if consteq(token, generate(counter)):
                return True, counter
        return False, 0

    #=============================================================================
    # uri parsing
    #=============================================================================
    @classmethod
    def from_uri(cls, uri):
        """
        create an OTP instance from a URI (such as returned by :meth:`to_uri`).

        :returns:
            :class:`TOTP` or :class:`HOTP` instance, as appropriate.

        :raises ValueError:
            if the uri cannot be parsed or contains errors.
        """
        # check for valid uri
        uri = to_unicode(uri, param="uri").strip()
        result = urlparse(uri)
        if result.scheme != "otpauth":
            raise cls._uri_error("wrong uri scheme")

        # lookup factory to handle OTP type, and hand things off to it.
        try:
            subcls = cls._type_map[result.netloc]
        except KeyError:
            raise cls._uri_error("unknown OTP type")
        return subcls._from_parsed_uri(result)

    @classmethod
    def _from_parsed_uri(cls, result):
        """
        internal from_uri() helper --
        hands off the main work to this function, once the appropriate subclass
        has been resolved.

        :param result: a urlparse() instance
        :returns: cls instance
        """

        # decode label from uri path
        label = result.path
        if label.startswith("/") and len(label) > 1:
            label = unquote(label[1:])
        else:
            raise cls._uri_error("missing label")

        # extract old-style issuer prefix
        if ":" in label:
            try:
                issuer, label = label.split(":")
            except ValueError: # too many ":"
                raise cls._uri_error("malformed label")
        else:
            issuer = None
        if label:
            label = label.strip() or None

        # parse query params
        params = dict(label=label)
        for k, v in parse_qsl(result.query):
            if k in params:
                raise cls._uri_error("duplicate parameter (%r)" % k)
            params[k] = v

        # synchronize issuer prefix w/ issuer param
        if issuer:
            if "issuer" not in params:
                params['issuer'] = issuer
            elif params['issuer'] != issuer:
                raise cls._uri_error("conflicting issuer identifiers")

        # convert query params to constructor kwds, and call constructor
        return cls(**cls._adapt_uri_params(**params))

    @classmethod
    def _adapt_uri_params(cls, label=None, secret=None, issuer=None,
                         digits=None, algorithm=None,
                          **extra):
        """
        from_uri() helper --
        converts uri params into constructor args.
        this handles the parameters common to TOTP & HOTP.
        """
        assert label, "from_uri() failed to provide label"
        if not secret:
            raise cls._uri_error("missing 'secret' parameter")
        kwds = dict(label=label, issuer=issuer, key=secret, format="base32")
        if digits:
            kwds['digits'] = cls._uri_parse_int(digits, "digits")
        if algorithm:
            kwds['alg'] = algorithm
        if extra:
            # malicious uri, deviation from spec, or newer revision of spec?
            # in either case, we issue warning and ignore extra params.
            warn("%s: unexpected parameters encountered in otp uri: %r" %
                 (cls, extra), exc.PasslibRuntimeWarning)
        return kwds

    @classmethod
    def _uri_error(cls, reason):
        """uri parsing helper -- creates preformatted error message"""
        prefix = cls.__name__ + ": " if cls.type else ""
        return ValueError("%sInvalid otpauth uri: %s" % (prefix, reason))

    @classmethod
    def _uri_parse_int(cls, source, param):
        """uri parsing helper -- int() wrapper"""
        try:
            return int(source)
        except ValueError:
            raise cls._uri_error("Malformed %r parameter" % param)

    #=============================================================================
    # uri rendering
    #=============================================================================
    def to_uri(self, label=None, issuer=None):
        """
        serialize key and configuration into a URI, per
        Google Auth's `KeyUriFormat <http://code.google.com/p/google-authenticator/wiki/KeyUriFormat>`_.

        :param str label:
            Label to associate with this token when generating a URI.
            Displayed to user by most OTP client applications (e.g. Google Authenticator),
            and typically has format such as ``"John Smith"`` or ``"jsmith@webservice.example.org"``.

            Defaults to **label** constructor argument. Must be provided in one or the other location.
            May not contain ``:``.

        :param str issuer:
            String identifying the token issuer (e.g. the domain or canonical name of your service).
            Optional but strongly recommended if you're rendering to a URI.
            Used internally by some OTP client applications (e.g. Google Authenticator) to distinguish entries
            which otherwise have the same label.

            Defaults to **issuer** constructor argument, or ``None``.
            May not contain ``:``.

        :returns:
            all the configuration information for this OTP token generator,
            encoded into a URI.

        :raises ValueError:
            * if a label was not provided either as an argument, or in the constructor.
            * if the label or issuer contains invalid characters.

        These URIs are frequently converted to a QRCode for transferring
        to a TOTP client application such as Google Auth. This can easily be done
        using external libraries such as `pyqrcode <https://pypi.python.org/pypi/PyQRCode>`_
        or `qrcode <https://pypi.python.org/pypi/qrcode>`_.
        Usage example::

            >>> from passlib.totp import TOTP
            >>> tp = TOTP('s3jdvb7qd2r7jpxx')
            >>> uri = tp.to_uri("user@example.org", "myservice.another-example.org")
            >>> uri
            'otpauth://totp/user@example.org?secret=S3JDVB7QD2R7JPXX&issuer=myservice.another-example.org'

            >>> # for example, the following uses PyQRCode
            >>> # to print the uri directly on an ANSI terminal as a qrcode:
            >>> import pyqrcode
            >>> pyqrcode.create(uri).terminal()
            (... output omitted ...)

        """
        # encode label
        if label is None:
            label = self.label
        if not label:
            raise ValueError("a label must be specified as argument, or in the constructor")
        self._check_label(label)
        # NOTE: reference examples in spec seem to indicate the '@' in a label
        #       shouldn't be escaped, though spec doesn't explicitly address this.
        # XXX: is '/' ok to leave unencoded?
        label = quote(label, '@')

        # encode query parameters
        args = self._to_uri_params()
        if issuer is None:
            issuer = self.issuer
        if issuer:
            self._check_issuer(issuer)
            args.append(("issuer", issuer))
        # NOTE: not using urllib.urlencode() because it encodes ' ' as '+';
        #       but spec says to use '%20', and not sure how fragile
        #       the various totp clients' parsers are.
        argstr = u("&").join(u("%s=%s") % (key, quote(value, ''))
                             for key, value in args)
        assert argstr, "argstr should never be empty"

        # render uri
        return u("otpauth://%s/%s?%s") % (self.type, label, argstr)

    def _to_uri_params(self):
        """return list of (key, param) entries for URI"""
        args = [("secret", self.base32_key)]
        if self.alg != "sha1":
            args.append(("algorithm", self.alg.upper()))
        if self.digits != 6:
            args.append(("digits", str(self.digits)))
        return args

    #=============================================================================
    # json parsing
    #=============================================================================
    @classmethod
    def from_string(cls, data, password=None):
        """
        Load / create an OTP object from a serialized json string
        (as generated by :meth:`to_string`).

        :arg data:
            serialized output from :meth:`to_string`, as unicode or ascii bytes.

        :param password:
            if the key was encrypted with a password, this must be provided.
            otherwise this option is ignored.

        :returns:
            a :class:`TOTP` or :class:`HOTP` instance, as appropriate.

        :raises ValueError:
            If the key has been encrypted with a password, but none was provided;
            or if the string cannot be recognized, parsed, or decoded.
        """
        if data.startswith("otpauth://"):
            return cls.from_uri(data)
        kwds = json.loads(data)
        if not (isinstance(kwds, dict) and "type" in kwds):
            raise cls._json_error("unrecognized json data")
        try:
            subcls = cls._type_map[kwds.pop('type')]
        except KeyError:
            raise cls._json_error("unknown OTP type")
        ver = kwds.pop("v", None)
        if not ver or ver < cls.min_json_version or ver > cls.json_version:
            raise cls._json_error("missing/unsupported version (%r)" % (ver,))
        # go ahead and mark as dirty (needs re-saving) if the version is too old
        kwds['dirty'] = (ver != cls.json_version)
        if password:
            # send password to constructor even if not encrypting,
            # so _enckey will get populated for to_string().
            kwds['password'] = password
        if 'enckey' in kwds:
            # handing encrypted key off to constructor, which handles the
            # decryption. this lets it get ahold of (and store) the original
            # encrypted key, so if to_string() is called again, the encrypted
            # key can be re-used.
            assert 'key' not in kwds # shouldn't be present w/ enckey
            assert 'format' not in kwds # shouldn't be present w/ enckey
            kwds.update(
                key = kwds.pop("enckey"),
                format = "encrypted",
            )
        elif 'key' in kwds:
            assert 'format' not in kwds # shouldn't be present, base32 assumed
        else:
            raise cls._json_error("missing enckey / key")
        return subcls(**subcls._from_json(ver, **kwds))

    @classmethod
    def _from_json(cls, version, **kwds):
        # default json format is just serialization of constructor kwds.
        return kwds

    @classmethod
    def _json_error(cls, reason):
        """json parsing helper -- creates preformatted error message"""
        prefix = cls.__name__ + ": " if cls.type else ""
        return ValueError("%sInvalid otp json string: %s" % (prefix, reason))

    #=============================================================================
    # json rendering
    #=============================================================================
    def to_string(self, password=None, cost=None):
        """
        serialize configuration & internal state to a json string,
        mainly for persisting client-specific state in a database.

        :param password:
            Optional password which will be used to encrypt the secret key.

            *(The key is encrypted using PBKDF2-HMAC-SHA256, see the source
            of the* :func:`encrypt_key` *function for details)*.

            If the TOTP object had a password provided to the constructor,
            to or :meth:`from_string`, you can set ``password=True`` here
            to simply re-use the previously encrypted secret key.

        :param cost:
            Optional time-cost factor for key encryption.
            This value corresponds to log2() of the number of PBKDF2
            rounds used, which currently defaults to 13.

        :returns:
            string containing the full state of the OTP object,
            serialized to an internal format (roughly, a JSON serialization
            of the constructor options).

        .. warning::

            The **password** should be kept in a secure location by your application,
            and contain a large amount of entropy (to prevent brute-force guessing).
            Since the encrypt/decrypt cycle is expected to be required
            to (de-)serialize TOTP instances every time a user logs in,
            the default work-factor (``cost``) is kept relatively low.
        """
        kwds = self._to_json()
        assert 'v' in kwds
        if password:
            # XXX: support a password_id so they can be migrated?
            #      e.g. make this work with peppers in CryptContext?
            if password is True:
                if not self._enckey:
                    raise RuntimeError("no password provided to constructor or to_string()")
                kwds['enckey'] = self._enckey
            else:
                kwds['enckey'] = encrypt_key(self.key, password, cost=cost)
        else:
            kwds['key'] = self.base32_key
        return json.dumps(kwds, sort_keys=True, separators=(",",":"))

    def _to_json(self):
        # NOTE: 'key' added by to_json() wrapper
        kwds = dict(type=self.type, v=self.json_version)
        if self.alg != "sha1":
            kwds['alg'] = self.alg
        if self.digits != 6:
            kwds['digits'] = self.digits
        if self.label:
            kwds['label'] = self.label
        if self.issuer:
            kwds['issuer'] = self.issuer
        return kwds

    #=============================================================================
    # eoc
    #=============================================================================

#=============================================================================
# HOTP helper
#=============================================================================
class HotpMatch(_SequenceMixin):
    """
    Object returned by :meth:`HOTP.verify`.
    It can be treated as a tuple of ``(valid, counter)``,
    or accessed via the following attributes:

    .. autoattribute:: valid
    .. autoattribute:: counter
    .. autoattribute:: counter_offset
    """
    #: bool flag indicating whether token matched
    #: (also reflected as object's boolean value)
    valid = False

    #: new HOTP counter value (1 + matched counter value);
    #: or previous counter value if there was no match.
    counter = 0

    #: how many counter values were skipped between expected counter value to matched counter value
    #: (0 if there was no match).
    counter_offset = 0

    def __init__(self, valid, counter, counter_offset):
        self.valid = valid
        self.counter = counter
        self.counter_offset = counter_offset

    def _as_tuple(self):
        return (self.valid, self.counter)

    def __nonzero__(self):
        return self.valid

    __bool__ = __nonzero__ # py2 compat

class HOTP(BaseOTP):
    """Helper for generating and verifying HOTP codes.

    Given a secret key and set of configuration options, this object
    offers methods for token generation, token validation, and serialization.
    It can also be used to track important persistent HOTP state,
    such as the next counter value.

    Constructor Options
    ===================
    In addition to the :ref:`BaseOTP Constructor Options <baseotp-constructor-options>`,
    this class accepts the following extra parameters:

    :param int counter:
        The initial counter value to use when generating new tokens via :meth:`generate_next()`,
        or when verifying them via :meth:`verify_next()`.

    Client-Side Token Generation
    ============================
    .. automethod:: generate
    .. automethod:: generate_next

    Server-Side Token Verification
    ==============================
    .. automethod:: verify
    .. automethod:: verify_next

    .. todo::

        Offer a resynchronization primitive which allows user to provide a large number of sequential tokens
        taken from a pre-determined counter range (google's "emergency recovery code" style);
        or at current counter, but with a much larger window (as referenced in the RFC).

    Provisioning & Serialization
    ============================
    The shared provisioning & serialization methods for the :class:`!TOTP` and :class:`!HOTP` classes
    are documented under:

    * :ref:`BaseOTP Client Provisioning <baseotp-client-provisioning>`
    * :ref:`BaseOTP Serialization <baseotp-serialization>`


    Internal State Attributes
    =========================
    The following attributes are used to track the internal state of this generator,
    and will be included in the output of :meth:`to_string`:

    .. autoattribute:: counter

    .. attribute:: dirty

        boolean flag set by :meth:`generate_next` and :meth:`verify_next`
        to indicate that the object's internal state has been modified since creation.

    (Note: All internal state attribute can be initialized via constructor options,
    but this is mainly an internal / testing detail).
    """
    #=============================================================================
    # class attrs
    #=============================================================================

    #: otpauth type this class implements
    type = "hotp"

    #=============================================================================
    # instance attrs
    #=============================================================================

    #: initial counter value (if configured from server)
    start = 0

    #: counter of next token to generate.
    counter = 0

    #=============================================================================
    # init
    #=============================================================================
    def __init__(self, key=None, format="base32",
                 # keyword only ...
                 start=0, counter=0,
                 **kwds):
        # call BaseOTP to handle common options
        super(HOTP, self).__init__(key, format, **kwds)

        # validate counter
        self._check_serial(counter, "counter")
        self.counter = counter

        # validate start
        # NOTE: when loading from URI, 'start' is set to match counter,
        #       as we can trust server won't take any older values.
        #       other than that case, 'start' generally isn't used.
        self._check_serial(start, "start")
        if start > self.counter:
            raise ValueError("start must be <= counter (%d)" % self.counter)
        self.start = start

    #=============================================================================
    # token management
    #=============================================================================
    def _normalize_counter(self, counter):
        """
        helper to normalize counter representation
        """
        if not isinstance(counter, int_types):
            raise exc.ExpectedTypeError(counter, "int", "counter")
        if counter < self.start:
            raise ValueError("counter must be >= start value (%d)" % self.start)
        return counter

    def generate(self, counter):
        """
        Low-level method to generate HOTP token for specified counter value.

        :arg int counter:
           counter value to use.

        :returns:
           (unicode) string containing decimal-formatted token

        Usage example::

            >>> h = HOTP('s3jdvb7qd2r7jpxx')
            >>> h.generate(1000)
            '763224'
            >>> h.generate(1001)
            '771031'

        .. seealso::
            This is a lowlevel method, which doesn't read or modify any state-dependant values
            (such as the current :attr:`counter` value).
            For a version which does, see :meth:`generate_next`.
        """
        counter = self._normalize_counter(counter)
        return self._generate(counter)

    def generate_next(self):
        """
        High-level method to generate a new HOTP token using next counter value.

        Unlike :meth:`generate`, this method uses the current :attr:`counter` value,
        and increments that counter before it returns.

        :returns:
           (unicode) string containing decimal-formatted token

        Usage example::

            >>> h = HOTP('s3jdvb7qd2r7jpxx', counter=1000)
            >>> h.counter
            1000
            >>> h.generate_next()
            '897212'
            >>> h.counter
            1001
        """
        counter = self.counter
        token = self.generate(counter)
        self.counter = counter + 1 # NOTE: not incrementing counter until generate succeeds
        self.dirty = True
        return token

    def verify(self, token, counter, window=1):
        """
        Low-level method to validate HOTP token against specified counter.

        :arg token:
            token to validate.
            may be integer or string (whitespace and hyphens are ignored).

        :param int counter:
            next counter value client was expected to use.

        :param window:
           How many additional steps past ``counter`` to search when looking for a match
           Defaults to 1.

           .. rst-class:: inline-title
           .. note::
              This is a forward-looking window only, as searching backwards
              would allow token-reuse, defeating the whole purpose of HOTP.

        :returns:

           ``(ok, counter)`` tuple (actually an :class:`HotpMatch` instance):

           * ``ok`` -- boolean indicating if token validated
           * ``counter`` -- if token validated, this is the new counter value (matched token value + 1);
             or the previous counter value if token didn't validate.

        Usage example::

            >>> h = HOTP('s3jdvb7qd2r7jpxx')
            >>> h.verify('897212', 1000) # token matches counter
            (True, 1000)
            >>> h.verify('897212', 999) # token w/in window=1
            (True, 1000)
            >>> h.verify('897212', 998) # token outside window
            (False, 998)

        .. seealso::
            This is a lowlevel method, which doesn't read or modify any state-dependant values
            (such as the next :attr:`counter` value).
            For a version which does, see :meth:`verify_next`.
        """
        counter = self._normalize_counter(counter)
        self._check_serial(window, "window")
        valid, match = self._find_match(token, counter, counter + window + 1)
        if valid:
           return HotpMatch(True, match + 1, match - counter)
        else:
           return HotpMatch(False, counter, 0)

    def verify_next(self, token, window=1):
        """
        High-level method to validate HOTP token against current counter value.

        Unlike :meth:`verify`, this method uses the current :attr:`counter` value,
        and updates that counter after a successful verification.

        :arg token:
            token to validate.
            may be integer or string (whitespace and hyphens are ignored).

        :param window:
           How many additional steps past ``counter`` to search when looking for a match
           Defaults to 1.

           .. rst-class:: inline-title
           .. note::
              This is a forward-looking window only, as using a backwards window
              would allow token-reuse, defeating the whole purpose of HOTP.

        :returns:
           boolean indicating if token validated

        Usage example::

            >>> h = HOTP('s3jdvb7qd2r7jpxx', counter=998)
            >>> h.verify_next('897212') # token outside window
            False
            >>> h.counter # counter not incremented
            998
            >>> h.verify_next('484807') # token matches counter 999, w/in window=1
            True
            >>> h.counter # counter has been incremented, now expecting counter=1000 next
            1000
        """
        counter = self.counter
        result = self.verify(token, counter, window=window)
        if result.valid:
           self.counter = result.counter
           self.dirty = True
        # XXX: return result instead? would only provide .skipped as extra data.
        return result.valid

    # TODO: resync(self, tokens, counter, window=100)
    #       helper to re-synchronize using series of sequential tokens,
    #       all of which must validate; per RFC recommendation.

    #=============================================================================
    # uri parsing
    #=============================================================================
    @classmethod
    def _adapt_uri_params(cls, counter=None, **kwds):
        """
        parse HOTP specific params, and let _BaseOTP handle rest.
        """
        kwds = super(HOTP, cls)._adapt_uri_params(**kwds)
        if counter is None:
            raise cls._uri_error("missing 'counter' parameter")
        # NOTE: when creating from a URI, we set the 'start' value as well,
        #       as sanity check on client-side, since we *know* minimum value
        #       server will accept.
        kwds['counter'] = kwds['start'] = cls._uri_parse_int(counter, "counter")
        return kwds

    #=============================================================================
    # uri rendering
    #=============================================================================
    def _to_uri_params(self):
        """
        add HOTP specific params, and let _BaseOTP handle rest.
        """
        args = super(HOTP, self)._to_uri_params()
        args.append(("counter", str(self.counter)))
        return args

    #=============================================================================
    # json rendering
    #=============================================================================
    def _to_json(self):
        kwds = super(HOTP, self)._to_json()
        if self.start:
            kwds['start'] = self.start
        if self.counter:
            kwds['counter'] = self.counter
        return kwds

    #=============================================================================
    # eoc
    #=============================================================================

# register subclass with from_uri() helper
BaseOTP._type_map[HOTP.type] = HOTP

#=============================================================================
# TOTP helper
#=============================================================================
class TotpToken(_SequenceMixin):
    """
    Object returned by :meth:`TOTP.generate` and :meth:`TOTP.generate_next`.
    It can be treated as a sequence of ``(token, expire_time)``,
    or accessed via the following attributes:

    .. autoattribute:: token
    .. autoattribute:: expire_time
    .. autoattribute:: counter

    ..
        undocumented attributes::

        .. autoattribute:: remaining
        .. autoattribute:: valid
    """
    #: OTP object that generated this token
    _otp = None

    #: Token as decimal-encoded ascii string.
    token = None

    #: HOTP counter value used to generate token (derived from time)
    counter = None

    def __init__(self, otp, token, counter):
        self._otp = otp
        self.token = token
        self.counter = counter

    def _as_tuple(self):
        return (self.token, self.expire_time)

    # @memoized_property
    # def start_time(self):
    #     """Timestamp marking beginning of period when token is valid"""
    #     return self.counter * self._otp.period

    @memoized_property
    def expire_time(self):
        """Timestamp marking end of period when token is valid"""
        return (self.counter + 1) * self._otp.period

    @property
    def remaining(self):
        """number of (float) seconds before token expires"""
        return max(0, self.expire_time - self._otp.now())

    @property
    def valid(self):
        """whether token is still valid"""
        return bool(self.remaining)

class TotpMatch(_SequenceMixin):
    """
    Object returned by :meth:`TOTP.verify`.
    It can be treated as a sequence of ``(valid, offset)``,
    or accessed via the following attributes:

    .. autoattribute:: valid
    .. autoattribute:: offset

    ..
        undocumented attributes:

        .. autoattribute:: time
        .. autoattribute:: counter
        .. autoattribute:: counter_offset
        .. autoattribute:: _previous_offset
        .. autoattribute:: _period
    """
    #: bool flag indicating whether token matched
    #: (also reflected as object's overall boolean value)
    valid = False

    #: TOTP counter value which token matched against;
    #: or ``0`` if there was no match.
    counter = 0

    #: Timestamp when verification was performed
    time = 0

    #: Previous offset value provided when verify() was called.
    _previous_offset = 0

    #: TOTP period (needed internally to calculate min_offset, etc).
    _period = 30

    def __init__(self, valid, counter, time, previous_offset, period):
        """
        .. warning::
            the constructor signature is an internal detail, and is subject to change.
        """
        self.valid = valid
        self.time = time
        self.counter = counter
        self._previous_offset = previous_offset
        self._period = period

    @memoized_property
    def counter_offset(self):
        """
        Number of integer counter steps that match was off from current time's counter step.
        """
        if not self.valid:
            return 0
        return self.counter - self.time // self._period

    @memoized_property
    def offset(self):
        """
        Suggested offset value for next time a token is verified from this client.
        If no match, reports previously provided offset value.
        """
        if not self.valid:
            return self._previous_offset
        return suggest_offset(history=[(self.time, self.counter_offset)],
                              period=self._period, default=self._previous_offset)

    def _as_tuple(self):
        return (self.valid, self.offset)

    def __nonzero__(self):
        return self.valid

    __bool__ = __nonzero__ # py2 compat

class TOTP(BaseOTP):
    """Helper for generating and verifying TOTP codes.

    Given a secret key and set of configuration options, this object
    offers methods for token generation, token validation, and serialization.
    It can also be used to track important persistent TOTP state,
    such as clock drift, and last counter used.

    Constructor Options
    ===================
    In addition to the :ref:`BaseOTP Constructor Options <baseotp-constructor-options>`,
    this class accepts the following extra parameters:

    :param int period:
        The time-step period to use, in integer seconds. Defaults to ``30``.

    :param now:
        Optional callable that should return current time for generator to use.
        Default to :func:`time.time`. This optional is generally not needed,
        and is mainly present for examples & unit-testing.

    .. warning::

        Overriding the default values for ``digits``, ``period``, or ``alg`` may
        cause problems with some OTP client programs. For instance, Google Authenticator
        claims it's defaults are hard-coded.

    Client-Side Token Generation
    ============================
    .. automethod:: generate
    .. automethod:: generate_next

    Server-Side Token Verification
    ==============================
    .. automethod:: verify
    .. automethod:: verify_next

    .. todo::

        Offer a resynchronization primitive which allows user to provide a large number of
        sequential tokens taken from a pre-determined time range (e.g.
        google's "emergency recovery code" style); or at current time, but with a much larger
        window (as referenced in the RFC).

    Provisioning & Serialization
    ============================
    The shared provisioning & serialization methods for the :class:`!TOTP` and :class:`!HOTP` classes
    are documented under:

    * :ref:`BaseOTP Client Provisioning <baseotp-client-provisioning>`
    * :ref:`BaseOTP Serialization <baseotp-serialization>`

    ..
        Undocumented Helper Methods
        ===========================

        .. automethod:: normalize_time

    Configuration Attributes
    ========================
    In addition to the :ref:`BaseOTP Configuration Attributes <baseotp-configuration-attributes>`,
    this class also offers the following extra attrs (which correspond to the extra constructor options):

    .. autoattribute:: period

    Internal State Attributes
    =========================
    The following attributes are used to track the internal state of this generator,
    and will be included in the output of :meth:`to_string`:

    .. autoattribute:: last_counter

    .. autoattribute:: _history

    .. attribute:: dirty

        boolean flag set by :meth:`generate_next` and :meth:`verify_next`
        to indicate that the object's internal state has been modified since creation.

    (Note: All internal state attribute can be initialized via constructor options,
    but this is mainly an internal / testing detail).
    """
    #=============================================================================
    # class attrs
    #=============================================================================

    #: otpauth type this class implements
    type = "totp"

    #: max history buffer size
    # NOTE: picked based on average size that suggest_offset() algorithm
    #       needs to settle down on predicted value, using `history1` from unittest as reference.
    MAX_HISTORY_SIZE = 8

    #=============================================================================
    # instance attrs
    #=============================================================================

    #: function to get system time in seconds, as needed by :meth:`generate` and :meth:`verify`.
    #: defaults to :func:`time.time`, but can be overridden on a per-instance basis.
    now = _time.time

    #: number of seconds per counter step.
    #: *(TOTP uses an internal time-derived counter which
    #: increments by 1 every* :attr:`!period` *seconds)*.
    period = 30

    #---------------------------------------------------------------------------
    # state attrs
    #---------------------------------------------------------------------------

    #: counter value of last token generated by :meth:`generate_next` *(client-side)*,
    #: or validated by :meth:`verify_next` *(server-side)*.
    last_counter = 0

    #: *(server-side only)* history of previous verifications performed by :meth:`verify_next`,
    #: and is used to estimate the **delay** parameter on a per-client basis.
    #:
    #: this is an internal attribute whose structure is subject to change,
    #: but currently is a list of 1 or more ``(timestamp, counter_offset)`` entries.
    #: it's maximum size is controlled by the class attribute ``TOTP.MAX_HISTORY_SIZE``.
    _history = None

    #=============================================================================
    # init
    #=============================================================================
    def __init__(self, key=None, format="base32",
                 # keyword only...
                 period=None,
                 last_counter=0, _history=None,
                 now=None, # NOTE: mainly used for unittesting
                 **kwds):
        # call BaseOTP to handle common options
        super(TOTP, self).__init__(key, format, **kwds)

        # use custom timer --
        # intended for examples & unittests, not real-world use.
        if now:
            assert isinstance(now(), num_types) and now() >= 0, \
                "now() function must return non-negative int/float"
            self.now = now

        # init period
        if period is not None:
            self._check_serial(period, "period", minval=1)
            self.period = period

        # init last counter value
        self._check_serial(last_counter, "last_counter")
        self.last_counter = last_counter

        # init history
        if _history:
            # TODO: run sanity check on structure of history object
            self._history = _history

    #=============================================================================
    # token management
    #=============================================================================

    #-------------------------------------------------------------------------
    # internal helpers
    #-------------------------------------------------------------------------
    def normalize_time(self, time):
        """
        Normalize time value to unix epoch seconds.

        :arg time:
            Can be ``None``, :class:`!datetime`,
            or unix epoch timestamp as :class:`!float` or :class:`!int`.
            If ``None``, uses current system time.
            Naive datetimes are treated as UTC.

        :returns:
            unix epoch timestamp as :class:`int`.
        """
        if isinstance(time, int_types):
            return time
        elif isinstance(time, float):
            return int(time)
        elif time is None:
            return int(self.now())
        elif hasattr(time, "utctimetuple"):
            # coerce datetime to UTC timestamp
            # NOTE: utctimetuple() assumes naive datetimes are in UTC
            # NOTE: we explicitly *don't* want microseconds.
            return calendar.timegm(time.utctimetuple())
        else:
            raise exc.ExpectedTypeError(time, "int, float, or datetime", "time")

    def _time_to_counter(self, time):
        """
        convert timestamp to HOTP counter using :attr:`period`.
        input is passed through :meth:`normalize_time`.
        """
        time = self.normalize_time(time)
        if time < 0:
            raise ValueError("time must be >= 0")
        return time // self.period

    #-------------------------------------------------------------------------
    # token generation
    #-------------------------------------------------------------------------
    def generate(self, time=None):
        """
        Low-level method to generate token for specified time.

        :arg time:
            Can be ``None``, :class:`!datetime`,
            or unix epoch timestamp as :class:`!float` or :class:`!int`.
            If ``None`` (the default), uses current system time.
            Naive datetimes are treated as UTC.

        :returns:

            sequence of ``(token, expire_time)`` (actually a :class:`TotpToken` instance):

            * ``token`` -- decimal-formatted token as a (unicode) string
            * ``expire_time`` -- unix epoch time when token will expire

        Usage example::

            >>> otp = TOTP('s3jdvb7qd2r7jpxx')
            >>> otp.generate(1419622739)
            ('897212', 1419622740)

            >>> # when you just need the token...
            >>> otp.generate(1419622739).token
            '897212'

        .. seealso::
            This is a lowlevel method, which doesn't read or modify any state-dependant values
            (such as the :attr:`last_counter` value).
            For a version which does, see :meth:`generate_next`.
        """
        counter = self._time_to_counter(time)
        token = self._generate(counter)
        return TotpToken(self, token, counter)

    def generate_next(self, reuse=False):
        """
        High-level method to generate TOTP token for current time.
        Unlike :meth:`generate`, this method takes into account the :attr:`last_counter` value,
        and updates that attribute to match the returned token.

        :param reuse:
            Controls whether a token can be issued twice within the same time :attr:`period`.

            By default (``False``), calling this method twice within the same time :attr:`period`
            will result in a :exc:`~passlib.exc.TokenReuseError`, since once a token has gone across the wire,
            it should be considered insecure.

            Setting this to ``True`` will allow multiple uses of the token within the same time period.

        :returns:

            sequence of ``(token, expire_time)`` (actually a :class:`TotpToken` instance):

            * ``token`` -- decimal-formatted token as a (unicode) string
            * ``expire_time`` -- unix epoch time when token will expire

        :raises ~passlib.exc.TokenReuseError:

            if an attempt is made to generate a token within the same time :attr:`period`
            (suppressed by ``reuse=True``).

        Usage example::

            >>> # IMPORTANT: THE 'now' PARAMETER SHOULD NOT BE USED IN PRODUCTION.
            >>> #            It's only used here to fix the totp generator's clock, so that
            >>> #            this example can be reproduced regardless of the actual system time.
            >>> totp = TOTP('s3jdvb7qd2r7jpxx', now=lambda : 1419622739)
            >>> totp.generate_next() # generate new token
            ('897212', 1419622740)

            >>> # or use attr access when you just need the token ...
            >>> totp.generate_next().token
            '897212'
        """
        time = self.normalize_time(None)
        result = self.generate(time)

        if result.counter < self.last_counter:
            # NOTE: this usually means system time has jumped back since last call.
            #       this will occasionally happen, so not throwing an error,
            #       but definitely worth issuing a warning.
            warn("TOTP.generate_next(): current time (%r) earlier than last-used time (%r); "
                 "did system clock change?" % (int(time), self.last_counter * self.period),
                 exc.PasslibSecurityWarning, stacklevel=1)

        elif result.counter == self.last_counter and not reuse:
            raise exc.TokenReuseError("Token already generated in this time period, "
                                      "please wait %d seconds for another." % result.remaining,
                                      expire_time=result.expire_time)

        self.last_counter = result.counter
        self.dirty = True
        return result

    #-------------------------------------------------------------------------
    # token verification
    #-------------------------------------------------------------------------

    def verify(self, token, time=None, window=30, offset=0, min_start=0):
        """
        Low-level method to validate TOTP token against specified timestamp.
        Searches within a window before & after the provided time,
        in order to account for transmission offset and drift in the client's clock.

        :arg token:
            Token to validate.
            may be integer or string (whitespace and hyphens are ignored).

        :param time:
            Unix epoch timestamp, can be any of :class:`!float`, :class:`!int`, or :class:`!datetime`.
            if ``None`` (the default), uses current system time.
            *this should correspond to the time the token was received from the client*.

        :param int window:
            How far backward and forward in time to search for a match.
            Measured in seconds. Defaults to ``30``.  Typically only useful if set
            to multiples of :attr:`period`.

        :param int offset:
            Offset timestamp by specified value, to account for transmission offset and / or client clock skew.
            Measured in seconds. Defaults to ``0``.

            Negative offset (the common case) indicates transmission delay,
            or that the client clock is running behind the server.
            Positive offset indicates the client clock is running ahead of the server
            (and by enough that it cancels out the transmission delay).

            .. note::

                You should ensure the server clock uses a reliable time source such as NTP,
                so that only the client clock needs to be accounted for.

        :returns:
            sequence of ``(valid, offset)`` (actually a :class:`TotpMatch` instance):

            * ``valid`` -- boolean flag indicating whether token matched
            * ``offset`` -- suggested offset value for next time token is verified from this client.

        :raises ValueError:
            if the provided token is not correctly formatted (e.g. wrong number of digits),
            or if one of the parameters has an invalid value.

        Usage example::

            >>> totp = TOTP('s3jdvb7qd2r7jpxx')
            >>> totp.verify('897212', 1419622729) # valid token for this time period
            (True, 19)
            >>> totp.verify('000492', 1419622729) # token from counter step 30 sec ago (within allowed window)
            (True, 49)
            >>> totp.verify('760389', 1419622729) # invalid token -- token from 60 sec ago (outside of window)
            (False, 0)

        .. seealso::
            This is a low-level method, which doesn't read or modify any state-dependant values
            (such as the :attr:`last_counter` value, or the previously recorded :attr:`drift`).
            For a version which does, see :meth:`verify_next`.
        """
        time = self.normalize_time(time)
        self._check_serial(window, "window")

        # NOTE: 'min_start' is internal parameter used by verify_next() to
        #       skip searching any counter values before last confirmed verification.
        client_time = time + offset
        start = max(min_start, self._time_to_counter(client_time - window))
        end = self._time_to_counter(client_time + window) + 1

        valid, counter = self._find_match(token, start, end)
        return TotpMatch(valid, counter, time, offset, self.period)

    def verify_next(self, token, reuse=False, window=30, offset=None):
        """
        High-level method to validate TOTP token against current system time.
        Unlike :meth:`verify`, this method takes into account the :attr:`last_counter` value,
        and updates that attribute if a match is found.

        Additionally, this method also stores an internal :attr;`_history` of previous successful
        verifications, which it uses to autocalculate the offset parameter before each call
        (in order to account for client clock drift).

        :arg token:
            token to validate.
            may be integer or string (whitespace and hyphens are ignored).

        :param bool reuse:
            Controls whether a token can be issued twice within the same time :attr:`period`.

            By default (``False``), attempting to verify the same token twice within the same time :attr:`period`
            will result in a :exc:`~passlib.exc.TokenReuseError`, since once a token has gone across the wire,
            it should be considered insecure.

            Setting this to ``True`` will silently allow multiple uses of the token within the same time period.

        :param int window:
            How far backward and forward in time to search for a match.
            Measured in seconds. Defaults to ``30``.  Typically only useful if set
            to multiples of :attr:`period`.

        :returns:
            Returns ``True`` if the token validated, ``False`` if not.

            May set the :attr:`dirty` attribute if the internal state was updated,
            and needs to be re-persisted by the application (see :meth:`to_json`).

        :raises ValueError:
            If the provided token is not correctly formed (e.g. wrong number of digits),
            or if one of the parameters has an invalid value.

        :raises ~passlib.exc.TokenReuseError:

            If an attempt is made to verify the current time period's token
            (suppressed by ``reuse=True``).

        Usage example::

            >>> # IMPORTANT: THE 'now' PARAMETER SHOULD NOT BE USED IN PRODUCTION.
            >>> #            It's only used here to fix the totp generator's clock, so that
            >>> #            this example can be reproduced regardless of the actual system time.
            >>> totp = TOTP('s3jdvb7qd2r7jpxx', now = lambda: 1419622739)
            >>> # wrong token
            >>> totp.verify_next('123456')
            False
            >>> # token from 30 sec ago (w/ window, will be accepted)
            >>> totp.verify_next('000492')
            True
            >>> # token from current period
            >>> totp.verify_next('897212')
            True
            >>> # token from 30 sec ago will now be rejected
            >>> totp.verify_next('000492')
            False
        """
        time = self.normalize_time(None)
        if offset is None:
            offset = self._next_offset(time)
        # NOTE: setting min_start so verify() doesn't even bother checking
        #       points before the last verified counter, no matter what offset or window is set to.
        result = self.verify(token, time, window=window, offset=offset, min_start=self.last_counter)
        assert result.time == time, "sanity check failed: verify().time didn't match input time"
        if not result.valid:
            return False

        if result.counter > self.last_counter:
            # accept new token, update internal state
            self.last_counter = result.counter
            self._add_offset(result.time, result.counter_offset)
            self.dirty = True
            return True

        assert result.counter == self.last_counter, "sanity check failed: 'min_start' not honored"

        if reuse:
            # allow reuse of current token
            return True

        else:
            raise exc.TokenReuseError("Token has already been used, please wait for another.",
                                      expire_time=(self.last_counter + 1) * self.period)

    def _next_offset(self, time):
        """
        internal helper for :meth:`verify_next` --
        return suggested offset for specified time, based on history.
        """
        return suggest_offset(self._history, self.period, time)

    def _add_offset(self, time, counter_offset):
        """
        internal helper for :meth:`verify_next` --
        appends an entry to the verification history.
        """
        history = self._history
        if history:
            # add entry to history
            history.append((time, counter_offset))

            # remove old entries
            while len(history) > self.MAX_HISTORY_SIZE:
                history.pop(0)

        elif self.MAX_HISTORY_SIZE > 0:
            # initialize history (if it hasn't been disabled)
            self._history = [(time, counter_offset)]

    #-------------------------------------------------------------------------
    # TODO: resync(self, tokens, time=None, min_tokens=10, window=100)
    #       helper to re-synchronize using series of sequential tokens,
    #       all of which must validate; per RFC recommendation.
    # NOTE: need to make sure this function is constant time
    #       (i.e. scans ALL tokens, and doesn't short-circuit after first mismatch)
    #-------------------------------------------------------------------------

    #=============================================================================
    # uri parsing
    #=============================================================================
    @classmethod
    def _adapt_uri_params(cls, period=None, **kwds):
        """
        parse TOTP specific params, and let _BaseOTP handle rest.
        """
        kwds = super(TOTP, cls)._adapt_uri_params(**kwds)
        if period:
            kwds['period'] = cls._uri_parse_int(period, "period")
        return kwds

    #=============================================================================
    # uri rendering
    #=============================================================================
    def _to_uri_params(self):
        """
        add TOTP specific arguments to URI, and let _BaseOTP handle rest.
        """
        args = super(TOTP, self)._to_uri_params()
        if self.period != 30:
            args.append(("period", str(self.period)))
        return args

    #=============================================================================
    # json rendering
    #=============================================================================
    def _to_json(self):
        kwds = super(TOTP, self)._to_json()
        if self.period != 30:
            kwds['period'] = self.period
        if self.last_counter:
            kwds['last_counter'] = self.last_counter
        if self._history:
            kwds['_history'] = self._history
        return kwds

    #=============================================================================
    # eoc
    #=============================================================================

# register subclass with from_uri() helper
BaseOTP._type_map[TOTP.type] = TOTP

#=============================================================================
# public frontends
#=============================================================================
def from_uri(uri):
    """
    create an OTP instance from a URI, such as returned by :meth:`TOTP.to_uri`.

    :raises ValueError:
        if the uri cannot be parsed or contains errors.

    :returns:
        :class:`TOTP` or :class:`HOTP` instance, as appropriate.
    """
    return BaseOTP.from_uri(uri)

def from_string(json, password=None):
    """
    load an OTP  instance from serialized json, such as returned by :meth:`TOTP.to_json`.

    :raises ValueError:
        if the json cannot be parsed or contains errors.

    :returns:
        :class:`TOTP` or :class:`HOTP` instance, as appropriate.
    """
    return BaseOTP.from_string(json, password=password)

#=============================================================================
# eof
#=============================================================================
