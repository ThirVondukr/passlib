"""passlib.totp -- TOTP / RFC6238 / Google Authenticator utilities.

Todo
====
* This module currently contains a functional TotpEngine() object,
  which does provide all the basic primitives. However, for the final
  release I'd like to have a hash-string looking object which stores
  entire state in a single string, and provide module-level primitives
  for easily manipulating them.

* The hash string should probably contain a minimum of:
    - prefix ("{TOTP}" or "$totp$")
    - engine parameters (period, digits, alg)
    - shared key
        - optionally pbkdf2+xor encrypt using  user password (+ application pepper)?
    - last authenticated timestamp (so app can reject subsequent ones)
    - drift of last authentication
        - xxx: need to find good reference for how to make this secure+useful

* Unittests, once api is finished.

References
==========
* Google's OTP uri spec, used for qrcodes -- http://code.google.com/p/google-authenticator/wiki/KeyUriFormat
* php-based OTP project, might have skew management logic -- http://www.multiotp.net/
* base32 -- http://tools.ietf.org/html/rfc3548#page-6
"""
#=============================================================================
# imports
#=============================================================================
from __future__ import division
# core
import logging; log = logging.getLogger(__name__)
import struct
import time
import re
import urllib
# site
# pkg
from passlib.utils import to_unicode, consteq, getrandbytes, rng
from passlib.utils.compat import (u, int_types, num_types, base_string_types,
                                  irange, bytes, byte_elem_value, BytesIO,
                                  join_byte_values, join_unicode, iter_byte_values)
from passlib.utils.pbkdf2 import get_prf, norm_hash_name
# local
__all__ = [
    "TotpEngine",
]

#=============================================================================
# internal helpers
#=============================================================================

# used to clean whitespace from tokens for comparison
_token_cleaner = re.compile(u("\s|[-]"))

#=============================================================================
#
#=============================================================================

class TotpEngine(object):
    """provides quick generation and matching of TOTP codes.

    Each instance gets configured with the options for a specific TOTP
    implementation, and then offers methods for creating & validating
    TOTP codes based on that configuration.

    :param key_size:
        size of generated keys, in bytes. defaults to digest size of selected
        prf. (note the base32-encoded key will be 1.6x longer).
    :param period:
        time step in seconds (defaults to ``30``)
    :param digits:
        number of digits to return (defaults to ``6``)
    :param prf:
        name of prf to use (defaults to ``"hmac-sha1"``)
    :param timer:
        timer function for generating new codes (defaults to :func:`time.time`)
    :param time_start:
        timer value to start counting time steps (defaults to ``0``).
    """
    #=============================================================================
    # instance attrs
    #=============================================================================

    #: size of keys to generate
    key_size = None

    #: time step in seconds
    period = 30

    #: number of digits in output code
    digits = 6

    #: name of hash algorithm in use (e.g. "sha-1")
    alg = None

    #: prf callable implementing HMAC-<alg>
    _prf = None

    #: alg digest size
    digest_size = None

    #: timer function
    timer = time.time

    #: agreed-upon timer offset
    time_start = 0

    #=============================================================================
    # init
    #=============================================================================
    def __init__(self, key_size=None, period=30, digits=6, alg="sha1",
                 timer=time.time, time_start=0, rng=rng):

        # validate period
        if not isinstance(period, int_types):
            raise TypeError("period must be an integer, not a %r" % type(period))
        if period < 1:
            raise ValueError("period must be a positive integer")
        self.period = period

        # validate digits
        if not isinstance(digits, int_types):
            raise TypeError("digits must be an integer, not a %r" % type(digits))
        if digits < 6 or digits > 9:
            raise ValueError("digits must in range 6..9 inclusive")
        self.digits = digits

        # validate prf, resolve to callable
        self.alg = norm_hash_name(alg)
        self._prf, self.digest_size = get_prf("hmac-" + self.alg)
        assert self.digest_size > 4, "how did you find this crazy hash?"

        # validate key size
        if key_size is None:
            key_size = self.digest_size
        if not isinstance(key_size, int_types):
            raise TypeError("key_size must be an integer, not a %r" % type(key_size))
        if key_size < 1:
            raise ValueError("key_size must be a positive integer")
        self.key_size = key_size

        # store timer & rng
        self.timer = timer
        self.rng = rng

        # validate time_start
        if not isinstance(time_start, num_types):
            raise TypeError("time_start must be a number, not a %r" % type(time_start))
        self.time_start = time_start

    #=============================================================================
    # key manipulation
    #=============================================================================

    def normkey(self, key):
        """normalize key representation"""
        return encode_base32(decode_base32(key))

    def genkey(self, key_size=None):
        """generate new base32-encoded key"""
        if key_size is None:
            key_size = self.key_size
        raw_key = getrandbytes(self.rng, key_size)
        return encode_base32(raw_key)

    #=============================================================================
    # token manipulation
    #=============================================================================
    def normtoken(self, token):
        """normalize token representation"""
        if isinstance(token, int_types):
            return u("%0*d") % (self.digits, token)
        else:
            token = to_unicode(token, param="token")
            # XXX: should we left-pad w/ zeros up to self.digits?
            return _token_cleaner.sub(u(""), token)

    def gentoken(self, key, time=None):
        """generate TOTP code for specified key & timestamp.

        :arg key: user-specific key as base32-encoded string
        :arg time: timestamp as float/int (if None, uses current time)
        :returns: string containing decimal token
        """
        # decode key
        if not isinstance(key, base_string_types):
            raise TypeError("key must be a string, not a %r" % type(key))
        raw_key = decode_base32(key)

        # generate counter & digest
        if time is None:
            time = self.timer()
        counter = int((time - self.time_start) // self.period)
        assert counter >= 0 # FIXME: does RFC define behavior? or throw error?
        digest = self._prf(raw_key, struct.pack(">Q", counter))
        assert len(digest) == self.digest_size, "sanity check failed"

        # truncate and derive token
        offset = byte_elem_value(digest[-1]) % (len(digest)-4)
        value = struct.unpack(">I", digest[offset:offset+4])[0] & 0x7fffffff
        return u("%0*d") % (self.digits, value % (10**self.digits))

    def makeuri(self, key, label):
        """convert key to uri (including current engine settings)"""
        assert "?" not in label
        key = self.normkey(key)
        # NOTE: reference examples seem to indicate the '@' in a label
        #       shouldn't be escaped, though google's spec doesn't address this.
        label = urllib.quote_plus(label, '@')
        result = u("otpauth://totp/%s?secret=%s") % (label, key)
        if self.alg != "sha1":
            result = u("%s&algorithm=%s") % (result, self.alg.upper())
        if self.digits != 6:
            result = u("%s&digits=%d") % (result, self.digits)
        if self.period != 30:
            result = u("%s&period=%d") % (result, self.period)
        return result

    def makeqrcode(self, key, label):
        """convert key to qrcode (including current engine settings)

        .. note::

            This method requires the external libraries
            ``qrcode`` and ``PIL``.
        """
        # XXX: is there a pure-python way to do this?
        #      saw a pure-python png library somewhere,
        #      maybe see about contributing patch to qrcode
        from passlib.utils.compat import BytesIO
        import qrcode
        buf = BytesIO()
        qrcode.make(self.makeuri(key, label)).save(buf)
        return buf.getvalue()

    #=============================================================================
    # verification
    #=============================================================================
    def verify(self, key, token, time=None):
        """verify token against counter. if time unset, uses current time"""
        return consteq(self.normtoken(token), self.gentoken(key, time))

    def verify_window(self, key, token, time=None, window=None):
        """wrapper around :meth:`verify` which tries to validate
        against tokens for +/- window seconds from time.
        returns (True/False, skew)
        """
        if time is None:
            time = self.timer()
        if window is None:
            window = self.period
        assert window >= 0
        skew = 0
        while skew <= window:
            if self.verify(key, token, time + skew):
                return True, skew
            if skew and self.verify(key, token, time - skew):
                return True, -skew
            skew += self.period
        return False, None

    #=============================================================================
    # eoc
    #=============================================================================

#=============================================================================
# base32 codec
#=============================================================================

# NOTE: stdlib offers base64.b32encode / b32decode,
#       but they are fragile and demand padding chars.
#       should look into a wrapper around them,
#       might be faster than scrap of code below:

_base32_alphabet = u('ABCDEFGHIJKLMNOPQRSTUVWXYZ234567')
_base32_map = dict((c,i) for i, c in enumerate(_base32_alphabet))
_base32_map.update((c.lower(), i) for i,c in enumerate(_base32_alphabet)
                   if c.isalpha())
_base32_map.update(**{
    # map some commonly mistyped chars
    u("0"): _base32_map[u("O")],
    u("1"): _base32_map[u("L")],
    u("8"): _base32_map[u("B")],
    ##u("9"): _base32_map[u("G")], # TODO: find out if this is generally accepted

    # common garbage/padding characters that we ignore entirely
    u("-"): None,
    u("="): None,
    u("~"): None,
})
assert all(v<32 for v in _base32_map.values())

def decode_base32(source):
    """decode base32-encoded string"""
    def helper():
        cur = 0
        bits = 0
        for char in to_unicode(source, param="source"):
            if char.isspace():
                continue
            try:
                value = _base32_map[char]
            except KeyError:
                raise ValueError("invalid characters in base32 string")
            cur = (cur<<5)|value
            bits += 5
            if bits > 7:
                bits -= 8
                yield cur >> bits
                cur &= (1<<bits)-1
        if bits and cur:
            # if cur isn't set, these are just padding bits we can ignore
            raise ValueError("unexpected end of base32 string")
    return join_byte_values(helper())

# TODO: have this (optionally?) include padding
def encode_base32(source):
    """convert raw bytes to base32-encoded string"""
    def helper():
        cur = 0
        bits = 0
        for value in iter_byte_values(source):
            cur = (cur<<8)|value
            bits += 8
            while bits > 4: # pop off and render 5 bits worth
                bits -= 5
                yield _base32_alphabet[cur >> bits]
                cur &= (1<<bits)-1
        if bits:
            yield _base32_alphabet[cur<<(5-bits)] # insert padding bits
    return join_unicode(helper())

#=============================================================================
# eof
#=============================================================================
