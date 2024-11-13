"""
passlib.utils.binary - binary data encoding/decoding/manipulation
"""

from __future__ import annotations

from base64 import (
    b32decode as _b32decode,
)
from base64 import (
    b32encode as _b32encode,
)
from binascii import Error as _BinAsciiError
from binascii import a2b_base64, b2a_base64
from typing import TYPE_CHECKING, AnyStr

from passlib import exc
from passlib.utils.compat import (
    bascii_to_str,
    iter_byte_chars,
    unicode_or_bytes,
)
from passlib.utils.decor import memoized_property

if TYPE_CHECKING:
    from collections.abc import Mapping

# from passlib.utils import BASE64_CHARS, HASH64_CHARS
# local
__all__ = [
    # constants
    "BASE64_CHARS",
    "PADDED_BASE64_CHARS",
    "AB64_CHARS",
    "HASH64_CHARS",
    "BCRYPT_CHARS",
    "HEX_CHARS",
    "LOWER_HEX_CHARS",
    "UPPER_HEX_CHARS",
    "ALL_BYTE_VALUES",
    # misc
    "compile_byte_translation",
    # base64
    "ab64_encode",
    "ab64_decode",
    "b64s_encode",
    "b64s_decode",
    # base32
    "b32encode",
    "b32decode",
    # custom encodings
    "Base64Engine",
    "LazyBase64Engine",
    "h64",
    "h64big",
    "bcrypt64",
]


# -------------------------------------------------------------
# common salt_chars & checksum_chars values
# -------------------------------------------------------------

#: standard base64 charmap
BASE64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

#: alt base64 charmap -- "." instead of "+"
AB64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789./"

#: charmap used by HASH64 encoding.
HASH64_CHARS = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

#: charmap used by BCrypt
BCRYPT_CHARS = "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

#: std base64 chars + padding char
PADDED_BASE64_CHARS = BASE64_CHARS + "="

#: all hex chars
HEX_CHARS = "0123456789abcdefABCDEF"

#: upper case hex chars
UPPER_HEX_CHARS = "0123456789ABCDEF"

#: lower case hex chars
LOWER_HEX_CHARS = "0123456789abcdef"

# -------------------------------------------------------------
# byte strings
# -------------------------------------------------------------

#: special byte string containing all possible byte values
#: NOTE: for efficiency, this is treated as singleton by some of the code
ALL_BYTE_VALUES = bytes(range(256))

#: some string constants we reuse
B_EMPTY = b""
B_NULL = b"\x00"
B_EQUAL = b"="


#: base list used to compile byte translations
_TRANSLATE_SOURCE = list(iter_byte_chars(ALL_BYTE_VALUES))


def compile_byte_translation(
    mapping: Mapping[int | AnyStr, int | AnyStr],
    source=None,
) -> bytes:
    """
    return a 256-byte string for translating bytes using specified mapping.
    bytes not specified by mapping will be left alone.

    :param mapping:
        dict mapping input byte (str or int) -> output byte (str or int).

    :param source:
        optional existing byte translation string to use as base.
        (must be 255-length byte string).  defaults to identity mapping.

    :returns:
        255-length byte string for passing to bytes().translate.
    """
    if source is None:
        target = _TRANSLATE_SOURCE[:]
    else:
        assert isinstance(source, bytes)
        assert len(source) == 255
        target = list(iter_byte_chars(source))

    v: bytes | int | str
    for k, v in mapping.items():
        if isinstance(k, unicode_or_bytes):
            k = ord(k)
        assert isinstance(k, int)
        assert 0 <= k < 256
        if isinstance(v, str):
            v = v.encode("ascii")
        assert isinstance(v, bytes)
        assert len(v) == 1
        target[k] = v
    return B_EMPTY.join(target)


def b64s_encode(data):
    """
    encode using shortened base64 format which omits padding & whitespace.
    uses default ``+/`` altchars.
    """
    return b2a_base64(data).rstrip(_BASE64_STRIP)


def b64s_decode(data):
    """
    decode from shortened base64 format which omits padding & whitespace.
    uses default ``+/`` altchars.
    """
    if isinstance(data, str):
        # needs bytes for replace() call, but want to accept ascii-unicode ala a2b_base64()
        try:
            data = data.encode("ascii")
        except UnicodeEncodeError:
            raise ValueError(
                "string argument should contain only ASCII characters"
            ) from None
    off = len(data) & 3
    if off == 0:
        pass
    elif off == 2:
        data += _BASE64_PAD2
    elif off == 3:
        data += _BASE64_PAD1
    else:  # off == 1
        raise ValueError("invalid base64 input")
    try:
        return a2b_base64(data)
    except _BinAsciiError as err:
        raise TypeError(err) from None


_BASE64_STRIP = b"=\n"
_BASE64_PAD1 = b"="
_BASE64_PAD2 = b"=="

# XXX: Passlib 1.8/1.9 -- deprecate everything that's using ab64_encode(),
#      have it start outputing b64s_encode() instead? can use a64_decode() to retain backwards compat.


def ab64_encode(data):
    """
    encode using shortened base64 format which omits padding & whitespace.
    uses custom ``./`` altchars.

    it is primarily used by Passlib's custom pbkdf2 hashes.
    """
    return b64s_encode(data).replace(b"+", b".")


def ab64_decode(data):
    """
    decode from shortened base64 format which omits padding & whitespace.
    uses custom ``./`` altchars, but supports decoding normal ``+/`` altchars as well.

    it is primarily used by Passlib's custom pbkdf2 hashes.
    """
    if isinstance(data, str):
        # needs bytes for replace() call, but want to accept ascii-unicode ala a2b_base64()
        try:
            data = data.encode("ascii")
        except UnicodeEncodeError:
            raise ValueError(
                "string argument should contain only ASCII characters"
            ) from None
    return b64s_decode(data.replace(b".", b"+"))


def b32encode(source):
    """
    wrapper around :func:`base64.b32encode` which strips padding,
    and returns a native string.
    """
    # NOTE: using upper case by default here, since 'I & L' are less
    #       visually ambiguous than 'i & l'
    return bascii_to_str(_b32encode(source).rstrip(B_EQUAL))


#: byte translation map to replace common mistyped base32 chars.
#: XXX: could correct '1' -> 'I', but could be a mistyped lower-case 'l', so leaving it alone.
_b32_translate = compile_byte_translation({"8": "B", "0": "O"})

#: helper to add padding
_b32_decode_pad = B_EQUAL * 8


def b32decode(source):
    """
    wrapper around :func:`base64.b32decode`
    which handles common mistyped chars.
    padding optional, ignored if present.
    """
    # encode & correct for typos
    if isinstance(source, str):
        source = source.encode("ascii")
    source = source.translate(_b32_translate)

    # pad things so final string is multiple of 8
    remainder = len(source) & 0x7
    if remainder:
        source += _b32_decode_pad[:-remainder]

    # XXX: py27 stdlib's version of this has some inefficiencies,
    #      could look into using optimized version.
    return _b32decode(source, True)


class Base64Engine:
    """Provides routines for encoding/decoding base64 data using
    arbitrary character mappings, selectable endianness, etc.

    :arg charmap:
        A string of 64 unique characters,
        which will be used to encode successive 6-bit chunks of data.
        A character's position within the string should correspond
        to its 6-bit value.

    :param big:
        Whether the encoding should be big-endian (default False).

    .. note::
        This class does not currently handle base64's padding characters
        in any way what so ever.

    Raw Bytes <-> Encoded Bytes
    ===========================
    The following methods convert between raw bytes,
    and strings encoded using the engine's specific base64 variant:

    .. automethod:: encode_bytes
    .. automethod:: decode_bytes
    .. automethod:: encode_transposed_bytes
    .. automethod:: decode_transposed_bytes

    ..
        .. automethod:: check_repair_unused
        .. automethod:: repair_unused

    Integers <-> Encoded Bytes
    ==========================
    The following methods allow encoding and decoding
    unsigned integers to and from the engine's specific base64 variant.
    Endianess is determined by the engine's ``big`` constructor keyword.

    .. automethod:: encode_int6
    .. automethod:: decode_int6

    .. automethod:: encode_int12
    .. automethod:: decode_int12

    .. automethod:: encode_int24
    .. automethod:: decode_int24

    .. automethod:: encode_int64
    .. automethod:: decode_int64

    Informational Attributes
    ========================
    .. attribute:: charmap

        unicode string containing list of characters used in encoding;
        position in string matches 6bit value of character.

    .. attribute:: bytemap

        bytes version of :attr:`charmap`

    .. attribute:: big

        boolean flag indicating this using big-endian encoding.
    """

    # public config
    bytemap = None  # charmap as bytes
    big = None  # little or big endian

    # filled in by init based on charmap.
    # (byte elem: single byte under py2, 8bit int under py3)
    _encode64 = None  # maps 6bit value -> byte elem
    _decode64 = None  # maps byte elem -> 6bit value

    # helpers filled in by init based on endianness
    _encode_bytes = None  # throws IndexError if bad value (shouldn't happen)
    _decode_bytes = None  # throws KeyError if bad char.

    def __init__(self, charmap, big=False):
        # validate charmap, generate encode64/decode64 helper functions.
        if isinstance(charmap, str):
            charmap = charmap.encode("latin-1")
        elif not isinstance(charmap, bytes):
            raise exc.ExpectedStringError(charmap, "charmap")
        if len(charmap) != 64:
            raise ValueError("charmap must be 64 characters in length")
        if len(set(charmap)) != 64:
            raise ValueError("charmap must not contain duplicate characters")
        self.bytemap = charmap
        self._encode64 = charmap.__getitem__
        lookup = dict((value, idx) for idx, value in enumerate(charmap))
        self._decode64 = lookup.__getitem__

        # validate big, set appropriate helper functions.
        self.big = big
        if big:
            self._encode_bytes = self._encode_bytes_big
            self._decode_bytes = self._decode_bytes_big
        else:
            self._encode_bytes = self._encode_bytes_little
            self._decode_bytes = self._decode_bytes_little

        # TODO: support padding character
        ##if padding is not None:
        ##    if isinstance(padding, unicode):
        ##        padding = padding.encode("latin-1")
        ##    elif not isinstance(padding, bytes):
        ##        raise TypeError("padding char must be unicode or bytes")
        ##    if len(padding) != 1:
        ##        raise ValueError("padding must be single character")
        ##self.padding = padding

    @property
    def charmap(self):
        """charmap as unicode"""
        return self.bytemap.decode("latin-1")

    def encode_bytes(self, source):
        """encode bytes to base64 string.

        :arg source: byte string to encode.
        :returns: byte string containing encoded data.
        """
        if not isinstance(source, bytes):
            raise TypeError(f"source must be bytes, not {type(source)}")
        chunks, tail = divmod(len(source), 3)
        next_value = iter(source).__next__
        gen = self._encode_bytes(next_value, chunks, tail)
        return bytes(map(self._encode64, gen))
        ##if tail:
        ##    padding = self.padding
        ##    if padding:
        ##        out += padding * (3-tail)

    def _encode_bytes_little(self, next_value, chunks, tail):
        """helper used by encode_bytes() to handle little-endian encoding"""
        #
        # output bit layout:
        #
        # first byte:   v1 543210
        #
        # second byte:  v1 ....76
        #              +v2 3210..
        #
        # third byte:   v2 ..7654
        #              +v3 10....
        #
        # fourth byte:  v3 765432
        #
        idx = 0
        while idx < chunks:
            v1 = next_value()
            v2 = next_value()
            v3 = next_value()
            yield v1 & 0x3F
            yield ((v2 & 0x0F) << 2) | (v1 >> 6)
            yield ((v3 & 0x03) << 4) | (v2 >> 4)
            yield v3 >> 2
            idx += 1
        if tail:
            v1 = next_value()
            if tail == 1:
                # note: 4 msb of last byte are padding
                yield v1 & 0x3F
                yield v1 >> 6
            else:
                assert tail == 2
                # note: 2 msb of last byte are padding
                v2 = next_value()
                yield v1 & 0x3F
                yield ((v2 & 0x0F) << 2) | (v1 >> 6)
                yield v2 >> 4

    def _encode_bytes_big(self, next_value, chunks, tail):
        """helper used by encode_bytes() to handle big-endian encoding"""
        #
        # output bit layout:
        #
        # first byte:   v1 765432
        #
        # second byte:  v1 10....
        #              +v2 ..7654
        #
        # third byte:   v2 3210..
        #              +v3 ....76
        #
        # fourth byte:  v3 543210
        #
        idx = 0
        while idx < chunks:
            v1 = next_value()
            v2 = next_value()
            v3 = next_value()
            yield v1 >> 2
            yield ((v1 & 0x03) << 4) | (v2 >> 4)
            yield ((v2 & 0x0F) << 2) | (v3 >> 6)
            yield v3 & 0x3F
            idx += 1
        if tail:
            v1 = next_value()
            if tail == 1:
                # note: 4 lsb of last byte are padding
                yield v1 >> 2
                yield (v1 & 0x03) << 4
            else:
                assert tail == 2
                # note: 2 lsb of last byte are padding
                v2 = next_value()
                yield v1 >> 2
                yield ((v1 & 0x03) << 4) | (v2 >> 4)
                yield ((v2 & 0x0F) << 2)

    def decode_bytes(self, source):
        """decode bytes from base64 string.

        :arg source: byte string to decode.
        :returns: byte string containing decoded data.
        """
        if not isinstance(source, bytes):
            raise TypeError(f"source must be bytes, not {type(source)}")
        ##padding = self.padding
        ##if padding:
        ##    # TODO: add padding size check?
        ##    source = source.rstrip(padding)
        chunks, tail = divmod(len(source), 4)
        if tail == 1:
            # only 6 bits left, can't encode a whole byte!
            raise ValueError("input string length cannot be == 1 mod 4")
        next_value = map(self._decode64, source).__next__
        try:
            return bytes(self._decode_bytes(next_value, chunks, tail))
        except KeyError as err:
            raise ValueError(f"invalid character: {err.args[0]!r}")

    def _decode_bytes_little(self, next_value, chunks, tail):
        """helper used by decode_bytes() to handle little-endian encoding"""
        #
        # input bit layout:
        #
        # first byte:   v1 ..543210
        #              +v2 10......
        #
        # second byte:  v2 ....5432
        #              +v3 3210....
        #
        # third byte:   v3 ......54
        #              +v4 543210..
        #
        idx = 0
        while idx < chunks:
            v1 = next_value()
            v2 = next_value()
            v3 = next_value()
            v4 = next_value()
            yield v1 | ((v2 & 0x3) << 6)
            yield (v2 >> 2) | ((v3 & 0xF) << 4)
            yield (v3 >> 4) | (v4 << 2)
            idx += 1
        if tail:
            # tail is 2 or 3
            v1 = next_value()
            v2 = next_value()
            yield v1 | ((v2 & 0x3) << 6)
            # NOTE: if tail == 2, 4 msb of v2 are ignored (should be 0)
            if tail == 3:
                # NOTE: 2 msb of v3 are ignored (should be 0)
                v3 = next_value()
                yield (v2 >> 2) | ((v3 & 0xF) << 4)

    def _decode_bytes_big(self, next_value, chunks, tail):
        """helper used by decode_bytes() to handle big-endian encoding"""
        #
        # input bit layout:
        #
        # first byte:   v1 543210..
        #              +v2 ......54
        #
        # second byte:  v2 3210....
        #              +v3 ....5432
        #
        # third byte:   v3 10......
        #              +v4 ..543210
        #
        idx = 0
        while idx < chunks:
            v1 = next_value()
            v2 = next_value()
            v3 = next_value()
            v4 = next_value()
            yield (v1 << 2) | (v2 >> 4)
            yield ((v2 & 0xF) << 4) | (v3 >> 2)
            yield ((v3 & 0x3) << 6) | v4
            idx += 1
        if tail:
            # tail is 2 or 3
            v1 = next_value()
            v2 = next_value()
            yield (v1 << 2) | (v2 >> 4)
            # NOTE: if tail == 2, 4 lsb of v2 are ignored (should be 0)
            if tail == 3:
                # NOTE: 2 lsb of v3 are ignored (should be 0)
                v3 = next_value()
                yield ((v2 & 0xF) << 4) | (v3 >> 2)

    # padmap2/3 - dict mapping last char of string ->
    # equivalent char with no padding bits set.

    def __make_padset(self, bits):
        """helper to generate set of valid last chars & bytes"""
        pset = set(c for i, c in enumerate(self.bytemap) if not i & bits)
        pset.update(c for i, c in enumerate(self.charmap) if not i & bits)
        return frozenset(pset)

    @memoized_property
    def _padinfo2(self):
        """mask to clear padding bits, and valid last bytes (for strings 2 % 4)"""
        # 4 bits of last char unused (lsb for big, msb for little)
        bits = 15 if self.big else (15 << 2)
        return ~bits, self.__make_padset(bits)

    @memoized_property
    def _padinfo3(self):
        """mask to clear padding bits, and valid last bytes (for strings 3 % 4)"""
        # 2 bits of last char unused (lsb for big, msb for little)
        bits = 3 if self.big else (3 << 4)
        return ~bits, self.__make_padset(bits)

    def check_repair_unused(self, source):
        """helper to detect & clear invalid unused bits in last character.

        :arg source:
            encoded data (as ascii bytes or unicode).

        :returns:
            `(True, result)` if the string was repaired,
            `(False, source)` if the string was ok as-is.
        """
        # figure out how many padding bits there are in last char.
        tail = len(source) & 3
        if tail == 2:
            mask, padset = self._padinfo2
        elif tail == 3:
            mask, padset = self._padinfo3
        elif not tail:
            return False, source
        else:
            raise ValueError("source length must != 1 mod 4")

        # check if last char is ok (padset contains bytes & unicode versions)
        last = source[-1]
        if last in padset:
            return False, source

        # we have dirty bits - repair the string by decoding last char,
        # clearing the padding bits via <mask>, and encoding new char.
        if isinstance(source, str):
            cm = self.charmap
            last = cm[cm.index(last) & mask]
            assert last in padset, "failed to generate valid padding char"
        else:
            # NOTE: this assumes ascii-compat encoding, and that
            # all chars used by encoding are 7-bit ascii.
            last = self._encode64(self._decode64(last) & mask)
            assert last in padset, "failed to generate valid padding char"
            last = bytes([last])
        return True, source[:-1] + last

    def repair_unused(self, source):
        return self.check_repair_unused(source)[1]

    ##def transcode(self, source, other):
    ##    return ''.join(
    ##        other.charmap[self.charmap.index(char)]
    ##        for char in source
    ##    )

    ##def random_encoded_bytes(self, size, random=None, unicode=False):
    ##    "return random encoded string of given size"
    ##    data = getrandstr(random or rng,
    ##                      self.charmap if unicode else self.bytemap, size)
    ##    return self.repair_unused(data)

    def encode_transposed_bytes(self, source, offsets):
        """encode byte string, first transposing source using offset list"""
        if not isinstance(source, bytes):
            raise TypeError(f"source must be bytes, not {type(source)}")
        tmp = bytes(source[off] for off in offsets)
        return self.encode_bytes(tmp)

    def decode_transposed_bytes(self, source, offsets):
        """decode byte string, then reverse transposition described by offset list"""
        # NOTE: if transposition does not use all bytes of source,
        # the original can't be recovered... and bytes() will throw
        # an error because 1+ values in <buf> will be None.
        tmp = self.decode_bytes(source)
        buf = [None] * len(offsets)
        for off, char in zip(offsets, tmp):
            buf[off] = char
        return bytes(buf)

    def _decode_int(self, source, bits):
        """decode base64 string -> integer

        :arg source: base64 string to decode.
        :arg bits: number of bits in resulting integer.

        :raises ValueError:
            * if the string contains invalid base64 characters.
            * if the string is not long enough - it must be at least
              ``int(ceil(bits/6))`` in length.

        :returns:
            a integer in the range ``0 <= n < 2**bits``
        """
        if not isinstance(source, bytes):
            raise TypeError(f"source must be bytes, not {type(source)}")
        big = self.big
        pad = -bits % 6
        chars = (bits + pad) / 6
        if len(source) != chars:
            raise ValueError("source must be %d chars" % (chars,))
        decode = self._decode64
        out = 0
        try:
            for c in source if big else reversed(source):
                out = (out << 6) + decode(c)
        except KeyError:
            raise ValueError(f"invalid character in string: {c!r}")
        if pad:
            # strip padding bits
            if big:
                out >>= pad
            else:
                out &= (1 << bits) - 1
        return out

    # ---------------------------------------------------------------
    # optimized versions for common integer sizes
    # ---------------------------------------------------------------

    def decode_int6(self, source):
        """decode single character -> 6 bit integer"""
        if not isinstance(source, bytes):
            raise TypeError(f"source must be bytes, not {type(source)}")
        if len(source) != 1:
            raise ValueError("source must be exactly 1 byte")
        # convert to 8bit int before doing lookup
        source = source[0]
        try:
            return self._decode64(source)
        except KeyError:
            raise ValueError("invalid character")

    def decode_int12(self, source):
        """decodes 2 char string -> 12-bit integer"""
        if not isinstance(source, bytes):
            raise TypeError(f"source must be bytes, not {type(source)}")
        if len(source) != 2:
            raise ValueError("source must be exactly 2 bytes")
        decode = self._decode64
        try:
            if self.big:
                return decode(source[1]) + (decode(source[0]) << 6)
            return decode(source[0]) + (decode(source[1]) << 6)
        except KeyError:
            raise ValueError("invalid character")

    def decode_int24(self, source):
        """decodes 4 char string -> 24-bit integer"""
        if not isinstance(source, bytes):
            raise TypeError(f"source must be bytes, not {type(source)}")
        if len(source) != 4:
            raise ValueError("source must be exactly 4 bytes")
        decode = self._decode64
        try:
            if self.big:
                return (
                    decode(source[3])
                    + (decode(source[2]) << 6)
                    + (decode(source[1]) << 12)
                    + (decode(source[0]) << 18)
                )
            return (
                decode(source[0])
                + (decode(source[1]) << 6)
                + (decode(source[2]) << 12)
                + (decode(source[3]) << 18)
            )
        except KeyError:
            raise ValueError("invalid character")

    def decode_int30(self, source):
        """decode 5 char string -> 30 bit integer"""
        return self._decode_int(source, 30)

    def decode_int64(self, source):
        """decode 11 char base64 string -> 64-bit integer

        this format is used primarily by des-crypt & variants to encode
        the DES output value used as a checksum.
        """
        return self._decode_int(source, 64)

    def _encode_int(self, value, bits):
        """encode integer into base64 format

        :arg value: non-negative integer to encode
        :arg bits: number of bits to encode

        :returns:
            a string of length ``int(ceil(bits/6.0))``.
        """
        assert value >= 0, "caller did not sanitize input"
        pad = -bits % 6
        bits += pad
        if self.big:
            itr = range(bits - 6, -6, -6)
            # shift to add lsb padding.
            value <<= pad
        else:
            itr = range(0, bits, 6)
            # padding is msb, so no change needed.
        return bytes(map(self._encode64, ((value >> off) & 0x3F for off in itr)))

    # ---------------------------------------------------------------
    # optimized versions for common integer sizes
    # ---------------------------------------------------------------

    def encode_int6(self, value):
        """encodes 6-bit integer -> single hash64 character"""
        if value < 0 or value > 63:
            raise ValueError("value out of range")
        return self.bytemap[value : value + 1]

    def encode_int12(self, value):
        """encodes 12-bit integer -> 2 char string"""
        if value < 0 or value > 0xFFF:
            raise ValueError("value out of range")
        raw = [value & 0x3F, (value >> 6) & 0x3F]
        if self.big:
            raw.reverse()
        return bytes(map(self._encode64, raw))

    def encode_int24(self, value):
        """encodes 24-bit integer -> 4 char string"""
        if value < 0 or value > 0xFFFFFF:
            raise ValueError("value out of range")
        raw = [
            value & 0x3F,
            (value >> 6) & 0x3F,
            (value >> 12) & 0x3F,
            (value >> 18) & 0x3F,
        ]
        if self.big:
            raw.reverse()
        return bytes(map(self._encode64, raw))

    def encode_int30(self, value):
        """decode 5 char string -> 30 bit integer"""
        if value < 0 or value > 0x3FFFFFFF:
            raise ValueError("value out of range")
        return self._encode_int(value, 30)

    def encode_int64(self, value):
        """encode 64-bit integer -> 11 char hash64 string

        this format is used primarily by des-crypt & variants to encode
        the DES output value used as a checksum.
        """
        if value < 0 or value > 0xFFFFFFFFFFFFFFFF:
            raise ValueError("value out of range")
        return self._encode_int(value, 64)


class LazyBase64Engine(Base64Engine):
    """Base64Engine which delays initialization until it's accessed"""

    _lazy_opts = None

    def __init__(self, *args, **kwds):
        self._lazy_opts = (args, kwds)

    def _lazy_init(self):
        args, kwds = self._lazy_opts
        super().__init__(*args, **kwds)
        del self._lazy_opts
        self.__class__ = Base64Engine

    def __getattribute__(self, attr):
        if not attr.startswith("_"):
            self._lazy_init()
        return object.__getattribute__(self, attr)


h64 = LazyBase64Engine(HASH64_CHARS)
h64big = LazyBase64Engine(HASH64_CHARS, big=True)
bcrypt64 = LazyBase64Engine(BCRYPT_CHARS, big=True)
