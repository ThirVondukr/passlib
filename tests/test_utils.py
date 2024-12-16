"""tests for passlib.util"""

from __future__ import annotations

import re
import warnings
from functools import partial
from typing import TYPE_CHECKING

import pytest

from passlib.utils import Base64Engine, is_ascii_safe, to_bytes
from passlib.utils.binary import h64, h64big
from passlib.utils.compat import join_bytes
from tests.utils import TestCase, hb, run_with_fixed_seeds

if TYPE_CHECKING:
    from collections.abc import Sequence


class MiscTest(TestCase):
    """tests various parts of utils module"""

    # NOTE: could test xor_bytes(), but it's exercised well enough by pbkdf2 test

    def test_compat(self):
        """test compat's lazymodule"""
        from passlib.utils import compat

        # "<module 'passlib.utils.compat' from 'passlib/utils/compat.pyc'>"
        assert re.search("^<module 'passlib.utils.compat' from '.*?'>$", repr(compat))

        # test synthentic dir()
        dir(compat)
        # FIXME: find another lazy-loaded attr to check, all current ones removed after py2 comapt gone.
        # self.assertTrue('UnicodeIO' in dir(compat))

    def test_classproperty(self):
        from passlib.utils.decor import classproperty

        def xprop_func(cls):
            return cls.xvar

        class test:
            xvar = 1

            xprop = classproperty(xprop_func)

        assert test.xprop == 1

        prop = test.__dict__["xprop"]
        assert prop.__func__ is xprop_func

    def test_deprecated_function(self):
        from passlib.utils.decor import deprecated_function
        # NOTE: not comprehensive, just tests the basic behavior

        @deprecated_function(deprecated="1.6", removed="1.8")
        def test_func(*args):
            """test docstring"""
            return args

        assert ".. deprecated::" in test_func.__doc__

        with pytest.warns(
            DeprecationWarning,
            match=r"the function tests.test_utils.test_func\(\) is deprecated as of Passlib 1.6, and will be removed in Passlib 1.8.",
        ):
            assert test_func(1, 2) == (1, 2)

    def test_memoized_property(self):
        from passlib.utils.decor import memoized_property

        class dummy:
            counter = 0

            @memoized_property
            def value(self):
                value = self.counter
                self.counter = value + 1
                return value

        d = dummy()
        assert d.value == 0
        assert d.value == 0
        assert d.counter == 1

    def test_getrandbytes(self):
        """getrandbytes()"""
        from passlib.utils import getrandbytes

        wrapper = partial(getrandbytes, self.getRandom())
        assert len(wrapper(0)) == 0
        a = wrapper(10)
        b = wrapper(10)
        assert isinstance(a, bytes)
        assert len(a) == 10
        assert len(b) == 10
        assert a != b

    @run_with_fixed_seeds(count=1024)
    def test_getrandstr(self, seed):
        """getrandstr()"""
        from passlib.utils import getrandstr

        wrapper = partial(getrandstr, self.getRandom(seed=seed))

        # count 0
        assert wrapper("abc", 0) == ""

        # count <0
        with pytest.raises(ValueError):
            wrapper("abc", -1)

        # letters 0
        with pytest.raises(ValueError):
            wrapper("", 0)

        # letters 1
        assert wrapper("a", 5) == "aaaaa"

        # NOTE: the following parts are non-deterministic,
        #       with a small chance of failure (outside chance it may pick
        #       a string w/o one char, even more remote chance of picking
        #       same string).  to combat this, we run it against multiple
        #       fixed seeds (using run_with_fixed_seeds decorator),
        #       and hope that they're sufficient to test the range of behavior.

        # letters
        x = wrapper("abc", 32)
        y = wrapper("abc", 32)
        assert isinstance(x, str)
        assert x != y
        assert sorted(set(x)) == ["a", "b", "c"]

        # bytes
        x = wrapper(b"abc", 32)
        y = wrapper(b"abc", 32)
        assert isinstance(x, bytes)
        assert x != y
        # NOTE: decoding this due to py3 bytes
        assert sorted(set(x.decode("ascii"))) == ["a", "b", "c"]

    def test_generate_password(self):
        """generate_password()"""
        from passlib.utils import generate_password

        warnings.filterwarnings(
            "ignore", r"The function.*generate_password\(\) is deprecated"
        )
        assert len(generate_password(15)) == 15

    def test_is_crypt_context(self):
        """test is_crypt_context()"""
        from passlib.context import CryptContext
        from passlib.utils import is_crypt_context

        cc = CryptContext(["des_crypt"])
        assert is_crypt_context(cc)
        assert is_crypt_context(cc)

    def test_genseed(self):
        """test genseed()"""
        import random

        from passlib.utils import genseed

        rng = random.Random(genseed())
        a = rng.randint(0, 10**10)

        rng = random.Random(genseed())
        b = rng.randint(0, 10**10)

        assert a != b

        rng.seed(genseed(rng))

    def test_consteq(self):
        """test consteq()"""
        # NOTE: this test is kind of over the top, but that's only because
        # this is used for the critical task of comparing hashes for equality.
        from passlib.utils import consteq

        # ensure error raises for wrong types
        with pytest.raises(TypeError):
            consteq("", b"")
        with pytest.raises(TypeError):
            consteq("", 1)
        with pytest.raises(TypeError):
            consteq("", None)

        with pytest.raises(TypeError):
            consteq(b"", "")
        with pytest.raises(TypeError):
            consteq(b"", 1)
        with pytest.raises(TypeError):
            consteq(b"", None)

        with pytest.raises(TypeError):
            consteq(None, "")
        with pytest.raises(TypeError):
            consteq(None, b"")
        with pytest.raises(TypeError):
            consteq(1, "")
        with pytest.raises(TypeError):
            consteq(1, b"")

        # check equal inputs compare correctly
        for value in [
            "a",
            "abc",
            "\xff\xa2\x12\x00" * 10,
        ]:
            assert consteq(value, value), f"value {value!r}:"
            assert consteq(value, value), f"value {value!r}:"

            value = value.encode("latin-1")
            assert consteq(value, value), f"value {value!r}:"

        # check non-equal inputs compare correctly
        for left, right in [
            # check same-size comparisons with differing contents fail.
            ("a", "c"),
            ("abcabc", "zbaabc"),
            ("abcabc", "abzabc"),
            ("abcabc", "abcabz"),
            (("\xff\xa2\x12\x00" * 10)[:-1] + "\x01", "\xff\xa2\x12\x00" * 10),
            # check different-size comparisons fail.
            ("", "a"),
            ("abc", "abcdef"),
            ("abc", "defabc"),
            ("qwertyuiopasdfghjklzxcvbnm", "abc"),
        ]:
            assert not consteq(left, right), f"values {left!r} {right!r}:"
            assert not consteq(right, left), f"values {right!r} {left!r}:"
            assert not consteq(left, right), f"values {left!r} {right!r}:"
            assert not consteq(right, left), f"values {right!r} {left!r}:"

            left = left.encode("latin-1")
            right = right.encode("latin-1")
            assert not consteq(left, right), f"values {left!r} {right!r}:"
            assert not consteq(right, left), f"values {right!r} {left!r}:"

        # TODO: add some tests to ensure we take THETA(strlen) time.
        # this might be hard to do reproducably.
        # NOTE: below code was used to generate stats for analysis
        ##from math import log as logb
        ##import timeit
        ##multipliers = [ 1<<s for s in range(9)]
        ##correct =   u"abcdefgh"*(1<<4)
        ##incorrect = u"abcdxfgh"
        ##print
        ##first = True
        ##for run in range(1):
        ##    times = []
        ##    chars = []
        ##    for m in multipliers:
        ##        supplied = incorrect * m
        ##        def test():
        ##            self.assertFalse(consteq(supplied,correct))
        ##            ##self.assertFalse(supplied == correct)
        ##        times.append(timeit.timeit(test, number=100000))
        ##        chars.append(len(supplied))
        ##    # output for wolfram alpha
        ##    print ", ".join("{%r, %r}" % (c,round(t,4)) for c,t in zip(chars,times))
        ##    def scale(c):
        ##        return logb(c,2)
        ##    print ", ".join("{%r, %r}" % (scale(c),round(t,4)) for c,t in zip(chars,times))
        ##    # output for spreadsheet
        ##    ##if first:
        ##    ##    print "na, " + ", ".join(str(c) for c in chars)
        ##    ##    first = False
        ##    ##print ", ".join(str(c) for c in [run] + times)

    def test_saslprep(self):
        """test saslprep() unicode normalizer"""
        self.require_stringprep()
        from passlib.utils import saslprep as sp

        # invalid types
        with pytest.raises(TypeError):
            sp(None)
        with pytest.raises(TypeError):
            sp(1)
        with pytest.raises(TypeError):
            sp(b"")

        # empty strings
        assert sp("") == ""
        assert sp("\xad") == ""

        # verify B.1 chars are stripped,
        assert sp("$\xad$\u200d$") == "$$$"

        # verify C.1.2 chars are replaced with space
        assert sp("$ $\xa0$\u3000$") == "$ $ $ $"

        # verify normalization to KC
        assert sp("à") == "à"
        assert sp("à") == "à"

        # verify various forbidden characters
        # control chars
        with pytest.raises(ValueError):
            sp("\u0000")
        with pytest.raises(ValueError):
            sp("\u007f")
        with pytest.raises(ValueError):
            sp("\u180e")
        with pytest.raises(ValueError):
            sp("\ufff9")
        # private use
        with pytest.raises(ValueError):
            sp("\ue000")
        # non-characters
        with pytest.raises(ValueError):
            sp("\ufdd0")
        # surrogates
        with pytest.raises(ValueError):
            sp("\ud800")
        # non-plaintext chars
        with pytest.raises(ValueError):
            sp("\ufffd")
        # non-canon
        with pytest.raises(ValueError):
            sp("\u2ff0")
        # change display properties
        with pytest.raises(ValueError):
            sp("\u200e")
        with pytest.raises(ValueError):
            sp("\u206f")
        # unassigned code points (as of unicode 3.2)
        with pytest.raises(ValueError):
            sp("\u0900")
        with pytest.raises(ValueError):
            sp("\ufff8")
        # tagging characters
        with pytest.raises(ValueError):
            sp("\U000e0001")

        # verify bidi behavior
        # if starts with R/AL -- must end with R/AL
        with pytest.raises(ValueError):
            sp("\u0627\u0031")
        assert sp("ا") == "ا"
        assert sp("اب") == "اب"
        assert sp("ا1ب") == "ا1ب"
        # if starts with R/AL --  cannot contain L
        with pytest.raises(ValueError):
            sp("\u0627\u0041\u0628")
        # if doesn't start with R/AL -- can contain R/AL, but L & EN allowed
        with pytest.raises(ValueError):
            sp("x\u0627z")
        assert sp("xAz") == "xAz"

        # ------------------------------------------------------
        # examples pulled from external sources, to be thorough
        # ------------------------------------------------------

        # rfc 4031 section 3 examples
        assert sp("I\xadX") == "IX"  # strip SHY
        assert sp("user") == "user"  # unchanged
        assert sp("USER") == "USER"  # case preserved
        assert sp("ª") == "a"  # normalize to KC form
        assert sp("Ⅸ") == "IX"  # normalize to KC form
        with pytest.raises(ValueError):
            sp("\u0007")  # forbid control chars
        with pytest.raises(ValueError):
            sp("\u0627\u0031")  # invalid bidi

        # rfc 3454 section 6 examples
        # starts with RAL char, must end with RAL char
        with pytest.raises(ValueError):
            sp("\u0627\u0031")
        assert sp("ا1ب") == "ا1ب"

    def test_splitcomma(self):
        from passlib.utils import splitcomma

        assert splitcomma("") == []
        assert splitcomma(",") == []
        assert splitcomma("a") == ["a"]
        assert splitcomma(" a , ") == ["a"]
        assert splitcomma(" a , b") == ["a", "b"]
        assert splitcomma(" a, b, ") == ["a", "b"]

    def test_utf8_truncate(self):
        """
        utf8_truncate()
        """
        from passlib.utils import utf8_truncate

        #
        # run through a bunch of reference strings,
        # and make sure they truncate properly across all possible indexes
        #
        for source in [
            # empty string
            b"",
            # strings w/ only single-byte chars
            b"1",
            b"123",
            b"\x1a",
            b"\x1a" * 10,
            b"\x7f",
            b"\x7f" * 10,
            # strings w/ properly formed UTF8 continuation sequences
            b"a\xc2\xa0\xc3\xbe\xc3\xbe",
            b"abcdefghjusdfaoiu\xc2\xa0\xc3\xbe\xc3\xbedsfioauweoiruer",
        ]:
            source.decode("utf-8")  # sanity check - should always be valid UTF8

            end = len(source)
            for idx in range(end + 16):
                prefix = f"source={source!r} index={idx!r}: "

                result = utf8_truncate(source, idx)

                # result should always be valid utf-8
                result.decode("utf-8")

                # result should never be larger than source
                assert len(result) <= end, prefix

                # result should always be in range(idx, idx+4)
                assert len(result) >= min(idx, end), prefix
                assert len(result) < min(idx + 4, end + 1), prefix

                # should be strict prefix of source
                assert result == source[: len(result)], prefix

        #
        # malformed utf8 --
        # strings w/ only initial chars (should cut just like single-byte chars)
        #
        for source in [
            b"\xca",
            b"\xca" * 10,
            # also test null bytes (not valid utf8, but this func should treat them like ascii)
            b"\x00",
            b"\x00" * 10,
        ]:
            end = len(source)
            for idx in range(end + 16):
                prefix = f"source={source!r} index={idx!r}: "
                result = utf8_truncate(source, idx)
                assert result == source[:idx], prefix

        #
        # malformed utf8 --
        # strings w/ only continuation chars (should cut at index+3)
        #
        for source in [
            b"\xaa",
            b"\xaa" * 10,
        ]:
            end = len(source)
            for idx in range(end + 16):
                prefix = f"source={source!r} index={idx!r}: "
                result = utf8_truncate(source, idx)
                assert result == source[: idx + 3], prefix

        #
        # string w/ some invalid utf8 --
        # * \xaa byte is too many continuation byte after \xff start byte
        # * \xab byte doesn't have preceding start byte
        # XXX: could also test continuation bytes w/o start byte, WITHIN the string.
        #      but think this covers edges well enough...
        #
        source = b"MN\xff\xa0\xa1\xa2\xaaOP\xab"

        assert utf8_truncate(source, 0) == b""  # index="M", stops there

        assert utf8_truncate(source, 1) == b"M"  # index="N", stops there

        assert utf8_truncate(source, 2) == b"MN"  # index="\xff", stops there

        assert (
            utf8_truncate(source, 3) == b"MN\xff\xa0\xa1\xa2"
        )  # index="\xa0", runs out after index+3="\xa2"

        assert (
            utf8_truncate(source, 4) == b"MN\xff\xa0\xa1\xa2\xaa"
        )  # index="\xa1", runs out after index+3="\xaa"

        assert (
            utf8_truncate(source, 5) == b"MN\xff\xa0\xa1\xa2\xaa"
        )  # index="\xa2", stops before "O"

        assert (
            utf8_truncate(source, 6) == b"MN\xff\xa0\xa1\xa2\xaa"
        )  # index="\xaa", stops before "O"

        assert (
            utf8_truncate(source, 7) == b"MN\xff\xa0\xa1\xa2\xaa"
        )  # index="O", stops there

        assert (
            utf8_truncate(source, 8) == b"MN\xff\xa0\xa1\xa2\xaaO"
        )  # index="P", stops there

        assert (
            utf8_truncate(source, 9) == b"MN\xff\xa0\xa1\xa2\xaaOP\xab"
        )  # index="\xab", runs out at end

        assert utf8_truncate(source, 10) == b"MN\xff\xa0\xa1\xa2\xaaOP\xab"  # index=end

        assert (
            utf8_truncate(source, 11) == b"MN\xff\xa0\xa1\xa2\xaaOP\xab"
        )  # index=end+1


class CodecTest(TestCase):
    """tests bytes/unicode helpers in passlib.utils"""

    def test_bytes(self):
        """test b() helper, bytes and native str type"""
        import builtins

        assert bytes is builtins.bytes

        assert isinstance(b"", bytes)
        assert isinstance(b"\x00\xff", bytes)
        assert b"\x00\xff".decode("latin-1") == "\x00ÿ"

    def test_to_bytes(self):
        """test to_bytes()"""

        # check unicode inputs
        assert to_bytes("abc") == b"abc"
        assert to_bytes("\x00ÿ") == b"\x00\xc3\xbf"

        # check unicode w/ encodings
        assert to_bytes("\x00ÿ", "latin-1") == b"\x00\xff"
        with pytest.raises(ValueError):
            to_bytes("\x00\xff", "ascii")

        # check bytes inputs
        assert to_bytes(b"abc") == b"abc"
        assert to_bytes(b"\x00\xff") == b"\x00\xff"
        assert to_bytes(b"\x00\xc3\xbf") == b"\x00\xc3\xbf"

        # check byte inputs ignores enocding
        assert to_bytes(b"\x00\xc3\xbf", "latin-1") == b"\x00\xc3\xbf"

        # check bytes transcoding
        assert to_bytes(b"\x00\xc3\xbf", "latin-1", "", "utf-8") == b"\x00\xff"

        # check other
        with pytest.raises(AssertionError):
            to_bytes("abc", None)
        with pytest.raises(TypeError):
            to_bytes(None)

    def test_to_unicode(self):
        """test to_unicode()"""
        from passlib.utils import to_unicode

        # check unicode inputs
        assert to_unicode("abc") == "abc"
        assert to_unicode("\x00ÿ") == "\x00ÿ"

        # check unicode input ignores encoding
        assert to_unicode("\x00ÿ", "ascii") == "\x00ÿ"

        # check bytes input
        assert to_unicode(b"abc") == "abc"
        assert to_unicode(b"\x00\xc3\xbf") == "\x00ÿ"
        assert to_unicode(b"\x00\xff", "latin-1") == "\x00ÿ"
        with pytest.raises(ValueError):
            to_unicode(b"\x00\xff")

        # check other
        with pytest.raises(AssertionError):
            to_unicode("abc", None)
        with pytest.raises(TypeError):
            to_unicode(None)

    def test_to_native_str(self):
        """test to_native_str()"""
        from passlib.utils import to_native_str

        # test plain ascii
        assert to_native_str("abc", "ascii") == "abc"
        assert to_native_str(b"abc", "ascii") == "abc"

        # test invalid ascii
        assert to_native_str("à", "ascii") == "à"
        with pytest.raises(UnicodeDecodeError):
            to_native_str(b"\xc3\xa0", "ascii")

        # test latin-1
        assert to_native_str("à", "latin-1") == "à"
        assert to_native_str(b"\xe0", "latin-1") == "à"

        # test utf-8
        assert to_native_str("à", "utf-8") == "à"
        assert to_native_str(b"\xc3\xa0", "utf-8") == "à"

        # other types rejected
        with pytest.raises(TypeError):
            to_native_str(None, "ascii")

    def test_is_ascii_safe(self):
        assert is_ascii_safe(b"\x00abc\x7f")
        assert is_ascii_safe("\x00abc\x7f")
        assert not is_ascii_safe(b"\x00abc\x80")
        assert not is_ascii_safe("\x00abc\x80")

    def test_is_same_codec(self):
        """test is_same_codec()"""
        from passlib.utils import is_same_codec

        assert is_same_codec(None, None)
        assert not is_same_codec(None, "ascii")

        assert is_same_codec("ascii", "ascii")
        assert is_same_codec("ascii", "ASCII")

        assert is_same_codec("utf-8", "utf-8")
        assert is_same_codec("utf-8", "utf8")
        assert is_same_codec("utf-8", "UTF_8")

        assert not is_same_codec("ascii", "utf-8")


class Base64EngineTest(TestCase):
    """test standalone parts of Base64Engine"""

    # NOTE: most Base64Engine testing done via _Base64Test subclasses below.

    def test_constructor(self):
        from passlib.utils.binary import AB64_CHARS, Base64Engine

        # bad charmap type
        with pytest.raises(TypeError):
            Base64Engine(1)

        # bad charmap size
        with pytest.raises(ValueError):
            Base64Engine(AB64_CHARS[:-1])

        # dup charmap letter
        with pytest.raises(ValueError):
            Base64Engine(AB64_CHARS[:-1] + "A")

    def test_ab64_decode(self):
        """ab64_decode()"""
        from passlib.utils.binary import ab64_decode

        # accept bytes or unicode
        assert ab64_decode(b"abc") == hb("69b7")
        assert ab64_decode("abc") == hb("69b7")

        # reject non-ascii unicode
        with pytest.raises(ValueError):
            ab64_decode("ab\xff")

        # underlying a2b_ascii treats non-base64 chars as "Incorrect padding"
        with pytest.raises(TypeError):
            ab64_decode(b"ab\xff")
        with pytest.raises(TypeError):
            ab64_decode(b"ab!")
        with pytest.raises(TypeError):
            ab64_decode("ab!")

        # insert correct padding, handle dirty padding bits
        assert ab64_decode(b"abcd") == hb("69b71d")  # 0 mod 4
        with pytest.raises(ValueError):
            ab64_decode(b"abcde")  # 1 mod 4
        assert ab64_decode(b"abcdef") == hb("69b71d79")  # 2 mod 4, dirty padding bits
        assert ab64_decode(b"abcdeQ") == hb("69b71d79")  # 2 mod 4, clean padding bits
        assert ab64_decode(b"abcdefg") == hb(
            "69b71d79f8"
        )  # 3 mod 4, clean padding bits

        # support "./" or "+/" altchars
        # (lets us transition to "+/" representation, merge w/ b64s_decode)
        assert ab64_decode(b"ab+/") == hb("69bfbf")
        assert ab64_decode(b"ab./") == hb("69bfbf")

    def test_ab64_encode(self):
        """ab64_encode()"""
        from passlib.utils.binary import ab64_encode

        # accept bytes
        assert ab64_encode(hb("69b7")) == b"abc"

        # reject unicode
        with pytest.raises(TypeError):
            ab64_encode(hb("69b7").decode("latin-1"))

        # insert correct padding before decoding
        assert ab64_encode(hb("69b71d")) == b"abcd"  # 0 mod 4
        assert ab64_encode(hb("69b71d79")) == b"abcdeQ"  # 2 mod 4
        assert ab64_encode(hb("69b71d79f8")) == b"abcdefg"  # 3 mod 4

        # output "./" altchars
        assert ab64_encode(hb("69bfbf")) == b"ab./"

    def test_b64s_decode(self):
        """b64s_decode()"""
        from passlib.utils.binary import b64s_decode

        # accept bytes or unicode
        assert b64s_decode(b"abc") == hb("69b7")
        assert b64s_decode("abc") == hb("69b7")

        # reject non-ascii unicode
        with pytest.raises(ValueError):
            b64s_decode("ab\xff")

        # underlying a2b_ascii treats non-base64 chars as "Incorrect padding"
        with pytest.raises(TypeError):
            b64s_decode(b"ab\xff")
        with pytest.raises(TypeError):
            b64s_decode(b"ab!")
        with pytest.raises(TypeError):
            b64s_decode("ab!")

        # insert correct padding, handle dirty padding bits
        assert b64s_decode(b"abcd") == hb("69b71d")  # 0 mod 4
        with pytest.raises(ValueError):
            b64s_decode(b"abcde")  # 1 mod 4
        assert b64s_decode(b"abcdef") == hb("69b71d79")  # 2 mod 4, dirty padding bits
        assert b64s_decode(b"abcdeQ") == hb("69b71d79")  # 2 mod 4, clean padding bits
        assert b64s_decode(b"abcdefg") == hb(
            "69b71d79f8"
        )  # 3 mod 4, clean padding bits

    def test_b64s_encode(self):
        """b64s_encode()"""
        from passlib.utils.binary import b64s_encode

        # accept bytes
        assert b64s_encode(hb("69b7")) == b"abc"

        # reject unicode
        with pytest.raises(TypeError):
            b64s_encode(hb("69b7").decode("latin-1"))

        # insert correct padding before decoding
        assert b64s_encode(hb("69b71d")) == b"abcd"  # 0 mod 4
        assert b64s_encode(hb("69b71d79")) == b"abcdeQ"  # 2 mod 4
        assert b64s_encode(hb("69b71d79f8")) == b"abcdefg"  # 3 mod 4

        # output "+/" altchars
        assert b64s_encode(hb("69bfbf")) == b"ab+/"


class _Base64Test(TestCase):
    """common tests for all Base64Engine instances"""

    # Base64Engine instance to test
    engine: Base64Engine | None = None

    # pairs of (raw, encoded) bytes to test - should encode/decode correctly
    encoded_data: Sequence[Sequence[bytes | int]] | None = None

    # tuples of (encoded, value, bits) for known integer encodings
    encoded_ints: Sequence[Sequence[bytes | int]] | None = None

    # invalid encoded byte
    bad_byte = b"?"

    # helper to generate bytemap-specific strings
    def m(self, *offsets):
        """generate byte string from offsets"""
        return join_bytes(self.engine.bytemap[o : o + 1] for o in offsets)

    def test_encode_bytes(self):
        """test encode_bytes() against reference inputs"""
        engine = self.engine
        encode = engine.encode_bytes
        for raw, encoded in self.encoded_data:
            result = encode(raw)
            assert result == encoded, f"encode {raw!r}:"

    def test_encode_bytes_bad(self):
        """test encode_bytes() with bad input"""
        engine = self.engine
        encode = engine.encode_bytes
        with pytest.raises(TypeError):
            encode("\x00")
        with pytest.raises(TypeError):
            encode(None)

    def test_decode_bytes(self):
        """test decode_bytes() against reference inputs"""
        engine = self.engine
        decode = engine.decode_bytes
        for raw, encoded in self.encoded_data:
            result = decode(encoded)
            assert result == raw, f"decode {encoded!r}:"

    def test_decode_bytes_padding(self):
        """test decode_bytes() ignores padding bits"""
        bchr = lambda v: bytes([v])  # noqa: E731
        engine = self.engine
        m = self.m
        decode = engine.decode_bytes
        BNULL = b"\x00"

        # length == 2 mod 4: 4 bits of padding
        assert decode(m(0, 0)) == BNULL
        for i in range(6):
            if engine.big:  # 4 lsb padding
                correct = BNULL if i < 4 else bchr(1 << (i - 4))
            else:  # 4 msb padding
                correct = bchr(1 << (i + 6)) if i < 2 else BNULL
            assert decode(m(0, 1 << i)) == correct, "%d/4 bits:" % i

        # length == 3 mod 4: 2 bits of padding
        assert decode(m(0, 0, 0)) == BNULL * 2
        for i in range(6):
            if engine.big:  # 2 lsb are padding
                correct = BNULL if i < 2 else bchr(1 << (i - 2))
            else:  # 2 msg are padding
                correct = bchr(1 << (i + 4)) if i < 4 else BNULL
            assert decode(m(0, 0, 1 << i)) == BNULL + correct, "%d/2 bits:" % i

    def test_decode_bytes_bad(self):
        """test decode_bytes() with bad input"""
        engine = self.engine
        decode = engine.decode_bytes

        # wrong size (1 % 4)
        with pytest.raises(ValueError):
            decode(engine.bytemap[:5])

        # wrong char
        assert self.bad_byte not in engine.bytemap
        with pytest.raises(ValueError):
            decode(self.bad_byte * 4)

        # wrong type
        with pytest.raises(TypeError):
            decode(engine.charmap[:4])
        with pytest.raises(TypeError):
            decode(None)

    def test_codec(self):
        """test encode_bytes/decode_bytes against random data"""
        engine = self.engine
        from passlib.utils import getrandbytes, getrandstr

        rng = self.getRandom()
        saw_zero = False
        for i in range(500):
            #
            # test raw -> encode() -> decode() -> raw
            #

            # generate some random bytes
            size = rng.randint(1 if saw_zero else 0, 12)
            if not size:
                saw_zero = True
            enc_size = (4 * size + 2) // 3
            raw = getrandbytes(rng, size)

            # encode them, check invariants
            encoded = engine.encode_bytes(raw)
            assert len(encoded) == enc_size

            # make sure decode returns original
            result = engine.decode_bytes(encoded)
            assert result == raw

            #
            # test encoded -> decode() -> encode() -> encoded
            #

            # generate some random encoded data
            if size % 4 == 1:
                size += rng.choice([-1, 1, 2])
            raw_size = 3 * size // 4
            encoded = getrandstr(rng, engine.bytemap, size)

            # decode them, check invariants
            raw = engine.decode_bytes(encoded)
            assert len(raw) == raw_size, "encoded %d:" % size

            # make sure encode returns original (barring padding bits)
            result = engine.encode_bytes(raw)
            if size % 4:
                assert result[:-1] == encoded[:-1]
            else:
                assert result == encoded

    def test_repair_unused(self):
        """test repair_unused()"""
        # NOTE: this test relies on encode_bytes() always returning clear
        # padding bits - which should be ensured by test vectors.
        from passlib.utils import getrandstr

        rng = self.getRandom()
        engine = self.engine
        check_repair_unused = self.engine.check_repair_unused
        i = 0
        while i < 300:
            size = rng.randint(0, 23)
            cdata = getrandstr(rng, engine.charmap, size).encode("ascii")
            if size & 3 == 1:
                # should throw error
                with pytest.raises(ValueError):
                    check_repair_unused(cdata)
                continue
            rdata = engine.encode_bytes(engine.decode_bytes(cdata))
            if rng.random() < 0.5:
                cdata = cdata.decode("ascii")
                rdata = rdata.decode("ascii")
            if cdata == rdata:
                # should leave unchanged
                ok, result = check_repair_unused(cdata)
                assert not ok
                assert result == rdata
            else:
                # should repair bits
                assert size % 4 != 0
                ok, result = check_repair_unused(cdata)
                assert ok
                assert result == rdata
            i += 1

    # NOTE: these tests assume normal encode/decode has been tested elsewhere.

    transposed = [
        # orig, result, transpose map
        (b"\x33\x22\x11", b"\x11\x22\x33", [2, 1, 0]),
        (b"\x22\x33\x11", b"\x11\x22\x33", [1, 2, 0]),
    ]

    transposed_dups = [
        # orig, result, transpose projection
        (b"\x11\x11\x22", b"\x11\x22\x33", [0, 0, 1]),
    ]

    def test_encode_transposed_bytes(self):
        """test encode_transposed_bytes()"""
        engine = self.engine
        for result, input, offsets in self.transposed + self.transposed_dups:
            tmp = engine.encode_transposed_bytes(input, offsets)
            out = engine.decode_bytes(tmp)
            assert out == result

        with pytest.raises(TypeError):
            engine.encode_transposed_bytes("a", [])

    def test_decode_transposed_bytes(self):
        """test decode_transposed_bytes()"""
        engine = self.engine
        for input, result, offsets in self.transposed:
            tmp = engine.encode_bytes(input)
            out = engine.decode_transposed_bytes(tmp, offsets)
            assert out == result

    def test_decode_transposed_bytes_bad(self):
        """test decode_transposed_bytes() fails if map is a one-way"""
        engine = self.engine
        for input, _, offsets in self.transposed_dups:
            tmp = engine.encode_bytes(input)
            with pytest.raises(TypeError):
                engine.decode_transposed_bytes(tmp, offsets)

    def check_int_pair(self, bits, encoded_pairs):
        """helper to check encode_intXX & decode_intXX functions"""
        rng = self.getRandom()
        engine = self.engine
        encode = getattr(engine, f"encode_int{bits}")
        decode = getattr(engine, f"decode_int{bits}")
        pad = -bits % 6
        chars = (bits + pad) // 6
        upper = 1 << bits

        # test encode func
        for value, encoded in encoded_pairs:
            result = encode(value)
            assert isinstance(result, bytes)
            assert result == encoded
        with pytest.raises(ValueError):
            encode(-1)
        with pytest.raises(ValueError):
            encode(upper)

        # test decode func
        for value, encoded in encoded_pairs:
            assert decode(encoded) == value, f"encoded {encoded!r}:"
        m = self.m
        with pytest.raises(ValueError):
            decode(m(0) * (chars + 1))
        with pytest.raises(ValueError):
            decode(m(0) * (chars - 1))
        with pytest.raises(ValueError):
            decode(self.bad_byte * chars)
        with pytest.raises(TypeError):
            decode(engine.charmap[0])
        with pytest.raises(TypeError):
            decode(None)

        # do random testing.
        from passlib.utils import getrandstr

        for i in range(100):
            # generate random value, encode, and then decode
            value = rng.randint(0, upper - 1)
            encoded = encode(value)
            assert len(encoded) == chars
            assert decode(encoded) == value

            # generate some random encoded data, decode, then encode.
            encoded = getrandstr(rng, engine.bytemap, chars)
            value = decode(encoded)
            assert value >= 0, f"decode {encoded!r} out of bounds:"
            assert value < upper, f"decode {encoded!r} out of bounds:"
            result = encode(value)
            if pad:
                assert result[:-2] == encoded[:-2]
            else:
                assert result == encoded

    def test_int6(self):
        m = self.m
        self.check_int_pair(6, [(0, m(0)), (63, m(63))])

    def test_int12(self):
        engine = self.engine
        m = self.m
        self.check_int_pair(
            12,
            [
                (0, m(0, 0)),
                (63, m(0, 63) if engine.big else m(63, 0)),
                (0xFFF, m(63, 63)),
            ],
        )

    def test_int24(self):
        engine = self.engine
        m = self.m
        self.check_int_pair(
            24,
            [
                (0, m(0, 0, 0, 0)),
                (63, m(0, 0, 0, 63) if engine.big else m(63, 0, 0, 0)),
                (0xFFFFFF, m(63, 63, 63, 63)),
            ],
        )

    def test_int64(self):
        # NOTE: this isn't multiple of 6, it has 2 padding bits appended
        # before encoding.
        engine = self.engine
        m = self.m
        self.check_int_pair(
            64,
            [
                (0, m(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)),
                (
                    63,
                    m(0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 60)
                    if engine.big
                    else m(63, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
                ),
                (
                    (1 << 64) - 1,
                    m(63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 60)
                    if engine.big
                    else m(63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 15),
                ),
            ],
        )

    def test_encoded_ints(self):
        """test against reference integer encodings"""
        if not self.encoded_ints:
            raise self.skipTests("none defined for class")
        engine = self.engine
        for data, value, bits in self.encoded_ints:
            encode = getattr(engine, "encode_int%d" % bits)
            decode = getattr(engine, "decode_int%d" % bits)
            assert encode(value) == data
            assert decode(data) == value


class H64_Test(_Base64Test):
    """test H64 codec functions"""

    engine = h64
    descriptionPrefix = "h64 codec"

    encoded_data = [
        # test lengths 0..6 to ensure tail is encoded properly
        (b"", b""),
        (b"\x55", b"J/"),
        (b"\x55\xaa", b"Jd8"),
        (b"\x55\xaa\x55", b"JdOJ"),
        (b"\x55\xaa\x55\xaa", b"JdOJe0"),
        (b"\x55\xaa\x55\xaa\x55", b"JdOJeK3"),
        (b"\x55\xaa\x55\xaa\x55\xaa", b"JdOJeKZe"),
        # test padding bits are null
        (b"\x55\xaa\x55\xaf", b"JdOJj0"),  # len = 1 mod 3
        (b"\x55\xaa\x55\xaa\x5f", b"JdOJey3"),  # len = 2 mod 3
    ]

    encoded_ints = [
        (b"z.", 63, 12),
        (b".z", 4032, 12),
    ]


class H64Big_Test(_Base64Test):
    """test H64Big codec functions"""

    engine = h64big
    descriptionPrefix = "h64big codec"

    encoded_data = [
        # test lengths 0..6 to ensure tail is encoded properly
        (b"", b""),
        (b"\x55", b"JE"),
        (b"\x55\xaa", b"JOc"),
        (b"\x55\xaa\x55", b"JOdJ"),
        (b"\x55\xaa\x55\xaa", b"JOdJeU"),
        (b"\x55\xaa\x55\xaa\x55", b"JOdJeZI"),
        (b"\x55\xaa\x55\xaa\x55\xaa", b"JOdJeZKe"),
        # test padding bits are null
        (b"\x55\xaa\x55\xaf", b"JOdJfk"),  # len = 1 mod 3
        (b"\x55\xaa\x55\xaa\x5f", b"JOdJeZw"),  # len = 2 mod 3
    ]

    encoded_ints = [
        (b".z", 63, 12),
        (b"z.", 4032, 12),
    ]
