"""tests for passlib.util"""

from functools import partial
import warnings


from passlib.utils import is_ascii_safe, to_bytes
from passlib.utils.compat import join_bytes
from tests.utils import TestCase, hb, run_with_fixed_seeds

from passlib.utils.binary import h64, h64big


class MiscTest(TestCase):
    """tests various parts of utils module"""

    # NOTE: could test xor_bytes(), but it's exercised well enough by pbkdf2 test

    def test_compat(self):
        """test compat's lazymodule"""
        from passlib.utils import compat

        # "<module 'passlib.utils.compat' from 'passlib/utils/compat.pyc'>"
        self.assertRegex(repr(compat), r"^<module 'passlib.utils.compat' from '.*?'>$")

        # test synthentic dir()
        dir(compat)
        # FIXME: find another lazy-loaded attr to check, all current ones removed after py2 comapt gone.
        # self.assertTrue('UnicodeIO' in dir(compat))

    def test_classproperty(self):
        from passlib.utils.decor import classproperty

        def xprop_func(cls):
            return cls.xvar

        class test(object):
            xvar = 1

            xprop = classproperty(xprop_func)

        self.assertEqual(test.xprop, 1)

        prop = test.__dict__["xprop"]
        self.assertIs(prop.__func__, xprop_func)

    def test_deprecated_function(self):
        from passlib.utils.decor import deprecated_function
        # NOTE: not comprehensive, just tests the basic behavior

        @deprecated_function(deprecated="1.6", removed="1.8")
        def test_func(*args):
            """test docstring"""
            return args

        self.assertTrue(".. deprecated::" in test_func.__doc__)

        with self.assertWarningList(
            dict(
                category=DeprecationWarning,
                message="the function tests.test_utils.test_func() "
                "is deprecated as of Passlib 1.6, and will be "
                "removed in Passlib 1.8.",
            )
        ):
            self.assertEqual(test_func(1, 2), (1, 2))

    def test_memoized_property(self):
        from passlib.utils.decor import memoized_property

        class dummy(object):
            counter = 0

            @memoized_property
            def value(self):
                value = self.counter
                self.counter = value + 1
                return value

        d = dummy()
        self.assertEqual(d.value, 0)
        self.assertEqual(d.value, 0)
        self.assertEqual(d.counter, 1)

    def test_getrandbytes(self):
        """getrandbytes()"""
        from passlib.utils import getrandbytes

        wrapper = partial(getrandbytes, self.getRandom())
        self.assertEqual(len(wrapper(0)), 0)
        a = wrapper(10)
        b = wrapper(10)
        self.assertIsInstance(a, bytes)
        self.assertEqual(len(a), 10)
        self.assertEqual(len(b), 10)
        self.assertNotEqual(a, b)

    @run_with_fixed_seeds(count=1024)
    def test_getrandstr(self, seed):
        """getrandstr()"""
        from passlib.utils import getrandstr

        wrapper = partial(getrandstr, self.getRandom(seed=seed))

        # count 0
        self.assertEqual(wrapper("abc", 0), "")

        # count <0
        self.assertRaises(ValueError, wrapper, "abc", -1)

        # letters 0
        self.assertRaises(ValueError, wrapper, "", 0)

        # letters 1
        self.assertEqual(wrapper("a", 5), "aaaaa")

        # NOTE: the following parts are non-deterministic,
        #       with a small chance of failure (outside chance it may pick
        #       a string w/o one char, even more remote chance of picking
        #       same string).  to combat this, we run it against multiple
        #       fixed seeds (using run_with_fixed_seeds decorator),
        #       and hope that they're sufficient to test the range of behavior.

        # letters
        x = wrapper("abc", 32)
        y = wrapper("abc", 32)
        self.assertIsInstance(x, str)
        self.assertNotEqual(x, y)
        self.assertEqual(sorted(set(x)), ["a", "b", "c"])

        # bytes
        x = wrapper(b"abc", 32)
        y = wrapper(b"abc", 32)
        self.assertIsInstance(x, bytes)
        self.assertNotEqual(x, y)
        # NOTE: decoding this due to py3 bytes
        self.assertEqual(sorted(set(x.decode("ascii"))), ["a", "b", "c"])

    def test_generate_password(self):
        """generate_password()"""
        from passlib.utils import generate_password

        warnings.filterwarnings(
            "ignore", "The function.*generate_password\(\) is deprecated"
        )
        self.assertEqual(len(generate_password(15)), 15)

    def test_is_crypt_context(self):
        """test is_crypt_context()"""
        from passlib.utils import is_crypt_context
        from passlib.context import CryptContext

        cc = CryptContext(["des_crypt"])
        self.assertTrue(is_crypt_context(cc))
        self.assertFalse(not is_crypt_context(cc))

    def test_genseed(self):
        """test genseed()"""
        import random
        from passlib.utils import genseed

        rng = random.Random(genseed())
        a = rng.randint(0, 10**10)

        rng = random.Random(genseed())
        b = rng.randint(0, 10**10)

        self.assertNotEqual(a, b)

        rng.seed(genseed(rng))

    def test_crypt(self):
        """test crypt.crypt() wrappers"""
        from passlib.utils import has_crypt, safe_crypt, test_crypt
        from passlib.registry import get_supported_os_crypt_schemes, get_crypt_handler

        # test everything is disabled
        supported = get_supported_os_crypt_schemes()
        if not has_crypt:
            self.assertEqual(supported, ())
            self.assertEqual(safe_crypt("test", "aa"), None)
            self.assertFalse(
                test_crypt("test", "aaqPiZY5xR5l.")
            )  # des_crypt() hash of "test"
            raise self.skipTest("crypt.crypt() not available")

        # expect there to be something supported, if crypt() is present
        if not supported:
            # NOTE: failures here should be investigated.  usually means one of:
            # 1) at least one of passlib's os_crypt detection routines is giving false negative
            # 2) crypt() ONLY supports some hash alg which passlib doesn't know about
            # 3) crypt() is present but completely disabled (never encountered this yet)
            raise self.fail("crypt() present, but no supported schemes found!")

        # pick cheap alg if possible, with minimum rounds, to speed up this test.
        # NOTE: trusting hasher class works properly (should have been verified using it's own UTs)
        for scheme in ("md5_crypt", "sha256_crypt"):
            if scheme in supported:
                break
        else:
            scheme = supported[-1]
        hasher = get_crypt_handler(scheme)
        if getattr(hasher, "min_rounds", None):
            hasher = hasher.using(rounds=hasher.min_rounds)

        # helpers to generate hashes & config strings to work with
        def get_hash(secret):
            assert isinstance(secret, str)
            hash = hasher.hash(secret)
            if isinstance(hash, bytes):  # py2
                hash = hash.decode("utf-8")
            assert isinstance(hash, str)
            return hash

        # test ascii password & return type
        s1 = "test"
        h1 = get_hash(s1)
        result = safe_crypt(s1, h1)
        self.assertIsInstance(result, str)
        self.assertEqual(result, h1)
        self.assertEqual(safe_crypt(to_bytes(s1), to_bytes(h1)), h1)

        # make sure crypt doesn't just blindly return h1 for whatever we pass in
        h1x = h1[:-2] + "xx"
        self.assertEqual(safe_crypt(s1, h1x), h1)

        # test utf-8 / unicode password
        s2 = "test\u1234"
        h2 = get_hash(s2)
        self.assertEqual(safe_crypt(s2, h2), h2)
        self.assertEqual(safe_crypt(to_bytes(s2), to_bytes(h2)), h2)

        # test rejects null chars in password
        self.assertRaises(ValueError, safe_crypt, "\x00", h1)

        # check test_crypt()
        self.assertTrue(test_crypt("test", h1))
        self.assertFalse(test_crypt("test", h1x))

        # check crypt returning variant error indicators
        # some platforms return None on errors, others empty string,
        # The BSDs in some cases return ":"
        import passlib.utils as mod

        orig = mod._crypt
        try:
            retval = None
            mod._crypt = lambda secret, hash: retval

            for retval in [None, "", ":", ":0", "*0"]:
                self.assertEqual(safe_crypt("test", h1), None)
                self.assertFalse(test_crypt("test", h1))

            retval = "xxx"
            self.assertEqual(safe_crypt("test", h1), "xxx")
            self.assertFalse(test_crypt("test", h1))

        finally:
            mod._crypt = orig

    def test_consteq(self):
        """test consteq()"""
        # NOTE: this test is kind of over the top, but that's only because
        # this is used for the critical task of comparing hashes for equality.
        from passlib.utils import consteq, str_consteq

        # ensure error raises for wrong types
        self.assertRaises(TypeError, consteq, "", b"")
        self.assertRaises(TypeError, consteq, "", 1)
        self.assertRaises(TypeError, consteq, "", None)

        self.assertRaises(TypeError, consteq, b"", "")
        self.assertRaises(TypeError, consteq, b"", 1)
        self.assertRaises(TypeError, consteq, b"", None)

        self.assertRaises(TypeError, consteq, None, "")
        self.assertRaises(TypeError, consteq, None, b"")
        self.assertRaises(TypeError, consteq, 1, "")
        self.assertRaises(TypeError, consteq, 1, b"")

        def consteq_supports_string(value):
            # compare_digest() only supports ascii unicode strings.
            # confirmed for: cpython 3.4, pypy3, pyston
            return consteq is str_consteq or is_ascii_safe(value)

        # check equal inputs compare correctly
        for value in [
            "a",
            "abc",
            "\xff\xa2\x12\x00" * 10,
        ]:
            if consteq_supports_string(value):
                self.assertTrue(consteq(value, value), "value %r:" % (value,))
            else:
                self.assertRaises(TypeError, consteq, value, value)
            self.assertTrue(str_consteq(value, value), "value %r:" % (value,))

            value = value.encode("latin-1")
            self.assertTrue(consteq(value, value), "value %r:" % (value,))

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
            if consteq_supports_string(left) and consteq_supports_string(right):
                self.assertFalse(consteq(left, right), "values %r %r:" % (left, right))
                self.assertFalse(consteq(right, left), "values %r %r:" % (right, left))
            else:
                self.assertRaises(TypeError, consteq, left, right)
                self.assertRaises(TypeError, consteq, right, left)
            self.assertFalse(str_consteq(left, right), "values %r %r:" % (left, right))
            self.assertFalse(str_consteq(right, left), "values %r %r:" % (right, left))

            left = left.encode("latin-1")
            right = right.encode("latin-1")
            self.assertFalse(consteq(left, right), "values %r %r:" % (left, right))
            self.assertFalse(consteq(right, left), "values %r %r:" % (right, left))

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
        self.assertRaises(TypeError, sp, None)
        self.assertRaises(TypeError, sp, 1)
        self.assertRaises(TypeError, sp, b"")

        # empty strings
        self.assertEqual(sp(""), "")
        self.assertEqual(sp("\u00ad"), "")

        # verify B.1 chars are stripped,
        self.assertEqual(sp("$\u00ad$\u200d$"), "$$$")

        # verify C.1.2 chars are replaced with space
        self.assertEqual(sp("$ $\u00a0$\u3000$"), "$ $ $ $")

        # verify normalization to KC
        self.assertEqual(sp("a\u0300"), "\u00e0")
        self.assertEqual(sp("\u00e0"), "\u00e0")

        # verify various forbidden characters
        # control chars
        self.assertRaises(ValueError, sp, "\u0000")
        self.assertRaises(ValueError, sp, "\u007f")
        self.assertRaises(ValueError, sp, "\u180e")
        self.assertRaises(ValueError, sp, "\ufff9")
        # private use
        self.assertRaises(ValueError, sp, "\ue000")
        # non-characters
        self.assertRaises(ValueError, sp, "\ufdd0")
        # surrogates
        self.assertRaises(ValueError, sp, "\ud800")
        # non-plaintext chars
        self.assertRaises(ValueError, sp, "\ufffd")
        # non-canon
        self.assertRaises(ValueError, sp, "\u2ff0")
        # change display properties
        self.assertRaises(ValueError, sp, "\u200e")
        self.assertRaises(ValueError, sp, "\u206f")
        # unassigned code points (as of unicode 3.2)
        self.assertRaises(ValueError, sp, "\u0900")
        self.assertRaises(ValueError, sp, "\ufff8")
        # tagging characters
        self.assertRaises(ValueError, sp, "\U000e0001")

        # verify bidi behavior
        # if starts with R/AL -- must end with R/AL
        self.assertRaises(ValueError, sp, "\u0627\u0031")
        self.assertEqual(sp("\u0627"), "\u0627")
        self.assertEqual(sp("\u0627\u0628"), "\u0627\u0628")
        self.assertEqual(sp("\u0627\u0031\u0628"), "\u0627\u0031\u0628")
        # if starts with R/AL --  cannot contain L
        self.assertRaises(ValueError, sp, "\u0627\u0041\u0628")
        # if doesn't start with R/AL -- can contain R/AL, but L & EN allowed
        self.assertRaises(ValueError, sp, "x\u0627z")
        self.assertEqual(sp("x\u0041z"), "x\u0041z")

        # ------------------------------------------------------
        # examples pulled from external sources, to be thorough
        # ------------------------------------------------------

        # rfc 4031 section 3 examples
        self.assertEqual(sp("I\u00adX"), "IX")  # strip SHY
        self.assertEqual(sp("user"), "user")  # unchanged
        self.assertEqual(sp("USER"), "USER")  # case preserved
        self.assertEqual(sp("\u00aa"), "a")  # normalize to KC form
        self.assertEqual(sp("\u2168"), "IX")  # normalize to KC form
        self.assertRaises(ValueError, sp, "\u0007")  # forbid control chars
        self.assertRaises(ValueError, sp, "\u0627\u0031")  # invalid bidi

        # rfc 3454 section 6 examples
        # starts with RAL char, must end with RAL char
        self.assertRaises(ValueError, sp, "\u0627\u0031")
        self.assertEqual(sp("\u0627\u0031\u0628"), "\u0627\u0031\u0628")

    def test_splitcomma(self):
        from passlib.utils import splitcomma

        self.assertEqual(splitcomma(""), [])
        self.assertEqual(splitcomma(","), [])
        self.assertEqual(splitcomma("a"), ["a"])
        self.assertEqual(splitcomma(" a , "), ["a"])
        self.assertEqual(splitcomma(" a , b"), ["a", "b"])
        self.assertEqual(splitcomma(" a, b, "), ["a", "b"])

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
                prefix = "source=%r index=%r: " % (source, idx)

                result = utf8_truncate(source, idx)

                # result should always be valid utf-8
                result.decode("utf-8")

                # result should never be larger than source
                self.assertLessEqual(len(result), end, msg=prefix)

                # result should always be in range(idx, idx+4)
                self.assertGreaterEqual(len(result), min(idx, end), msg=prefix)
                self.assertLess(len(result), min(idx + 4, end + 1), msg=prefix)

                # should be strict prefix of source
                self.assertEqual(result, source[: len(result)], msg=prefix)

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
                prefix = "source=%r index=%r: " % (source, idx)
                result = utf8_truncate(source, idx)
                self.assertEqual(result, source[:idx], msg=prefix)

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
                prefix = "source=%r index=%r: " % (source, idx)
                result = utf8_truncate(source, idx)
                self.assertEqual(result, source[: idx + 3], msg=prefix)

        #
        # string w/ some invalid utf8 --
        # * \xaa byte is too many continuation byte after \xff start byte
        # * \xab byte doesn't have preceding start byte
        # XXX: could also test continuation bytes w/o start byte, WITHIN the string.
        #      but think this covers edges well enough...
        #
        source = b"MN\xff\xa0\xa1\xa2\xaaOP\xab"

        self.assertEqual(utf8_truncate(source, 0), b"")  # index="M", stops there

        self.assertEqual(utf8_truncate(source, 1), b"M")  # index="N", stops there

        self.assertEqual(utf8_truncate(source, 2), b"MN")  # index="\xff", stops there

        self.assertEqual(
            utf8_truncate(source, 3), b"MN\xff\xa0\xa1\xa2"
        )  # index="\xa0", runs out after index+3="\xa2"

        self.assertEqual(
            utf8_truncate(source, 4), b"MN\xff\xa0\xa1\xa2\xaa"
        )  # index="\xa1", runs out after index+3="\xaa"

        self.assertEqual(
            utf8_truncate(source, 5), b"MN\xff\xa0\xa1\xa2\xaa"
        )  # index="\xa2", stops before "O"

        self.assertEqual(
            utf8_truncate(source, 6), b"MN\xff\xa0\xa1\xa2\xaa"
        )  # index="\xaa", stops before "O"

        self.assertEqual(
            utf8_truncate(source, 7), b"MN\xff\xa0\xa1\xa2\xaa"
        )  # index="O", stops there

        self.assertEqual(
            utf8_truncate(source, 8), b"MN\xff\xa0\xa1\xa2\xaaO"
        )  # index="P", stops there

        self.assertEqual(
            utf8_truncate(source, 9), b"MN\xff\xa0\xa1\xa2\xaaOP\xab"
        )  # index="\xab", runs out at end

        self.assertEqual(
            utf8_truncate(source, 10), b"MN\xff\xa0\xa1\xa2\xaaOP\xab"
        )  # index=end

        self.assertEqual(
            utf8_truncate(source, 11), b"MN\xff\xa0\xa1\xa2\xaaOP\xab"
        )  # index=end+1


# =============================================================================
# byte/unicode helpers
# =============================================================================
class CodecTest(TestCase):
    """tests bytes/unicode helpers in passlib.utils"""

    def test_bytes(self):
        """test b() helper, bytes and native str type"""
        import builtins

        self.assertIs(bytes, builtins.bytes)

        self.assertIsInstance(b"", bytes)
        self.assertIsInstance(b"\x00\xff", bytes)
        self.assertEqual(b"\x00\xff".decode("latin-1"), "\x00\xff")

    def test_to_bytes(self):
        """test to_bytes()"""
        from passlib.utils import to_bytes

        # check unicode inputs
        self.assertEqual(to_bytes("abc"), b"abc")
        self.assertEqual(to_bytes("\x00\xff"), b"\x00\xc3\xbf")

        # check unicode w/ encodings
        self.assertEqual(to_bytes("\x00\xff", "latin-1"), b"\x00\xff")
        self.assertRaises(ValueError, to_bytes, "\x00\xff", "ascii")

        # check bytes inputs
        self.assertEqual(to_bytes(b"abc"), b"abc")
        self.assertEqual(to_bytes(b"\x00\xff"), b"\x00\xff")
        self.assertEqual(to_bytes(b"\x00\xc3\xbf"), b"\x00\xc3\xbf")

        # check byte inputs ignores enocding
        self.assertEqual(to_bytes(b"\x00\xc3\xbf", "latin-1"), b"\x00\xc3\xbf")

        # check bytes transcoding
        self.assertEqual(to_bytes(b"\x00\xc3\xbf", "latin-1", "", "utf-8"), b"\x00\xff")

        # check other
        self.assertRaises(AssertionError, to_bytes, "abc", None)
        self.assertRaises(TypeError, to_bytes, None)

    def test_to_unicode(self):
        """test to_unicode()"""
        from passlib.utils import to_unicode

        # check unicode inputs
        self.assertEqual(to_unicode("abc"), "abc")
        self.assertEqual(to_unicode("\x00\xff"), "\x00\xff")

        # check unicode input ignores encoding
        self.assertEqual(to_unicode("\x00\xff", "ascii"), "\x00\xff")

        # check bytes input
        self.assertEqual(to_unicode(b"abc"), "abc")
        self.assertEqual(to_unicode(b"\x00\xc3\xbf"), "\x00\xff")
        self.assertEqual(to_unicode(b"\x00\xff", "latin-1"), "\x00\xff")
        self.assertRaises(ValueError, to_unicode, b"\x00\xff")

        # check other
        self.assertRaises(AssertionError, to_unicode, "abc", None)
        self.assertRaises(TypeError, to_unicode, None)

    def test_to_native_str(self):
        """test to_native_str()"""
        from passlib.utils import to_native_str

        # test plain ascii
        self.assertEqual(to_native_str("abc", "ascii"), "abc")
        self.assertEqual(to_native_str(b"abc", "ascii"), "abc")

        # test invalid ascii
        self.assertEqual(to_native_str("\xe0", "ascii"), "\xe0")
        self.assertRaises(UnicodeDecodeError, to_native_str, b"\xc3\xa0", "ascii")

        # test latin-1
        self.assertEqual(to_native_str("\xe0", "latin-1"), "\xe0")
        self.assertEqual(to_native_str(b"\xe0", "latin-1"), "\xe0")

        # test utf-8
        self.assertEqual(to_native_str("\xe0", "utf-8"), "\xe0")
        self.assertEqual(to_native_str(b"\xc3\xa0", "utf-8"), "\xe0")

        # other types rejected
        self.assertRaises(TypeError, to_native_str, None, "ascii")

    def test_is_ascii_safe(self):
        """test is_ascii_safe()"""
        from passlib.utils import is_ascii_safe

        self.assertTrue(is_ascii_safe(b"\x00abc\x7f"))
        self.assertTrue(is_ascii_safe("\x00abc\x7f"))
        self.assertFalse(is_ascii_safe(b"\x00abc\x80"))
        self.assertFalse(is_ascii_safe("\x00abc\x80"))

    def test_is_same_codec(self):
        """test is_same_codec()"""
        from passlib.utils import is_same_codec

        self.assertTrue(is_same_codec(None, None))
        self.assertFalse(is_same_codec(None, "ascii"))

        self.assertTrue(is_same_codec("ascii", "ascii"))
        self.assertTrue(is_same_codec("ascii", "ASCII"))

        self.assertTrue(is_same_codec("utf-8", "utf-8"))
        self.assertTrue(is_same_codec("utf-8", "utf8"))
        self.assertTrue(is_same_codec("utf-8", "UTF_8"))

        self.assertFalse(is_same_codec("ascii", "utf-8"))


# =============================================================================
# base64engine
# =============================================================================
class Base64EngineTest(TestCase):
    """test standalone parts of Base64Engine"""

    # NOTE: most Base64Engine testing done via _Base64Test subclasses below.

    def test_constructor(self):
        from passlib.utils.binary import Base64Engine, AB64_CHARS

        # bad charmap type
        self.assertRaises(TypeError, Base64Engine, 1)

        # bad charmap size
        self.assertRaises(ValueError, Base64Engine, AB64_CHARS[:-1])

        # dup charmap letter
        self.assertRaises(ValueError, Base64Engine, AB64_CHARS[:-1] + "A")

    def test_ab64_decode(self):
        """ab64_decode()"""
        from passlib.utils.binary import ab64_decode

        # accept bytes or unicode
        self.assertEqual(ab64_decode(b"abc"), hb("69b7"))
        self.assertEqual(ab64_decode("abc"), hb("69b7"))

        # reject non-ascii unicode
        self.assertRaises(ValueError, ab64_decode, "ab\xff")

        # underlying a2b_ascii treats non-base64 chars as "Incorrect padding"
        self.assertRaises(TypeError, ab64_decode, b"ab\xff")
        self.assertRaises(TypeError, ab64_decode, b"ab!")
        self.assertRaises(TypeError, ab64_decode, "ab!")

        # insert correct padding, handle dirty padding bits
        self.assertEqual(ab64_decode(b"abcd"), hb("69b71d"))  # 0 mod 4
        self.assertRaises(ValueError, ab64_decode, b"abcde")  # 1 mod 4
        self.assertEqual(
            ab64_decode(b"abcdef"), hb("69b71d79")
        )  # 2 mod 4, dirty padding bits
        self.assertEqual(
            ab64_decode(b"abcdeQ"), hb("69b71d79")
        )  # 2 mod 4, clean padding bits
        self.assertEqual(
            ab64_decode(b"abcdefg"), hb("69b71d79f8")
        )  # 3 mod 4, clean padding bits

        # support "./" or "+/" altchars
        # (lets us transition to "+/" representation, merge w/ b64s_decode)
        self.assertEqual(ab64_decode(b"ab+/"), hb("69bfbf"))
        self.assertEqual(ab64_decode(b"ab./"), hb("69bfbf"))

    def test_ab64_encode(self):
        """ab64_encode()"""
        from passlib.utils.binary import ab64_encode

        # accept bytes
        self.assertEqual(ab64_encode(hb("69b7")), b"abc")

        # reject unicode
        self.assertRaises(TypeError, ab64_encode, hb("69b7").decode("latin-1"))

        # insert correct padding before decoding
        self.assertEqual(ab64_encode(hb("69b71d")), b"abcd")  # 0 mod 4
        self.assertEqual(ab64_encode(hb("69b71d79")), b"abcdeQ")  # 2 mod 4
        self.assertEqual(ab64_encode(hb("69b71d79f8")), b"abcdefg")  # 3 mod 4

        # output "./" altchars
        self.assertEqual(ab64_encode(hb("69bfbf")), b"ab./")

    def test_b64s_decode(self):
        """b64s_decode()"""
        from passlib.utils.binary import b64s_decode

        # accept bytes or unicode
        self.assertEqual(b64s_decode(b"abc"), hb("69b7"))
        self.assertEqual(b64s_decode("abc"), hb("69b7"))

        # reject non-ascii unicode
        self.assertRaises(ValueError, b64s_decode, "ab\xff")

        # underlying a2b_ascii treats non-base64 chars as "Incorrect padding"
        self.assertRaises(TypeError, b64s_decode, b"ab\xff")
        self.assertRaises(TypeError, b64s_decode, b"ab!")
        self.assertRaises(TypeError, b64s_decode, "ab!")

        # insert correct padding, handle dirty padding bits
        self.assertEqual(b64s_decode(b"abcd"), hb("69b71d"))  # 0 mod 4
        self.assertRaises(ValueError, b64s_decode, b"abcde")  # 1 mod 4
        self.assertEqual(
            b64s_decode(b"abcdef"), hb("69b71d79")
        )  # 2 mod 4, dirty padding bits
        self.assertEqual(
            b64s_decode(b"abcdeQ"), hb("69b71d79")
        )  # 2 mod 4, clean padding bits
        self.assertEqual(
            b64s_decode(b"abcdefg"), hb("69b71d79f8")
        )  # 3 mod 4, clean padding bits

    def test_b64s_encode(self):
        """b64s_encode()"""
        from passlib.utils.binary import b64s_encode

        # accept bytes
        self.assertEqual(b64s_encode(hb("69b7")), b"abc")

        # reject unicode
        self.assertRaises(TypeError, b64s_encode, hb("69b7").decode("latin-1"))

        # insert correct padding before decoding
        self.assertEqual(b64s_encode(hb("69b71d")), b"abcd")  # 0 mod 4
        self.assertEqual(b64s_encode(hb("69b71d79")), b"abcdeQ")  # 2 mod 4
        self.assertEqual(b64s_encode(hb("69b71d79f8")), b"abcdefg")  # 3 mod 4

        # output "+/" altchars
        self.assertEqual(b64s_encode(hb("69bfbf")), b"ab+/")


class _Base64Test(TestCase):
    """common tests for all Base64Engine instances"""

    # ===================================================================
    # class attrs
    # ===================================================================

    # Base64Engine instance to test
    engine = None

    # pairs of (raw, encoded) bytes to test - should encode/decode correctly
    encoded_data = None

    # tuples of (encoded, value, bits) for known integer encodings
    encoded_ints = None

    # invalid encoded byte
    bad_byte = b"?"

    # helper to generate bytemap-specific strings
    def m(self, *offsets):
        """generate byte string from offsets"""
        return join_bytes(self.engine.bytemap[o : o + 1] for o in offsets)

    # ===================================================================
    # test encode_bytes
    # ===================================================================
    def test_encode_bytes(self):
        """test encode_bytes() against reference inputs"""
        engine = self.engine
        encode = engine.encode_bytes
        for raw, encoded in self.encoded_data:
            result = encode(raw)
            self.assertEqual(result, encoded, "encode %r:" % (raw,))

    def test_encode_bytes_bad(self):
        """test encode_bytes() with bad input"""
        engine = self.engine
        encode = engine.encode_bytes
        self.assertRaises(TypeError, encode, "\x00")
        self.assertRaises(TypeError, encode, None)

    # ===================================================================
    # test decode_bytes
    # ===================================================================
    def test_decode_bytes(self):
        """test decode_bytes() against reference inputs"""
        engine = self.engine
        decode = engine.decode_bytes
        for raw, encoded in self.encoded_data:
            result = decode(encoded)
            self.assertEqual(result, raw, "decode %r:" % (encoded,))

    def test_decode_bytes_padding(self):
        """test decode_bytes() ignores padding bits"""
        bchr = lambda v: bytes([v])  # noqa: E731
        engine = self.engine
        m = self.m
        decode = engine.decode_bytes
        BNULL = b"\x00"

        # length == 2 mod 4: 4 bits of padding
        self.assertEqual(decode(m(0, 0)), BNULL)
        for i in range(0, 6):
            if engine.big:  # 4 lsb padding
                correct = BNULL if i < 4 else bchr(1 << (i - 4))
            else:  # 4 msb padding
                correct = bchr(1 << (i + 6)) if i < 2 else BNULL
            self.assertEqual(decode(m(0, 1 << i)), correct, "%d/4 bits:" % i)

        # length == 3 mod 4: 2 bits of padding
        self.assertEqual(decode(m(0, 0, 0)), BNULL * 2)
        for i in range(0, 6):
            if engine.big:  # 2 lsb are padding
                correct = BNULL if i < 2 else bchr(1 << (i - 2))
            else:  # 2 msg are padding
                correct = bchr(1 << (i + 4)) if i < 4 else BNULL
            self.assertEqual(decode(m(0, 0, 1 << i)), BNULL + correct, "%d/2 bits:" % i)

    def test_decode_bytes_bad(self):
        """test decode_bytes() with bad input"""
        engine = self.engine
        decode = engine.decode_bytes

        # wrong size (1 % 4)
        self.assertRaises(ValueError, decode, engine.bytemap[:5])

        # wrong char
        self.assertTrue(self.bad_byte not in engine.bytemap)
        self.assertRaises(ValueError, decode, self.bad_byte * 4)

        # wrong type
        self.assertRaises(TypeError, decode, engine.charmap[:4])
        self.assertRaises(TypeError, decode, None)

    # ===================================================================
    # encode_bytes+decode_bytes
    # ===================================================================
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
            self.assertEqual(len(encoded), enc_size)

            # make sure decode returns original
            result = engine.decode_bytes(encoded)
            self.assertEqual(result, raw)

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
            self.assertEqual(len(raw), raw_size, "encoded %d:" % size)

            # make sure encode returns original (barring padding bits)
            result = engine.encode_bytes(raw)
            if size % 4:
                self.assertEqual(result[:-1], encoded[:-1])
            else:
                self.assertEqual(result, encoded)

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
                self.assertRaises(ValueError, check_repair_unused, cdata)
                continue
            rdata = engine.encode_bytes(engine.decode_bytes(cdata))
            if rng.random() < 0.5:
                cdata = cdata.decode("ascii")
                rdata = rdata.decode("ascii")
            if cdata == rdata:
                # should leave unchanged
                ok, result = check_repair_unused(cdata)
                self.assertFalse(ok)
                self.assertEqual(result, rdata)
            else:
                # should repair bits
                self.assertNotEqual(size % 4, 0)
                ok, result = check_repair_unused(cdata)
                self.assertTrue(ok)
                self.assertEqual(result, rdata)
            i += 1

    # ===================================================================
    # test transposed encode/decode - encoding independant
    # ===================================================================
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
            self.assertEqual(out, result)

        self.assertRaises(TypeError, engine.encode_transposed_bytes, "a", [])

    def test_decode_transposed_bytes(self):
        """test decode_transposed_bytes()"""
        engine = self.engine
        for input, result, offsets in self.transposed:
            tmp = engine.encode_bytes(input)
            out = engine.decode_transposed_bytes(tmp, offsets)
            self.assertEqual(out, result)

    def test_decode_transposed_bytes_bad(self):
        """test decode_transposed_bytes() fails if map is a one-way"""
        engine = self.engine
        for input, _, offsets in self.transposed_dups:
            tmp = engine.encode_bytes(input)
            self.assertRaises(TypeError, engine.decode_transposed_bytes, tmp, offsets)

    # ===================================================================
    # test 6bit handling
    # ===================================================================
    def check_int_pair(self, bits, encoded_pairs):
        """helper to check encode_intXX & decode_intXX functions"""
        rng = self.getRandom()
        engine = self.engine
        encode = getattr(engine, "encode_int%s" % bits)
        decode = getattr(engine, "decode_int%s" % bits)
        pad = -bits % 6
        chars = (bits + pad) // 6
        upper = 1 << bits

        # test encode func
        for value, encoded in encoded_pairs:
            result = encode(value)
            self.assertIsInstance(result, bytes)
            self.assertEqual(result, encoded)
        self.assertRaises(ValueError, encode, -1)
        self.assertRaises(ValueError, encode, upper)

        # test decode func
        for value, encoded in encoded_pairs:
            self.assertEqual(decode(encoded), value, "encoded %r:" % (encoded,))
        m = self.m
        self.assertRaises(ValueError, decode, m(0) * (chars + 1))
        self.assertRaises(ValueError, decode, m(0) * (chars - 1))
        self.assertRaises(ValueError, decode, self.bad_byte * chars)
        self.assertRaises(TypeError, decode, engine.charmap[0])
        self.assertRaises(TypeError, decode, None)

        # do random testing.
        from passlib.utils import getrandstr

        for i in range(100):
            # generate random value, encode, and then decode
            value = rng.randint(0, upper - 1)
            encoded = encode(value)
            self.assertEqual(len(encoded), chars)
            self.assertEqual(decode(encoded), value)

            # generate some random encoded data, decode, then encode.
            encoded = getrandstr(rng, engine.bytemap, chars)
            value = decode(encoded)
            self.assertGreaterEqual(value, 0, "decode %r out of bounds:" % encoded)
            self.assertLess(value, upper, "decode %r out of bounds:" % encoded)
            result = encode(value)
            if pad:
                self.assertEqual(result[:-2], encoded[:-2])
            else:
                self.assertEqual(result, encoded)

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
            self.assertEqual(encode(value), data)
            self.assertEqual(decode(data), value)


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


# =============================================================================
# eof
# =============================================================================
