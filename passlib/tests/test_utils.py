"""tests for passlib.util"""
#=========================================================
#imports
#=========================================================
from __future__ import with_statement
#core
from binascii import hexlify, unhexlify
import sys
import random
import warnings
#site
#pkg
#module
from passlib.utils.compat import b, bytes, bascii_to_str, irange, PY2, PY3, u, \
                                 unicode
from passlib.tests.utils import TestCase, Params as ak, enable_option, catch_warnings

def hb(source):
    return unhexlify(b(source))

#=========================================================
#byte funcs
#=========================================================
class MiscTest(TestCase):
    "tests various parts of utils module"

    #NOTE: could test xor_bytes(), but it's exercised well enough by pbkdf2 test

    def test_getrandbytes(self):
        "test getrandbytes()"
        from passlib.utils import getrandbytes, rng
        def f(*a,**k):
            return getrandbytes(rng, *a, **k)
        self.assertEqual(len(f(0)), 0)
        a = f(10)
        b = f(10)
        self.assertIsInstance(a, bytes)
        self.assertEqual(len(a), 10)
        self.assertEqual(len(b), 10)
        self.assertNotEqual(a, b)

    def test_getrandstr(self):
        "test getrandstr()"
        from passlib.utils import getrandstr, rng
        def f(*a,**k):
            return getrandstr(rng, *a, **k)

        #count 0
        self.assertEqual(f('abc',0), '')

        #count <0
        self.assertRaises(ValueError, f, 'abc', -1)

        #letters 0
        self.assertRaises(ValueError, f, '', 0)

        #letters 1
        self.assertEqual(f('a',5), 'aaaaa')

        #letters
        x = f(u('abc'), 16)
        y = f(u('abc'), 16)
        self.assertIsInstance(x, unicode)
        self.assertNotEqual(x,y)
        self.assertEqual(sorted(set(x)), [u('a'),u('b'),u('c')])

        #bytes
        x = f(b('abc'), 16)
        y = f(b('abc'), 16)
        self.assertIsInstance(x, bytes)
        self.assertNotEqual(x,y)
        #NOTE: decoding this due to py3 bytes
        self.assertEqual(sorted(set(x.decode("ascii"))), [u('a'),u('b'),u('c')])

        #generate_password
        from passlib.utils import generate_password
        self.assertEqual(len(generate_password(15)), 15)

    def test_is_crypt_context(self):
        "test is_crypt_context()"
        from passlib.utils import is_crypt_context
        from passlib.context import CryptContext
        cc = CryptContext(["des_crypt"])
        self.assertTrue(is_crypt_context(cc))
        self.assertFalse(not is_crypt_context(cc))

    def test_genseed(self):
        "test genseed()"
        import random
        from passlib.utils import genseed
        rng = random.Random(genseed())
        a = rng.randint(0, 100000)

        rng = random.Random(genseed())
        b = rng.randint(0, 100000)

        self.assertNotEqual(a,b)

        rng.seed(genseed(rng))

    def test_safe_os_crypt(self):
        "test safe_os_crypt() wrapper"
        from passlib.utils import safe_os_crypt

        if not safe_os_crypt:
            raise self.skipTest("stdlib crypt module not available")

        #NOTE: this is assuming EVERY crypt will support des_crypt.
        #      if this fails on some platform, this test will need modifying.

        #test normal case
        ok, hash = safe_os_crypt(u('test'), u('aa'))
        self.assertTrue(ok)
        self.assertIsInstance(hash, unicode)
        self.assertEqual(hash, u('aaqPiZY5xR5l.'))

        #test hash-as-bytes
        self.assertRaises(TypeError, safe_os_crypt, u('test'), b('aa'))

        #test password as ascii
        ret = safe_os_crypt(b('test'), u('aa'))
        self.assertEqual(ret, (True, u('aaqPiZY5xR5l.')))

        #test unicode password w/ high char
        ret = safe_os_crypt(u('test\u1234'), u('aa'))
        self.assertEqual(ret, (True, u('aahWwbrUsKZk.')))

        #test utf-8 password w/ high char
        ret = safe_os_crypt(b('test\xe1\x88\xb4'), u('aa'))
        self.assertEqual(ret, (True, u('aahWwbrUsKZk.')))

        #test latin-1 password
        ret = safe_os_crypt(b('test\xff'), u('aa'))
        if PY3:
            self.assertEqual(ret, (False, None))
        else:
            self.assertEqual(ret, (True, u('aaOx.5nbTU/.M')))

        # test safe_os_crypt() handles os_crypt() returning None
        # (Python's Modules/_cryptmodule.c notes some platforms may do this
        # when algorithm is not supported)
        import passlib.utils as mod
        orig = mod.os_crypt
        try:
            mod.os_crypt = lambda secret, hash: None
            self.assertEqual(safe_os_crypt(u('test'), u('aa')), (False,None))
        finally:
            mod.os_crypt = orig

    def test_consteq(self):
        "test consteq()"
        # NOTE: this test is kind of over the top, but that's only because
        # this is used for the critical task of comparing hashes for equality.
        from passlib.utils import consteq

        # ensure error raises for wrong types
        self.assertRaises(TypeError, consteq, u(''), b(''))
        self.assertRaises(TypeError, consteq, u(''), 1)
        self.assertRaises(TypeError, consteq, u(''), None)

        self.assertRaises(TypeError, consteq, b(''), u(''))
        self.assertRaises(TypeError, consteq, b(''), 1)
        self.assertRaises(TypeError, consteq, b(''), None)

        self.assertRaises(TypeError, consteq, None, u(''))
        self.assertRaises(TypeError, consteq, None, b(''))
        self.assertRaises(TypeError, consteq, 1, u(''))
        self.assertRaises(TypeError, consteq, 1, b(''))

        # check equal inputs compare correctly
        for value in [
                u("a"),
                u("abc"),
                u("\xff\xa2\x12\x00")*10,
            ]:
            self.assertTrue(consteq(value, value), "value %r:" % (value,))
            value = value.encode("latin-1")
            self.assertTrue(consteq(value, value), "value %r:" % (value,))

        # check non-equal inputs compare correctly
        for l,r in [
                # check same-size comparisons with differing contents fail.
                (u("a"),         u("c")),
                (u("abcabc"),    u("zbaabc")),
                (u("abcabc"),    u("abzabc")),
                (u("abcabc"),    u("abcabz")),
                ((u("\xff\xa2\x12\x00")*10)[:-1] + u("\x01"),
                    u("\xff\xa2\x12\x00")*10),

                # check different-size comparisons fail.
                (u(""),       u("a")),
                (u("abc"),    u("abcdef")),
                (u("abc"),    u("defabc")),
                (u("qwertyuiopasdfghjklzxcvbnm"), u("abc")),
            ]:
            self.assertFalse(consteq(l, r), "values %r %r:" % (l,r))
            self.assertFalse(consteq(r, l), "values %r %r:" % (r,l))
            l = l.encode("latin-1")
            r = r.encode("latin-1")
            self.assertFalse(consteq(l, r), "values %r %r:" % (l,r))
            self.assertFalse(consteq(r, l), "values %r %r:" % (r,l))

        # TODO: add some tests to ensure we take THETA(strlen) time.
        # this might be hard to do reproducably.
        # NOTE: below code was used to generate stats for analysis
        ##from math import log as logb
        ##import timeit
        ##multipliers = [ 1<<s for s in irange(9)]
        ##correct =   u"abcdefgh"*(1<<4)
        ##incorrect = u"abcdxfgh"
        ##print
        ##first = True
        ##for run in irange(1):
        ##    times = []
        ##    chars = []
        ##    for m in multipliers:
        ##        supplied = incorrect * m
        ##        def test():
        ##            self.assertFalse(consteq(supplied,correct))
        ##            #self.assertFalse(supplied == correct)
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
        "test saslprep() unicode normalizer"
        from passlib.utils import saslprep as sp

        # invalid types
        self.assertRaises(TypeError, sp, None)
        self.assertRaises(TypeError, sp, 1)
        self.assertRaises(TypeError, sp, b(''))

        # empty strings
        self.assertEqual(sp(u('')), u(''))
        self.assertEqual(sp(u('\u00AD')), u(''))

        # verify B.1 chars are stripped,
        self.assertEqual(sp(u("$\u00AD$\u200D$")), u("$$$"))

        # verify C.1.2 chars are replaced with space
        self.assertEqual(sp(u("$ $\u00A0$\u3000$")), u("$ $ $ $"))

        # verify normalization to KC
        self.assertEqual(sp(u("a\u0300")), u("\u00E0"))
        self.assertEqual(sp(u("\u00E0")), u("\u00E0"))

        # verify various forbidden characters
            # control chars
        self.assertRaises(ValueError, sp, u("\u0000"))
        self.assertRaises(ValueError, sp, u("\u007F"))
        self.assertRaises(ValueError, sp, u("\u180E"))
        self.assertRaises(ValueError, sp, u("\uFFF9"))
            # private use
        self.assertRaises(ValueError, sp, u("\uE000"))
            # non-characters
        self.assertRaises(ValueError, sp, u("\uFDD0"))
            # surrogates
        self.assertRaises(ValueError, sp, u("\uD800"))
            # non-plaintext chars
        self.assertRaises(ValueError, sp, u("\uFFFD"))
            # non-canon
        self.assertRaises(ValueError, sp, u("\u2FF0"))
            # change display properties
        self.assertRaises(ValueError, sp, u("\u200E"))
        self.assertRaises(ValueError, sp, u("\u206F"))
            # unassigned code points (as of unicode 3.2)
        self.assertRaises(ValueError, sp, u("\u0900"))
        self.assertRaises(ValueError, sp, u("\uFFF8"))

        # verify bidi behavior
            # if starts with R/AL -- must end with R/AL
        self.assertRaises(ValueError, sp, u("\u0627\u0031"))
        self.assertEqual(sp(u("\u0627")), u("\u0627"))
        self.assertEqual(sp(u("\u0627\u0628")), u("\u0627\u0628"))
        self.assertEqual(sp(u("\u0627\u0031\u0628")), u("\u0627\u0031\u0628"))
            # if starts with R/AL --  cannot contain L
        self.assertRaises(ValueError, sp, u("\u0627\u0041\u0628"))
            # if doesn't start with R/AL -- can contain R/AL, but L & EN allowed
        self.assertRaises(ValueError, sp, u("x\u0627z"))
        self.assertEqual(sp(u("x\u0041z")), u("x\u0041z"))

        #------------------------------------------------------
        # examples pulled from external sources, to be thorough
        #------------------------------------------------------

        # rfc 4031 section 3 examples
        self.assertEqual(sp(u("I\u00ADX")), u("IX")) # strip SHY
        self.assertEqual(sp(u("user")), u("user")) # unchanged
        self.assertEqual(sp(u("USER")), u("USER")) # case preserved
        self.assertEqual(sp(u("\u00AA")), u("a")) # normalize to KC form
        self.assertEqual(sp(u("\u2168")), u("IX")) # normalize to KC form
        self.assertRaises(ValueError, sp, u("\u0007")) # forbid control chars
        self.assertRaises(ValueError, sp, u("\u0627\u0031")) # invalid bidi

        # rfc 3454 section 6 examples
            # starts with RAL char, must end with RAL char
        self.assertRaises(ValueError, sp, u("\u0627\u0031"))
        self.assertEqual(sp(u("\u0627\u0031\u0628")), u("\u0627\u0031\u0628"))

#=========================================================
#byte/unicode helpers
#=========================================================
class CodecTest(TestCase):
    "tests bytes/unicode helpers in passlib.utils"

    def test_bytes(self):
        "test b() helper, bytes and native str type"
        if PY3:
            import builtins
            self.assertIs(bytes, builtins.bytes)
        else:
            import __builtin__ as builtins
            self.assertIs(bytes, builtins.str)

        self.assertIsInstance(b(''), bytes)
        self.assertIsInstance(b('\x00\xff'), bytes)
        if PY3:
            self.assertEqual(b('\x00\xff').decode("latin-1"), "\x00\xff")
        else:
            self.assertEqual(b('\x00\xff'), "\x00\xff")

    def test_to_bytes(self):
        "test to_bytes()"
        from passlib.utils import to_bytes

        #check unicode inputs
        self.assertEqual(to_bytes(u('abc')),                  b('abc'))
        self.assertEqual(to_bytes(u('\x00\xff')),             b('\x00\xc3\xbf'))

        #check unicode w/ encodings
        self.assertEqual(to_bytes(u('\x00\xff'), 'latin-1'),  b('\x00\xff'))
        self.assertRaises(ValueError, to_bytes, u('\x00\xff'), 'ascii')
        self.assertRaises(TypeError, to_bytes, u('abc'),      None)

        #check bytes inputs
        self.assertEqual(to_bytes(b('abc')),                b('abc'))
        self.assertEqual(to_bytes(b('\x00\xff')),           b('\x00\xff'))
        self.assertEqual(to_bytes(b('\x00\xc3\xbf')),       b('\x00\xc3\xbf'))

        #check byte inputs ignores enocding
        self.assertEqual(to_bytes(b('\x00\xc3\xbf'), "latin-1"),
                                                            b('\x00\xc3\xbf'))
        self.assertEqual(to_bytes(b('\x00\xc3\xbf'), None, "utf-8"),
                                                            b('\x00\xc3\xbf'))

        #check bytes transcoding
        self.assertEqual(to_bytes(b('\x00\xc3\xbf'), "latin-1", "utf-8"),
                                                            b('\x00\xff'))

        #check other
        self.assertRaises(TypeError, to_bytes, None)

    def test_to_unicode(self):
        "test to_unicode()"
        from passlib.utils import to_unicode

        #check unicode inputs
        self.assertEqual(to_unicode(u('abc')),                u('abc'))
        self.assertEqual(to_unicode(u('\x00\xff')),           u('\x00\xff'))

        #check unicode input ignores encoding
        self.assertEqual(to_unicode(u('\x00\xff'), None),     u('\x00\xff'))
        self.assertEqual(to_unicode(u('\x00\xff'), "ascii"),  u('\x00\xff'))

        #check bytes input
        self.assertEqual(to_unicode(b('abc')),              u('abc'))
        self.assertEqual(to_unicode(b('\x00\xc3\xbf')),     u('\x00\xff'))
        self.assertEqual(to_unicode(b('\x00\xff'), 'latin-1'),
                                                            u('\x00\xff'))
        self.assertRaises(ValueError, to_unicode, b('\x00\xff'))
        self.assertRaises(TypeError, to_unicode, b('\x00\xff'), None)

        #check other
        self.assertRaises(TypeError, to_unicode, None)

    def test_to_native_str(self):
        "test to_native_str()"
        from passlib.utils import to_native_str

        # test plain ascii
        self.assertEqual(to_native_str(u('abc', 'ascii')), 'abc')
        self.assertEqual(to_native_str(b('abc', 'ascii')), 'abc')

        # test invalid ascii
        if PY3:
            self.assertEqual(to_native_str(u('\xE0'), 'ascii'), '\xE0')
            self.assertRaises(UnicodeDecodeError, to_native_str, b('\xC3\xA0'),
                              'ascii')
        else:
            self.assertRaises(UnicodeEncodeError, to_native_str, u('\xE0'),
                              'ascii')
            self.assertEqual(to_native_str(b('\xC3\xA0'), 'ascii'), '\xC3\xA0')

        # test latin-1
        self.assertEqual(to_native_str(u('\xE0'), 'latin-1'), '\xE0')
        self.assertEqual(to_native_str(b('\xE0'), 'latin-1'), '\xE0')

        # test utf-8
        self.assertEqual(to_native_str(u('\xE0'), 'utf-8'),
                         '\xE0' if PY3 else '\xC3\xA0')
        self.assertEqual(to_native_str(b('\xC3\xA0'), 'utf-8'),
                         '\xE0' if PY3 else '\xC3\xA0')

        # other types rejected
        self.assertRaises(TypeError, to_native_str, None, 'ascii')

    def test_is_ascii_safe(self):
        "test is_ascii_safe()"
        from passlib.utils import is_ascii_safe
        self.assertTrue(is_ascii_safe(b("\x00abc\x7f")))
        self.assertTrue(is_ascii_safe(u("\x00abc\x7f")))
        self.assertFalse(is_ascii_safe(b("\x00abc\x80")))
        self.assertFalse(is_ascii_safe(u("\x00abc\x80")))

    def test_is_same_codec(self):
        "test is_same_codec()"
        from passlib.utils import is_same_codec

        self.assertTrue(is_same_codec(None, None))
        self.assertFalse(is_same_codec(None, 'ascii'))

        self.assertTrue(is_same_codec("ascii", "ascii"))
        self.assertTrue(is_same_codec("ascii", "ASCII"))

        self.assertTrue(is_same_codec("utf-8", "utf-8"))
        self.assertTrue(is_same_codec("utf-8", "utf8"))
        self.assertTrue(is_same_codec("utf-8", "UTF_8"))

        self.assertFalse(is_same_codec("ascii", "utf-8"))

#=========================================================
#test des module
#=========================================================
import passlib.utils.des as des

class DesTest(TestCase):

    #test vectors taken from http://www.skepticfiles.org/faq/testdes.htm

    #data is list of (key, plaintext, ciphertext), all as 64 bit hex string
    test_des_vectors = [
        (line[4:20], line[21:37], line[38:54])
        for line in
b("""    0000000000000000 0000000000000000 8CA64DE9C1B123A7
    FFFFFFFFFFFFFFFF FFFFFFFFFFFFFFFF 7359B2163E4EDC58
    3000000000000000 1000000000000001 958E6E627A05557B
    1111111111111111 1111111111111111 F40379AB9E0EC533
    0123456789ABCDEF 1111111111111111 17668DFC7292532D
    1111111111111111 0123456789ABCDEF 8A5AE1F81AB8F2DD
    0000000000000000 0000000000000000 8CA64DE9C1B123A7
    FEDCBA9876543210 0123456789ABCDEF ED39D950FA74BCC4
    7CA110454A1A6E57 01A1D6D039776742 690F5B0D9A26939B
    0131D9619DC1376E 5CD54CA83DEF57DA 7A389D10354BD271
    07A1133E4A0B2686 0248D43806F67172 868EBB51CAB4599A
    3849674C2602319E 51454B582DDF440A 7178876E01F19B2A
    04B915BA43FEB5B6 42FD443059577FA2 AF37FB421F8C4095
    0113B970FD34F2CE 059B5E0851CF143A 86A560F10EC6D85B
    0170F175468FB5E6 0756D8E0774761D2 0CD3DA020021DC09
    43297FAD38E373FE 762514B829BF486A EA676B2CB7DB2B7A
    07A7137045DA2A16 3BDD119049372802 DFD64A815CAF1A0F
    04689104C2FD3B2F 26955F6835AF609A 5C513C9C4886C088
    37D06BB516CB7546 164D5E404F275232 0A2AEEAE3FF4AB77
    1F08260D1AC2465E 6B056E18759F5CCA EF1BF03E5DFA575A
    584023641ABA6176 004BD6EF09176062 88BF0DB6D70DEE56
    025816164629B007 480D39006EE762F2 A1F9915541020B56
    49793EBC79B3258F 437540C8698F3CFA 6FBF1CAFCFFD0556
    4FB05E1515AB73A7 072D43A077075292 2F22E49BAB7CA1AC
    49E95D6D4CA229BF 02FE55778117F12A 5A6B612CC26CCE4A
    018310DC409B26D6 1D9D5C5018F728C2 5F4C038ED12B2E41
    1C587F1C13924FEF 305532286D6F295A 63FAC0D034D9F793
    0101010101010101 0123456789ABCDEF 617B3A0CE8F07100
    1F1F1F1F0E0E0E0E 0123456789ABCDEF DB958605F8C8C606
    E0FEE0FEF1FEF1FE 0123456789ABCDEF EDBFD1C66C29CCC7
    0000000000000000 FFFFFFFFFFFFFFFF 355550B2150E2451
    FFFFFFFFFFFFFFFF 0000000000000000 CAAAAF4DEAF1DBAE
    0123456789ABCDEF 0000000000000000 D5D44FF720683D0D
    FEDCBA9876543210 FFFFFFFFFFFFFFFF 2A2BB008DF97C2F2
    """).split(b("\n")) if line.strip()
    ]

    def test_des_encrypt_block(self):
        for k,p,c in self.test_des_vectors:
            k = unhexlify(k)
            p = unhexlify(p)
            c = unhexlify(c)
            result = des.des_encrypt_block(k,p)
            self.assertEqual(result, c, "key=%r p=%r:" % (k,p))

        #test 7 byte key
        #FIXME: use a better key
        k,p,c = b('00000000000000'), b('FFFFFFFFFFFFFFFF'), b('355550B2150E2451')
        k = unhexlify(k)
        p = unhexlify(p)
        c = unhexlify(c)
        result = des.des_encrypt_block(k,p)
        self.assertEqual(result, c, "key=%r p=%r:" % (k,p))

    def test_mdes_encrypt_int_block(self):
        for k,p,c in self.test_des_vectors:
            k = int(k,16)
            p = int(p,16)
            c = int(c,16)
            result = des.mdes_encrypt_int_block(k,p, salt=0, rounds=1)
            self.assertEqual(result, c, "key=%r p=%r:" % (k,p))

    #TODO: test other des methods (eg: mdes_encrypt_int_block w/ salt & rounds)
    # though des-crypt builtin backend test should thump it well enough

#=========================================================
# base64engine
#=========================================================
class _Base64Test(TestCase):
    "common tests for all Base64Engine instances"
    #=========================================================
    # class attrs
    #=========================================================

    # Base64Engine instance to test
    engine = None

    # pairs of (raw, encoded) bytes to test - should encode/decode correctly
    encoded_data = None

    # tuples of (encoded, value, bits) for known integer encodings
    encoded_ints = None

    # invalid encoded byte
    bad_byte = b("?")

    # helper to generate bytemap-specific strings
    def m(self, *offsets):
        "generate byte string from offsets"
        return b("").join(self.engine.bytemap[o:o+1] for o in offsets)

    #=========================================================
    # test encode_bytes
    #=========================================================
    def test_encode_bytes(self):
        "test encode_bytes() against reference inputs"
        engine = self.engine
        encode = engine.encode_bytes
        for raw, encoded in self.encoded_data:
            result = encode(raw)
            self.assertEqual(result, encoded, "encode %r:" % (raw,))

    def test_encode_bytes_bad(self):
        "test encode_bytes() with bad input"
        engine = self.engine
        encode = engine.encode_bytes
        self.assertRaises(TypeError, encode, u('\x00'))
        self.assertRaises(TypeError, encode, None)

    #=========================================================
    # test decode_bytes
    #=========================================================
    def test_decode_bytes(self):
        "test decode_bytes() against reference inputs"
        engine = self.engine
        decode = engine.decode_bytes
        for raw, encoded in self.encoded_data:
            result = decode(encoded)
            self.assertEqual(result, raw, "decode %r:" % (encoded,))

    def test_decode_bytes_padding(self):
        "test decode_bytes() ignores padding bits"
        bchr = (lambda v: bytes([v])) if PY3 else chr
        engine = self.engine
        m = self.m
        decode = engine.decode_bytes
        BNULL = b("\x00")

        # length == 2 mod 4: 4 bits of padding
        self.assertEqual(decode(m(0,0)), BNULL)
        for i in range(0,6):
            if engine.big: # 4 lsb padding
                correct = BNULL if i < 4 else bchr(1<<(i-4))
            else: # 4 msb padding
                correct = bchr(1<<(i+6)) if i < 2 else BNULL
            self.assertEqual(decode(m(0,1<<i)), correct, "%d/4 bits:" % i)

        # length == 3 mod 4: 2 bits of padding
        self.assertEqual(decode(m(0,0,0)), BNULL*2)
        for i in range(0,6):
            if engine.big: # 2 lsb are padding
                correct = BNULL if i < 2 else bchr(1<<(i-2))
            else: # 2 msg are padding
                correct = bchr(1<<(i+4)) if i < 4 else BNULL
            self.assertEqual(decode(m(0,0,1<<i)), BNULL + correct,
                             "%d/2 bits:" % i)

    def test_decode_bytes_bad(self):
        "test decode_bytes() with bad input"
        engine = self.engine
        decode = engine.decode_bytes

        # wrong size (1 % 4)
        self.assertRaises(ValueError, decode, engine.bytemap[:5])

        # wrong char
        self.assertTrue(self.bad_byte not in engine.bytemap)
        self.assertRaises(ValueError, decode, self.bad_byte*4)

        # wrong type
        self.assertRaises(TypeError, decode, engine.charmap[:4])
        self.assertRaises(TypeError, decode, None)

    #=========================================================
    # encode_bytes+decode_bytes
    #=========================================================
    def test_codec(self):
        "test encode_bytes/decode_bytes against random data"
        engine = self.engine
        from passlib.utils import getrandbytes, getrandstr
        saw_zero = False
        for i in irange(500):
            #
            # test raw -> encode() -> decode() -> raw
            #

            # generate some random bytes
            size = random.randint(1 if saw_zero else 0, 12)
            if not size:
                saw_zero = True
            enc_size = (4*size+2)//3
            raw = getrandbytes(random, size)

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
                size += random.choice([-1,1,2])
            raw_size = 3*size//4
            encoded = getrandstr(random, engine.bytemap, size)

            # decode them, check invariants
            raw = engine.decode_bytes(encoded)
            self.assertEqual(len(raw), raw_size, "encoded %d:" % size)

            # make sure encode returns original (barring padding bits)
            result = engine.encode_bytes(raw)
            if size % 4:
                self.assertEqual(result[:-1], encoded[:-1])
            else:
                self.assertEqual(result, encoded)

    #=========================================================
    # test transposed encode/decode - encoding independant
    #=========================================================
    # NOTE: these tests assume normal encode/decode has been tested elsewhere.

    transposed = [
        # orig, result, transpose map
        (b("\x33\x22\x11"), b("\x11\x22\x33"),[2,1,0]),
        (b("\x22\x33\x11"), b("\x11\x22\x33"),[1,2,0]),
    ]

    transposed_dups = [
        # orig, result, transpose projection
        (b("\x11\x11\x22"), b("\x11\x22\x33"),[0,0,1]),
    ]

    def test_encode_transposed_bytes(self):
        "test encode_transposed_bytes()"
        engine = self.engine
        for result, input, offsets in self.transposed + self.transposed_dups:
            tmp = engine.encode_transposed_bytes(input, offsets)
            out = engine.decode_bytes(tmp)
            self.assertEqual(out, result)

    def test_decode_transposed_bytes(self):
        "test decode_transposed_bytes()"
        engine = self.engine
        for input, result, offsets in self.transposed:
            tmp = engine.encode_bytes(input)
            out = engine.decode_transposed_bytes(tmp, offsets)
            self.assertEqual(out, result)

    def test_decode_transposed_bytes_bad(self):
        "test decode_transposed_bytes() fails if map is a one-way"
        engine = self.engine
        for input, _, offsets in self.transposed_dups:
            tmp = engine.encode_bytes(input)
            self.assertRaises(TypeError, engine.decode_transposed_bytes, tmp,
                              offsets)

    #=========================================================
    # test 6bit handling
    #=========================================================
    def check_int_pair(self, bits, encoded_pairs):
        "helper to check encode_intXX & decode_intXX functions"
        engine = self.engine
        encode = getattr(engine, "encode_int%s" % bits)
        decode = getattr(engine, "decode_int%s" % bits)
        pad = -bits % 6
        chars = (bits+pad)/6
        upper = 1<<bits

        # test encode func
        for value, encoded in encoded_pairs:
            self.assertEqual(encode(value), encoded)
        self.assertRaises(ValueError, encode, -1)
        self.assertRaises(ValueError, encode, upper)

        # test decode func
        for value, encoded in encoded_pairs:
            self.assertEqual(decode(encoded), value, "encoded %r:" % (encoded,))
        m = self.m
        self.assertRaises(ValueError, decode, m(0)*(chars+1))
        self.assertRaises(ValueError, decode, m(0)*(chars-1))
        self.assertRaises(ValueError, decode, self.bad_byte*chars)
        self.assertRaises(TypeError, decode, engine.charmap[0])
        self.assertRaises(TypeError, decode, None)

        # do random testing.
        from passlib.utils import getrandbytes, getrandstr
        for i in irange(100):
            # generate random value, encode, and then decode
            value = random.randint(0, upper-1)
            encoded = encode(value)
            self.assertEqual(len(encoded), chars)
            self.assertEqual(decode(encoded), value)

            # generate some random encoded data, decode, then encode.
            encoded = getrandstr(random, engine.bytemap, chars)
            value = decode(encoded)
            self.assertGreaterEqual(value, 0, "decode %r out of bounds:" % encoded)
            self.assertLess(value, upper, "decode %r out of bounds:" % encoded)
            result = encode(value)
            if pad:
                self.assertEqual(result[:-2], encoded[:-2])
            else:
                self.assertEqual(result, encoded)

    def test_int6(self):
        engine = self.engine
        m = self.m
        self.check_int_pair(6, [(0, m(0)), (63, m(63))])

    def test_int12(self):
        engine = self.engine
        m = self.m
        self.check_int_pair(12,[(0, m(0,0)),
            (63, m(0,63) if engine.big else m(63,0)), (0xFFF, m(63,63))])

    def test_int24(self):
        engine = self.engine
        m = self.m
        self.check_int_pair(24,[(0, m(0,0,0,0)),
            (63, m(0,0,0,63) if engine.big else m(63,0,0,0)),
            (0xFFFFFF, m(63,63,63,63))])

    def test_int64(self):
        # NOTE: this isn't multiple of 6, it has 2 padding bits appended
        # before encoding.
        engine = self.engine
        m = self.m
        self.check_int_pair(64, [(0, m(0,0,0,0, 0,0,0,0, 0,0,0)),
                (63, m(0,0,0,0, 0,0,0,0, 0,3,60) if engine.big else
                     m(63,0,0,0, 0,0,0,0, 0,0,0)),
                ((1<<64)-1, m(63,63,63,63, 63,63,63,63, 63,63,60) if engine.big
                    else m(63,63,63,63, 63,63,63,63, 63,63,15))])

    def test_encoded_ints(self):
        "test against reference integer encodings"
        if not self.encoded_ints:
            raise self.skipTests("none defined for class")
        engine = self.engine
        for encoded, value, bits in self.encoded_ints:
            encode = getattr(engine, "encode_int%d" % bits)
            decode = getattr(engine, "decode_int%d" % bits)
            self.assertEqual(encode(value), encoded)
            self.assertEqual(decode(encoded), value)

    #=========================================================
    # eoc
    #=========================================================

# NOTE: testing H64 & H64Big should be sufficient to verify
# that Base64Engine() works in general.
from passlib.utils import h64, h64big

class H64_Test(_Base64Test):
    "test H64 codec functions"
    engine = h64
    case_prefix = "h64 codec"

    encoded_data = [
        #test lengths 0..6 to ensure tail is encoded properly
        (b(""),b("")),
        (b("\x55"),b("J/")),
        (b("\x55\xaa"),b("Jd8")),
        (b("\x55\xaa\x55"),b("JdOJ")),
        (b("\x55\xaa\x55\xaa"),b("JdOJe0")),
        (b("\x55\xaa\x55\xaa\x55"),b("JdOJeK3")),
        (b("\x55\xaa\x55\xaa\x55\xaa"),b("JdOJeKZe")),

        #test padding bits are null
        (b("\x55\xaa\x55\xaf"),b("JdOJj0")), # len = 1 mod 3
        (b("\x55\xaa\x55\xaa\x5f"),b("JdOJey3")), # len = 2 mod 3
    ]

    encoded_ints = [
        ("z.", 63, 12),
        (".z", 4032, 12),
    ]

class H64Big_Test(_Base64Test):
    "test H64Big codec functions"
    engine = h64big
    case_prefix = "h64big codec"

    encoded_data = [
        #test lengths 0..6 to ensure tail is encoded properly
        (b(""),b("")),
        (b("\x55"),b("JE")),
        (b("\x55\xaa"),b("JOc")),
        (b("\x55\xaa\x55"),b("JOdJ")),
        (b("\x55\xaa\x55\xaa"),b("JOdJeU")),
        (b("\x55\xaa\x55\xaa\x55"),b("JOdJeZI")),
        (b("\x55\xaa\x55\xaa\x55\xaa"),b("JOdJeZKe")),

        #test padding bits are null
        (b("\x55\xaa\x55\xaf"),b("JOdJfk")), # len = 1 mod 3
        (b("\x55\xaa\x55\xaa\x5f"),b("JOdJeZw")), # len = 2 mod 3
    ]

    encoded_ints = [
        (".z", 63, 12),
        ("z.", 4032, 12),
    ]

#=========================================================
#test md4
#=========================================================
class _MD4_Test(TestCase):
    #test vectors from http://www.faqs.org/rfcs/rfc1320.html - A.5

    hash = None

    vectors = [
        # input -> hex digest
        (b(""), "31d6cfe0d16ae931b73c59d7e0c089c0"),
        (b("a"), "bde52cb31de33e46245e05fbdbd6fb24"),
        (b("abc"), "a448017aaf21d8525fc10ae87aa6729d"),
        (b("message digest"), "d9130a8164549fe818874806e1c7014b"),
        (b("abcdefghijklmnopqrstuvwxyz"), "d79e1c308aa5bbcdeea8ed63df412da9"),
        (b("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"), "043f8582f241db351ce627e153e7f0e4"),
        (b("12345678901234567890123456789012345678901234567890123456789012345678901234567890"), "e33b4ddc9c38f2199c3e7b164fcc0536"),
    ]

    def test_md4_update(self):
        "test md4 update"
        md4 = self.hash
        h = md4(b(''))
        self.assertEqual(h.hexdigest(), "31d6cfe0d16ae931b73c59d7e0c089c0")

        #NOTE: under py2, hashlib methods try to encode to ascii,
        #      though shouldn't rely on that.
        if PY3:
            self.assertRaises(TypeError, h.update, u('x'))

        h.update(b('a'))
        self.assertEqual(h.hexdigest(), "bde52cb31de33e46245e05fbdbd6fb24")

        h.update(b('bcdefghijklmnopqrstuvwxyz'))
        self.assertEqual(h.hexdigest(), "d79e1c308aa5bbcdeea8ed63df412da9")

    def test_md4_hexdigest(self):
        "test md4 hexdigest()"
        md4 = self.hash
        for input, hex in self.vectors:
            out = md4(input).hexdigest()
            self.assertEqual(out, hex)

    def test_md4_digest(self):
        "test md4 digest()"
        md4 = self.hash
        for input, hex in self.vectors:
            out = bascii_to_str(hexlify(md4(input).digest()))
            self.assertEqual(out, hex)

    def test_md4_copy(self):
        "test md4 copy()"
        md4 = self.hash
        h = md4(b('abc'))

        h2 = h.copy()
        h2.update(b('def'))
        self.assertEqual(h2.hexdigest(), '804e7f1c2586e50b49ac65db5b645131')

        h.update(b('ghi'))
        self.assertEqual(h.hexdigest(), 'c5225580bfe176f6deeee33dee98732c')

#
#now do a bunch of things to test multiple possible backends.
#
import passlib.utils.md4 as md4_mod

has_ssl_md4 = (md4_mod.md4 is not md4_mod._builtin_md4)

if has_ssl_md4:
    class MD4_SSL_Test(_MD4_Test):
        case_prefix = "MD4 (SSL version)"
        hash = staticmethod(md4_mod.md4)

if not has_ssl_md4 or enable_option("cover"):
    class MD4_Builtin_Test(_MD4_Test):
        case_prefix = "MD4 (builtin version)"
        hash = md4_mod._builtin_md4

#=========================================================
#test passlib.utils.pbkdf2
#=========================================================
import hashlib
import hmac
from passlib.utils import pbkdf2

#TODO: should we bother testing hmac_sha1() function? it's verified via sha1_crypt testing.

class KdfTest(TestCase):
    "test kdf helpers"

    def test_pbkdf1(self):
        "test pbkdf1"
        for secret, salt, rounds, klen, hash, correct in [
            #http://www.di-mgt.com.au/cryptoKDFs.html
            (b('password'), hb('78578E5A5D63CB06'), 1000, 16, 'sha1',
                hb('dc19847e05c64d2faf10ebfb4a3d2a20')),
        ]:
            result = pbkdf2.pbkdf1(secret, salt, rounds, klen, hash)
            self.assertEqual(result, correct)

        #test rounds < 1
        #test klen < 0
        #test klen > block size
        #test invalid hash

#NOTE: this is not run directly, but via two subclasses (below)
class _Pbkdf2BackendTest(TestCase):
    "test builtin unix crypt backend"
    enable_m2crypto = False

    def setUp(self):
        #disable m2crypto support so we'll always use software backend
        if not self.enable_m2crypto:
            self._orig_EVP = pbkdf2._EVP
            pbkdf2._EVP = None
        else:
            #set flag so tests can check for m2crypto presence quickly
            self.enable_m2crypto = bool(pbkdf2._EVP)
        pbkdf2._clear_prf_cache()

    def tearDown(self):
        if not self.enable_m2crypto:
            pbkdf2._EVP = self._orig_EVP
        pbkdf2._clear_prf_cache()

    #TODO: test get_prf() behavior in various situations - though overall behavior tested via pbkdf2

    def test_rfc3962(self):
        "rfc3962 test vectors"
        self.assertFunctionResults(pbkdf2.pbkdf2, [
            # result, secret, salt, rounds, keylen, digest="sha1"

            #test case 1 / 128 bit
            (
                hb("cdedb5281bb2f801565a1122b2563515"),
                b("password"), b("ATHENA.MIT.EDUraeburn"), 1, 16
            ),

            #test case 2 / 128 bit
            (
                hb("01dbee7f4a9e243e988b62c73cda935d"),
                b("password"), b("ATHENA.MIT.EDUraeburn"), 2, 16
            ),

            #test case 2 / 256 bit
            (
                hb("01dbee7f4a9e243e988b62c73cda935da05378b93244ec8f48a99e61ad799d86"),
                b("password"), b("ATHENA.MIT.EDUraeburn"), 2, 32
            ),

            #test case 3 / 256 bit
            (
                hb("5c08eb61fdf71e4e4ec3cf6ba1f5512ba7e52ddbc5e5142f708a31e2e62b1e13"),
                b("password"), b("ATHENA.MIT.EDUraeburn"), 1200, 32
            ),

            #test case 4 / 256 bit
            (
                hb("d1daa78615f287e6a1c8b120d7062a493f98d203e6be49a6adf4fa574b6e64ee"),
                b("password"), b('\x12\x34\x56\x78\x78\x56\x34\x12'), 5, 32
            ),

            #test case 5 / 256 bit
            (
                hb("139c30c0966bc32ba55fdbf212530ac9c5ec59f1a452f5cc9ad940fea0598ed1"),
                b("X"*64), b("pass phrase equals block size"), 1200, 32
            ),

            #test case 6 / 256 bit
            (
                hb("9ccad6d468770cd51b10e6a68721be611a8b4d282601db3b36be9246915ec82a"),
                b("X"*65), b("pass phrase exceeds block size"), 1200, 32
            ),
        ])

    def test_rfc6070(self):
        "rfc6070 test vectors"
        self.assertFunctionResults(pbkdf2.pbkdf2, [

            (
                hb("0c60c80f961f0e71f3a9b524af6012062fe037a6"),
                b("password"), b("salt"), 1, 20,
            ),

            (
                hb("ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957"),
                b("password"), b("salt"), 2, 20,
            ),

            (
                hb("4b007901b765489abead49d926f721d065a429c1"),
                b("password"), b("salt"), 4096, 20,
            ),

            #just runs too long - could enable if ALL option is set
            ##(
            ##
            ##    unhexlify("eefe3d61cd4da4e4e9945b3d6ba2158c2634e984"),
            ##    "password", "salt", 16777216, 20,
            ##),

            (
                hb("3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038"),
                b("passwordPASSWORDpassword"),
                b("saltSALTsaltSALTsaltSALTsaltSALTsalt"),
                4096, 25,
            ),

            (
                hb("56fa6aa75548099dcc37d7f03425e0c3"),
                b("pass\00word"), b("sa\00lt"), 4096, 16,
            ),
        ])

    def test_invalid_values(self):

        #invalid rounds
        self.assertRaises(ValueError, pbkdf2.pbkdf2, b('password'), b('salt'), -1, 16)
        self.assertRaises(ValueError, pbkdf2.pbkdf2, b('password'), b('salt'), 0, 16)
        self.assertRaises(TypeError, pbkdf2.pbkdf2, b('password'), b('salt'), 'x', 16)

        #invalid keylen
        self.assertRaises(ValueError, pbkdf2.pbkdf2, b('password'), b('salt'),
                                                     1, 20*(2**32-1)+1)

        #invalid salt type
        self.assertRaises(TypeError, pbkdf2.pbkdf2, b('password'), 5, 1, 10)

        #invalid secret type
        self.assertRaises(TypeError, pbkdf2.pbkdf2, 5, b('salt'), 1, 10)

        #invalid hash
        self.assertRaises(ValueError, pbkdf2.pbkdf2, b('password'), b('salt'), 1, 16, 'hmac-foo')
        self.assertRaises(ValueError, pbkdf2.pbkdf2, b('password'), b('salt'), 1, 16, 'foo')
        self.assertRaises(TypeError, pbkdf2.pbkdf2, b('password'), b('salt'), 1, 16, 5)

    def test_default_keylen(self):
        "test keylen==-1"
        self.assertEqual(len(pbkdf2.pbkdf2(b('password'), b('salt'), 1, -1,
                                           prf='hmac-sha1')), 20)

        self.assertEqual(len(pbkdf2.pbkdf2(b('password'), b('salt'), 1, -1,
                                           prf='hmac-sha256')), 32)

    def test_hmac_sha1(self):
        "test independant hmac_sha1() method"
        self.assertEqual(
            pbkdf2.hmac_sha1(b("secret"), b("salt")),
            b('\xfc\xd4\x0c;]\r\x97\xc6\xf1S\x8d\x93\xb9\xeb\xc6\x00\x04.\x8b\xfe')
            )

    def test_sha1_string(self):
        "test various prf values"
        self.assertEqual(
            pbkdf2.pbkdf2(b("secret"), b("salt"), 10, 16, "hmac-sha1"),
            b('\xe2H\xfbk\x136QF\xf8\xacc\x07\xcc"(\x12')
        )

    def test_sha512_string(self):
        "test alternate digest string (sha512)"
        self.assertFunctionResults(pbkdf2.pbkdf2, [
            # result, secret, salt, rounds, keylen, digest="sha1"

            #case taken from example in http://grub.enbug.org/Authentication
            (
               hb("887CFF169EA8335235D8004242AA7D6187A41E3187DF0CE14E256D85ED97A97357AAA8FF0A3871AB9EEFF458392F462F495487387F685B7472FC6C29E293F0A0"),
               b("hello"),
               hb("9290F727ED06C38BA4549EF7DE25CF5642659211B7FC076F2D28FEFD71784BB8D8F6FB244A8CC5C06240631B97008565A120764C0EE9C2CB0073994D79080136"),
               10000, 64, "hmac-sha512"
            ),
        ])

    def test_sha512_function(self):
        "test custom digest function"
        def prf(key, msg):
            return hmac.new(key, msg, hashlib.sha512).digest()

        self.assertFunctionResults(pbkdf2.pbkdf2, [
            # result, secret, salt, rounds, keylen, digest="sha1"

            #case taken from example in http://grub.enbug.org/Authentication
            (
               hb("887CFF169EA8335235D8004242AA7D6187A41E3187DF0CE14E256D85ED97A97357AAA8FF0A3871AB9EEFF458392F462F495487387F685B7472FC6C29E293F0A0"),
               b("hello"),
               hb("9290F727ED06C38BA4549EF7DE25CF5642659211B7FC076F2D28FEFD71784BB8D8F6FB244A8CC5C06240631B97008565A120764C0EE9C2CB0073994D79080136"),
               10000, 64, prf,
            ),
        ])

has_m2crypto = (pbkdf2._EVP is not None)

if has_m2crypto:
    class Pbkdf2_M2Crypto_Test(_Pbkdf2BackendTest):
        case_prefix = "pbkdf2 (m2crypto backend)"
        enable_m2crypto = True

if not has_m2crypto or enable_option("cover"):
    class Pbkdf2_Builtin_Test(_Pbkdf2BackendTest):
        case_prefix = "pbkdf2 (builtin backend)"
        enable_m2crypto = False

#=========================================================
#EOF
#=========================================================
