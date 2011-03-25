"""tests for passlib.util"""
#=========================================================
#imports
#=========================================================
#core
from binascii import hexlify, unhexlify
import sys
import random
#site
#pkg
#module
from passlib import utils
from passlib.context import CryptContext
from passlib.utils import h64, des, Undef, sys_bits
from passlib.utils.md4 import md4
from passlib.tests.utils import TestCase, Params as ak, enable_option

#=========================================================
#byte funcs
#=========================================================
class UtilsTest(TestCase):

    def test_undef(self):
        "test Undef singleton"
        self.assertEqual(repr(Undef), "<Undef>")
        self.assertFalse(Undef==None,)
        self.assertFalse(Undef==Undef,)
        self.assertFalse(Undef==True,)
        self.assertTrue(Undef!=None,)
        self.assertTrue(Undef!=Undef,)
        self.assertTrue(Undef!=True,)

    def test_list_to_bytes(self):
        self.assertFunctionResults(utils.list_to_bytes, [
            #standard big endian
            ak('\x00', [0], 1),
            ak('\x01', [1], 1),
            ak('\x00\x01', [1], 2),
            ak('\x00\x01', [0, 1], 2),
            ak('\x00\x00\x01', [1], 3),
            ak('\x00\x00\x00\x00', [0], 4),
            ak('\x00\x00\x00\x01', [1], 4),
            ak('\x00\x00\x00\xff', [255], 4),
            ak('\x00\x00\x01\xff', [1, 255], 4),
            ak('\x04\x03\x02\x01', [4, 3, 2, 1], 4),

            #standard little endian
            ak('\x00', [0], 1, order="little"),
            ak('\x01', [1], 1, order="little"),
            ak('\x01\x00', [1], 2, order="little"),
            ak('\x01\x00', [0, 1], 2, order="little"),
            ak('\x01\x00\x00', [1], 3, order="little"),
            ak('\x00\x00\x00\x00', [0], 4, order="little"),
            ak('\x01\x00\x00\x00', [1], 4, order="little"),
            ak('\xff\x00\x00\x00', [255], 4, order="little"),
            ak('\xff\x01\x00\x00', [1, 255], 4, order="little"),
            ak('\x01\x02\x03\x04', [4, 3, 2, 1], 4, order="little"),

            ])

        #check bytes size check
        self.assertRaises(ValueError, utils.list_to_bytes, [])
        self.assertRaises(ValueError, utils.list_to_bytes, [], bytes=0)
        self.assertRaises(ValueError, utils.list_to_bytes, [0, 0], bytes=1)

        #check bytes bound check
        self.assertRaises(ValueError, utils.list_to_bytes, [256], bytes=1)

        #quick check native mode works right
        if sys.byteorder == "little":
            self.assertEqual(utils.list_to_bytes([1], 3, order="native"), '\x01\x00\x00')
        else:
            self.assertEqual(utils.list_to_bytes([1], 3, order="native"), '\x00\x00\x01')

    def test_bytes_to_list(self):
        self.assertFunctionResults(utils.bytes_to_list, [

            #standard big endian
            ak([1], '\x01'),
            ak([0, 1], '\x00\x01'),
            ak([0, 0, 1], '\x00\x00\x01'),
            ak([0, 0, 0, 0],'\x00\x00\x00\x00'),
            ak([0, 0, 0, 1],'\x00\x00\x00\x01'),
            ak([0, 0, 0, 255],'\x00\x00\x00\xff'),
            ak([0, 0, 1, 0],'\x00\x00\x01\x00'),
            ak([4, 3, 2, 1],'\x04\x03\x02\x01'),

            #standard little endian
            ak([1], '\x01', order="little"),
            ak([0, 1], '\x01\x00', order="little"),
            ak([0, 0, 1], '\x01\x00\x00', order="little"),
            ak([0, 0, 0, 0], '\x00\x00\x00\x00', order="little"),
            ak([0, 0, 0, 1], '\x01\x00\x00\x00', order="little"),
            ak([0, 0, 0, 255], '\xff\x00\x00\x00', order="little"),
            ak([0, 0, 1, 0], '\x00\x01\x00\x00', order="little"),
            ak([4, 3, 2, 1],'\x01\x02\x03\x04', order="little"),

            ])

        #quick check native mode works right
        if sys.byteorder == "little":
            self.assertEqual(utils.bytes_to_list('\x01\x00\x00', order="native"), [0, 0, 1])
        else:
            self.assertEqual(utils.bytes_to_list('\x00\x00\x01', order="native"), [0, 0, 1])

    def test_getrandbytes(self):
        def f(*a,**k):
            return utils.getrandbytes(utils.rng, *a, **k)
        self.assertEqual(len(f(0)), 0)
        a = f(10)
        b = f(10)
        self.assertEqual(len(a), 10)
        self.assertEqual(len(b), 10)
        self.assertNotEqual(a, b)

    def test_getrandstr(self):
        def f(*a,**k):
            return utils.getrandstr(utils.rng, *a, **k)

        #count 0
        self.assertEqual(f('abc',0), '')

        #count <0
        self.assertRaises(ValueError, f, 'abc', -1)

        #letters 0
        self.assertRaises(ValueError, f, '', 0)

        #letters 1
        self.assertEqual(f('a',5), 'aaaaa')

        #letters
        a = f('abc', 16)
        b = f('abc', 16)
        self.assertNotEqual(a,b)
        self.assertEqual(sorted(set(a)), ['a','b','c'])

    def test_is_crypt_context(self):
        cc = CryptContext(["des_crypt"])
        self.assertTrue(utils.is_crypt_context(cc))
        self.assertFalse(not utils.is_crypt_context(cc))

    def test_genseed(self):
        rng = utils.random.Random(utils.genseed())
        a = rng.randint(0, 100000)

        rng = utils.random.Random(utils.genseed())
        b = rng.randint(0, 100000)

        self.assertNotEqual(a,b)

        rng.seed(utils.genseed(rng))

#=========================================================
#test des module
#=========================================================
class DesTest(TestCase):

    #test vectors taken from http://www.skepticfiles.org/faq/testdes.htm

    #data is list of (key, plaintext, ciphertext), all as 64 bit hex string
    test_des_vectors = [
        (line[4:20], line[21:37], line[38:54])
        for line in
 """    0000000000000000 0000000000000000 8CA64DE9C1B123A7
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
    """.split("\n") if line.strip()
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
        k,p,c = '00000000000000', 'FFFFFFFFFFFFFFFF', '355550B2150E2451'
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
#hash64
#=========================================================
class H64_Test(TestCase):
    "test H64 codec functions"
    case_prefix = "H64 codec"

    #=========================================================
    #test basic encode/decode
    #=========================================================
    encoded_bytes = [
        #test lengths 0..6 to ensure tail is encoded properly
        ("",""),
        ("\x55","J/"),
        ("\x55\xaa","Jd8"),
        ("\x55\xaa\x55","JdOJ"),
        ("\x55\xaa\x55\xaa","JdOJe0"),
        ("\x55\xaa\x55\xaa\x55","JdOJeK3"),
        ("\x55\xaa\x55\xaa\x55\xaa","JdOJeKZe"),

        #test padding bits are null
        ("\x55\xaa\x55\xaf","JdOJj0"), # len = 1 mod 3
        ("\x55\xaa\x55\xaa\x5f","JdOJey3"), # len = 2 mod 3
    ]

    decode_padding_bytes = [
        #len = 2 mod 4 -> 2 msb of last digit is padding
        ("..", "\x00"), # . = h64.CHARS[0b000000]
        (".0", "\x80"), # 0 = h64.CHARS[0b000010]
        (".2", "\x00"), # 2 = h64.CHARS[0b000100]
        (".U", "\x00"), # U = h64.CHARS[0b100000]

        #len = 3 mod 4 -> 4 msb of last digit is padding
        ("...", "\x00\x00"),
        ("..6", "\x00\x80"), # 6 = h64.CHARS[0b001000]
        ("..E", "\x00\x00"), # E = h64.CHARS[0b010000]
        ("..U", "\x00\x00"),
    ]

    def test_encode_bytes(self):
        for source, result in self.encoded_bytes:
            out = h64.encode_bytes(source)
            self.assertEqual(out, result)

    def test_decode_bytes(self):
        for result, source in self.encoded_bytes:
            out = h64.decode_bytes(source)
            self.assertEqual(out, result)

        #wrong size (1 % 4)
        self.assertRaises(ValueError, h64.decode_bytes, 'abcde')

    def test_encode_int(self):
        self.assertEqual(h64.encode_int(63, 11, True), '..........z')
        self.assertEqual(h64.encode_int(63, 11), 'z..........')

        self.assertRaises(ValueError, h64.encode_int64, -1)

    def test_decode_int(self):
        self.assertEqual(h64.decode_int64('...........'), 0)

        self.assertRaises(ValueError, h64.decode_int12, 'a?')
        self.assertRaises(ValueError, h64.decode_int24, 'aaa?')
        self.assertRaises(ValueError, h64.decode_int64, 'aaa?aaa?aaa')
        self.assertRaises(ValueError, h64.decode_dc_int64, 'aaa?aaa?aaa')

    def test_decode_bytes_padding(self):
        for source, result in self.decode_padding_bytes:
            out = h64.decode_bytes(source)
            self.assertEqual(out, result)

    def test_decode_int6(self):
        self.assertEquals(h64.decode_int6('.'),0)
        self.assertEquals(h64.decode_int6('z'),63)
        self.assertRaises(ValueError, h64.decode_int6, '?')

    def test_encode_int6(self):
        self.assertEquals(h64.encode_int6(0),'.')
        self.assertEquals(h64.encode_int6(63),'z')
        self.assertRaises(ValueError, h64.encode_int6, -1)
        self.assertRaises(ValueError, h64.encode_int6, 64)

    #=========================================================
    #test transposed encode/decode
    #=========================================================
    encode_transposed = [
        ("\x33\x22\x11", "\x11\x22\x33",[2,1,0]),
        ("\x22\x33\x11", "\x11\x22\x33",[1,2,0]),
    ]

    encode_transposed_dups = [
        ("\x11\x11\x22", "\x11\x22\x33",[0,0,1]),
    ]

    def test_encode_transposed_bytes(self):
        for result, input, offsets in self.encode_transposed + self.encode_transposed_dups:
            tmp = h64.encode_transposed_bytes(input, offsets)
            out = h64.decode_bytes(tmp)
            self.assertEqual(out, result)

    def test_decode_transposed_bytes(self):
        for input, result, offsets in self.encode_transposed:
            tmp = h64.encode_bytes(input)
            out = h64.decode_transposed_bytes(tmp, offsets)
            self.assertEqual(out, result)

    def test_decode_transposed_bytes_bad(self):
        for input, _, offsets in self.encode_transposed_dups:
            tmp = h64.encode_bytes(input)
            self.assertRaises(TypeError, h64.decode_transposed_bytes, tmp, offsets)

    #=========================================================
    #TODO: test other h64 methods
    #=========================================================

#=========================================================
#test md4
#=========================================================
class MD4_Test(TestCase):
    #test vectors from http://www.faqs.org/rfcs/rfc1320.html - A.5

    vectors = [
        # input -> hex digest
        ("", "31d6cfe0d16ae931b73c59d7e0c089c0"),
        ("a", "bde52cb31de33e46245e05fbdbd6fb24"),
        ("abc", "a448017aaf21d8525fc10ae87aa6729d"),
        ("message digest", "d9130a8164549fe818874806e1c7014b"),
        ("abcdefghijklmnopqrstuvwxyz", "d79e1c308aa5bbcdeea8ed63df412da9"),
        ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "043f8582f241db351ce627e153e7f0e4"),
        ("12345678901234567890123456789012345678901234567890123456789012345678901234567890", "e33b4ddc9c38f2199c3e7b164fcc0536"),
    ]

    def test_md4_update(self):
        "test md4 update"
        h = md4('')
        self.assertEqual(h.hexdigest(), "31d6cfe0d16ae931b73c59d7e0c089c0")

        h.update('a')
        self.assertEqual(h.hexdigest(), "bde52cb31de33e46245e05fbdbd6fb24")

        h.update('bcdefghijklmnopqrstuvwxyz')
        self.assertEqual(h.hexdigest(), "d79e1c308aa5bbcdeea8ed63df412da9")

    def test_md4_hexdigest(self):
        "test md4 hexdigest()"
        for input, hex in self.vectors:
            out = md4(input).hexdigest()
            self.assertEqual(out, hex)

    def test_md4_digest(self):
        "test md4 digest()"
        for input, hex in self.vectors:
            out = md4(input).digest()
            self.assertEqual(hexlify(out), hex)

    def test_md4_copy(self):
        "test md4 copy()"
        h = md4('abc')

        h2 = h.copy()
        h2.update('def')
        self.assertEquals(h2.hexdigest(), '804e7f1c2586e50b49ac65db5b645131')

        h.update('ghi')
        self.assertEquals(h.hexdigest(), 'c5225580bfe176f6deeee33dee98732c')

#=========================================================
#test passlib.utils.pbkdf2
#=========================================================
import hashlib
import hmac
from passlib.utils import pbkdf2

#TODO: should we bother testing hmac_sha1() function? it's verified via sha1_crypt testing.

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

    def tearDown(self):
        if not self.enable_m2crypto:
            pbkdf2._EVP = self._orig_EVP

    def test_rfc3962(self):
        "rfc3962 test vectors"
        self.assertFunctionResults(pbkdf2.pbkdf2, [
            # result, secret, salt, rounds, keylen, digest="sha1"

            #test case 1 / 128 bit
            (
                unhexlify("cdedb5281bb2f801565a1122b2563515"),
                "password", "ATHENA.MIT.EDUraeburn", 1, 16
            ),

            #test case 2 / 128 bit
            (
                unhexlify("01dbee7f4a9e243e988b62c73cda935d"),
                "password", "ATHENA.MIT.EDUraeburn", 2, 16
            ),

            #test case 2 / 256 bit
            (
                unhexlify("01dbee7f4a9e243e988b62c73cda935da05378b93244ec8f48a99e61ad799d86"),
                "password", "ATHENA.MIT.EDUraeburn", 2, 32
            ),

            #test case 3 / 256 bit
            (
                unhexlify("5c08eb61fdf71e4e4ec3cf6ba1f5512ba7e52ddbc5e5142f708a31e2e62b1e13"),
                "password", "ATHENA.MIT.EDUraeburn", 1200, 32
            ),

            #test case 4 / 256 bit
            (
                unhexlify("d1daa78615f287e6a1c8b120d7062a493f98d203e6be49a6adf4fa574b6e64ee"),
                "password", '\x12\x34\x56\x78\x78\x56\x34\x12', 5, 32
            ),

            #test case 5 / 256 bit
            (
                unhexlify("139c30c0966bc32ba55fdbf212530ac9c5ec59f1a452f5cc9ad940fea0598ed1"),
                "X"*64, "pass phrase equals block size", 1200, 32
            ),

            #test case 6 / 256 bit
            (
                unhexlify("9ccad6d468770cd51b10e6a68721be611a8b4d282601db3b36be9246915ec82a"),
                "X"*65, "pass phrase exceeds block size", 1200, 32
            ),
        ])

    def test_invalid_values(self):

        #invalid rounds
        self.assertRaises(ValueError, pbkdf2.pbkdf2, 'password', 'salt', -1, 16)
        self.assertRaises(ValueError, pbkdf2.pbkdf2, 'password', 'salt', 0, 16)
        self.assertRaises(TypeError, pbkdf2.pbkdf2, 'password', 'salt', 'x', 16)

        #invalid keylen
        self.assertRaises(ValueError, pbkdf2.pbkdf2, 'password', 'salt', 1, 20*(2**32-1)+1)

        #invalid salt type
        self.assertRaises(TypeError, pbkdf2.pbkdf2, 'password', 5, 1, 10)

        #invalid secret type
        self.assertRaises(TypeError, pbkdf2.pbkdf2, 5, 'salt', 1, 10)

        #invalid hash
        self.assertRaises(ValueError, pbkdf2.pbkdf2, 'password', 'salt', 1, 16, 'hmac-foo')
        self.assertRaises(ValueError, pbkdf2.pbkdf2, 'password', 'salt', 1, 16, 'foo')
        self.assertRaises(TypeError, pbkdf2.pbkdf2, 'password', 'salt', 1, 16, 5)

    def test_hmac_sha1(self):
        "test independant hmac_sha1() method"
        self.assertEqual(
            pbkdf2.hmac_sha1("secret", "salt"),
            '\xfc\xd4\x0c;]\r\x97\xc6\xf1S\x8d\x93\xb9\xeb\xc6\x00\x04.\x8b\xfe'
            )

    def test_hmac_sha1_string(self):
        "test various prf values"
        self.assertEqual(
            pbkdf2.pbkdf2(u"secret", u"salt", 10, 16, "hmac-sha1"),
            '\xe2H\xfbk\x136QF\xf8\xacc\x07\xcc"(\x12'
        )

    def test_sha512_string(self):
        "test alternate digest string (sha512)"
        self.assertFunctionResults(pbkdf2.pbkdf2, [
            # result, secret, salt, rounds, keylen, digest="sha1"

            #case taken from example in http://grub.enbug.org/Authentication
            (
               unhexlify("887CFF169EA8335235D8004242AA7D6187A41E3187DF0CE14E256D85ED97A97357AAA8FF0A3871AB9EEFF458392F462F495487387F685B7472FC6C29E293F0A0"),
               "hello",
               unhexlify("9290F727ED06C38BA4549EF7DE25CF5642659211B7FC076F2D28FEFD71784BB8D8F6FB244A8CC5C06240631B97008565A120764C0EE9C2CB0073994D79080136"),
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
               unhexlify("887CFF169EA8335235D8004242AA7D6187A41E3187DF0CE14E256D85ED97A97357AAA8FF0A3871AB9EEFF458392F462F495487387F685B7472FC6C29E293F0A0"),
               "hello",
               unhexlify("9290F727ED06C38BA4549EF7DE25CF5642659211B7FC076F2D28FEFD71784BB8D8F6FB244A8CC5C06240631B97008565A120764C0EE9C2CB0073994D79080136"),
               10000, 64, prf,
            ),
        ])

if (not pbkdf2._EVP and enable_option("active-backends", "all-backends")) or (pbkdf2._EVP and enable_option("active-backends")):
    class Builtin_Pbkdf2BackendTest(_Pbkdf2BackendTest):
        case_prefix = "builtin pbkdf2() backend"
        enable_m2crypto = False

if pbkdf2._EVP and enable_option("active-backends"):

    class M2Crypto_Pbkdf2BackendTest(_Pbkdf2BackendTest):
        case_prefix = "m2crypto pbkdf2() backend"
        enable_m2crypto = True

#=========================================================
#EOF
#=========================================================
