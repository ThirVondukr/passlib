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
from passlib.utils import h64, des
from passlib.utils.md4 import md4
from passlib.tests.utils import TestCase, Params as ak
#=========================================================
#byte funcs
#=========================================================
class BytesTest(TestCase):

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

#=========================================================
#test slow_bcrypt module
#=========================================================
from passlib.utils import _slow_bcrypt as slow_bcrypt

class BCryptUtilTest(TestCase):
    "test passlib.utils._slow_bcrypt utility funcs"

    def test_encode64(self):
        encode = slow_bcrypt.encode_base64
        self.assertFunctionResults(encode, [
            ('', ''),
            ('..', '\x00'),
            ('...', '\x00\x00'),
            ('....', '\x00\x00\x00'),
            ('9u', '\xff'),
            ('996', '\xff\xff'),
            ('9999', '\xff\xff\xff'),
            ])

    def test_decode64(self):
        decode = slow_bcrypt.decode_base64
        self.assertFunctionResults(decode, [
            ('', ''),
            ('\x00', '..'),
            ('\x00\x00', '...'),
            ('\x00\x00\x00', '....'),
            ('\xff', '9u', ),
            ('\xff\xff','996'),
            ('\xff\xff\xff','9999'),
            ])


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

    def test_decode_bytes_padding(self):
        for source, result in self.decode_padding_bytes:
            out = h64.decode_bytes(source)
            self.assertEqual(out, result)

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

#=========================================================
#EOF
#=========================================================
