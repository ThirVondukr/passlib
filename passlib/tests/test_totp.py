"""passlib.tests -- test passlib.totp"""
#=============================================================================
# imports
#=============================================================================
from __future__ import unicode_literals
# core
from passlib.utils.compat import PY3
import base64
import datetime
from functools import partial
import logging; log = logging.getLogger(__name__)
import random
import sys
import time as _time
# site
# pkg
from passlib import exc
from passlib.utils import to_bytes, to_unicode
from passlib.utils.compat import unicode, u
from passlib.tests.utils import TestCase, time_call
# local
__all__ = [
    "EngineTest",
]

#=============================================================================
# helpers
#=============================================================================

# XXX: python 3 changed what error base64.b16decode() throws, from TypeError to base64.Error().
#      it wasn't until 3.3 that base32decode() also got changed.
#      really should normalize this in the code to a single BinaryDecodeError,
#      predicting this cross-version is getting unmanagable.
Base32DecodeError = Base16DecodeError = TypeError
if sys.version_info >= (3,0):
    from binascii import Error as Base16DecodeError
if sys.version_info >= (3,3):
    from binascii import Error as Base32DecodeError

PASS1 = "abcdef"
PASS2 = b"\x00\xFF"
KEY1 = '4AOGGDBBQSYHNTUZ'
KEY1_RAW = b'\xe0\x1cc\x0c!\x84\xb0v\xce\x99'
KEY2_RAW = b'\xee]\xcb9\x870\x06 D\xc8y/\xa54&\xe4\x9c\x13\xc2\x18'
KEY3 = 'S3JDVB7QD2R7JPXX' # used in docstrings
KEY4 = 'JBSWY3DPEHPK3PXP' # from google keyuri spec

# NOTE: for randtime() below,
#       * want at least 7 bits on fractional side, to test fractional times to at least 0.01s precision
#       * want at least 32 bits on integer side, to test for 32-bit epoch issues.
#       most systems *should* have 53 bit mantissa, leaving plenty of room on both ends,
#       so using (1<<37) as scale, to allocate 16 bits on fractional side, but generate reasonable # of > 1<<32 times.
#       sanity check that we're above 44 ensures minimum requirements (44 - 37 int = 7 frac)
assert sys.float_info.radix == 2, "unexpected float_info.radix"
assert sys.float_info.mant_dig >= 44, "double precision unexpectedly small"

# work out maximum value acceptable by hosts's time_t
# this is frequently 2**37, though smaller on some systems.
max_time_t = 30
while True:
    try:
        datetime.datetime.utcfromtimestamp(max_time_t << 1)
        max_time_t <<= 1
    except ValueError:
        break

def randtime():
    """return random epoch time"""
    return random.random() * max_time_t

def randcounter():
    """return random counter"""
    return random.randint(0, (1 << 32) - 1)

#=============================================================================
# util tests
#=============================================================================

class UtilsTest(TestCase):
    descriptionPrefix = "passlib.totp"

    #=============================================================================
    # encrypt_key() & decrypt_key() helpers
    #=============================================================================
    def test_decrypt_key(self):
        """decrypt_key()"""
        from passlib.totp import decrypt_key, ENCRYPTED_TOTP

        # reference v2 key
        CIPHER1 = '2-D-6D7N7W53O7HHS37NLUFQ-MHCTEGSNPFN5CGBJ'
        if ENCRYPTED_TOTP:
            self.assertEqual(decrypt_key(CIPHER1, PASS1), KEY1_RAW)
        else:
            self.assertRaises(RuntimeError, decrypt_key, CIPHER1, PASS1)
            raise self.skipTest("'cryptography' package not installed")

        # base32, should be case insensitive
        self.assertEqual(decrypt_key(CIPHER1.lower(), PASS1), KEY1_RAW)

        # different salt
        CIPHER2 = '2-D-SPZJ54Y6IPUD2BYA4C6A-ZGDXXTVQOWYLC2AU'
        self.assertEqual(decrypt_key(CIPHER2, PASS1), KEY1_RAW)

        # different sized key, password, and cost
        CIPHER3 = '2-8-FCCTARTIJWE7CPQHUDKA-D2DRS32YESGHHINWFFCELKN7Z6NAHM4M'
        self.assertEqual(decrypt_key(CIPHER3, PASS2), KEY2_RAW)

        # wrong password should silently result in wrong key, rather than throwing error
        other = decrypt_key(CIPHER1, PASS2)
        self.assertEqual(other, b'\xafD6.F7\xeb\x19\x05Q')

        # malformed strings
        def assert_malformed(enckey):
            self.assertRaisesRegex(ValueError, "malformed .* data", decrypt_key, enckey, PASS1)
        assert_malformed("abc") # unrecognized string
        assert_malformed('2-C-EISCJBCQVL2V4C7') # too few sections
        assert_malformed('2-C-EISCJBCQVL2V4C7-KTTAWJP2RT4MYGWR-FOO') # too many sections
        assert_malformed('2-C-EISCJBCQVL2V4C@-KTTAWJP2RT4MYGWR') # invalid char in salt
        assert_malformed('2-C-EISCJBCQVL2V4C-KTTAWJP2RT4MYGWR') # invalid size of b32 encoded salt
        self.assertRaisesRegex(ValueError, "unknown .* version", decrypt_key, '9' + CIPHER1[1:], PASS1) # unknown version

    def test_decrypt_key_using_v1(self):
        """decrypt_key() -- legacy formats"""
        from passlib.totp import decrypt_key

        # v1 encoding of KEY1
        CIPHER = '1-C-EISCJBCQVL2V4C7B-KTTAWJP2RT4MYGWR'
        self.assertEqual(decrypt_key(CIPHER, PASS1), KEY1_RAW)

        # v1 encoding of KEY2
        CIPHER = '1-8-5HOZXE2SVJ2Q5QPY-ZI2WYDXLIMTPU5UIMFSJJOEPJLSI2Q6Q'
        self.assertEqual(decrypt_key(CIPHER, PASS2), KEY2_RAW)

    def test_encrypt_key(self):
        """encrypt_key()"""
        from passlib.totp import encrypt_key, decrypt_key, ENCRYPTED_TOTP

        if not ENCRYPTED_TOTP:
            self.assertRaises(RuntimeError, encrypt_key, KEY1_RAW, PASS1)
            raise self.skipTest("'cryptography' package not installed")

        def test(key, pwd, **k):
            result = encrypt_key(key, pwd, **k)
            self.assertRegex(result, "^2-[A-F0-9]+-[A-Z0-9]+-[A-Z0-9]+$") # has right format
            self.assertEqual(decrypt_key(result, pwd), key) # decrypts correctly
            return result

        # basic behavior
        result = test(KEY1_RAW, PASS1)
        self.assertEqual(len(result), 41) # expected size based on default salt size

        # creates new salt each time
        other = encrypt_key(KEY1_RAW, PASS1)
        self.assertNotEqual(other, result)

        # custom cost
        result = test(KEY1_RAW, PASS1, cost=10)
        self.assertTrue(result.startswith("2-A-"))

        # larger key
        result2 = test(KEY2_RAW, PASS1)
        self.assertEqual(len(result2), 57) # expected size based on default salt size

        # border case: empty key
        # XXX: might want to allow this, but documenting behavior for now
        self.assertRaises(ValueError, encrypt_key, b"", PASS1)

        # border case: empty password
        test(KEY1_RAW, "")

        # border case: password as bytes
        result = encrypt_key(KEY1_RAW, PASS2)
        self.assertEqual(decrypt_key(result, PASS2), KEY1_RAW)

    def test_encrypt_key_salt_size(self):
        """ENCRYPT_SALT_SIZE"""
        from passlib.totp import encrypt_key, ENCRYPTED_TOTP
        from passlib import totp

        if not ENCRYPTED_TOTP:
            raise self.skipTest("'cryptography' package not installed")

        self.addCleanup(setattr, totp, "ENCRYPT_SALT_SIZE", totp.ENCRYPT_SALT_SIZE)

        totp.ENCRYPT_SALT_SIZE = 10
        result = encrypt_key(KEY1_RAW, PASS1)

        totp.ENCRYPT_SALT_SIZE = 30
        result2 = encrypt_key(KEY1_RAW, PASS1)

        self.assertEqual(len(result2), len(result) + (30-10) * 8/5.0)

    def test_encrypt_key_cost(self):
        """ENCRYPT_COST"""
        from passlib.totp import encrypt_key, ENCRYPTED_TOTP
        from passlib import totp

        if not ENCRYPTED_TOTP:
            raise self.skipTest("'cryptography' package not installed")

        self.addCleanup(setattr, totp, "ENCRYPT_COST", totp.ENCRYPT_COST)

        # time default cost
        totp.ENCRYPT_COST -= 2
        delta, _ = time_call(partial(encrypt_key, KEY1_RAW, PASS1), maxtime=0)

        # this should take (2**3=8) times as long
        totp.ENCRYPT_COST += 3
        delta2, _ = time_call(partial(encrypt_key, KEY1_RAW, PASS1), maxtime=0)

        self.assertAlmostEqual(delta2, delta*8, delta=(delta*8)*0.5)

    #=============================================================================
    # client offset helpers
    #=============================================================================

    # sample history used by suggest_offset() test
    history1 = [
         (1420563115, 0),  # -25
         (1420563140, 0),  # -20
         (1420563246, 0),  #  -6
         (1420563363, -1), # -33
         (1420563681, 0),  # -21
         (1420569854, 0),  # -14
         (1420571296, 0),  # -16
         (1420579589, 0),  # -29
         (1420580848, 0),  # -28
         (1420580989, 0),  # -19
         (1420581126, -1), # -36
         (1420582973, 0),  # -23
         (1420583342, -1), # -32
    ]

    def test_suggest_offset(self):
        """suggest_offset()"""
        from passlib.totp import suggest_offset, DEFAULT_OFFSET

        # test reference sample
        history1 = self.history1
        result1 = suggest_offset(history1, 30)
        self.assertAlmostEqual(result1, -9, delta=10)

        # translation by multiple of period should have no effect
        for diff in range(-3, 4):
            translate = diff * 30
            history2 = [(time + translate, diff) for time, diff in history1]
            self.assertEqual(suggest_offset(history2, 30), result1,
                                   msg="history1 translated by %ds: " % translate)

        # in general, translations shouldn't send value too far away from original
        # (may relax this for new situations)
        for translate in range(-30, 30):
            history2 = [(time + translate, diff) for time, diff in history1]
            self.assertAlmostEqual(suggest_offset(history2, 30), result1, delta=10,
                                   msg="history1 translated by %ds: " % translate)

        # handle 2 element history
        self.assertAlmostEqual(suggest_offset(history1[:2]), -9, delta=10)

        # handle 1 element history
        self.assertAlmostEqual(suggest_offset(history1[:1]), -9, delta=10)

        # empty history should use default
        self.assertAlmostEqual(suggest_offset([]), DEFAULT_OFFSET)
        self.assertAlmostEqual(suggest_offset([], default=-10), -10)

        # fuzz test on random values
        size = random.randint(0, 16)
        elems = [ (randtime(), random.randint(-2,3)) for _ in range(size)]
        suggest_offset(elems)

    #=============================================================================
    # eoc
    #=============================================================================

#=============================================================================
# common code
#=============================================================================

#: used as base value for RFC test vector keys
RFC_KEY_BYTES_20 = "12345678901234567890".encode("ascii")
RFC_KEY_BYTES_32 = (RFC_KEY_BYTES_20*2)[:32]
RFC_KEY_BYTES_64 = (RFC_KEY_BYTES_20*4)[:64]

class _BaseOTPTest(TestCase):
    """
    common code shared by TotpTest & HotpTest
    """
    #=============================================================================
    # class attrs
    #=============================================================================

    #: BaseOTP subclass we're testing.
    OtpType = None

    #=============================================================================
    # setup
    #=============================================================================
    def setUp(self):
        super(_BaseOTPTest, self).setUp()

        # clear norm_hash_name() cache so 'unknown hash' warnings get emitted each time
        from passlib.crypto.digest import lookup_hash
        lookup_hash.clear_cache()

    #=============================================================================
    # subclass utils
    #=============================================================================
    def randotp(self, **kwds):
        """
        helper which generates a random OtpType instance.
        """
        if "key" not in kwds:
            kwds['new'] = True
        kwds.setdefault("digits", random.randint(6, 10))
        kwds.setdefault("alg", random.choice(["sha1", "sha256", "sha512"]))
        return self.OtpType(**kwds)

    def test_randotp(self):
        """
        internal test -- randotp()
        """
        otp1 = self.randotp()
        otp2 = self.randotp()

        self.assertNotEqual(otp1.key, otp2.key, "key not randomized:")

        # NOTE: has (1/5)**10 odds of failure
        for _ in range(10):
            if otp1.digits != otp2.digits:
                break
            otp2 = self.randotp()
        else:
            self.fail("digits not randomized")

        # NOTE: has (1/3)**10 odds of failure
        for _ in range(10):
            if otp1.alg != otp2.alg:
                break
            otp2 = self.randotp()
        else:
            self.fail("alg not randomized")

    #=============================================================================
    # constructor
    #=============================================================================
    def test_ctor_w_new(self):
        """constructor -- 'new'  parameter"""
        OTP = self.OtpType

        # exactly one of 'key' or 'new' is required
        self.assertRaises(TypeError, OTP)
        self.assertRaises(TypeError, OTP, key='4aoggdbbqsyhntuz', new=True)

        # generates new key
        otp = OTP(new=True)
        otp2 = OTP(new=True)
        self.assertNotEqual(otp.key, otp2.key)

    def test_ctor_w_size(self):
        """constructor -- 'size'  parameter"""
        OTP = self.OtpType

        # should default to digest size, per RFC
        self.assertEqual(len(OTP(new=True, alg="sha1").key), 20)
        self.assertEqual(len(OTP(new=True, alg="sha256").key), 32)
        self.assertEqual(len(OTP(new=True, alg="sha512").key), 64)

        # explicit key size
        self.assertEqual(len(OTP(new=True, size=10).key), 10)
        self.assertEqual(len(OTP(new=True, size=16).key), 16)

        # for new=True, maximum size enforced (based on alg)
        self.assertRaises(ValueError, OTP, new=True, size=21, alg="sha1")

        # for new=True, minimum size enforced
        self.assertRaises(ValueError, OTP, new=True, size=9)

        # for existing key, minimum size is only warned about
        with self.assertWarningList([
                dict(category=exc.PasslibSecurityWarning, message_re=".*for security purposes, secret key must be.*")
                ]):
            _ = OTP('0A'*9, 'hex')

    def test_ctor_w_key_and_format(self):
        """constructor -- 'key' and 'format' parameters"""
        OTP = self.OtpType

        # handle base32 encoding (the default)
        self.assertEqual(OTP(KEY1).key, KEY1_RAW)

            # .. w/ lower case
        self.assertEqual(OTP(KEY1.lower()).key, KEY1_RAW)

            # .. w/ spaces (e.g. user-entered data)
        self.assertEqual(OTP(' 4aog gdbb qsyh ntuz ').key, KEY1_RAW)

            # .. w/ invalid char
        self.assertRaises(Base32DecodeError, OTP, 'ao!ggdbbqsyhntuz')

        # handle hex encoding
        self.assertEqual(OTP('e01c630c2184b076ce99', 'hex').key, KEY1_RAW)

            # .. w/ invalid char
        self.assertRaises(Base16DecodeError, OTP, 'X01c630c2184b076ce99', 'hex')

        # handle raw bytes
        self.assertEqual(OTP(KEY1_RAW, "raw").key, KEY1_RAW)

    def test_ctor_w_alg(self):
        """constructor -- 'alg' parameter"""
        OTP = self.OtpType

        # normalize hash names
        self.assertEqual(OTP(KEY1, alg="SHA-256").alg, "sha256")
        self.assertEqual(OTP(KEY1, alg="SHA256").alg, "sha256")

        # invalid alg
        self.assertRaises(ValueError, OTP, KEY1, alg="SHA-333")

    def test_ctor_w_digits(self):
        """constructor -- 'digits' parameter"""
        OTP = self.OtpType
        self.assertRaises(ValueError, OTP, KEY1, digits=5)
        self.assertEqual(OTP(KEY1, digits=6).digits, 6)  # min value
        self.assertEqual(OTP(KEY1, digits=10).digits, 10)  # max value
        self.assertRaises(ValueError, OTP, KEY1, digits=11)

    def test_ctor_w_label(self):
        """constructor -- 'label' parameter"""
        OTP = self.OtpType
        self.assertEqual(OTP(KEY1).label, None)
        self.assertEqual(OTP(KEY1, label="foo@bar").label, "foo@bar")
        self.assertRaises(ValueError, OTP, KEY1, label="foo:bar")

    def test_ctor_w_issuer(self):
        """constructor -- 'issuer' parameter"""
        OTP = self.OtpType
        self.assertEqual(OTP(KEY1).issuer, None)
        self.assertEqual(OTP(KEY1, issuer="foo.com").issuer, "foo.com")
        self.assertRaises(ValueError, OTP, KEY1, issuer="foo.com:bar")

    # NOTE: 'dirty' is internal parameter,
    #       tested via .generate_next(), .verify_next(),
    #       and to_string() / from_string()

    #=============================================================================
    # internal helpers
    #=============================================================================

    def test_normalize_token(self):
        """normalize_token()"""
        otp = self.randotp(digits=7)

        self.assertEqual(otp.normalize_token('1234567'), '1234567')
        self.assertEqual(otp.normalize_token(b'1234567'), '1234567')

        self.assertEqual(otp.normalize_token(1234567), '1234567')
        self.assertEqual(otp.normalize_token(234567), '0234567')

        self.assertRaises(TypeError, otp.normalize_token, 1234567.0)
        self.assertRaises(TypeError, otp.normalize_token, None)

        self.assertRaises(ValueError, otp.normalize_token, '123456')
        self.assertRaises(ValueError, otp.normalize_token, '01234567')

    #=============================================================================
    # key attrs
    #=============================================================================

    def test_key_attrs(self):
        """pretty_key() and .key attributes"""
        OTP = self.OtpType

        # test key attrs
        otp = OTP(KEY1_RAW, "raw")
        self.assertEqual(otp.key, KEY1_RAW)
        self.assertEqual(otp.hex_key, 'e01c630c2184b076ce99')
        self.assertEqual(otp.base32_key, KEY1)

        # test pretty_key()
        self.assertEqual(otp.pretty_key(), '4AOG-GDBB-QSYH-NTUZ')
        self.assertEqual(otp.pretty_key(sep=" "), '4AOG GDBB QSYH NTUZ')
        self.assertEqual(otp.pretty_key(sep=False), KEY1)
        self.assertEqual(otp.pretty_key(format="hex"), 'e01c-630c-2184-b076-ce99')

        # quick fuzz test: make attr access works for random key & random size
        otp = OTP(new=True, size=random.randint(10, 20))
        _ = otp.hex_key
        _ = otp.base32_key
        _ = otp.pretty_key()

    #=============================================================================
    # eoc
    #=============================================================================

#=============================================================================
# TOTP
#=============================================================================
from passlib.totp import TOTP

class TotpTest(_BaseOTPTest):
    #=============================================================================
    # class attrs
    #=============================================================================
    descriptionPrefix = "passlib.totp.TOTP"
    OtpType = TOTP

    #=============================================================================
    # test vectors
    #=============================================================================

    #: default options used by test vectors (unless otherwise stated)
    vector_defaults = dict(format="base32", alg="sha1", period=30, digits=8)

    #: various TOTP test vectors,
    #: each element in list has format [options, (time, token <, int(expires)>), ...]
    vectors = [

        #-------------------------------------------------------------------------
        # passlib test vectors
        #-------------------------------------------------------------------------

        # 10 byte key, 6 digits
        [dict(key="ACDEFGHJKL234567", digits=6),
            # test fencepost to make sure we're rounding right
            (1412873399, '221105'), # == 29 mod 30
            (1412873400, '178491'), # == 0 mod 30
            (1412873401, '178491'), # == 1 mod 30
            (1412873429, '178491'), # == 29 mod 30
            (1412873430, '915114'), # == 0 mod 30
        ],

        # 10 byte key, 8 digits
        [dict(key="ACDEFGHJKL234567", digits=8),
            # should be same as 6 digits (above), but w/ 2 more digits on left side of token.
            (1412873399, '20221105'), # == 29 mod 30
            (1412873400, '86178491'), # == 0 mod 30
            (1412873401, '86178491'), # == 1 mod 30
            (1412873429, '86178491'), # == 29 mod 30
            (1412873430, '03915114'), # == 0 mod 30
        ],

        # sanity check on key used in docstrings
        [dict(key="S3JD-VB7Q-D2R7-JPXX", digits=6),
            (1419622709, '000492'),
            (1419622739, '897212'),
        ],

        #-------------------------------------------------------------------------
        # reference vectors taken from http://tools.ietf.org/html/rfc6238, appendix B
        # NOTE: while appendix B states same key used for all tests, the reference
        #       code in the appendix repeats the key up to the alg's block size,
        #       and uses *that* as the secret... so that's what we're doing here.
        #-------------------------------------------------------------------------

        # sha1 test vectors
        [dict(key=RFC_KEY_BYTES_20, format="raw", alg="sha1"),
            (59, '94287082'),
            (1111111109, '07081804'),
            (1111111111, '14050471'),
            (1234567890, '89005924'),
            (2000000000, '69279037'),
            (20000000000, '65353130'),
        ],

        # sha256 test vectors
        [dict(key=RFC_KEY_BYTES_32, format="raw", alg="sha256"),
            (59, '46119246'),
            (1111111109, '68084774'),
            (1111111111, '67062674'),
            (1234567890, '91819424'),
            (2000000000, '90698825'),
            (20000000000, '77737706'),
        ],

        # sha512 test vectors
        [dict(key=RFC_KEY_BYTES_64, format="raw", alg="sha512"),
            (59, '90693936'),
            (1111111109, '25091201'),
            (1111111111, '99943326'),
            (1234567890, '93441116'),
            (2000000000, '38618901'),
            (20000000000, '47863826'),
        ],

        #-------------------------------------------------------------------------
        # other test vectors
        #-------------------------------------------------------------------------

        # generated at http://blog.tinisles.com/2011/10/google-authenticator-one-time-password-algorithm-in-javascript
        [dict(key="JBSWY3DPEHPK3PXP", digits=6), (1409192430, '727248'), (1419890990, '122419')],
        [dict(key="JBSWY3DPEHPK3PXP", digits=9, period=41), (1419891152, '662331049')],

        # found in https://github.com/eloquent/otis/blob/develop/test/suite/Totp/Value/TotpValueGeneratorTest.php, line 45
        [dict(key=RFC_KEY_BYTES_20, format="raw", period=60), (1111111111, '19360094')],
        [dict(key=RFC_KEY_BYTES_32, format="raw", alg="sha256", period=60), (1111111111, '40857319')],
        [dict(key=RFC_KEY_BYTES_64, format="raw", alg="sha512", period=60), (1111111111, '37023009')],

    ]

    def iter_test_vectors(self):
        """
        helper to iterate over test vectors.
        yields ``(totp, time, token, expires, prefix)`` tuples.
        """
        from passlib.totp import TOTP
        for row in self.vectors:
            kwds = self.vector_defaults.copy()
            kwds.update(row[0])
            for entry in row[1:]:
                if len(entry) == 3:
                    time, token, expires = entry
                else:
                    time, token = entry
                    expires = None
                # NOTE: not re-using otp between calls so that stateful methods
                #       (like .verify) don't have problems.
                log.debug("test vector: %r time=%r token=%r expires=%r", kwds, time, token, expires)
                otp = TOTP(**kwds)
                prefix = "alg=%r time=%r token=%r: " % (otp.alg, time, token)
                yield otp, time, token, expires, prefix

    #=============================================================================
    # subclass utils
    #=============================================================================
    def randotp(self, **kwds):
        """
        helper which generates a random .OtpType instance for testing.
        """
        if "period" not in kwds:
            kwds['period'] = random.randint(10, 120)
        return super(TotpTest, self).randotp(**kwds)

    #=============================================================================
    # constructor
    #=============================================================================

    # NOTE: common behavior handled by _BaseOTPTest

    def test_ctor_w_period(self):
        """constructor -- 'period' parameter"""
        OTP = self.OtpType

        # default
        self.assertEqual(OTP(KEY1).period, 30)

        # explicit value
        self.assertEqual(OTP(KEY1, period=63).period, 63)

        # reject wrong type
        self.assertRaises(TypeError, OTP, KEY1, period=1.5)
        self.assertRaises(TypeError, OTP, KEY1, period='abc')

        # reject non-positive values
        self.assertRaises(ValueError, OTP, KEY1, period=0)
        self.assertRaises(ValueError, OTP, KEY1, period=-1)

    def test_ctor_w_now(self):
        """constructor -- 'now' parameter"""

        # NOTE: reading time w/ normalize_time() to make sure custom .now actually has effect.

        # default -- time.time
        otp = self.randotp()
        self.assertIs(otp.now, _time.time)
        self.assertAlmostEqual(otp.normalize_time(None), int(_time.time()))

        # custom function
        counter = [123.12]
        def now():
            counter[0] += 1
            return counter[0]
        otp = self.randotp(now=now)
        # NOTE: TOTP() constructor currently invokes this twice, using up counter values 124 & 125
        self.assertEqual(otp.normalize_time(None), 126)
        self.assertEqual(otp.normalize_time(None), 127)

        # require callable
        self.assertRaises(TypeError, self.randotp, now=123)

        # require returns int/float
        msg_re = r"now\(\) function must return non-negative"
        self.assertRaisesRegex(AssertionError, msg_re, self.randotp, now=lambda : 'abc')

        # require returns non-negative value
        self.assertRaisesRegex(AssertionError, msg_re, self.randotp, now=lambda : -1)

    # NOTE: 'last_counter', '_history' are internal parameters,
    #       tested by from_string() / to_string().

    #=============================================================================
    # internal helpers
    #=============================================================================

    def test_normalize_time(self):
        """normalize_time()"""
        otp = self.randotp()

        for _ in range(10):
            time = randtime()
            tint = int(time)

            self.assertEqual(otp.normalize_time(time), tint)
            self.assertEqual(otp.normalize_time(tint + 0.5), tint)

            self.assertEqual(otp.normalize_time(tint), tint)

            dt = datetime.datetime.utcfromtimestamp(time)
            self.assertEqual(otp.normalize_time(dt), tint)

            otp.now = lambda: time
            self.assertEqual(otp.normalize_time(None), tint)

        self.assertRaises(TypeError, otp.normalize_time, '1234')

    #=============================================================================
    # key attrs
    #=============================================================================

    # NOTE: handled by _BaseOTPTest

    #=============================================================================
    # generate()
    #=============================================================================
    def test_totp_token(self):
        """generate() -- TotpToken() class"""
        from passlib.totp import TOTP, TotpToken

        # test known set of values
        otp = TOTP('s3jdvb7qd2r7jpxx')
        result = otp.generate(1419622739)
        self.assertIsInstance(result, TotpToken)
        self.assertEqual(result.token, '897212')
        self.assertEqual(result.counter, 47320757)
        ##self.assertEqual(result.start_time, 1419622710)
        self.assertEqual(result.expire_time, 1419622740)
        self.assertEqual(result, ('897212', 1419622740))
        self.assertEqual(len(result), 2)
        self.assertEqual(result[0], '897212')
        self.assertEqual(result[1], 1419622740)
        self.assertRaises(IndexError, result.__getitem__, -3)
        self.assertRaises(IndexError, result.__getitem__, 2)
        self.assertTrue(result)

        # time dependant bits...
        otp.now = lambda : 1419622739.5
        self.assertEqual(result.remaining, 0.5)
        self.assertTrue(result.valid)

        otp.now = lambda : 1419622741
        self.assertEqual(result.remaining, 0)
        self.assertFalse(result.valid)

        # same time -- shouldn't return same object, but should be equal
        result2 = otp.generate(1419622739)
        self.assertIsNot(result2, result)
        self.assertEqual(result2, result)

        # diff time in period -- shouldn't return same object, but should be equal
        result3 = otp.generate(1419622711)
        self.assertIsNot(result3, result)
        self.assertEqual(result3, result)

        # shouldn't be equal
        result4 = otp.generate(1419622999)
        self.assertNotEqual(result4, result)

    def test_generate(self):
        """generate()"""
        from passlib.totp import TOTP

        # generate token
        otp = TOTP(new=True)
        time = randtime()
        result = otp.generate(time)
        token = result.token
        self.assertIsInstance(token, unicode)
        start_time = result.counter * 30

        # should generate same token for next 29s
        self.assertEqual(otp.generate(start_time + 29).token, token)

        # and new one at 30s
        self.assertNotEqual(otp.generate(start_time + 30).token, token)

        # verify round-trip conversion of datetime
        dt = datetime.datetime.utcfromtimestamp(time)
        self.assertEqual(int(otp.normalize_time(dt)), int(time))

        # handle datetime object
        self.assertEqual(otp.generate(dt).token, token)

        # omitting value should use current time
        otp.now = lambda : time
        self.assertEqual(otp.generate().token, token)

        # reject invalid time
        self.assertRaises(ValueError, otp.generate, -1)

    def test_generate_w_reference_vectors(self, for_generate_next=False):
        """generate() -- reference vectors"""
        for otp, time, token, expires, prefix in self.iter_test_vectors():
            # should output correct token for specified time
            if for_generate_next:
                otp.now = lambda: time
                result = otp.generate_next()
            else:
                result = otp.generate(time)
            self.assertEqual(result.token, token, msg=prefix)
            self.assertEqual(result.counter, time // otp.period, msg=prefix)
            if expires:
                self.assertEqual(result.expire_time, expires)

    #=============================================================================
    # generate_next()
    #=============================================================================

    def test_generate_next(self):
        """generate_next()"""
        from passlib.totp import TOTP
        from passlib.exc import PasslibSecurityWarning

        # init random key & time
        time = randtime()
        otp = self.randotp()
        period = otp.period
        counter = otp._time_to_counter(time)
        start = counter * period
        self.assertFalse(otp.dirty)
        otp.now = lambda: time # fix generator's time for duration of test

        # generate token
        otp.last_counter = 0
        result = otp.generate_next()
        token = result.token
        self.assertEqual(result.counter, counter)
        ##self.assertEqual(result.start_time, start)
        self.assertEqual(otp.last_counter, counter)
        self.assertTrue(otp.verify(token, start))
        self.assertTrue(otp.dirty)

        # should generate same token for next 29s
        otp.last_counter = 0
        otp.dirty = False
        otp.now = lambda : start + period - 1
        self.assertEqual(otp.generate_next().token, token)
        self.assertEqual(otp.last_counter, counter)
        self.assertTrue(otp.dirty)

        # and new one at 30s
        otp.last_counter = 0
        otp.now = lambda : start + period
        token2 = otp.generate_next().token
        self.assertNotEqual(token2, token)
        self.assertEqual(otp.last_counter, counter + 1)
        self.assertTrue(otp.verify(token2, start + period))

        # check check we issue a warning time is earlier than last counter.
        otp.last_counter = counter + 1
        otp.now = lambda : time
        with self.assertWarningList([
                dict(message_re=".*earlier than last-used time.*", category=PasslibSecurityWarning),
                ]):
            self.assertTrue(otp.generate_next().token)
        self.assertEqual(otp.last_counter, counter)

    def test_generate_next_w_reuse_flag(self):
        """generate_next() -- reuse flag"""
        from passlib.totp import TOTP
        from passlib.exc import TokenReuseError
        otp = TOTP(new=True)
        token = otp.generate_next().token
        self.assertRaises(TokenReuseError, otp.generate_next)
        self.assertEqual(otp.generate_next(reuse=True).token, token)

    def test_generate_next_w_reference_vectors(self):
        """generate_next() -- reference vectors"""
        self.test_generate_w_reference_vectors(for_generate_next=True)

    #=============================================================================
    # TotpMatch() -- verify()'s return value
    #=============================================================================

    def test_totp_match_w_valid_token(self):
        """verify() -- valid TotpMatch object"""
        from passlib.totp import TotpMatch

        time = 141230981
        token = '781501'
        otp = TOTP(KEY3, now=lambda : time + 24 * 3600)
        result = otp.verify(token, time)

        # test type
        self.assertIsInstance(result, TotpMatch)

        # test attrs
        self.assertTrue(result.valid)
        self.assertAlmostEqual(result.offset, 0, delta=10) # xxx: alter this if suggest_offset() is updated?
        self.assertEqual(result.time, time)
        self.assertEqual(result.counter, time // 30)
        self.assertEqual(result.counter_offset, 0)
        self.assertEqual(result._previous_offset, 0)

        # test tuple
        self.assertEqual(len(result), 2)
        self.assertEqual(result, (True, result.offset))
        self.assertRaises(IndexError, result.__getitem__, -3)
        self.assertEqual(result[0], True)
        self.assertEqual(result[1], result.offset)
        self.assertRaises(IndexError, result.__getitem__, 2)

        # test bool
        self.assertTrue(result)

    def test_totp_match_w_older_token(self):
        """verify() -- valid TotpMatch object with future token"""
        from passlib.totp import TotpMatch

        time = 141230981
        token = '781501'
        otp = TOTP(KEY3, now=lambda : time + 24 * 3600)
        result = otp.verify(token, time - 30)

        # test type
        self.assertIsInstance(result, TotpMatch)

        # test attrs
        self.assertTrue(result.valid)
        self.assertAlmostEqual(result.offset, 30, delta=10) # xxx: alter this if suggest_offset() is updated?
        self.assertEqual(result.time, time - 30)
        self.assertEqual(result.counter, time // 30)
        self.assertEqual(result.counter_offset, 1)
        self.assertEqual(result._previous_offset, 0)

        # test tuple
        self.assertEqual(len(result), 2)
        self.assertEqual(result, (True, result.offset))
        self.assertRaises(IndexError, result.__getitem__, -3)
        self.assertEqual(result[0], True)
        self.assertEqual(result[1], result.offset)
        self.assertRaises(IndexError, result.__getitem__, 2)

        # test bool
        self.assertTrue(result)

    def test_totp_match_w_new_token(self):
        """verify() -- valid TotpMatch object with past token"""
        from passlib.totp import TotpMatch

        time = 141230981
        token = '781501'
        otp = TOTP(KEY3, now=lambda : time + 24 * 3600)
        result = otp.verify(token, time + 30)

        # test type
        self.assertIsInstance(result, TotpMatch)

        # test attrs
        self.assertTrue(result.valid)
        # NOTE: may need to alter this next line if suggest_offset() is updated ...
        self.assertAlmostEqual(result.offset, -20, delta=10)
        self.assertEqual(result.time, time + 30)
        self.assertEqual(result.counter, time // 30)
        self.assertEqual(result.counter_offset, -1)
        self.assertEqual(result._previous_offset, 0)

        # test tuple
        self.assertEqual(len(result), 2)
        self.assertEqual(result, (True, result.offset))
        self.assertRaises(IndexError, result.__getitem__, -3)
        self.assertEqual(result[0], True)
        self.assertEqual(result[1], result.offset)
        self.assertRaises(IndexError, result.__getitem__, 2)

        # test bool
        self.assertTrue(result)

    def test_totp_match_w_invalid_token(self):
        """verify() -- invalid TotpMatch object"""
        from passlib.totp import TotpMatch

        time = 141230981
        token = '781501'
        otp = TOTP(KEY3, now=lambda : time + 24 * 3600)
        result = otp.verify(token, time + 60)

        # test type
        self.assertIsInstance(result, TotpMatch)

        # test attrs
        self.assertFalse(result.valid)
        self.assertEqual(result.offset, 0)
        self.assertEqual(result.time, time + 60)
        self.assertEqual(result.counter, 0)
        self.assertEqual(result.counter_offset, 0)
        self.assertEqual(result._previous_offset, 0)

        # test tuple
        self.assertEqual(len(result), 2)
        self.assertEqual(result, (False, result.offset))
        self.assertRaises(IndexError, result.__getitem__, -3)
        self.assertEqual(result[0], False)
        self.assertEqual(result[1], result.offset)
        self.assertRaises(IndexError, result.__getitem__, 2)

        # test bool
        self.assertFalse(result)

    #=============================================================================
    # verify()
    #=============================================================================

    def test_verify_w_window(self, for_verify_next=False):
        """verify() -- 'time' and 'window' parameters"""

        # init generator
        time = orig_time = randtime()
        otp = self.randotp()
        period = otp.period
        if for_verify_next:
            verify = self._create_verify_next_wrapper(otp)
        else:
            verify = otp.verify
        token = otp.generate(time).token

        # init test helper
        def test(correct_valid, correct_counter_offset, token, time, **kwds):
            """helper to test verify() output"""
            # NOTE: TotpMatch return type tested more throughly above ^^^
            result = verify(token, time, **kwds)
            msg = "key=%r alg=%r period=%r token=%r orig_time=%r time=%r:" % \
                  (otp.base32_key, otp.alg, otp.period, token, orig_time, time)
            self.assertEqual(result.valid, correct_valid, msg=msg)
            if correct_valid:
                self.assertEqual(result.counter_offset, correct_counter_offset)
            else:
                self.assertEqual(result.counter_offset, 0)
            self.assertEqual(otp.normalize_time(result.time), otp.normalize_time(time))

        #-------------------------------
        # basic validation, and 'window' parameter
        #-------------------------------

        # validate against previous counter (passes if window >= period)
        test(False, 0, token, time - period, window=0)
        test(True,  1, token, time - period, window=period)
        test(True,  1, token, time - period, window=2 * period)

        # validate against current counter
        test(True,  0, token, time, window=0)

        # validate against next counter (passes if window >= period)
        test(False, 0, token, time + period, window=0)
        test(True, -1, token, time + period, window=period)
        test(True, -1, token, time + period, window=2 * period)

        # validate against two time steps later (should never pass)
        test(False, 0, token, time + 2 * period, window=0)
        test(False, 0, token, time + 2 * period, window=period)
        test(True, -2, token, time + 2 * period, window=2 * period)

        # TODO: test window values that aren't multiples of period
        #       (esp ensure counter rounding works correctly)

        #-------------------------------
        # offset param
        #-------------------------------

        # TODO: test offset param

        # TODO: test offset + window

        #-------------------------------
        # time normalization
        #-------------------------------

        # handle datetimes
        dt = datetime.datetime.utcfromtimestamp(time)
        test(True, 0,       token, dt, window=0)

        # reject invalid time
        self.assertRaises(ValueError, otp.verify, token, -1)

    def test_verify_w_token_normalization(self, for_verify_next=False):
        """verify() -- token normalization"""
        # setup test helper
        otp = TOTP('otxl2f5cctbprpzx')
        if for_verify_next:
            verify = self._create_verify_next_wrapper(otp)
        else:
            verify = otp.verify
        time = 1412889861

        # separators / spaces should be stripped (orig token '332136')
        self.assertTrue(verify('    3 32-136  ', time).valid)

        # ascii bytes
        self.assertTrue(verify(b'332136', time).valid)

        # too few digits
        self.assertRaises(ValueError, verify, '12345', time)

        # invalid char
        self.assertRaises(ValueError, verify, '12345X', time)

        # leading zeros count towards size
        self.assertRaises(ValueError, verify, '0123456', time)

    def test_verify_w_reference_vectors(self, for_verify_next=False):
        """verify() -- reference vectors"""
        for otp, time, token, expires, msg in self.iter_test_vectors():
            # create wrapper
            if for_verify_next:
                verify = self._create_verify_next_wrapper(otp)
            else:
                verify = otp.verify

            # token should verify against time
            if for_verify_next:
                real_offset = -divmod(time, otp.period)[1]
                msg = "%s(with next_offset=%r, real_offset=%r):" % (msg, otp._next_offset(time),
                                                                    real_offset)
            result = verify(token, time)
            self.assertTrue(result.valid, msg=msg)
            self.assertEqual(result.counter, time // otp.period, msg=msg)

            # should NOT verify against another time
            result = verify(token, time + 100, window=0)
            self.assertFalse(result.valid, msg=msg)

    #=============================================================================
    # verify_next()
    #=============================================================================
    def _create_verify_next_wrapper(self, otp):
        """
        returns a wrapper around verify_next()
        which makes it's signature & return match verify(),
        to helper out shared test code.
        """
        from passlib.totp import TotpMatch
        def wrapper(token, time, **kwds):
            # reset internal state
            time = otp.normalize_time(time)
            otp.last_counter = 0
            otp._history = None
            # fix current time
            orig = otp.now
            try:
                otp.now = lambda: time
                # run verify next w/in our sandbox
                offset = otp._next_offset(time)
                valid = otp.verify_next(token, **kwds)
            finally:
                otp.now = orig
            # create fake TotpMatch instance to return
            result = TotpMatch(valid, otp.last_counter, time, offset, otp.period)
            # check that history was populated correctly
            if valid:
                self.assertEqual(otp._history[0][1], result.counter_offset)
            else:
                self.assertEqual(otp._history, None)
            return result
        return wrapper

    def test_verify_next_w_window(self):
        """verify_next() -- 'window' parameter"""
        self.test_verify_w_window(for_verify_next=True)

    def test_verify_next_w_token_normalization(self):
        """verify_next() -- token normalization"""
        self.test_verify_w_token_normalization(for_verify_next=True)

    def test_verify_next_w_last_counter(self):
        """verify_next() -- 'last_counter' and '_history' attributes"""
        from passlib.exc import TokenReuseError

        # init generator
        otp = self.randotp()
        period = otp.period

        time = randtime()
        result = otp.generate(time)
        self.assertEqual(otp.last_counter, 0) # ensure generate() didn't touch it
        token = result.token
        counter = result.counter
        otp.now = lambda : time # fix verify_next() time for duration of test

        # verify token
        self.assertTrue(otp.verify_next(token))
        self.assertEqual(otp.last_counter, counter)

        # test reuse policies
        self.assertRaises(TokenReuseError, otp.verify_next, token)
        self.assertRaises(TokenReuseError, otp.verify_next, token, reuse=False)
        self.assertTrue(otp.verify_next(token, reuse=True))
        self.assertEqual(otp.last_counter, counter)

        # should reject older token even if within window
        otp.last_counter = counter
        old_token = otp.generate(time - period).token
        self.assertFalse(otp.verify_next(old_token))
        self.assertFalse(otp.verify_next(old_token, reuse="ignore"))
        self.assertFalse(otp.verify_next(old_token, reuse="allow"))
        self.assertEqual(otp.last_counter, counter)

        # next token should advance .last_counter
        otp.last_counter = counter
        token2 = otp.generate(time + period).token
        otp.now = lambda: time + period
        self.assertTrue(otp.verify_next(token2))
        self.assertEqual(otp.last_counter, counter + 1)

    # TODO: test history & suggested offset for next time.

    # TODO: test dirty flag behavior

    def test_verify_next_w_reference_vectors(self):
        """verify_next() -- reference vectors"""
        self.test_verify_w_reference_vectors(for_verify_next=True)

    #=============================================================================
    # uri serialization
    #=============================================================================
    def test_from_uri(self):
        """from_uri()"""
        from passlib.totp import from_uri, TOTP

        # URIs from https://code.google.com/p/google-authenticator/wiki/KeyUriFormat

        #--------------------------------------------------------------------------------
        # canonical uri
        #--------------------------------------------------------------------------------
        otp = from_uri("otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&"
                       "issuer=Example")
        self.assertIsInstance(otp, TOTP)
        self.assertEqual(otp.key, b'Hello!\xde\xad\xbe\xef')
        self.assertEqual(otp.label, "alice@google.com")
        self.assertEqual(otp.issuer, "Example")
        self.assertEqual(otp.alg, "sha1") # default
        self.assertEqual(otp.period, 30) # default
        self.assertEqual(otp.digits, 6) # default

        #--------------------------------------------------------------------------------
        # secret param
        #--------------------------------------------------------------------------------

        # secret case insensitive
        otp = from_uri("otpauth://totp/Example:alice@google.com?secret=jbswy3dpehpk3pxp&"
                       "issuer=Example")
        self.assertEqual(otp.key, b'Hello!\xde\xad\xbe\xef')

        # missing secret
        self.assertRaises(ValueError, from_uri, "otpauth://totp/Example:alice@google.com?digits=6")

        # undecodable secret
        self.assertRaises(Base32DecodeError, from_uri, "otpauth://totp/Example:alice@google.com?"
                                                       "secret=JBSWY3DPEHP@3PXP")

        #--------------------------------------------------------------------------------
        # label param
        #--------------------------------------------------------------------------------

        # w/ encoded space
        otp = from_uri("otpauth://totp/Provider1:Alice%20Smith?secret=JBSWY3DPEHPK3PXP&"
                       "issuer=Provider1")
        self.assertEqual(otp.label, "Alice Smith")
        self.assertEqual(otp.issuer, "Provider1")

        # w/ encoded space and colon
        # (note url has leading space before 'alice') -- taken from KeyURI spec
        otp = from_uri("otpauth://totp/Big%20Corporation%3A%20alice@bigco.com?"
                       "secret=JBSWY3DPEHPK3PXP")
        self.assertEqual(otp.label, "alice@bigco.com")
        self.assertEqual(otp.issuer, "Big Corporation")

        #--------------------------------------------------------------------------------
        # issuer param / prefix
        #--------------------------------------------------------------------------------

        # 'new style' issuer only
        otp = from_uri("otpauth://totp/alice@bigco.com?secret=JBSWY3DPEHPK3PXP&issuer=Big%20Corporation")
        self.assertEqual(otp.label, "alice@bigco.com")
        self.assertEqual(otp.issuer, "Big Corporation")

        # new-vs-old issuer mismatch
        self.assertRaises(ValueError, TOTP.from_uri,
                          "otpauth://totp/Provider1:alice?secret=JBSWY3DPEHPK3PXP&issuer=Provider2")

        #--------------------------------------------------------------------------------
        # algorithm param
        #--------------------------------------------------------------------------------

        # custom alg
        otp = from_uri("otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&algorithm=SHA256")
        self.assertEqual(otp.alg, "sha256")

        # unknown alg
        self.assertRaises(ValueError, from_uri, "otpauth://totp/Example:alice@google.com?"
                                                "secret=JBSWY3DPEHPK3PXP&algorithm=SHA333")

        #--------------------------------------------------------------------------------
        # digit param
        #--------------------------------------------------------------------------------

        # custom digits
        otp = from_uri("otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&digits=8")
        self.assertEqual(otp.digits, 8)

        # digits out of range / invalid
        self.assertRaises(ValueError, from_uri, "otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&digits=A")
        self.assertRaises(ValueError, from_uri, "otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&digits=%20")
        self.assertRaises(ValueError, from_uri, "otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&digits=15")

        #--------------------------------------------------------------------------------
        # period param
        #--------------------------------------------------------------------------------

        # custom period
        otp = from_uri("otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&period=63")
        self.assertEqual(otp.period, 63)

        # reject period < 1
        self.assertRaises(ValueError, from_uri, "otpauth://totp/Example:alice@google.com?"
                                                "secret=JBSWY3DPEHPK3PXP&period=0")

        self.assertRaises(ValueError, from_uri, "otpauth://totp/Example:alice@google.com?"
                                                "secret=JBSWY3DPEHPK3PXP&period=-1")

        #--------------------------------------------------------------------------------
        # unrecognized param
        #--------------------------------------------------------------------------------

        # should issue warning, but otherwise ignore extra param
        with self.assertWarningList([
            dict(category=exc.PasslibRuntimeWarning, message_re="unexpected parameters encountered")
        ]):
            otp = from_uri("otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&"
                           "foo=bar&period=63")
        self.assertEqual(otp.base32_key, KEY4)
        self.assertEqual(otp.period, 63)

    def test_to_uri(self):
        """to_uri()"""

        #-------------------------------------------------------------------------
        # label & issuer parameters
        #-------------------------------------------------------------------------

        # with label & issuer
        otp = TOTP(KEY4, alg="sha1", digits=6, period=30)
        self.assertEqual(otp.to_uri("alice@google.com", "Example Org"),
                         "otpauth://totp/alice@google.com?secret=JBSWY3DPEHPK3PXP&"
                         "issuer=Example%20Org")

        # label is required
        self.assertRaises(ValueError, otp.to_uri, None, "Example Org")

        # with label only
        self.assertEqual(otp.to_uri("alice@google.com"),
                         "otpauth://totp/alice@google.com?secret=JBSWY3DPEHPK3PXP")

        # with default label from constructor
        otp.label = "alice@google.com"
        self.assertEqual(otp.to_uri(),
                         "otpauth://totp/alice@google.com?secret=JBSWY3DPEHPK3PXP")

        # with default label & default issuer from constructor
        otp.issuer = "Example Org"
        self.assertEqual(otp.to_uri(),
                         "otpauth://totp/alice@google.com?secret=JBSWY3DPEHPK3PXP"
                         "&issuer=Example%20Org")

        # reject invalid label
        self.assertRaises(ValueError, otp.to_uri, "label:with:semicolons")

        # reject invalid issue
        self.assertRaises(ValueError, otp.to_uri, "alice@google.com", "issuer:with:semicolons")

        #-------------------------------------------------------------------------
        # algorithm parameter
        #-------------------------------------------------------------------------
        self.assertEqual(TOTP(KEY4, alg="sha256").to_uri("alice@google.com"),
                         "otpauth://totp/alice@google.com?secret=JBSWY3DPEHPK3PXP&"
                         "algorithm=SHA256")

        #-------------------------------------------------------------------------
        # digits parameter
        #-------------------------------------------------------------------------
        self.assertEqual(TOTP(KEY4, digits=8).to_uri("alice@google.com"),
                         "otpauth://totp/alice@google.com?secret=JBSWY3DPEHPK3PXP&"
                         "digits=8")

        #-------------------------------------------------------------------------
        # period parameter
        #-------------------------------------------------------------------------
        self.assertEqual(TOTP(KEY4, period=63).to_uri("alice@google.com"),
                         "otpauth://totp/alice@google.com?secret=JBSWY3DPEHPK3PXP&"
                         "period=63")

    #=============================================================================
    # json serialization
    #=============================================================================

    # TODO: from_string()
    #           with uri
    #           without needed password
    #           with needed password
    #           with bad version, decode error

    # TODO: to_string()
    #           with password
    #           with custom cost
    #           with password=True

    # TODO: check history, last_counter are preserved

    #=============================================================================
    # eoc
    #=============================================================================

#=============================================================================
# HOTP
#=============================================================================
from passlib.totp import HOTP

class HotpTest(_BaseOTPTest):
    #=============================================================================
    # class attrs
    #=============================================================================
    descriptionPrefix = "passlib.totp.HOTP"
    OtpType = HOTP

    #=============================================================================
    # test vectors
    #=============================================================================

    #: default options used by test vectors (unless otherwise stated)
    vector_defaults = dict(format="base32", alg="sha1")

    #: various TOTP test vectors,
    #: each element in list has format [options, (counter, token), ...]
    vectors = [

        #-------------------------------------------------------------------------
        # reference vectors taken from http://tools.ietf.org/html/rfc4226, appendix D
        #-------------------------------------------------------------------------

        # table 2 "decimal" column
        [dict(key=RFC_KEY_BYTES_20, format="raw", digits=10),
            (0, '1284755224'),
            (1, '1094287082'),
            (2, '0137359152'),
            (3, '1726969429'),
            (4, '1640338314'),
            (5, '0868254676'),
            (6, '1918287922'),
            (7, '0082162583'),
            (8, '0673399871'),
            (9, '0645520489'),
        ],

        # table 2 "HOTP" column
        [dict(key=RFC_KEY_BYTES_20, format="raw", digits=6),
            (0, '755224'),
            (1, '287082'),
            (2, '359152'),
            (3, '969429'),
            (4, '338314'),
            (5, '254676'),
            (6, '287922'),
            (7, '162583'),
            (8, '399871'),
            (9, '520489'),
        ],

        #-------------------------------------------------------------------------
        # test vectors from
        # https://github.com/eloquent/otis/blob/develop/test/suite/Hotp/Value/HotpValueTest.php
        #-------------------------------------------------------------------------

        # sha256 variant of RFC test vectors -- 10 digit token
        [dict(key=RFC_KEY_BYTES_20, format="raw", digits=10, alg="sha256"),
            (0, '2074875740'),
            (1, '1332247374'),
            (2, '1766254785'),
            (3, '0667496144'),
            (4, '1625480556'),
            (5, '0089697997'),
            (6, '0640191609'),
            (7, '1267579288'),
            (8, '1883895912'),
            (9, '0223184989'),
        ],

        # sha256 variant of RFC test vectors -- 6 digit token
        [dict(key=RFC_KEY_BYTES_20, format="raw", digits=6, alg="sha256"),
            (0, '875740'),
            (1, '247374'),
            (2, '254785'),
            (3, '496144'),
            (4, '480556'),
            (5, '697997'),
            (6, '191609'),
            (7, '579288'),
            (8, '895912'),
            (9, '184989'),
        ],

        # sha512 variant of RFC test vectors -- 10 digit token
        [dict(key=RFC_KEY_BYTES_20, format="raw", digits=10, alg="sha512"),
            (0, '0604125165'),
            (1, '0369342147'),
            (2, '0671730102'),
            (3, '0573778726'),
            (4, '1581937510'),
            (5, '1516848329'),
            (6, '0836266680'),
            (7, '0022588359'),
            (8, '0245039399'),
            (9, '1033643409'),
        ],

        # sha512 variant of RFC test vectors -- 6 digit token
        [dict(key=RFC_KEY_BYTES_20, format="raw", digits=6, alg="sha512"),
            (0, '125165'),
            (1, '342147'),
            (2, '730102'),
            (3, '778726'),
            (4, '937510'),
            (5, '848329'),
            (6, '266680'),
            (7, '588359'),
            (8, '039399'),
            (9, '643409'),
        ],

        #-------------------------------------------------------------------------
        # other test vectors
        #-------------------------------------------------------------------------

        # taken from example at
        # http://stackoverflow.com/questions/8529265/google-authenticator-implementation-in-python
        [dict(key='MZXW633PN5XW6MZX', digits=6),
            (1, '448400'),
            (2, '656122'),
            (3, '457125'),
            (4, '035022'),
            (5, '401553'),
            (6, '581333'),
            (7, '016329'),
            (8, '529359'),
            (9, '171710'),
        ],

        # source unknown
        [dict(key='MFRGGZDFMZTWQ2LK', digits=6),
            (1, '765705'),
            (2, '816065'),
            (4, '713385'),
        ],

    ]

    def iter_test_vectors(self):
        """
        helper to iterate over test vectors.
        yields ``(hotp_object, counter, token, prefix)`` tuples.
        """
        for row in self.vectors:
            kwds = self.vector_defaults.copy()
            kwds.update(row[0])
            for entry in row[1:]:
                counter, token = entry
                # NOTE: not re-using otp between calls so that stateful methods
                #       (like .verify) don't have problems.
                log.debug("test vector: %r counter=%r token=%r", kwds, counter, token)
                otp = HOTP(**kwds)
                prefix = "reference(key=%r, alg=%r, counter=%r, token=%r): " % (otp.base32_key, otp.alg, counter, token)
                yield otp, counter, token, prefix

    #=============================================================================
    # subclass utils
    #=============================================================================
    def randotp(self, **kwds):
        """
        helper which generates a random OtpType instance.
        """
        if "counter" not in kwds:
            kwds["counter"] = randcounter()
        return super(HotpTest, self).randotp(**kwds)

    #=============================================================================
    # constructor
    #=============================================================================

    # NOTE: common behavior handled by _BaseOTPTest

    def test_ctor_w_counter(self):
        """constructor -- 'counter' parameter"""

        # default
        otp = HOTP(KEY1)
        self.assertEqual(otp.counter, 0)

        # explicit value
        otp = HOTP(KEY1, counter=1234)
        self.assertEqual(otp.counter, 1234)

        # reject wrong type
        self.assertRaises(TypeError, HOTP, KEY1, counter=1.0)
        self.assertRaises(TypeError, HOTP, KEY1, counter='abc')

        # reject negative value
        self.assertRaises(ValueError, HOTP, KEY1, counter=-1)

    # NOTE: 'start' is internal parameter, tested by from_string() / to_string()

    #=============================================================================
    # generate()
    #=============================================================================
    def test_generate(self):
        """generate() -- basic behavior"""

        # generate token
        counter = randcounter()
        otp = self.randotp()
        token = otp.generate(counter)
        self.assertIsInstance(token, unicode)

        # should generate same token
        self.assertEqual(otp.generate(counter), token)

        # and new one for other counters
        self.assertNotEqual(otp.generate(counter-1), token)
        self.assertNotEqual(otp.generate(counter+1), token)

        # value requires
        self.assertRaises(TypeError, otp.generate)

        # reject invalid counter
        self.assertRaises(ValueError, otp.generate, -1)

    def test_generate_w_reference_vectors(self):
        """generate() -- reference vectors"""
        for otp, counter, token, msg in self.iter_test_vectors():
            # should output correct token for specified counter
            result = otp.generate(counter)
            self.assertEqual(result, token, msg=msg)

    #=============================================================================
    # generate_next()
    #=============================================================================

    def test_generate_next(self):
        """generate_next() -- basic behavior

        .. note:: also tests 'counter' and 'dirty' attributes
        """

        # init random counter & key
        counter = randcounter()
        otp = self.randotp(counter=counter)
        self.assertFalse(otp.dirty)

        # generate token
        token = otp.generate_next()
        self.assertEqual(otp.counter, counter + 1) # should increment counter
        self.assertTrue(otp.verify(token, counter)) # should have used .counter
        self.assertTrue(otp.dirty)

        # should generate new token and increment counter
        token = otp.generate_next()
        self.assertEqual(otp.counter, counter + 2) # should increment counter
        self.assertTrue(otp.verify(token, counter + 1)) # should have used .counter

    def test_generate_next_w_reference_vectors(self):
        """generate_next() -- reference vectors"""
        for otp, counter, token, msg in self.iter_test_vectors():
            # should output correct token for specified counter
            otp.counter = counter
            result = otp.generate_next()
            self.assertEqual(result, token, msg=msg)

    #=============================================================================
    # HotpMatch() -- verify()'s return value
    #=============================================================================
    def test_hotp_match_w_valid_token(self):
        """verify() -- valid HotpMatch object"""
        from passlib.totp import HotpMatch

        otp = HOTP(KEY3)
        counter = 41230981
        token = '775167'
        result = otp.verify(token, counter)

        # test type
        self.assertIsInstance(result, HotpMatch)

        # test attrs
        self.assertTrue(result.valid)
        self.assertEqual(result.counter, counter+1)
        self.assertEqual(result.counter_offset, 0)

        # test tuple
        self.assertEqual(len(result), 2)
        self.assertEqual(result, (True, counter+1))
        self.assertRaises(IndexError, result.__getitem__, -3)
        self.assertEqual(result[0], True)
        self.assertEqual(result[1], counter+1)
        self.assertRaises(IndexError, result.__getitem__, 2)

        # test bool
        self.assertTrue(result)

    def test_hotp_match_w_skipped_counter(self):
        """verify() -- valid HotpMatch object w/ skipped counter"""
        from passlib.totp import HotpMatch

        otp = HOTP(KEY3)
        counter = 41230981
        token = '775167'
        result = otp.verify(token, counter-1)

        # test type
        self.assertIsInstance(result, HotpMatch)

        # test attrs
        self.assertTrue(result.valid)
        self.assertEqual(result.counter, counter + 1)
        self.assertEqual(result.counter_offset, 1)

        # test tuple
        self.assertEqual(len(result), 2)
        self.assertEqual(result, (True, counter + 1))
        self.assertRaises(IndexError, result.__getitem__, -3)
        self.assertEqual(result[0], True)
        self.assertEqual(result[1], counter + 1)
        self.assertRaises(IndexError, result.__getitem__, 2)

        # test bool
        self.assertTrue(result)

    def test_hotp_match_w_invalid_token(self):
        """verify() -- invalid HotpMatch object"""
        from passlib.totp import HotpMatch

        otp = HOTP(KEY3)
        counter = 41230981
        token = '775167'
        result = otp.verify(token, counter+1)

        # test type
        self.assertIsInstance(result, HotpMatch)

        # test attrs
        self.assertFalse(result.valid)
        self.assertEqual(result.counter, counter + 1)
        self.assertEqual(result.counter_offset, 0)

        # test tuple
        self.assertEqual(len(result), 2)
        self.assertEqual(result, (False, counter + 1))
        self.assertRaises(IndexError, result.__getitem__, -3)
        self.assertEqual(result[0], False)
        self.assertEqual(result[1], counter + 1)
        self.assertRaises(IndexError, result.__getitem__, 2)

        # test bool
        self.assertFalse(result)

    #=============================================================================
    # verify()
    #=============================================================================
    def test_verify_w_window(self, for_verify_next=False):
        """verify() -- 'counter' & 'window' parameters"""
        # init generator
        counter = randcounter()
        otp = self.randotp()
        if for_verify_next:
            verify = self._create_verify_next_wrapper(otp)
        else:
            verify = otp.verify
        token = otp.generate(counter)

        # init test helper
        def test(valid, counter_offset, token, counter, **kwds):
            """helper to test verify() output"""
            # NOTE: HotpMatch return type tested more throughly above ^^^
            result = verify(token, counter, **kwds)
            self.assertEqual(result.valid, valid)
            if valid:
                self.assertEqual(result.counter, counter + 1 + counter_offset)
            else:
                self.assertEqual(result.counter, counter)
            self.assertEqual(result.counter_offset, counter_offset)

        # validate against previous counter step (passes if window >= 1)
        test(False, 0,   token, counter-1, window=0)
        test(True,  1,   token, counter-1) # window=1 is default
        test(True,  1,   token, counter-1, window=2)

        # validate against current counter step
        test(True, 0,    token, counter, window=0)

        # validate against next counter step (should never pass)
        test(False, 0,   token, counter+1, window=0)
        test(False, 0,   token, counter+1) # window=1 is default
        test(False, 0,   token, counter+1, window=2)

    def test_verify_w_token_normalization(self, for_verify_next=False):
        """verify() -- token normalization"""
        # setup test helper
        otp = HOTP(KEY3)
        if for_verify_next:
            verify = self._create_verify_next_wrapper(otp)
        else:
            verify = otp.verify

        # separators / spaces should be stripped (orig token '049644')
        counter = 2889830
        correct = (True, counter+1)
        self.assertEqual(verify('    0 49-644  ', counter), correct)

        # ascii bytes
        self.assertEqual(verify(b'049644', counter), correct)

        # integer value (leading 0 should be implied)
        self.assertEqual(verify(49644, counter), correct)

        # too few digits
        self.assertRaises(ValueError, verify, '12345', counter)

        # invalid char
        self.assertRaises(ValueError, verify, '12345X', counter)

        # leading zeros count towards size
        self.assertRaises(ValueError, verify, '0123456', counter)

    def test_verify_w_reference_vectors(self, for_verify_next=False):
        """verify() -- reference vectors"""
        for otp, counter, token, msg in self.iter_test_vectors():
            # create wrapper
            if for_verify_next:
                verify = self._create_verify_next_wrapper(otp)
            else:
                verify = otp.verify

            # token should match counter *exactly*
            result = verify(token, counter, window=0)
            self.assertTrue(result.valid, msg=msg)
            self.assertEqual(result.counter, counter+1, msg=msg) # NOTE: will report *next* counter valid
            self.assertEqual(result.counter_offset, 0, msg=msg)

            # should NOT verify against another counter
            result = verify(token, counter + 100, window=0)
            self.assertFalse(result.valid, msg=msg)
            self.assertEqual(result.counter, counter + 100, msg=msg)
            self.assertEqual(result.counter_offset, 0, msg=msg)

    #=============================================================================
    # verify_next()
    #=============================================================================
    def _create_verify_next_wrapper(self, otp):
        """
        returns a wrapper around verify_next()
        which makes it's signature & return match verify(),
        to helper out shared test code.
        """
        from passlib.totp import HotpMatch
        def wrapper(token, counter=None, **kwds):
            otp.counter = counter
            valid = otp.verify_next(token, **kwds)
            return HotpMatch(valid, otp.counter, otp.counter - 1 - counter if valid else 0)
        return wrapper

    def test_verify_next_w_window(self):
        """verify_next() -- 'window' parameter"""
        self.test_verify_w_window(for_verify_next=True)

    def test_verify_next_w_token_normalization(self):
        """verify_next() -- token normalization"""
        self.test_verify_w_token_normalization(for_verify_next=True)

    def test_verify_next_w_counter(self):
        """verify_next() -- 'counter' and 'dirty' attributes"""

        # init generator
        counter = randcounter()
        otp = self.randotp(counter=counter)
        token = otp.generate(counter)
        self.assertEqual(otp.counter, counter)
        self.assertFalse(otp.dirty)

        # verify token, should advance counter & set dirty flag
        self.assertTrue(otp.verify_next(token))
        self.assertEqual(otp.counter, counter + 1)
        self.assertTrue(otp.dirty)

        # reverify should reject token, leaving counter & dirty flag alone.
        otp.counter = counter + 1
        otp.dirty = False
        self.assertFalse(otp.verify_next(token))
        self.assertEqual(otp.counter, counter + 1)
        self.assertFalse(otp.dirty)

    def test_verify_next_w_reference_vectors(self):
        """verify_next() -- reference vectors"""
        self.test_verify_w_reference_vectors(for_verify_next=True)

    #=============================================================================
    # uri serialization
    #=============================================================================

    def test_from_uri(self):
        """from_uri()"""
        from passlib.totp import from_uri

        # URIs adapted from https://code.google.com/p/google-authenticator/wiki/KeyUriFormat
        # NOTE: that source doesn't give HOTP examples, so these were created
        #       by altering the TOTP example.

        #--------------------------------------------------------------------------------
        # canonical uri
        #--------------------------------------------------------------------------------
        otp = from_uri("otpauth://hotp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&"
                       "counter=123&issuer=Example")
        self.assertIsInstance(otp, HOTP)
        self.assertEqual(otp.key, b'Hello!\xde\xad\xbe\xef')
        self.assertEqual(otp.label, "alice@google.com")
        self.assertEqual(otp.issuer, "Example")
        self.assertEqual(otp.alg, "sha1")  # implicit default
        self.assertEqual(otp.digits, 6)  # implicit default
        self.assertEqual(otp.counter, 123)
        
        #--------------------------------------------------------------------------------
        # secret param
        #--------------------------------------------------------------------------------

        # secret case insensitive
        otp = from_uri("otpauth://hotp/Example:alice@google.com?secret=jbswy3dpehpk3pxp&"
                       "counter=123&issuer=Example")
        self.assertEqual(otp.key, b'Hello!\xde\xad\xbe\xef')

        # missing secret
        self.assertRaises(ValueError, from_uri, "otpauth://hotp/Example:alice@google.com?"
                                                "counter=123")

        # undecodable secret
        self.assertRaises(Base32DecodeError, from_uri, "otpauth://hotp/Example:alice@google.com?"
                                                       "secret=JBSWY3DPEHP@3PXP&counter=123")

        #--------------------------------------------------------------------------------
        # label param
        #--------------------------------------------------------------------------------

        # w/ encoded space
        otp = from_uri("otpauth://hotp/Provider1:Alice%20Smith?secret=JBSWY3DPEHPK3PXP&"
                       "counter=123&issuer=Provider1")
        self.assertEqual(otp.label, "Alice Smith")
        self.assertEqual(otp.issuer, "Provider1")
        
        # w/ encoded space and colon
        # (note url has leading space before 'alice')
        otp = from_uri("otpauth://hotp/Big%20Corporation%3A%20alice@bigco.com?"
                       "secret=JBSWY3DPEHPK3PXP&counter=123")
        self.assertEqual(otp.label, "alice@bigco.com")
        self.assertEqual(otp.issuer, "Big Corporation")
        
        #--------------------------------------------------------------------------------
        # issuer param / prefix
        #--------------------------------------------------------------------------------

        # 'new style' issuer only
        otp = from_uri("otpauth://hotp/alice@bigco.com?secret=JBSWY3DPEHPK3PXP&counter=123&"
                       "issuer=Big%20Corporation")
        self.assertEqual(otp.label, "alice@bigco.com")
        self.assertEqual(otp.issuer, "Big Corporation")
        
        # new-vs-old issuer mismatch
        self.assertRaises(ValueError, from_uri, "otpauth://hotp/Provider1:alice?"
                                                "secret=JBSWY3DPEHPK3PXP&counter=123&"
                                                "issuer=Provider2")

        #--------------------------------------------------------------------------------
        # algorithm param
        #--------------------------------------------------------------------------------

        # custom alg
        otp = from_uri("otpauth://hotp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&"
                       "counter=123&algorithm=SHA256")
        self.assertEqual(otp.alg, "sha256")
        
        # unknown alg
        self.assertRaises(ValueError, from_uri, "otpauth://hotp/Example:alice@google.com?"
                                                "secret=JBSWY3DPEHPK3PXP&counter=123"
                                                "&algorithm=SHA333")
        
        #--------------------------------------------------------------------------------
        # digit param
        #--------------------------------------------------------------------------------

        # custom digits
        otp = from_uri("otpauth://hotp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&"
                       "counter=123&digits=8")
        self.assertEqual(otp.digits, 8)
        
        # digits out of range / invalid
        self.assertRaises(ValueError, from_uri, "otpauth://hotp/Example:alice@google.com?"
                                                "secret=JBSWY3DPEHPK3PXP&counter=123&digits=A")

        self.assertRaises(ValueError, from_uri, "otpauth://hotp/Example:alice@google.com?"
                                                "secret=JBSWY3DPEHPK3PXP&counter=123&digits=%20")

        self.assertRaises(ValueError, from_uri, "otpauth://hotp/Example:alice@google.com?"
                                                "secret=JBSWY3DPEHPK3PXP&counter=123&digits=15")
        
        #--------------------------------------------------------------------------------
        # counter param
        # (deserializing should also set 'start' value)
        #--------------------------------------------------------------------------------

        # zero counter
        otp = from_uri("otpauth://hotp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&counter=0")
        self.assertEqual(otp.counter, 0)
        self.assertEqual(otp.start, 0)

        # custom counter
        otp = from_uri("otpauth://hotp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&counter=456")
        self.assertEqual(otp.counter, 456)
        self.assertEqual(otp.start, 456)

        # reject missing counter
        self.assertRaises(ValueError, from_uri, "otpauth://hotp/Example:alice@google.com?"
                                                "secret=JBSWY3DPEHPK3PXP")

        # reject negative counter
        self.assertRaises(ValueError, from_uri, "otpauth://hotp/Example:alice@google.com?"
                                                "secret=JBSWY3DPEHPK3PXP&counter=-1")

        #--------------------------------------------------------------------------------
        # unrecognized param
        #--------------------------------------------------------------------------------

        # should issue warning, but otherwise ignore extra param
        with self.assertWarningList([
            dict(category=exc.PasslibRuntimeWarning, message_re="unexpected parameters encountered")
        ]):
            otp = from_uri("otpauth://hotp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&"
                           "foo=bar&counter=123")
        self.assertEqual(otp.base32_key, KEY4)
        self.assertEqual(otp.counter, 123)

    def test_to_uri(self):
        """to_uri()"""

        #-------------------------------------------------------------------------
        # label & issuer parameters
        #-------------------------------------------------------------------------

        # with label & issuer
        otp = HOTP(KEY4, alg="sha1", digits=6, counter=0)
        self.assertEqual(otp.to_uri("alice@google.com", "Example Org"),
                         "otpauth://hotp/alice@google.com?secret=JBSWY3DPEHPK3PXP&"
                         "counter=0&issuer=Example%20Org")

        # label is required
        self.assertRaises(ValueError, otp.to_uri, None, "Example Org")

        # with label only
        self.assertEqual(otp.to_uri("alice@google.com"),
                         "otpauth://hotp/alice@google.com?secret=JBSWY3DPEHPK3PXP&counter=0")

        # with default label from constructor
        otp.label = "alice@google.com"
        self.assertEqual(otp.to_uri(),
                         "otpauth://hotp/alice@google.com?secret=JBSWY3DPEHPK3PXP&counter=0")

        # with default label & default issuer from constructor
        otp.issuer = "Example Org"
        self.assertEqual(otp.to_uri(),
                         "otpauth://hotp/alice@google.com?secret=JBSWY3DPEHPK3PXP&counter=0"
                         "&issuer=Example%20Org")

        # reject invalid label
        self.assertRaises(ValueError, otp.to_uri, "label:with:semicolons")

        # reject invalid issue
        self.assertRaises(ValueError, otp.to_uri, "alice@google.com", "issuer:with:semicolons")

        #-------------------------------------------------------------------------
        # algorithm parameter
        #-------------------------------------------------------------------------
        self.assertEqual(HOTP(KEY4, alg="sha256").to_uri("alice@google.com"),
                         "otpauth://hotp/alice@google.com?secret=JBSWY3DPEHPK3PXP&"
                         "algorithm=SHA256&counter=0")

        #-------------------------------------------------------------------------
        # digits parameter
        #-------------------------------------------------------------------------
        self.assertEqual(HOTP(KEY4, digits=8).to_uri("alice@google.com"),
                         "otpauth://hotp/alice@google.com?secret=JBSWY3DPEHPK3PXP&"
                         "digits=8&counter=0")

        #-------------------------------------------------------------------------
        # counter parameter
        #-------------------------------------------------------------------------
        self.assertEqual(HOTP(KEY4, counter=456).to_uri("alice@google.com"),
                         "otpauth://hotp/alice@google.com?secret=JBSWY3DPEHPK3PXP&"
                         "counter=456")

        # sanity check that start parameter is NOT the one being used.
        otp = HOTP(KEY4, start=123, counter=456)
        self.assertEqual(otp.start, 123)
        self.assertEqual(otp.to_uri("alice@google.com"),
                         "otpauth://hotp/alice@google.com?secret=JBSWY3DPEHPK3PXP&"
                         "counter=456")

    #=============================================================================
    # json serialization
    #=============================================================================

    # TODO: from_string()
    #           with uri
    #           without needed password
    #           with needed password
    #           with bad version, decode error

    # TODO: to_string()
    #           with password
    #           with custom cost
    #           with password=True

    # TODO: test 'counter' and 'start' are preserved.

    #=============================================================================
    # eoc
    #=============================================================================

#=============================================================================
# eof
#=============================================================================
