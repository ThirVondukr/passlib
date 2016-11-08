"""passlib.tests -- test passlib.totp"""
#=============================================================================
# imports
#=============================================================================
# core
import datetime
from functools import partial
import logging; log = logging.getLogger(__name__)
import random
import sys
import time as _time
# site
# pkg
from passlib import exc
from passlib.utils.compat import unicode, u
from passlib.tests.utils import TestCase, time_call
# subject
from passlib.totp import OTPContext, AES_SUPPORT
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

def to_b32_size(raw_size):
    return (raw_size * 8 + 4) // 5

#=============================================================================
# util tests
#=============================================================================

class UtilsTest(TestCase):
    descriptionPrefix = "passlib.totp"

    #=============================================================================
    #
    #=============================================================================

    #=============================================================================
    # eoc
    #=============================================================================

#=============================================================================
# context
#=============================================================================
class OTPContextTest(TestCase):
    descriptionPrefix = "passlib.totp.OTPContext"

    #=============================================================================
    # constructor
    #=============================================================================

    def test_secrets_types(self):
        """constructor -- 'secrets' param -- input types"""

        # no secrets
        context = OTPContext()
        self.assertEqual(context._secrets, {})
        self.assertFalse(context.can_encrypt)

        # dict
        ref = {"1": b"aaa", "2": b"bbb"}
        context = OTPContext(ref)
        self.assertEqual(context._secrets, ref)
        self.assertEqual(context.can_encrypt, AES_SUPPORT)

        # # list
        # context = OTPContext(list(ref.items()))
        # self.assertEqual(context._secrets, ref)

        # # iter
        # context = OTPContext(iter(ref.items()))
        # self.assertEqual(context._secrets, ref)

        # "tag:value" string
        context = OTPContext("\n 1: aaa\n# comment\n \n2: bbb   ")
        self.assertEqual(context._secrets, ref)

        # ensure ":" allowed in secret
        context = OTPContext("1: aaa: bbb \n# comment\n \n2: bbb   ")
        self.assertEqual(context._secrets, {"1": b"aaa: bbb", "2": b"bbb"})

        # json dict
        context = OTPContext('{"1":"aaa","2":"bbb"}')
        self.assertEqual(context._secrets, ref)

        # # json list
        # context = OTPContext('[["1","aaa"],["2","bbb"]]')
        # self.assertEqual(context._secrets, ref)

        # invalid type
        self.assertRaises(TypeError, OTPContext, 123)

        # invalid json obj
        self.assertRaises(TypeError, OTPContext, "[123]")

        # # invalid list items
        # self.assertRaises(ValueError, OTPContext, ["1", b"aaa"])

        # forbid empty secret
        self.assertRaises(ValueError, OTPContext, {"1": "aaa", "2": ""})

    def test_secrets_tags(self):
        """constructor -- 'secrets' param -- tag/value normalization"""

        # test reference
        ref = {"1": b"aaa", "02": b"bbb", "C": b"ccc"}
        context = OTPContext(ref)
        self.assertEqual(context._secrets, ref)

        # accept unicode
        context = OTPContext({u("1"): b"aaa", u("02"): b"bbb", u("C"): b"ccc"})
        self.assertEqual(context._secrets, ref)

        # normalize int tags
        context = OTPContext({1: b"aaa", "02": b"bbb", "C": b"ccc"})
        self.assertEqual(context._secrets, ref)

        # forbid non-str/int tags
        self.assertRaises(TypeError, OTPContext, {(1,): "aaa"})

        # accept valid tags
        context = OTPContext({"1-2_3.4": b"aaa"})

        # forbid invalid tags
        self.assertRaises(ValueError, OTPContext, {"-abc": "aaa"})
        self.assertRaises(ValueError, OTPContext, {"ab*$": "aaa"})

        # coerce value to bytes
        context = OTPContext({"1": u("aaa"), "02": "bbb", "C": b"ccc"})
        self.assertEqual(context._secrets, ref)

        # forbid invalid value types
        self.assertRaises(TypeError, OTPContext, {"1": 123})
        self.assertRaises(TypeError, OTPContext, {"1": None})
        self.assertRaises(TypeError, OTPContext, {"1": []})

    # TODO: test secrets_path

    def test_default_tag(self):
        """constructor -- 'default_tag' param"""

        # should sort numerically
        context = OTPContext({"1": "one", "02": "two"})
        self.assertEqual(context._default_tag, "02")
        self.assertEqual(context._default_secret, b"two")

        # should sort alphabetically if non-digit present
        context = OTPContext({"1": "one", "02": "two", "A": "aaa"})
        self.assertEqual(context._default_tag, "A")
        self.assertEqual(context._default_secret, b"aaa")

        # should use honor custom tag
        context = OTPContext({"1": "one", "02": "two", "A": "aaa"}, default_tag="1")
        self.assertEqual(context._default_tag, "1")
        self.assertEqual(context._default_secret, b"one")

        # throw error on unknown value
        self.assertRaises(KeyError, OTPContext, {"1": "one", "02": "two", "A": "aaa"},
                          default_tag="B")

        # should be empty
        context = OTPContext()
        self.assertEqual(context._default_tag, None)
        self.assertEqual(context._default_secret, None)

    # TODO: test 'cost' param

    #=============================================================================
    # frontends
    #=============================================================================
    def test_new(self):
        """.new()"""
        from passlib.totp import OTPContext, TOTP

        context = OTPContext()

        # object bound to context
        totp = context.new()
        self.assertIsInstance(totp, TOTP)
        self.assertIs(totp.context, context)

        # creates new key each time
        totp2 = context.new()
        self.assertNotEqual(totp2.key, totp.key)

        # passes remaining params through
        totp3 = context.new(digits=6)
        self.assertEqual(totp3.digits, 6)

        totp4 = context.new(digits=9)
        self.assertEqual(totp4.digits, 9)

    # TODO: test from_uri(), from_json()

    # TODO: test .changed when deserializing from outtdated tag / encryption parameters

    #=============================================================================
    # encrypt_key() & decrypt_key() helpers
    #=============================================================================
    def require_aes_support(self, canary=None):
        if AES_SUPPORT:
            canary and canary()
        else:
            canary and self.assertRaises(RuntimeError, canary)
            raise self.skipTest("'cryptography' package not installed")

    def test_decrypt_key(self):
        """.decrypt_key()"""

        context = OTPContext({"1": PASS1, "2": PASS2})

        # check for support
        CIPHER1 = dict(v=1, c=13, s='6D7N7W53O7HHS37NLUFQ',
                       k='MHCTEGSNPFN5CGBJ', t='1')
        self.require_aes_support(canary=partial(context.decrypt_key, CIPHER1))

        # reference key
        self.assertEqual(context.decrypt_key(CIPHER1)[0], KEY1_RAW)

        # different salt used to encrypt same raw key
        CIPHER2 = dict(v=1, c=13, s='SPZJ54Y6IPUD2BYA4C6A',
                       k='ZGDXXTVQOWYLC2AU', t='1')
        self.assertEqual(context.decrypt_key(CIPHER2)[0], KEY1_RAW)

        # different sized key, password, and cost
        CIPHER3 = dict(v=1, c=8, s='FCCTARTIJWE7CPQHUDKA',
                       k='D2DRS32YESGHHINWFFCELKN7Z6NAHM4M', t='2')
        self.assertEqual(context.decrypt_key(CIPHER3)[0], KEY2_RAW)

        # wrong password should silently result in wrong key
        temp = CIPHER1.copy()
        temp.update(t='2')
        self.assertEqual(context.decrypt_key(temp)[0], b'\xafD6.F7\xeb\x19\x05Q')

        # missing tag should throw error
        temp = CIPHER1.copy()
        temp.update(t='3')
        self.assertRaises(KeyError, context.decrypt_key, temp)

        # unknown version should throw error
        temp = CIPHER1.copy()
        temp.update(v=999)
        self.assertRaises(ValueError, context.decrypt_key, temp)

    def test_decrypt_key_needs_recrypt(self):
        """.decrypt_key() -- needs_recrypt flag"""
        self.require_aes_support()

        context = OTPContext({"1": PASS1, "2": PASS2}, cost=13)

        # ref should be accepted
        ref = dict(v=1, c=13, s='AAAA', k='AAAA', t='2')
        self.assertFalse(context.decrypt_key(ref)[1])

        # wrong cost
        temp = ref.copy()
        temp.update(c=8)
        self.assertTrue(context.decrypt_key(temp)[1])

        # wrong tag
        temp = ref.copy()
        temp.update(t="1")
        self.assertTrue(context.decrypt_key(temp)[1])

        # XXX: should this check salt_size?

    def assertSaneResult(self, result, context, key, tag="1",
                         needs_recrypt=False):
        """check encrypt_key() result has expected format"""

        self.assertEqual(set(result), set(["v", "t", "c", "s", "k"]))

        self.assertEqual(result['v'], 1)
        self.assertEqual(result['t'], tag)
        self.assertEqual(result['c'], context.cost)

        self.assertEqual(len(result['s']), to_b32_size(context.salt_size))
        self.assertEqual(len(result['k']), to_b32_size(len(key)))

        result_key, result_needs_recrypt = context.decrypt_key(result)
        self.assertEqual(result_key, key)
        self.assertEqual(result_needs_recrypt, needs_recrypt)

    def test_encrypt_key(self):
        """.encrypt_key()"""

        # check for support
        context = OTPContext({"1": PASS1}, cost=5)
        self.require_aes_support(canary=partial(context.encrypt_key, KEY1_RAW))

        # basic behavior
        result = context.encrypt_key(KEY1_RAW)
        self.assertSaneResult(result, context, KEY1_RAW)

        # creates new salt each time
        other = context.encrypt_key(KEY1_RAW)
        self.assertSaneResult(result, context, KEY1_RAW)
        self.assertNotEqual(other['s'], result['s'])
        self.assertNotEqual(other['k'], result['k'])

        # honors custom cost
        context2 = OTPContext({"1": PASS1}, cost=6)
        result = context2.encrypt_key(KEY1_RAW)
        self.assertSaneResult(result, context2, KEY1_RAW)

        # honors default tag
        context2 = OTPContext({"1": PASS1, "2": PASS2})
        result = context2.encrypt_key(KEY1_RAW)
        self.assertSaneResult(result, context2, KEY1_RAW, tag="2")

        # honor salt size
        context2 = OTPContext({"1": PASS1})
        context2.salt_size = 64
        result = context2.encrypt_key(KEY1_RAW)
        self.assertSaneResult(result, context2, KEY1_RAW)

        # larger key
        result = context.encrypt_key(KEY2_RAW)
        self.assertSaneResult(result, context, KEY2_RAW)

        # border case: empty key
        # XXX: might want to allow this, but documenting behavior for now
        self.assertRaises(ValueError, context.encrypt_key, b"")

    def test_encrypt_cost_timing(self):
        """verify cost parameter via timing"""
        self.require_aes_support()

        # time default cost
        context = OTPContext({"1": "aaa"})
        context.cost -= 2
        delta, _ = time_call(partial(context.encrypt_key, KEY1_RAW), maxtime=0)

        # this should take (2**3=8) times as long
        context.cost += 3
        delta2, _ = time_call(partial(context.encrypt_key, KEY1_RAW), maxtime=0)

        self.assertAlmostEqual(delta2, delta*8, delta=(delta*8)*0.5)

    #=============================================================================
    # eoc
    #=============================================================================

#=============================================================================
# common OTP code
#=============================================================================

#: used as base value for RFC test vector keys
RFC_KEY_BYTES_20 = "12345678901234567890".encode("ascii")
RFC_KEY_BYTES_32 = (RFC_KEY_BYTES_20*2)[:32]
RFC_KEY_BYTES_64 = (RFC_KEY_BYTES_20*4)[:64]

# TODO: this class is separate from TotpTest due to historical issue,
#       when there was a base class, and a separate HOTP class.
#       these test case classes should probably be combined.
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

        self.assertRaises(exc.MalformedTokenError, otp.normalize_token, '123456')
        self.assertRaises(exc.MalformedTokenError, otp.normalize_token, '01234567')

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

    def test_generate_w_reference_vectors(self):
        """generate() -- reference vectors"""
        for otp, time, token, expires, prefix in self.iter_test_vectors():
            # should output correct token for specified time
            result = otp.generate(time)
            self.assertEqual(result.token, token, msg=prefix)
            self.assertEqual(result.counter, time // otp.period, msg=prefix)
            if expires:
                self.assertEqual(result.expire_time, expires)

    #=============================================================================
    # TotpMatch() -- verify()'s return value
    #=============================================================================

    def assertTotpMatch(self, match, time, skipped, period=30, window=30, msg=''):
        from passlib.totp import TotpMatch

        # test type
        self.assertIsInstance(match, TotpMatch)

        # totp sanity check
        self.assertIsInstance(match.totp, TOTP)
        self.assertEqual(match.totp.period, period)

        # test attrs
        self.assertEqual(match.time, time, msg=msg + " matched time:")
        expected = time // period
        counter = expected + skipped
        self.assertEqual(match.counter, counter, msg=msg + " matched counter:")
        self.assertEqual(match.expected_counter, expected, msg=msg + " expected counter:")
        self.assertEqual(match.skipped, skipped, msg=msg + " skipped:")
        self.assertEqual(match.cache_seconds, period + window)
        expire_time = (counter + 1) * period
        self.assertEqual(match.expire_time, expire_time)
        self.assertEqual(match.cache_time, expire_time + window)

        # test tuple
        self.assertEqual(len(match), 2)
        self.assertEqual(match, (counter, time))
        self.assertRaises(IndexError, match.__getitem__, -3)
        self.assertEqual(match[0], counter)
        self.assertEqual(match[1], time)
        self.assertRaises(IndexError, match.__getitem__, 2)

        # test bool
        self.assertTrue(match)

    def test_totp_match_w_valid_token(self):
        """verify() -- valid TotpMatch object"""
        time = 141230981
        token = '781501'
        otp = TOTP(KEY3, now=lambda : time + 24 * 3600)
        result = otp.verify(token, time)
        self.assertTotpMatch(result, time=time, skipped=0)

    def test_totp_match_w_older_token(self):
        """verify() -- valid TotpMatch object with future token"""
        from passlib.totp import TotpMatch

        time = 141230981
        token = '781501'
        otp = TOTP(KEY3, now=lambda: time + 24 * 3600)
        result = otp.verify(token, time - 30)
        self.assertTotpMatch(result, time=time - 30, skipped=1)

    def test_totp_match_w_new_token(self):
        """verify() -- valid TotpMatch object with past token"""
        from passlib.totp import TotpMatch

        time = 141230981
        token = '781501'
        otp = TOTP(KEY3, now=lambda : time + 24 * 3600)
        result = otp.verify(token, time + 30)
        self.assertTotpMatch(result, time=time + 30, skipped=-1)

    def test_totp_match_w_invalid_token(self):
        """verify() -- invalid TotpMatch object"""
        from passlib.totp import TotpMatch

        time = 141230981
        token = '781501'
        otp = TOTP(KEY3, now=lambda : time + 24 * 3600)
        self.assertRaises(exc.InvalidTokenError, otp.verify, token, time + 60)

    #=============================================================================
    # verify()
    #=============================================================================

    def assertVerifyMatches(self, expect_skipped, token, time,  # *
                            otp, gen_time=None, **kwds):
        """helper to test otp.verify() output is correct"""
        # NOTE: TotpMatch return type tested more throughly above ^^^
        msg = "key=%r alg=%r period=%r token=%r gen_time=%r time=%r:" % \
              (otp.base32_key, otp.alg, otp.period, token, gen_time, time)
        result = otp.verify(token, time, **kwds)
        self.assertTotpMatch(result,
                             time=otp.normalize_time(time),
                             period=otp.period,
                             window=kwds.get("window", 30),
                             skipped=expect_skipped,
                             msg=msg)

    def assertVerifyRaises(self, exc_class, token, time,  # *
                          otp, gen_time=None,
                          **kwds):
        """helper to test otp.verify() throws correct error"""
        # NOTE: TotpMatch return type tested more throughly above ^^^
        msg = "key=%r alg=%r period=%r token=%r gen_time=%r time=%r:" % \
              (otp.base32_key, otp.alg, otp.period, token, gen_time, time)
        return self.assertRaises(exc_class, otp.verify, token, time,
                                 __msg__=msg, **kwds)

    def test_verify_w_window(self):
        """verify() -- 'time' and 'window' parameters"""

        # init generator & helper
        otp = self.randotp()
        period = otp.period
        time = randtime()
        token = otp.generate(time).token
        common = dict(otp=otp, gen_time=time)
        assertMatches = partial(self.assertVerifyMatches, **common)
        assertRaises = partial(self.assertVerifyRaises, **common)

        #-------------------------------
        # basic validation, and 'window' parameter
        #-------------------------------

        # validate against previous counter (passes if window >= period)
        assertRaises(exc.InvalidTokenError, token, time - period, window=0)
        assertMatches(+1, token, time - period, window=period)
        assertMatches(+1, token, time - period, window=2 * period)

        # validate against current counter
        assertMatches(0, token, time, window=0)

        # validate against next counter (passes if window >= period)
        assertRaises(exc.InvalidTokenError, token, time + period, window=0)
        assertMatches(-1, token, time + period, window=period)
        assertMatches(-1, token, time + period, window=2 * period)

        # validate against two time steps later (should never pass)
        assertRaises(exc.InvalidTokenError, token, time + 2 * period, window=0)
        assertRaises(exc.InvalidTokenError, token, time + 2 * period, window=period)
        assertMatches(-2, token, time + 2 * period, window=2 * period)

        # TODO: test window values that aren't multiples of period
        #       (esp ensure counter rounding works correctly)

        #-------------------------------
        # time normalization
        #-------------------------------

        # handle datetimes
        dt = datetime.datetime.utcfromtimestamp(time)
        assertMatches(0, token, dt, window=0)

        # reject invalid time
        assertRaises(ValueError, token, -1)

    def test_verify_w_skew(self):
        """verify() -- 'skew' parameters"""
        # init generator & helper
        otp = self.randotp()
        period = otp.period
        time = randtime()
        common = dict(otp=otp, gen_time=time)
        assertMatches = partial(self.assertVerifyMatches, **common)
        assertRaises = partial(self.assertVerifyRaises, **common)

        # assume client is running far behind server / has excessive transmission delay
        skew = 3 * period
        behind_token = otp.generate(time - skew).token
        assertRaises(exc.InvalidTokenError, behind_token, time, window=0)
        assertMatches(-3, behind_token, time, window=0, skew=-skew)

        # assume client is running far ahead of server
        ahead_token = otp.generate(time + skew).token
        assertRaises(exc.InvalidTokenError, ahead_token, time, window=0)
        assertMatches(+3, ahead_token, time, window=0, skew=skew)

        # TODO: test skew + larger window

    def test_verify_w_reuse(self):
        """verify() -- 'reuse' and 'last_counter' parameters"""

        # init generator & helper
        otp = self.randotp()
        period = otp.period
        time = randtime()
        tdata = otp.generate(time)
        token = tdata.token
        counter = tdata.counter
        expire_time = tdata.expire_time
        common = dict(otp=otp, gen_time=time)
        assertMatches = partial(self.assertVerifyMatches, **common)
        assertRaises = partial(self.assertVerifyRaises, **common)

        # last counter unset --
        # previous period's token should count as valid
        assertMatches(-1, token, time + period, window=period)

        # last counter set 2 periods ago --
        # previous period's token should count as valid
        assertMatches(-1, token, time + period, last_counter=counter-1,
                      window=period)

        # last counter set 2 periods ago --
        # 2 periods ago's token should NOT count as valid, even if reuse=True
        assertRaises(exc.InvalidTokenError, token, time + 2 * period,
                     last_counter=counter, window=period, reuse=True)

        # last counter set 1 period ago --
        # previous period's token should now be rejected as 'used'
        err = assertRaises(exc.UsedTokenError, token, time + period,
                           last_counter=counter, window=period)
        self.assertEqual(err.expire_time, expire_time)

        # last counter set 1 period ago, reuse allowed
        assertMatches(-1, token, time + period, last_counter=counter,
                      window=period, reuse=True)

        # last counter set to current period --
        # current period's token should be rejected
        err = assertRaises(exc.UsedTokenError, token, time,
                           last_counter=counter, window=0)
        self.assertEqual(err.expire_time, expire_time)

        # last counter set to current period, reuse allowed
        assertMatches(0, token, time, last_counter=counter,
                      window=0, reuse=True)

    def test_verify_w_token_normalization(self):
        """verify() -- token normalization"""
        # setup test helper
        otp = TOTP('otxl2f5cctbprpzx')
        verify = otp.verify
        time = 1412889861

        # separators / spaces should be stripped (orig token '332136')
        self.assertTrue(verify('    3 32-136  ', time))

        # ascii bytes
        self.assertTrue(verify(b'332136', time))

        # too few digits
        self.assertRaises(exc.MalformedTokenError, verify, '12345', time)

        # invalid char
        self.assertRaises(exc.MalformedTokenError, verify, '12345X', time)

        # leading zeros count towards size
        self.assertRaises(exc.MalformedTokenError, verify, '0123456', time)

    def test_verify_w_reference_vectors(self):
        """verify() -- reference vectors"""
        for otp, time, token, expires, msg in self.iter_test_vectors():
            # create wrapper
            verify = otp.verify

            # token should verify against time
            result = verify(token, time)
            self.assertTrue(result)
            self.assertEqual(result.counter, time // otp.period, msg=msg)

            # should NOT verify against another time
            self.assertRaises(exc.InvalidTokenError, verify, token, time + 100, window=0)

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

    # TODO: from_json()
    #           with uri
    #           with dict
    #           with bad version, decode error

    # TODO: to_json()
    # TODO: to_dict()
    #           with encrypt=False
    #           with encrypt="auto" + context + secrets
    #           with encrypt="auto" + context + no secrets
    #           with encrypt="auto" + no context
    #           with encrypt=True + context + secrets
    #           with encrypt=True + context + no secrets
    #           with encrypt=True + no context

    # TODO: last_counter is preserved

    #=============================================================================
    # eoc
    #=============================================================================

#=============================================================================
# eof
#=============================================================================
