"""tests for passlib.utils.(des|pbkdf2|md4)"""
#=============================================================================
# imports
#=============================================================================
from __future__ import with_statement, division
# core
from binascii import hexlify, unhexlify
import hashlib
import re
import warnings
# site
# pkg
# module
from passlib.utils.compat import PY3, u, JYTHON
from passlib.tests.utils import TestCase, TEST_MODE, skipUnless

#=============================================================================
# support
#=============================================================================
def hb(source):
    """
    helper for represent byte strings in hex.

    usage: ``hb("deadbeef23")``
    """
    source = re.sub("\s", "", source)
    if PY3:
        source = source.encode("ascii")
    return unhexlify(source)

#=============================================================================
# test assorted crypto helpers
#=============================================================================
class HashInfoTest(TestCase):
    """test various crypto functions"""
    descriptionPrefix = "passlib.crypto.digest"

    #: list of formats norm_hash_name() should support
    norm_hash_formats = ["hashlib", "iana"]

    #: test cases for norm_hash_name()
    #: each row contains (iana name, hashlib name, ... 0+ unnormalized names)
    norm_hash_samples = [
        # real hashes
        ("md5",       "md5",         "SCRAM-MD5-PLUS",   "MD-5"),
        ("sha1",      "sha-1",       "SCRAM-SHA-1",      "SHA1"),
        ("sha256",    "sha-256",     "SHA_256",          "sha2-256"),
        ("ripemd",    "ripemd",      "SCRAM-RIPEMD",     "RIPEMD"),
        ("ripemd160", "ripemd-160",  "SCRAM-RIPEMD-160", "RIPEmd160"),

        # fake hashes (to check if fallback normalization behaves sanely)
        ("sha4_256",  "sha4-256",    "SHA4-256",         "SHA-4-256"),
        ("test128",   "test-128",    "TEST128"),
        ("test2",     "test2",       "TEST-2"),
        ("test3_128",  "test3-128",   "TEST-3-128"),
    ]

    def test_norm_hash_name(self):
        """norm_hash_name()"""
        from itertools import chain
        from passlib.crypto.digest import norm_hash_name, _known_hash_names

        # snapshot warning state, ignore unknown hash warnings
        ctx = warnings.catch_warnings()
        ctx.__enter__()
        self.addCleanup(ctx.__exit__)
        warnings.filterwarnings("ignore", '.*unknown hash')

        # test string types
        self.assertEqual(norm_hash_name(u("MD4")), "md4")
        self.assertEqual(norm_hash_name(b"MD4"), "md4")
        self.assertRaises(TypeError, norm_hash_name, None)

        # test selected results
        for row in chain(_known_hash_names, self.norm_hash_samples):
            for idx, format in enumerate(self.norm_hash_formats):
                correct = row[idx]
                for value in row:
                    result = norm_hash_name(value, format)
                    self.assertEqual(result, correct,
                                     "name=%r, format=%r:" % (value,
                                                              format))

    def test_lookup_hash_ctor(self):
        """lookup_hash() -- constructor"""
        from passlib.crypto.digest import lookup_hash

        # invalid/unknown names should be rejected
        self.assertRaises(ValueError, lookup_hash, "new")
        self.assertRaises(ValueError, lookup_hash, "__name__")
        self.assertRaises(ValueError, lookup_hash, "sha4")

        # 1. should return hashlib builtin if found
        self.assertEqual(lookup_hash("md5"), (hashlib.md5, 16, 64))

        # 2. should return wrapper around hashlib.new() if found
        try:
            hashlib.new("sha")
            has_sha = True
        except ValueError:
            has_sha = False
        if has_sha:
            record = lookup_hash("sha")
            const = record[0]
            self.assertEqual(record, (const, 20, 64))
            self.assertEqual(hexlify(const(b"abc").digest()),
                             b"0164b8a914cd2a5e74c4f7ff082c4d97f1edf880")

        else:
            self.assertRaises(ValueError, lookup_hash, "sha")

        # 3. should fall back to builtin md4
        try:
            hashlib.new("md4")
            has_md4 = True
        except ValueError:
            has_md4 = False
        record = lookup_hash("md4")
        const = record[0]
        if not has_md4:
            from passlib.crypto._md4 import md4
            self.assertIs(const, md4)
        self.assertEqual(record, (const, 16, 64))
        self.assertEqual(hexlify(const(b"abc").digest()),
                         b"a448017aaf21d8525fc10ae87aa6729d")

        # 4. unknown names should be rejected
        self.assertRaises(ValueError, lookup_hash, "xxx256")

        # should memoize records
        self.assertIs(lookup_hash("md5"), lookup_hash("md5"))

    def test_lookup_hash_metadata(self):
        """lookup_hash() -- metadata"""

        from passlib.crypto.digest import lookup_hash

        # quick test of metadata using known reference - sha256
        info = lookup_hash("sha256")
        self.assertEqual(info.name, "sha256")
        self.assertEqual(info.iana_name, "sha-256")
        self.assertEqual(info.block_size, 64)
        self.assertEqual(info.digest_size, 32)
        self.assertIs(lookup_hash("SHA2-256"), info)

        # quick test of metadata using known reference - md5
        info = lookup_hash("md5")
        self.assertEqual(info.name, "md5")
        self.assertEqual(info.iana_name, "md5")
        self.assertEqual(info.block_size, 64)
        self.assertEqual(info.digest_size, 16)

    def test_lookup_hash_alt_types(self):
        """lookup_hash() -- alternate types"""

        from passlib.crypto.digest import lookup_hash

        info = lookup_hash("sha256")
        self.assertIs(lookup_hash(info), info)
        self.assertIs(lookup_hash(info.const), info)

        self.assertRaises(TypeError, lookup_hash, 123)

    # TODO: write full test of compile_hmac() -- currently relying on pbkdf2_hmac() tests

#=============================================================================
# test PBKDF1 support
#=============================================================================
class Pbkdf1_Test(TestCase):
    """test kdf helpers"""
    descriptionPrefix = "passlib.crypto.digest.pbkdf1"

    pbkdf1_tests = [
        # (password, salt, rounds, keylen, hash, result)

        #
        # from http://www.di-mgt.com.au/cryptoKDFs.html
        #
        (b'password', hb('78578E5A5D63CB06'), 1000, 16, 'sha1', hb('dc19847e05c64d2faf10ebfb4a3d2a20')),

        #
        # custom
        #
        (b'password', b'salt', 1000, 0, 'md5',    b''),
        (b'password', b'salt', 1000, 1, 'md5',    hb('84')),
        (b'password', b'salt', 1000, 8, 'md5',    hb('8475c6a8531a5d27')),
        (b'password', b'salt', 1000, 16, 'md5', hb('8475c6a8531a5d27e386cd496457812c')),
        (b'password', b'salt', 1000, None, 'md5', hb('8475c6a8531a5d27e386cd496457812c')),
        (b'password', b'salt', 1000, None, 'sha1', hb('4a8fd48e426ed081b535be5769892fa396293efb')),
    ]
    if not JYTHON: # FIXME: find out why not jython, or reenable this.
        pbkdf1_tests.append(
            (b'password', b'salt', 1000, None, 'md4', hb('f7f2e91100a8f96190f2dd177cb26453'))
        )

    def test_known(self):
        """test reference vectors"""
        from passlib.crypto.digest import pbkdf1
        for secret, salt, rounds, keylen, digest, correct in self.pbkdf1_tests:
            result = pbkdf1(digest, secret, salt, rounds, keylen)
            self.assertEqual(result, correct)

    def test_border(self):
        """test border cases"""
        from passlib.crypto.digest import pbkdf1
        def helper(secret=b'secret', salt=b'salt', rounds=1, keylen=1, hash='md5'):
            return pbkdf1(hash, secret, salt, rounds, keylen)
        helper()

        # salt/secret wrong type
        self.assertRaises(TypeError, helper, secret=1)
        self.assertRaises(TypeError, helper, salt=1)

        # non-existent hashes
        self.assertRaises(ValueError, helper, hash='missing')

        # rounds < 1 and wrong type
        self.assertRaises(ValueError, helper, rounds=0)
        self.assertRaises(TypeError, helper, rounds='1')

        # keylen < 0, keylen > block_size, and wrong type
        self.assertRaises(ValueError, helper, keylen=-1)
        self.assertRaises(ValueError, helper, keylen=17, hash='md5')
        self.assertRaises(TypeError, helper, keylen='1')

#=============================================================================
# test PBKDF2-HMAC support
#=============================================================================

# import the test subject
from passlib.crypto.digest import pbkdf2_hmac

class _Common_Pbkdf2_Test(TestCase):
    """test pbkdf2() support"""

    pbkdf2_test_vectors = [
        # (result, secret, salt, rounds, keylen, digest="sha1")

        #
        # from rfc 3962
        #

            # test case 1 / 128 bit
            (
                hb("cdedb5281bb2f801565a1122b2563515"),
                b"password", b"ATHENA.MIT.EDUraeburn", 1, 16
            ),

            # test case 2 / 128 bit
            (
                hb("01dbee7f4a9e243e988b62c73cda935d"),
                b"password", b"ATHENA.MIT.EDUraeburn", 2, 16
            ),

            # test case 2 / 256 bit
            (
                hb("01dbee7f4a9e243e988b62c73cda935da05378b93244ec8f48a99e61ad799d86"),
                b"password", b"ATHENA.MIT.EDUraeburn", 2, 32
            ),

            # test case 3 / 256 bit
            (
                hb("5c08eb61fdf71e4e4ec3cf6ba1f5512ba7e52ddbc5e5142f708a31e2e62b1e13"),
                b"password", b"ATHENA.MIT.EDUraeburn", 1200, 32
            ),

            # test case 4 / 256 bit
            (
                hb("d1daa78615f287e6a1c8b120d7062a493f98d203e6be49a6adf4fa574b6e64ee"),
                b"password", b'\x12\x34\x56\x78\x78\x56\x34\x12', 5, 32
            ),

            # test case 5 / 256 bit
            (
                hb("139c30c0966bc32ba55fdbf212530ac9c5ec59f1a452f5cc9ad940fea0598ed1"),
                b"X"*64, b"pass phrase equals block size", 1200, 32
            ),

            # test case 6 / 256 bit
            (
                hb("9ccad6d468770cd51b10e6a68721be611a8b4d282601db3b36be9246915ec82a"),
                b"X"*65, b"pass phrase exceeds block size", 1200, 32
            ),

        #
        # from rfc 6070
        #
            (
                hb("0c60c80f961f0e71f3a9b524af6012062fe037a6"),
                b"password", b"salt", 1, 20,
            ),

            (
                hb("ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957"),
                b"password", b"salt", 2, 20,
            ),

            (
                hb("4b007901b765489abead49d926f721d065a429c1"),
                b"password", b"salt", 4096, 20,
            ),

            # just runs too long - could enable if ALL option is set
            ##(
            ##
            ##    hb("eefe3d61cd4da4e4e9945b3d6ba2158c2634e984"),
            ##    "password", "salt", 16777216, 20,
            ##),

            (
                hb("3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038"),
                b"passwordPASSWORDpassword",
                b"saltSALTsaltSALTsaltSALTsaltSALTsalt",
                4096, 25,
            ),

            (
                hb("56fa6aa75548099dcc37d7f03425e0c3"),
                b"pass\00word", b"sa\00lt", 4096, 16,
            ),

        #
        # from example in http://grub.enbug.org/Authentication
        #
            (
               hb("887CFF169EA8335235D8004242AA7D6187A41E3187DF0CE14E256D85ED"
                  "97A97357AAA8FF0A3871AB9EEFF458392F462F495487387F685B7472FC"
                  "6C29E293F0A0"),
               b"hello",
               hb("9290F727ED06C38BA4549EF7DE25CF5642659211B7FC076F2D28FEFD71"
                  "784BB8D8F6FB244A8CC5C06240631B97008565A120764C0EE9C2CB0073"
                  "994D79080136"),
               10000, 64, "sha512"
            ),

        #
        # custom tests
        #
            (
                hb('e248fb6b13365146f8ac6307cc222812'),
                b"secret", b"salt", 10, 16, "sha1",
            ),
            (
                hb('e248fb6b13365146f8ac6307cc2228127872da6d'),
                b"secret", b"salt", 10, None, "sha1",
            ),

        ]

    def test_known(self):
        """test reference vectors"""
        for row in self.pbkdf2_test_vectors:
            correct, secret, salt, rounds, keylen = row[:5]
            digest = row[5] if len(row) == 6 else "sha1"
            result = pbkdf2_hmac(digest, secret, salt, rounds, keylen)
            self.assertEqual(result, correct)

    def test_border(self):
        """test border cases"""
        def helper(secret=b'password', salt=b'salt', rounds=1, keylen=None, digest="sha1"):
            return pbkdf2_hmac(digest, secret, salt, rounds, keylen)
        helper()

        # invalid rounds
        self.assertRaises(ValueError, helper, rounds=0)
        self.assertRaises(TypeError, helper, rounds='x')

        # invalid keylen
        helper(keylen=0)
        self.assertRaises(ValueError, helper, keylen=-1)
        self.assertRaises(ValueError, helper, keylen=20*(2**32-1)+1)
        self.assertRaises(TypeError, helper, keylen='x')

        # invalid secret/salt type
        self.assertRaises(TypeError, helper, salt=5)
        self.assertRaises(TypeError, helper, secret=5)

        # invalid hash
        self.assertRaises(ValueError, helper, digest='foo')
        self.assertRaises(TypeError, helper, digest=5)

    def test_default_keylen(self):
        """test keylen==None"""
        def helper(secret=b'password', salt=b'salt', rounds=1, keylen=None, digest="sha1"):
            return pbkdf2_hmac(digest, secret, salt, rounds, keylen)
        self.assertEqual(len(helper(digest='sha1')), 20)
        self.assertEqual(len(helper(digest='sha256')), 32)

#------------------------------------------------------------------------
# create subclasses to test with- and without- m2crypto
#------------------------------------------------------------------------

def has_m2crypto():
    try:
        import M2Crypto
        return True
    except ImportError:
        return False

@skipUnless(has_m2crypto(), "M2Crypto not found")
class Pbkdf2_M2Crypto_Test(_Common_Pbkdf2_Test):
    descriptionPrefix = "passlib.crypto.digest.pbkdf2_hmac() <m2crypto backend>"

@skipUnless(TEST_MODE("full") or not has_m2crypto(), "skipped under current test mode")
class Pbkdf2_Builtin_Test(_Common_Pbkdf2_Test):
    descriptionPrefix = "passlib.crypto.digest.pbkdf2_hmac() <builtin backend>"

    def setUp(self):
        super(Pbkdf2_Builtin_Test, self).setUp()
        # make sure m2crypto support is disabled, to force pure-python backend
        import passlib.crypto.digest as mod
        self.addCleanup(setattr, mod, "_m2crypto_pbkdf2_hmac_sha1",
                        mod._m2crypto_pbkdf2_hmac_sha1)
        mod._m2crypto_pbkdf2_hmac_sha1 = None

#=============================================================================
# eof
#=============================================================================
