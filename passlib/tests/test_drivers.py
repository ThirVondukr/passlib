"""tests for passlib.pwhash -- (c) Assurance Technologies 2003-2009"""
#=========================================================
#imports
#=========================================================
from __future__ import with_statement
#core
import hashlib
import logging; log = logging.getLogger(__name__)
import warnings
#site
#pkg
from passlib import hash
from passlib.tests.utils import TestCase, HandlerCase, create_backend_case, \
        enable_option, b, catch_warnings
#module


#=========================================================
#some
#=========================================================

#some common unicode passwords which used as test cases...
UPASS_WAV = u'\u0399\u03c9\u03b1\u03bd\u03bd\u03b7\u03c2'
UPASS_USD = u"\u20AC\u00A5$"
UPASS_TABLE = u"t\u00e1\u0411\u2113\u0259"

#=========================================================
#apr md5 crypt
#=========================================================
from passlib.handlers.md5_crypt import apr_md5_crypt
class AprMd5CryptTest(HandlerCase):
    handler = apr_md5_crypt

    #values taken from http://httpd.apache.org/docs/2.2/misc/password_encryptions.html
    known_correct_hashes = [
        ('myPassword', '$apr1$r31.....$HqJZimcKQFAMYayBlzkrA/'),
        ]

    known_malformed_hashes = [
        #bad char in otherwise correct hash
        '$apr1$r31.....$HqJZimcKQFAMYayBlzkrA!'
        ]

#=========================================================
#bcrypt
#=========================================================
class _BCryptTest(HandlerCase):
    "base for BCrypt test cases"

    handler = hash.bcrypt
    secret_chars = 72

    known_correct_hashes = [
        #selected bcrypt test vectors
        ('', '$2a$06$DCq7YPn5Rq63x1Lad4cll.TV4S6ytwfsfvkgY8jIucDrjc8deX1s.'),
        ('a', '$2a$10$k87L/MF28Q673VKh8/cPi.SUl7MU/rWuSiIDDFayrKk/1tBsSQu4u'),
        ('abc', '$2a$10$WvvTPHKwdBJ3uk0Z37EMR.hLA2W6N9AEBhEgrAOljy2Ae5MtaSIUi'),
        ('abcdefghijklmnopqrstuvwxyz',
                '$2a$10$fVH8e28OQRj9tqiDXs1e1uxpsjN0c7II7YPKXua2NAKYvM6iQk7dq'),
        ('~!@#$%^&*()      ~!@#$%^&*()PNBFRD',
                '$2a$10$LgfYWkbzEvQ4JakH7rOvHe0y8pHKF9OaFgwUZ2q7W2FFZmZzJYlfS'),
        ]

    known_unidentified_hashes = [
        #unsupported minor version
        "$2b$12$EXRkfkdmXn!gzds2SSitu.MW9.gAVqa9eLS1//RYtYCmB1eLHg.9q",
    ]

    known_malformed_hashes = [
        #bad char in otherwise correct hash
        "$2a$12$EXRkfkdmXn!gzds2SSitu.MW9.gAVqa9eLS1//RYtYCmB1eLHg.9q",

        #rounds not zero-padded (pybcrypt rejects this, therefore so do we)
        '$2a$6$DCq7YPn5Rq63x1Lad4cll.TV4S6ytwfsfvkgY8jIucDrjc8deX1s.'

        #NOTE: salts with padding bits set are technically malformed,
        #      but that's one we can reliably correct & issue warning for.
        ]

    #===============================================================
    # extra tests
    #===============================================================
    def iter_external_verifiers(self):
        try:
            from bcrypt import hashpw
        except ImportError:
            pass
        else:
            def check_pybcrypt(secret, hash):
                self.assertEqual(hashpw(secret, hash), hash,
                                 "pybcrypt: bcrypt.hashpw(%r,%r):" % (secret, hash))
            yield check_pybcrypt

        try:
            from bcryptor.engine import Engine
        except ImportError:
            pass
        else:
            def check_bcryptor(secret, hash):
                result = Engine(False).hash_key(secret, hash)
                self.assertEqual(result, hash,
                                 "bcryptor: hash_key(%r,%r):" % (secret, hash))
            yield check_bcryptor

    def test_90_idents(self):
        "test identifier validation"
        handler = self.handler

        kwds = dict(checksum='8CIhhFCj15KqqFvo/n.Jatx8dJ92f82',
                    salt='VlsfIX9.apXuQBr6tego0.',
                    rounds=12, ident="2a", strict=True)

        handler(**kwds)

        kwds['ident'] = None
        self.assertRaises(ValueError, handler, **kwds)

        del kwds['strict']

        kwds['ident'] = 'Q'
        self.assertRaises(ValueError, handler, **kwds)

    #===============================================================
    # see issue 25 - https://code.google.com/p/passlib/issues/detail?id=25
    # bcrypt's salt ends with 4 padding bits.
    # openbsd, pybcrypt, etc assume these bits are always 0.
    # passlib <= 1.5.2 generated salts where this wasn't usually the case.
    # as of 1.5.3, we want to always generate salts w/ 0 padding,
    # and clear the padding of any incoming hashes
    #===============================================================
    def do_genconfig(self, **kwds):
        # correct provided salts to handle ending correctly,
        # so test_33_genconfig_saltchars doesn't throw warnings.
        if 'salt' in kwds:
            from passlib.handlers.bcrypt import BCHARS, BSLAST
            salt = kwds['salt']
            if salt and salt[-1] not in BSLAST:
                salt = salt[:-1] + BCHARS[BCHARS.index(salt[-1])&~15]
            kwds['salt'] = salt
        return self.handler.genconfig(**kwds)

    def test_91_bcrypt_padding(self):
        "test passlib correctly handles bcrypt padding bits"
        bcrypt = self.handler

        def check_warning(wlog):
            self.assertWarningMatches(wlog.pop(0),
                message_re="^encountered a bcrypt hash with incorrectly set padding bits.*",
            )
            self.assertFalse(wlog)

        def check_padding(hash):
            "check bcrypt hash doesn't have salt padding bits set"
            assert hash.startswith("$2a$") and len(hash) >= 28
            self.assertTrue(hash[28] in BSLAST,
                            "padding bits set in hash: %r" % (hash,))

        #===============================================================
        # test generated salts
        #===============================================================
        from passlib.handlers.bcrypt import BCHARS, BSLAST

        # make sure genconfig & encrypt don't return bad hashes.
        # bug had 15/16 chance of occurring every time salt generated.
        # so we call it a few different way a number of times.
        for i in xrange(6):
            check_padding(bcrypt.genconfig())
        for i in xrange(3):
            check_padding(bcrypt.encrypt("bob", rounds=bcrypt.min_rounds))

        # check passing salt to genconfig causes it to be normalized.
        with catch_warnings(record=True) as wlog:
            warnings.simplefilter("always")

            hash = bcrypt.genconfig(salt="."*21 + "A.")
            check_warning(wlog)
            self.assertEqual(hash, "$2a$12$" + "." * 22)

            hash = bcrypt.genconfig(salt="."*23)
            self.assertFalse(wlog)
            self.assertEqual(hash, "$2a$12$" + "." * 22)

        #===============================================================
        # test handling existing hashes
        #===============================================================

        # 2 bits of salt padding set
        PASS1 = "loppux"
        BAD1  = "$2a$12$oaQbBqq8JnSM1NHRPQGXORm4GCUMqp7meTnkft4zgSnrbhoKdDV0C"
        GOOD1 = "$2a$12$oaQbBqq8JnSM1NHRPQGXOOm4GCUMqp7meTnkft4zgSnrbhoKdDV0C"

        # all 4 bits of salt padding set
        PASS2 = "Passlib11"
        BAD2  = "$2a$12$M8mKpW9a2vZ7PYhq/8eJVcUtKxpo6j0zAezu0G/HAMYgMkhPu4fLK"
        GOOD2 = "$2a$12$M8mKpW9a2vZ7PYhq/8eJVOUtKxpo6j0zAezu0G/HAMYgMkhPu4fLK"

        # bad checksum padding
        PASS3 = "test"
        BAD3  = "$2a$04$yjDgE74RJkeqC0/1NheSSOrvKeu9IbKDpcQf/Ox3qsrRS/Kw42qIV"
        GOOD3 = "$2a$04$yjDgE74RJkeqC0/1NheSSOrvKeu9IbKDpcQf/Ox3qsrRS/Kw42qIS"

        # make sure genhash() corrects input
        with catch_warnings(record=True) as wlog:
            warnings.simplefilter("always")

            self.assertEqual(bcrypt.genhash(PASS1, BAD1), GOOD1)
            check_warning(wlog)

            self.assertEqual(bcrypt.genhash(PASS2, BAD2), GOOD2)
            check_warning(wlog)

            self.assertEqual(bcrypt.genhash(PASS2, GOOD2), GOOD2)
            self.assertFalse(wlog)
            
            self.assertEqual(bcrypt.genhash(PASS3, BAD3), GOOD3)
            check_warning(wlog)
            self.assertFalse(wlog)
            
        # make sure verify works on both bad and good hashes
        with catch_warnings(record=True) as wlog:
            warnings.simplefilter("always")

            self.assertTrue(bcrypt.verify(PASS1, BAD1))
            check_warning(wlog)

            self.assertTrue(bcrypt.verify(PASS1, GOOD1))
            self.assertFalse(wlog)

        #===============================================================
        # test normhash cleans things up correctly
        #===============================================================
        with catch_warnings(record=True) as wlog:
            warnings.simplefilter("always")
            self.assertEqual(bcrypt.normhash(BAD1), GOOD1)
            self.assertEqual(bcrypt.normhash(BAD2), GOOD2)
            self.assertEqual(bcrypt.normhash(GOOD1), GOOD1)
            self.assertEqual(bcrypt.normhash(GOOD2), GOOD2)
            self.assertEqual(bcrypt.normhash("$md5$abc"), "$md5$abc")

hash.bcrypt._no_backends_msg() #call this for coverage purposes

#create test cases for specific backends
Pybcrypt_BCryptTest = create_backend_case(_BCryptTest, "pybcrypt")
Bcryptor_BCryptTest = create_backend_case(_BCryptTest, "bcryptor")
OsCrypt_BCryptTest = create_backend_case(_BCryptTest, "os_crypt")

#=========================================================
#bigcrypt
#=========================================================
from passlib.handlers.des_crypt import bigcrypt

class BigCryptTest(HandlerCase):
    handler = bigcrypt

    #TODO: find an authortative source of test vectors,
    #these were found in docs and messages on the web.
    known_correct_hashes = [
        ("passphrase",               "qiyh4XPJGsOZ2MEAyLkfWqeQ"),
        ("This is very long passwd", "f8.SVpL2fvwjkAnxn8/rgTkwvrif6bjYB5c"),
    ]

    known_unidentified_hashes = [
        #one char short
        "qiyh4XPJGsOZ2MEAyLkfWqe"
    ]

    #omit des_crypt from known other, it looks like bigcrypt
    known_other_hashes = [row for row in HandlerCase.known_other_hashes if row[0] != "des_crypt"]

#=========================================================
#bsdi crypt
#=========================================================
class _BSDiCryptTest(HandlerCase):
    "test BSDiCrypt algorithm"
    handler = hash.bsdi_crypt
    known_correct_hashes = [
        (" ", "_K1..crsmZxOLzfJH8iw"),
        ("my", '_KR/.crsmykRplHbAvwA'), #<- to detect old 12-bit rounds bug
        ("my socra", "_K1..crsmf/9NzZr1fLM"),
        ("my socrates", '_K1..crsmOv1rbde9A9o'),
        ("my socrates note", "_K1..crsm/2qeAhdISMA"),
    ]
    known_unidentified_hashes = [
        #bad char in otherwise correctly formatted hash
       "_K1.!crsmZxOLzfJH8iw"
    ]

OsCrypt_BSDiCryptTest = create_backend_case(_BSDiCryptTest, "os_crypt")
Builtin_BSDiCryptTest = create_backend_case(_BSDiCryptTest, "builtin")

#=========================================================
#crypt16
#=========================================================
from passlib.handlers.des_crypt import crypt16

class Crypt16Test(HandlerCase):
    handler = crypt16
    secret_chars = 16

    #TODO: find an authortative source of test vectors
    #instead of just msgs around the web
    #   (eg http://seclists.org/bugtraq/1999/Mar/76)
    known_correct_hashes = [
        ("passphrase",  "qi8H8R7OM4xMUNMPuRAZxlY."),
        ("printf",      "aaCjFz4Sh8Eg2QSqAReePlq6"),
        ("printf",      "AA/xje2RyeiSU0iBY3PDwjYo"),
        ("LOLOAQICI82QB4IP", "/.FcK3mad6JwYt8LVmDqz9Lc"),
        ("LOLOAQICI",   "/.FcK3mad6JwYSaRHJoTPzY2"),
        ("LOLOAQIC",    "/.FcK3mad6JwYelhbtlysKy6"),
        ("L",           "/.CIu/PzYCkl6elhbtlysKy6"),
        ]
#=========================================================
#des crypt
#=========================================================
from passlib.handlers.des_crypt import des_crypt

class _DesCryptTest(HandlerCase):
    "test des-crypt algorithm"
    handler = des_crypt
    secret_chars = 8

    known_correct_hashes = [
        #secret, example hash which matches secret
        ('', 'OgAwTx2l6NADI'),
        (' ', '/Hk.VPuwQTXbc'),
        ('test', 'N1tQbOFcM5fpg'),
        ('Compl3X AlphaNu3meric', 'um.Wguz3eVCx2'),
        ('4lpHa N|_|M3r1K W/ Cur5Es: #$%(*)(*%#', 'sNYqfOyauIyic'),
        ('AlOtBsOl', 'cEpWz5IUCShqM'),
        (u'hell\u00D6', 'saykDgk3BPZ9E'),
        ]
    known_unidentified_hashes = [
        #bad char in otherwise correctly formatted hash
        '!gAwTx2l6NADI',
        ]

    def test_invalid_secret_chars(self):
        self.assertRaises(ValueError, self.do_encrypt, 'sec\x00t')

OsCrypt_DesCryptTest = create_backend_case(_DesCryptTest, "os_crypt")
Builtin_DesCryptTest = create_backend_case(_DesCryptTest, "builtin")

#=========================================================
#django
#=========================================================
class _DjangoHelper(object):

    def test_django_reference(self):
        "run known correct hashes through Django's check_password()"
        if not self.known_correct_hashes:
            return self.skipTest("no known correct hashes specified")
        from passlib.tests.test_ext_django import has_django1
        if not has_django1:
            return self.skipTest("Django not installed")
        from django.contrib.auth.models import check_password
        for secret, hash in self.all_correct_hashes:
            self.assertTrue(check_password(secret, hash))
            self.assertFalse(check_password('x' + secret, hash))

class DjangoDisabledTest(HandlerCase):
    "test django_disabled"

    #NOTE: this class behaves VERY differently from a normal password hash,
    #so we subclass & disable a number of the default tests.
    #TODO: combine these features w/ unix_fallback and other disabled handlers.

    handler = hash.django_disabled
    handler_type = "disabled"

    def test_20_verify_positive(self):
        for secret, result in [
            ("password", "!"),
            ("", "!"),
        ]:
            self.assertFalse(self.do_verify(secret, result))

    def test_50_encrypt_plain(self):
        "test encrypt() basic behavior"
        secret = UPASS_USD
        result = self.do_encrypt(secret)
        self.assertEqual(result, "!")
        self.assertTrue(not self.do_verify(secret, result))

class DjangoDesCryptTest(HandlerCase, _DjangoHelper):
    "test django_des_crypt"
    handler = hash.django_des_crypt
    secret_chars = 8

    known_correct_hashes = [
        #ensures only first two digits of salt count.
        ("password",         'crypt$c2$c2M87q...WWcU'),
        ("password",         'crypt$c2e86$c2M87q...WWcU'),
        ("passwordignoreme", 'crypt$c2.AZ$c2M87q...WWcU'),

        #ensures utf-8 used for unicode
        (UPASS_USD, 'crypt$c2e86$c2hN1Bxd6ZiWs'),
        (UPASS_TABLE, 'crypt$0.aQs$0.wB.TT0Czvlo'),
        (u"hell\u00D6", "crypt$sa$saykDgk3BPZ9E"),

        #prevent regression of issue 22
        ("foo", 'crypt$MNVY.9ajgdvDQ$MNVY.9ajgdvDQ'),
    ]

    known_unidentified_hashes = [
        'sha1$aa$bb',
    ]

    known_malformed_hashes = [
        # checksum too short
        'crypt$c2$c2M87q',

        # salt must be >2
        'crypt$$c2M87q...WWcU',
        'crypt$f$c2M87q...WWcU',

        # this format duplicates salt inside checksum,
        # reject any where the two copies don't match
        'crypt$ffe86$c2M87q...WWcU',
    ]

class DjangoSaltedMd5Test(HandlerCase, _DjangoHelper):
    "test django_salted_md5"
    handler = hash.django_salted_md5

    known_correct_hashes = [
        #test extra large salt
        ("password",    'md5$123abcdef$c8272612932975ee80e8a35995708e80'),

        #test unicode uses utf-8
        (UPASS_USD,     'md5$c2e86$92105508419a81a6babfaecf876a2fa0'),
        (UPASS_TABLE,   'md5$d9eb8$01495b32852bffb27cf5d4394fe7a54c'),
    ]

    known_unidentified_hashes = [
        'sha1$aa$bb',
    ]

    known_malformed_hashes = [
        # checksum too short
        'md5$aa$bb',
    ]

class DjangoSaltedSha1Test(HandlerCase, _DjangoHelper):
    "test django_salted_sha1"
    handler = hash.django_salted_sha1

    known_correct_hashes = [
        #test extra large salt
        ("password",'sha1$123abcdef$e4a1877b0e35c47329e7ed7e58014276168a37ba'),

        #test unicode uses utf-8
        (UPASS_USD,     'sha1$c2e86$0f75c5d7fbd100d587c127ef0b693cde611b4ada'),
        (UPASS_TABLE,   'sha1$6d853$ef13a4d8fb57aed0cb573fe9c82e28dc7fd372d4'),

        #generic password
        ("MyPassword",  'sha1$54123$893cf12e134c3c215f3a76bd50d13f92404a54d3'),
    ]

    known_unidentified_hashes = [
        'md5$aa$bb',
    ]

    known_malformed_hashes = [
        # checksum too short
        'sha1$c2e86$0f75',
    ]

#=========================================================
#fshp
#=========================================================
class FSHPTest(HandlerCase):
    "test fshp algorithm"
    handler = hash.fshp

    known_correct_hashes = [
        #secret, example hash which matches secret

        #test vectors from FSHP reference implementation
        ('test', '{FSHP0|0|1}qUqP5cyxm6YcTAhz05Hph5gvu9M='),

        ('test',
            '{FSHP1|8|4096}MTIzNDU2NzjTdHcmoXwNc0f'
            'f9+ArUHoN0CvlbPZpxFi1C6RDM/MHSA=='
            ),

        ('OrpheanBeholderScryDoubt',
            '{FSHP1|8|4096}GVSUFDAjdh0vBosn1GUhz'
            'GLHP7BmkbCZVH/3TQqGIjADXpc+6NCg3g=='
            ),
        ('ExecuteOrder66',
            '{FSHP3|16|8192}0aY7rZQ+/PR+Rd5/I9ss'
            'RM7cjguyT8ibypNaSp/U1uziNO3BVlg5qPU'
            'ng+zHUDQC3ao/JbzOnIBUtAeWHEy7a2vZeZ'
            '7jAwyJJa2EqOsq4Io='
            ),
        ]

    known_unidentified_hashes = [
        #bad char in otherwise correctly formatted hash
        '{FSHX0|0|1}qUqP5cyxm6YcTAhz05Hph5gvu9M=',
        'FSHP0|0|1}qUqP5cyxm6YcTAhz05Hph5gvu9M=',
        ]

    known_malformed_hashes = [
        #wrong salt size
        '{FSHP0|1|1}qUqP5cyxm6YcTAhz05Hph5gvu9M=',

        #bad rounds
        '{FSHP0|0|A}qUqP5cyxm6YcTAhz05Hph5gvu9M=',
    ]

#=========================================================
#hex digests
#=========================================================
from passlib.handlers import digests

class HexMd4Test(HandlerCase):
    handler = digests.hex_md4
    known_correct_hashes = [ ("password", '8a9d093f14f8701df17732b2bb182c74')]

class HexMd5Test(HandlerCase):
    handler = digests.hex_md5
    known_correct_hashes = [ ("password", '5f4dcc3b5aa765d61d8327deb882cf99')]

class HexSha1Test(HandlerCase):
    handler = digests.hex_sha1
    known_correct_hashes = [ ("password", '5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8')]

class HexSha256Test(HandlerCase):
    handler = digests.hex_sha256
    known_correct_hashes = [ ("password", '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8')]

class HexSha512Test(HandlerCase):
    handler = digests.hex_sha512
    known_correct_hashes = [ ("password", 'b109f3bbbc244eb82441917ed06d618b9008dd09b3befd1b5e07394c706a8bb980b1d7785e5976ec049b46df5f1326af5a2ea6d103fd07c95385ffab0cacbc86')]

#=========================================================
#ldap hashes
#=========================================================
from passlib.handlers import ldap_digests

class LdapMd5Test(HandlerCase):
    handler = ldap_digests.ldap_md5
    known_correct_hashes = [ ("helloworld", '{MD5}/F4DjTilcDIIVEHn/nAQsA==')]

class LdapSha1Test(HandlerCase):
    handler = ldap_digests.ldap_sha1
    known_correct_hashes = [ ("helloworld", '{SHA}at+xg6SiyUovktq1redipHiJpaE=')]

class LdapSaltedMd5Test(HandlerCase):
    handler = ldap_digests.ldap_salted_md5
    known_correct_hashes = [ ("testing1234", '{SMD5}UjFY34os/pnZQ3oQOzjqGu4yeXE=')]

class LdapSaltedSha1Test(HandlerCase):
    handler = ldap_digests.ldap_salted_sha1
    known_correct_hashes = [ ("testing123", '{SSHA}0c0blFTXXNuAMHECS4uxrj3ZieMoWImr'),
            ("secret", "{SSHA}0H+zTv8o4MR4H43n03eCsvw1luG8LdB7"),
            ]

class LdapPlaintextTest(HandlerCase):
    handler = ldap_digests.ldap_plaintext
    known_correct_hashes = [ ("password", 'password') ]
    known_unidentified_hashes = [ "{FOO}bar" ]

    known_other_hashes = [ ("ldap_md5", "{MD5}/F4DjTilcDIIVEHn/nAQsA==")]

#NOTE: since the ldap_{crypt} handlers are all wrappers,
# don't need separate test. have just one for end-to-end testing purposes.

class _LdapMd5CryptTest(HandlerCase):
    handler = ldap_digests.ldap_md5_crypt

    known_correct_hashes = [
        ('', '{CRYPT}$1$dOHYPKoP$tnxS1T8Q6VVn3kpV8cN6o.'),
        (' ', '{CRYPT}$1$m/5ee7ol$bZn0kIBFipq39e.KDXX8I0'),
        ('test', '{CRYPT}$1$ec6XvcoW$ghEtNK2U1MC5l.Dwgi3020'),
        ('Compl3X AlphaNu3meric', '{CRYPT}$1$nX1e7EeI$ljQn72ZUgt6Wxd9hfvHdV0'),
        ('4lpHa N|_|M3r1K W/ Cur5Es: #$%(*)(*%#', '{CRYPT}$1$jQS7o98J$V6iTcr71CGgwW2laf17pi1'),
        ('test', '{CRYPT}$1$SuMrG47N$ymvzYjr7QcEQjaK5m1PGx1'),
        ]

    known_malformed_hashes = [
        #bad char in otherwise correct hash
        '{CRYPT}$1$dOHYPKoP$tnxS1T8Q6VVn3kpV8cN6o!',
        ]

OsCrypt_LdapMd5CryptTest = create_backend_case(_LdapMd5CryptTest, "os_crypt")
Builtin_LdapMd5CryptTest = create_backend_case(_LdapMd5CryptTest, "builtin")

#=========================================================
#ldap_pbkdf2_{digest}
#=========================================================
from passlib.handlers import pbkdf2 as pk2

#NOTE: since these are all wrappers for the pbkdf2_{digest} hasehs,
# they don't extensive separate testing.

class LdapPbkdf2Test(TestCase):

    def test_wrappers(self):
        "test ldap pbkdf2 wrappers"

        self.assertTrue(
            pk2.ldap_pbkdf2_sha1.verify(
                "password",
                '{PBKDF2}1212$OB.dtnSEXZK8U5cgxU/GYQ$y5LKPOplRmok7CZp/aqVDVg8zGI',
            )
        )

        self.assertTrue(
            pk2.ldap_pbkdf2_sha256.verify(
                "password",
                '{PBKDF2-SHA256}1212$4vjV83LKPjQzk31VI4E0Vw$hsYF68OiOUPdDZ1Fg'
                '.fJPeq1h/gXXY7acBp9/6c.tmQ'
            )
        )

        self.assertTrue(
            pk2.ldap_pbkdf2_sha512.verify(
                "password",
                '{PBKDF2-SHA512}1212$RHY0Fr3IDMSVO/RSZyb5ow$eNLfBK.eVozomMr.1gYa1'
                '7k9B7KIK25NOEshvhrSX.esqY3s.FvWZViXz4KoLlQI.BzY/YTNJOiKc5gBYFYGww'
            )
        )

#=========================================================
#md5 crypt
#=========================================================
from passlib.handlers.md5_crypt import md5_crypt, raw_md5_crypt
class _Md5CryptTest(HandlerCase):
    handler = md5_crypt

    known_correct_hashes = [
        #NOTE: would need to patch HandlerCase to coerce hashes
        #to_hash_str() for this first one to work under py3.
##        ('', b('$1$dOHYPKoP$tnxS1T8Q6VVn3kpV8cN6o.')),
        ('', '$1$dOHYPKoP$tnxS1T8Q6VVn3kpV8cN6o.'),
        (' ', '$1$m/5ee7ol$bZn0kIBFipq39e.KDXX8I0'),
        ('test', '$1$ec6XvcoW$ghEtNK2U1MC5l.Dwgi3020'),
        ('Compl3X AlphaNu3meric', '$1$nX1e7EeI$ljQn72ZUgt6Wxd9hfvHdV0'),
        ('4lpHa N|_|M3r1K W/ Cur5Es: #$%(*)(*%#', '$1$jQS7o98J$V6iTcr71CGgwW2laf17pi1'),
        ('test', '$1$SuMrG47N$ymvzYjr7QcEQjaK5m1PGx1'),
        (b('test'), '$1$SuMrG47N$ymvzYjr7QcEQjaK5m1PGx1'),
        ]

    known_malformed_hashes = [
        #bad char in otherwise correct hash
        '$1$dOHYPKoP$tnxS1T8Q6VVn3kpV8cN6o!',
        ]

    def test_raw(self):
        self.assertEqual(raw_md5_crypt(u's',u's'*16), u'YgmLTApYTv12qgTwBoj8i/')

OsCrypt_Md5CryptTest = create_backend_case(_Md5CryptTest, "os_crypt")
Builtin_Md5CryptTest = create_backend_case(_Md5CryptTest, "builtin")

#=========================================================
#mysql 323 & 41
#=========================================================
from passlib.handlers.mysql import mysql323, mysql41

class Mysql323Test(HandlerCase):
    handler = mysql323

    known_correct_hashes = [
        ('mypass', '6f8c114b58f2ce9e'),
    ]
    known_unidentified_hashes = [
        #bad char in otherwise correct hash
        '6z8c114b58f2ce9e',
    ]

    def test_whitespace(self):
        "check whitespace is ignored per spec"
        h = self.do_encrypt("mypass")
        h2 = self.do_encrypt("my pass")
        self.assertEqual(h, h2)

class Mysql41Test(HandlerCase):
    handler = mysql41
    known_correct_hashes = [
        ('mypass', '*6C8989366EAF75BB670AD8EA7A7FC1176A95CEF4'),
    ]
    known_unidentified_hashes = [
        #bad char in otherwise correct hash
        '*6Z8989366EAF75BB670AD8EA7A7FC1176A95CEF4',
    ]

#=========================================================
#NTHASH for unix
#=========================================================
from passlib.handlers.nthash import nthash

class NTHashTest(HandlerCase):
    handler = nthash

    known_correct_hashes = [
        ('passphrase', '$3$$7f8fe03093cc84b267b109625f6bbf4b'),
        ('passphrase', '$NT$7f8fe03093cc84b267b109625f6bbf4b'),
    ]

    known_malformed_hashes = [
        #bad char in otherwise correct hash
        '$3$$7f8fe03093cc84b267b109625f6bbfxb',
    ]

    def test_idents(self):
        handler = self.handler

        kwds = dict(checksum='7f8fe03093cc84b267b109625f6bbf4b', ident="3", strict=True)
        handler(**kwds)

        kwds['ident'] = None
        self.assertRaises(ValueError, handler, **kwds)

        del kwds['strict']
        kwds['ident'] = 'Q'
        self.assertRaises(ValueError, handler, **kwds)

#=========================================================
#oracle 10 & 11
#=========================================================
from passlib.handlers.oracle import oracle10, oracle11

class Oracle10Test(HandlerCase):
    handler = oracle10

    known_correct_hashes = [
        # ((secret,user),hash)
        (('tiger',          'scott'),       'F894844C34402B67'),
        ((u'ttTiGGeR',      u'ScO'),        '7AA1A84E31ED7771'),
        (("d_syspw",        "SYSTEM"),      '1B9F1F9A5CB9EB31'),
        (("strat_passwd",   "strat_user"),  'AEBEDBB4EFB5225B'),
        #TODO: get more test vectors (especially ones which properly test unicode / non-ascii)
        #existing vectors taken from - http://www.petefinnigan.com/default/default_password_list.htm
    ]

    known_unidentified_hashes = [
        #bad 'z' char in otherwise correct hash
        'F894844C34402B6Z',
    ]

    def test_user(self):
        "check user kwd is required for encrypt/verify"
        self.assertRaises(TypeError, self.handler.encrypt, 'mypass')
        self.assertRaises(ValueError, self.handler.encrypt, 'mypass', None)
        self.assertRaises(TypeError, self.handler.verify, 'mypass', 'CC60FA650C497E52')

    #NOTE: all of the methods below are merely to override
    # the default test harness in order to insert a default username
    # when encrypt/verify/etc are called.

    def create_mismatch(self, secret):
        if isinstance(secret, tuple):
            secret, user = secret
            return 'x' + secret, user
        else:
            return 'x' + secret

    def do_encrypt(self, secret, **kwds):
        if isinstance(secret, tuple):
            secret, user = secret
        else:
            user = 'default'
        assert 'user' not in kwds
        kwds['user'] = user
        return self.handler.encrypt(secret, **kwds)

    def do_verify(self, secret, hash):
        if isinstance(secret, tuple):
            secret, user = secret
        else:
            user = 'default'
        return self.handler.verify(secret, hash, user=user)

    def do_genhash(self, secret, config):
        if isinstance(secret, tuple):
            secret, user = secret
        else:
            user = 'default'
        return self.handler.genhash(secret, config, user=user)

class Oracle11Test(HandlerCase):
    handler = oracle11
    known_correct_hashes = [
        ("SHAlala", "S:2BFCFDF5895014EE9BB2B9BA067B01E0389BB5711B7B5F82B7235E9E182C"),
        #TODO: find more test vectors
    ]

#=========================================================
#pbkdf2 hashes
#=========================================================
from passlib.handlers import pbkdf2 as pk2

class AtlassianPbkdf2Sha1Test(HandlerCase):
    handler = pk2.atlassian_pbkdf2_sha1
    known_correct_hashes = [
        ("admin", '{PKCS5S2}c4xaeTQM0lUieMS3V5voiexyX9XhqC2dBd5ecVy60IPksHChwoTAVYFrhsgoq8/p'),
        (u'\u0399\u03c9\u03b1\u03bd\u03bd\u03b7\u03c2',
                  "{PKCS5S2}cE9Yq6Am5tQGdHSHhky2XLeOnURwzaLBG2sur7FHKpvy2u0qDn6GcVGRjlmJoIUy"),
    ]

    known_malformed_hashes = [
        #bad char
        '{PKCS5S2}c4xaeTQM0lUieMS3V5voiexyX9XhqC2dBd5ecVy60IPksHChwoTAVYFrhsgoq!/p'

        #bad size, missing padding
        '{PKCS5S2}c4xaeTQM0lUieMS3V5voiexyX9XhqC2dBd5ecVy60IPksHChwoTAVYFrhsgoq8/'

        #bad size, with correct padding
        '{PKCS5S2}c4xaeTQM0lUieMS3V5voiexyX9XhqC2dBd5ecVy60IPksHChwoTAVYFrhsgoq8/='
    ]

class Pbkdf2Sha1Test(HandlerCase):
    handler = pk2.pbkdf2_sha1
    known_correct_hashes = [
        ("password", '$pbkdf2$1212$OB.dtnSEXZK8U5cgxU/GYQ$y5LKPOplRmok7CZp/aqVDVg8zGI'),
        (u'\u0399\u03c9\u03b1\u03bd\u03bd\u03b7\u03c2',
            '$pbkdf2$1212$THDqatpidANpadlLeTeOEg$HV3oi1k5C5LQCgG1BMOL.BX4YZc'),
    ]

class Pbkdf2Sha256Test(HandlerCase):
    handler = pk2.pbkdf2_sha256
    known_correct_hashes = [
        ("password",
            '$pbkdf2-sha256$1212$4vjV83LKPjQzk31VI4E0Vw$hsYF68OiOUPdDZ1Fg.fJPeq1h/gXXY7acBp9/6c.tmQ'
            ),
        (u'\u0399\u03c9\u03b1\u03bd\u03bd\u03b7\u03c2',
            '$pbkdf2-sha256$1212$3SABFJGDtyhrQMVt1uABPw$WyaUoqCLgvz97s523nF4iuOqZNbp5Nt8do/cuaa7AiI'
            ),
    ]

class Pbkdf2Sha512Test(HandlerCase):
    handler = pk2.pbkdf2_sha512
    known_correct_hashes = [
        ("password",
            '$pbkdf2-sha512$1212$RHY0Fr3IDMSVO/RSZyb5ow$eNLfBK.eVozomMr.1gYa1'
            '7k9B7KIK25NOEshvhrSX.esqY3s.FvWZViXz4KoLlQI.BzY/YTNJOiKc5gBYFYGww'
            ),
        (u'\u0399\u03c9\u03b1\u03bd\u03bd\u03b7\u03c2',
            '$pbkdf2-sha512$1212$KkbvoKGsAIcF8IslDR6skQ$8be/PRmd88Ps8fmPowCJt'
            'tH9G3vgxpG.Krjt3KT.NP6cKJ0V4Prarqf.HBwz0dCkJ6xgWnSj2ynXSV7MlvMa8Q'
            ),
    ]

class CtaPbkdf2Sha1Test(HandlerCase):
    handler = pk2.cta_pbkdf2_sha1
    known_correct_hashes = [
        #test vectors from original implementation
        (u"hashy the \N{SNOWMAN}", '$p5k2$1000$ZxK4ZBJCfQg=$jJZVscWtO--p1-xIZl6jhO2LKR0='),

        #additional test vectors
        ("password", "$p5k2$1$$h1TDLGSw9ST8UMAPeIE13i0t12c="),
        (u'\u0399\u03c9\u03b1\u03bd\u03bd\u03b7\u03c2',
            "$p5k2$4321$OTg3NjU0MzIx$jINJrSvZ3LXeIbUdrJkRpN62_WQ="),
        ]

class DlitzPbkdf2Sha1Test(HandlerCase):
    handler = pk2.dlitz_pbkdf2_sha1
    known_correct_hashes = [
        #test vectors from original implementation
        ('cloadm',  '$p5k2$$exec$r1EWMCMk7Rlv3L/RNcFXviDefYa0hlql'),
        ('gnu',     '$p5k2$c$u9HvcT4d$Sd1gwSVCLZYAuqZ25piRnbBEoAesaa/g'),
        ('dcl',     '$p5k2$d$tUsch7fU$nqDkaxMDOFBeJsTSfABsyn.PYUXilHwL'),
        ('spam',    '$p5k2$3e8$H0NX9mT/$wk/sE8vv6OMKuMaqazCJYDSUhWY9YB2J'),
        (u'\u0399\u03c9\u03b1\u03bd\u03bd\u03b7\u03c2',
                    '$p5k2$$KosHgqNo$9mjN8gqjt02hDoP0c2J0ABtLIwtot8cQ'),
        ]

class GrubPbkdf2Sha512Test(HandlerCase):
    handler = pk2.grub_pbkdf2_sha512
    known_correct_hashes = [
        #test vectors generated from cmd line tool

        #salt=32 bytes
        (u'\u0399\u03c9\u03b1\u03bd\u03bd\u03b7\u03c2',
            'grub.pbkdf2.sha512.10000.BCAC1CEC5E4341C8C511C529'
            '7FA877BE91C2817B32A35A3ECF5CA6B8B257F751.6968526A'
            '2A5B1AEEE0A29A9E057336B48D388FFB3F600233237223C21'
            '04DE1752CEC35B0DD1ED49563398A282C0F471099C2803FBA'
            '47C7919CABC43192C68F60'),

        #salt=64 bytes
        ('toomanysecrets',
            'grub.pbkdf2.sha512.10000.9B436BB6978682363D5C449B'
            'BEAB322676946C632208BC1294D51F47174A9A3B04A7E4785'
            '986CD4EA7470FAB8FE9F6BD522D1FC6C51109A8596FB7AD48'
            '7C4493.0FE5EF169AFFCB67D86E2581B1E251D88C777B98BA'
            '2D3256ECC9F765D84956FC5CA5C4B6FD711AA285F0A04DCF4'
            '634083F9A20F4B6F339A52FBD6BED618E527B'),

        ]

#=========================================================
#PHPass Portable Crypt
#=========================================================
from passlib.handlers.phpass import phpass

class PHPassTest(HandlerCase):
    handler = phpass

    known_correct_hashes = [
        ('', '$P$7JaFQsPzJSuenezefD/3jHgt5hVfNH0'),
        ('compL3X!', '$P$FiS0N5L672xzQx1rt1vgdJQRYKnQM9/'),
        ('test12345', '$P$9IQRaTwmfeRo7ud9Fh4E2PdI0S3r.L0'), #from the source
        ]

    known_malformed_hashes = [
        #bad char in otherwise correct hash
        '$P$9IQRaTwmfeRo7ud9Fh4E2PdI0S3r!L0',
        ]

    def test_idents(self):
        handler = self.handler

        kwds = dict(checksum='eRo7ud9Fh4E2PdI0S3r.L0', salt='IQRaTwmf', rounds=9, ident="P", strict=True)
        handler(**kwds)

        kwds['ident'] = None
        self.assertRaises(ValueError, handler, **kwds)

        del kwds['strict']
        kwds['ident'] = 'Q'
        self.assertRaises(ValueError, handler, **kwds)

#=========================================================
#plaintext
#=========================================================
from passlib.handlers.misc import plaintext

class PlaintextTest(HandlerCase):
    handler = plaintext

    known_correct_hashes = [
        ('',''),
        ('password', 'password'),
    ]

    known_other_hashes = [] #all strings are identified as belonging to this scheme

    accepts_empty_hash = True

#=========================================================
#postgres_md5
#=========================================================
from passlib.handlers.postgres import postgres_md5

class PostgresMD5CryptTest(HandlerCase):
    handler = postgres_md5
    known_correct_hashes = [
        # ((secret,user),hash)
        (('mypass', 'postgres'), 'md55fba2ea04fd36069d2574ea71c8efe9d'),
        (('mypass', 'root'), 'md540c31989b20437833f697e485811254b'),
        (("testpassword",'testuser'), 'md5d4fc5129cc2c25465a5370113ae9835f'),
    ]
    known_unidentified_hashes = [
        #bad 'z' char in otherwise correct hash
        'md54zc31989b20437833f697e485811254b',
    ]

    #NOTE: used to support secret=(password, user) format, but removed it for now.
    ##def test_tuple_mode(self):
    ##    "check tuple mode works for encrypt/verify"
    ##    self.assertEqual(self.handler.encrypt(('mypass', 'postgres')),
    ##        'md55fba2ea04fd36069d2574ea71c8efe9d')
    ##    self.assertEqual(self.handler.verify(('mypass', 'postgres'),
    ##        'md55fba2ea04fd36069d2574ea71c8efe9d'), True)

    def test_user(self):
        "check user kwd is required for encrypt/verify"
        self.handler.encrypt("mypass", u'user')
        self.assertRaises(TypeError, self.handler.encrypt, 'mypass')
        self.assertRaises(ValueError, self.handler.encrypt, 'mypass', None)
        self.assertRaises(TypeError, self.handler.verify, 'mypass', 'md55fba2ea04fd36069d2574ea71c8efe9d')

    def create_mismatch(self, secret):
        if isinstance(secret, tuple):
            secret, user = secret
            return 'x' + secret, user
        else:
            return 'x' + secret

    def do_encrypt(self, secret, **kwds):
        if isinstance(secret, tuple):
            secret, user = secret
        else:
            user = 'default'
        assert 'user' not in kwds
        kwds['user'] = user
        return self.handler.encrypt(secret, **kwds)

    def do_verify(self, secret, hash):
        if isinstance(secret, tuple):
            secret, user = secret
        else:
            user = 'default'
        return self.handler.verify(secret, hash, user=user)

    def do_genhash(self, secret, config):
        if isinstance(secret, tuple):
            secret, user = secret
        else:
            user = 'default'
        return self.handler.genhash(secret, config, user=user)

#=========================================================
# (netbsd's) sha1 crypt
#=========================================================
class _SHA1CryptTest(HandlerCase):
    handler = hash.sha1_crypt

    known_correct_hashes = [
        ("password", "$sha1$19703$iVdJqfSE$v4qYKl1zqYThwpjJAoKX6UvlHq/a"),
        ("password", "$sha1$21773$uV7PTeux$I9oHnvwPZHMO0Nq6/WgyGV/tDJIH"),
    ]

    known_malformed_hashes = [
        #bad char in otherwise correct hash
        '$sha1$21773$u!7PTeux$I9oHnvwPZHMO0Nq6/WgyGV/tDJIH',

        #zero padded rounds
        '$sha1$01773$uV7PTeux$I9oHnvwPZHMO0Nq6/WgyGV/tDJIH',
    ]

OsCrypt_SHA1CryptTest = create_backend_case(_SHA1CryptTest, "os_crypt")
Builtin_SHA1CryptTest = create_backend_case(_SHA1CryptTest, "builtin")

#=========================================================
#roundup
#=========================================================

#NOTE: all roundup hashes use PrefixWrapper,
# so there's nothing natively to test.
# so we just have a few quick cases...
from passlib.handlers import roundup

class RoundupTest(TestCase):

    def _test_pair(self, h, secret, hash):
        self.assertTrue(h.verify(secret, hash))
        self.assertFalse(h.verify('x'+secret, hash))

    def test_pairs(self):
        self._test_pair(
            roundup.ldap_hex_sha1,
            "sekrit",
            '{SHA}8d42e738c7adee551324955458b5e2c0b49ee655')

        self._test_pair(
            roundup.ldap_hex_md5,
            "sekrit",
            '{MD5}ccbc53f4464604e714f69dd11138d8b5')

        self._test_pair(
            ldap_digests.ldap_des_crypt,
            "sekrit",
            '{CRYPT}nFia0rj2TT59A')

        self._test_pair(
            roundup.roundup_plaintext,
            "sekrit",
            '{plaintext}sekrit')

        self._test_pair(
            pk2.ldap_pbkdf2_sha1,
            "sekrit",
            '{PBKDF2}5000$7BvbBq.EZzz/O0HuwX3iP.nAG3s$g3oPnFFaga2BJaX5PoPRljl4XIE')

#=========================================================
#sha256-crypt
#=========================================================
from passlib.handlers.sha2_crypt import sha256_crypt, raw_sha_crypt

class _SHA256CryptTest(HandlerCase):
    handler = sha256_crypt

    known_correct_hashes = [
        ('', '$5$rounds=10428$uy/jIAhCetNCTtb0$YWvUOXbkqlqhyoPMpN8BMe.ZGsGx2aBvxTvDFI613c3'),
        (' ', '$5$rounds=10376$I5lNtXtRmf.OoMd8$Ko3AI1VvTANdyKhBPavaRjJzNpSatKU6QVN9uwS9MH.'),
        ('test', '$5$rounds=11858$WH1ABM5sKhxbkgCK$aTQsjPkz0rBsH3lQlJxw9HDTDXPKBxC0LlVeV69P.t1'),
        ('Compl3X AlphaNu3meric', '$5$rounds=10350$o.pwkySLCzwTdmQX$nCMVsnF3TXWcBPOympBUUSQi6LGGloZoOsVJMGJ09UB'),
        ('4lpHa N|_|M3r1K W/ Cur5Es: #$%(*)(*%#', '$5$rounds=11944$9dhlu07dQMRWvTId$LyUI5VWkGFwASlzntk1RLurxX54LUhgAcJZIt0pYGT7'),
        (u'with unic\u00D6de', '$5$rounds=1000$IbG0EuGQXw5EkMdP$LQ5AfPf13KufFsKtmazqnzSGZ4pxtUNw3woQ.ELRDF4'),
        ]

    known_malformed_hashes = [
        #bad char in otherwise correct hash
        '$5$rounds=10428$uy/:jIAhCetNCTtb0$YWvUOXbkqlqhyoPMpN8BMeZGsGx2aBvxTvDFI613c3',

        #zero-padded rounds
       '$5$rounds=010428$uy/jIAhCetNCTtb0$YWvUOXbkqlqhyoPMpN8BMe.ZGsGx2aBvxTvDFI613c3',
    ]

    #NOTE: these test cases taken from official specification at http://www.akkadia.org/drepper/SHA-crypt.txt
    known_correct_configs = [
        #config, secret, result
        ( "$5$saltstring", "Hello world!",
          "$5$saltstring$5B8vYYiY.CVt1RlTTf8KbXBH3hsxY/GNooZaBBGWEc5" ),
        ( "$5$rounds=10000$saltstringsaltstring", "Hello world!",
          "$5$rounds=10000$saltstringsaltst$3xv.VbSHBb41AL9AvLeujZkZRBAwqFMz2."
          "opqey6IcA" ),
        ( "$5$rounds=5000$toolongsaltstring", "This is just a test",
          "$5$rounds=5000$toolongsaltstrin$Un/5jzAHMgOGZ5.mWJpuVolil07guHPvOW8"
          "mGRcvxa5" ),
        ( "$5$rounds=1400$anotherlongsaltstring",
          "a very much longer text to encrypt.  This one even stretches over more"
          "than one line.",
          "$5$rounds=1400$anotherlongsalts$Rx.j8H.h8HjEDGomFU8bDkXm3XIUnzyxf12"
          "oP84Bnq1" ),
        ( "$5$rounds=77777$short",
          "we have a short salt string but not a short password",
          "$5$rounds=77777$short$JiO1O3ZpDAxGJeaDIuqCoEFysAe1mZNJRs3pw0KQRd/" ),
        ( "$5$rounds=123456$asaltof16chars..", "a short string",
          "$5$rounds=123456$asaltof16chars..$gP3VQ/6X7UUEW3HkBn2w1/Ptq2jxPyzV/"
          "cZKmF/wJvD" ),
        ( "$5$rounds=10$roundstoolow", "the minimum number is still observed",
          "$5$rounds=1000$roundstoolow$yfvwcWrQ8l/K0DAWyuPMDNHpIVlTQebY9l/gL97"
          "2bIC" ),
    ]

    def filter_known_config_warnings(self):
        warnings.filterwarnings("ignore", "sha256_crypt does not allow less than 1000 rounds: 10", UserWarning)

    def test_raw(self):
        #run some tests on raw backend func to ensure it works right
        self.assertEqual(
             raw_sha_crypt(b('secret'), b('salt')*10, 1, hashlib.md5),
             (b('\x1f\x96\x1cO\x11\xa9h\x12\xc4\xf3\x9c\xee\xf5\x93\xf3\xdd'),
            b('saltsaltsaltsalt'),
            1000)
            )
        self.assertRaises(ValueError, raw_sha_crypt, b('secret'), b('$'), 1, hashlib.md5)

OsCrypt_SHA256CryptTest = create_backend_case(_SHA256CryptTest, "os_crypt")
Builtin_SHA256CryptTest = create_backend_case(_SHA256CryptTest, "builtin")

#=========================================================
#test sha512-crypt
#=========================================================
from passlib.handlers.sha2_crypt import sha512_crypt

class _SHA512CryptTest(HandlerCase):
    handler = sha512_crypt

    known_correct_hashes = [
        ('', '$6$rounds=11021$KsvQipYPWpr93wWP$v7xjI4X6vyVptJjB1Y02vZC5SaSijBkGmq1uJhPr3cvqvvkd42Xvo48yLVPFt8dvhCsnlUgpX.//Cxn91H4qy1'),
        (' ', '$6$rounds=11104$ED9SA4qGmd57Fq2m$q/.PqACDM/JpAHKmr86nkPzzuR5.YpYa8ZJJvI8Zd89ZPUYTJExsFEIuTYbM7gAGcQtTkCEhBKmp1S1QZwaXx0'),
        ('test', '$6$rounds=11531$G/gkPn17kHYo0gTF$Kq.uZBHlSBXyzsOJXtxJruOOH4yc0Is13uY7yK0PvAvXxbvc1w8DO1RzREMhKsc82K/Jh8OquV8FZUlreYPJk1'),
        ('Compl3X AlphaNu3meric', '$6$rounds=10787$wakX8nGKEzgJ4Scy$X78uqaX1wYXcSCtS4BVYw2trWkvpa8p7lkAtS9O/6045fK4UB2/Jia0Uy/KzCpODlfVxVNZzCCoV9s2hoLfDs/'),
        ('4lpHa N|_|M3r1K W/ Cur5Es: #$%(*)(*%#', '$6$rounds=11065$5KXQoE1bztkY5IZr$Jf6krQSUKKOlKca4hSW07MSerFFzVIZt/N3rOTsUgKqp7cUdHrwV8MoIVNCk9q9WL3ZRMsdbwNXpVk0gVxKtz1'),
        ]

    known_malformed_hashes = [
        #zero-padded rounds
        '$6$rounds=011021$KsvQipYPWpr93wWP$v7xjI4X6vyVptJjB1Y02vZC5SaSijBkGmq1uJhPr3cvqvvkd42Xvo48yLVPFt8dvhCsnlUgpX.//Cxn91H4qy1',
        #bad char in otherwise correct hash
        '$6$rounds=11021$KsvQipYPWpr9:wWP$v7xjI4X6vyVptJjB1Y02vZC5SaSijBkGmq1uJhPr3cvqvvkd42Xvo48yLVPFt8dvhCsnlUgpX.//Cxn91H4qy1',
    ]

    #NOTE: these test cases taken from official specification at http://www.akkadia.org/drepper/SHA-crypt.txt
    known_correct_configs = [
        #config, secret, result
        ("$6$saltstring", "Hello world!",
        "$6$saltstring$svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817G3uBnIFNjnQJu"
        "esI68u4OTLiBFdcbYEdFCoEOfaS35inz1" ),

      ( "$6$rounds=10000$saltstringsaltstring", "Hello world!",
        "$6$rounds=10000$saltstringsaltst$OW1/O6BYHV6BcXZu8QVeXbDWra3Oeqh0sb"
        "HbbMCVNSnCM/UrjmM0Dp8vOuZeHBy/YTBmSK6H9qs/y3RnOaw5v." ),

      ( "$6$rounds=5000$toolongsaltstring", "This is just a test",
        "$6$rounds=5000$toolongsaltstrin$lQ8jolhgVRVhY4b5pZKaysCLi0QBxGoNeKQ"
        "zQ3glMhwllF7oGDZxUhx1yxdYcz/e1JSbq3y6JMxxl8audkUEm0" ),

      ( "$6$rounds=1400$anotherlongsaltstring",
        "a very much longer text to encrypt.  This one even stretches over more"
        "than one line.",
        "$6$rounds=1400$anotherlongsalts$POfYwTEok97VWcjxIiSOjiykti.o/pQs.wP"
        "vMxQ6Fm7I6IoYN3CmLs66x9t0oSwbtEW7o7UmJEiDwGqd8p4ur1" ),

      ( "$6$rounds=77777$short",
        "we have a short salt string but not a short password",
        "$6$rounds=77777$short$WuQyW2YR.hBNpjjRhpYD/ifIw05xdfeEyQoMxIXbkvr0g"
        "ge1a1x3yRULJ5CCaUeOxFmtlcGZelFl5CxtgfiAc0" ),

      ( "$6$rounds=123456$asaltof16chars..", "a short string",
        "$6$rounds=123456$asaltof16chars..$BtCwjqMJGx5hrJhZywWvt0RLE8uZ4oPwc"
        "elCjmw2kSYu.Ec6ycULevoBK25fs2xXgMNrCzIMVcgEJAstJeonj1" ),

      ( "$6$rounds=10$roundstoolow", "the minimum number is still observed",
        "$6$rounds=1000$roundstoolow$kUMsbe306n21p9R.FRkW3IGn.S9NPN0x50YhH1x"
        "hLsPuWGsUSklZt58jaTfF4ZEQpyUNGc0dqbpBYYBaHHrsX." ),
    ]

    def filter_known_config_warnings(self):
        warnings.filterwarnings("ignore", "sha512_crypt does not allow less than 1000 rounds: 10", UserWarning)

OsCrypt_SHA512CryptTest = create_backend_case(_SHA512CryptTest, "os_crypt")
Builtin_SHA512CryptTest = create_backend_case(_SHA512CryptTest, "builtin")

#=========================================================
#sun md5 crypt
#=========================================================
from passlib.handlers.sun_md5_crypt import sun_md5_crypt, raw_sun_md5_crypt

class SunMD5CryptTest(HandlerCase):
    handler = sun_md5_crypt

    known_correct_hashes = [
        #TODO: this scheme needs some real test vectors,
        # especially due to the "bare salt" issue.

        #--------------------------------------
        #sample hashes culled from web messages
        #--------------------------------------

        #http://forums.halcyoninc.com/showthread.php?t=258
        ("Gpcs3_adm", "$md5$zrdhpMlZ$$wBvMOEqbSjU.hu5T2VEP01"),

        #http://www.c0t0d0s0.org/archives/4453-Less-known-Solaris-features-On-passwords-Part-2-Using-stronger-password-hashing.html
        ("aa12345678", "$md5$vyy8.OVF$$FY4TWzuauRl4.VQNobqMY."),

        #http://www.cuddletech.com/blog/pivot/entry.php?id=778
        ("this", "$md5$3UqYqndY$$6P.aaWOoucxxq.l00SS9k0"),

        #http://compgroups.net/comp.unix.solaris/password-file-in-linux-and-solaris-8-9
        ("passwd", "$md5$RPgLF6IJ$WTvAlUJ7MqH5xak2FMEwS/"),

        #-------------------------------
        #potential sample hashes - all have issues
        #-------------------------------

        #source: http://solaris-training.com/301_HTML/docs/deepdiv.pdf page 27
        #FIXME: password unknown
        #"$md5,rounds=8000$kS9FT1JC$$mnUrRO618lLah5iazwJ9m1"

        #source: http://www.visualexams.com/310-303.htm
        #XXX: this has 9 salt chars unlike all other hashes. is that valid?
        #FIXME: password unknown
        #"$md5,rounds=2006$2amXesSj5$$kCF48vfPsHDjlKNXeEw7V."

        ]

    known_correct_configs = [
        #(config, secret, hash)

        #---------------------------
        #test salt string handling
        #
        #these tests attempt to verify that passlib is handling
        #the "bare salt" issue (see sun md5 crypt docs)
        #in a sane manner
        #---------------------------

        #config with "$" suffix, hash strings with "$$" suffix,
        # should all be treated the same, with one "$" added to salt digest.
        ("$md5$3UqYqndY$",
            "this", "$md5$3UqYqndY$$6P.aaWOoucxxq.l00SS9k0"),
        ("$md5$3UqYqndY$$x",
            "this", "$md5$3UqYqndY$$6P.aaWOoucxxq.l00SS9k0"),

        #config with no suffix, hash strings with "$" suffix,
        # should all be treated the same, and no suffix added to salt digest.
        #NOTE: this is just a guess re: config w/ no suffix,
        #      but otherwise there's no sane way to encode bare_salt=False
        #      within config string.
        ("$md5$RPgLF6IJ",
            "passwd", "$md5$RPgLF6IJ$WTvAlUJ7MqH5xak2FMEwS/"),
        ("$md5$RPgLF6IJ$x",
            "passwd", "$md5$RPgLF6IJ$WTvAlUJ7MqH5xak2FMEwS/"),
    ]

    known_malformed_hashes = [
        #bad char in otherwise correct hash
        "$md5$RPgL!6IJ$WTvAlUJ7MqH5xak2FMEwS/",

        #2+ "$" at end of salt in config
        #NOTE: not sure what correct behavior is, so forbidding format for now.
        "$md5$3UqYqndY$$",

        #3+ "$" at end of salt in hash
        #NOTE: not sure what correct behavior is, so forbidding format for now.
        "$md5$RPgLa6IJ$$$WTvAlUJ7MqH5xak2FMEwS/",

        ]

#=========================================================
#unix fallback
#=========================================================
from passlib.handlers.misc import unix_fallback

class UnixFallbackTest(HandlerCase):
    #NOTE: this class behaves VERY differently from a normal password hash,
    #so we subclass & disable a number of the default tests.
    #TODO: combine some of these features w/ django_disabled and other fallback handlers.

    handler = unix_fallback

    known_correct_hashes = [ ("passwordwc",""), ]
    known_other_hashes = []
    accepts_empty_hash = True

    #NOTE: to ease testing, this sets enable_wildcard iff the string 'wc' is in the secret

    def do_verify(self, secret, hash):
        return self.handler.verify(secret, hash, enable_wildcard='wc' in secret)

    def test_50_encrypt_plain(self):
        "test encrypt() basic behavior"
        secret = u"\u20AC\u00A5$"
        result = self.do_encrypt(secret)
        self.assertEqual(result, "!")
        self.assertTrue(not self.do_verify(secret, result))

    def test_wildcard(self):
        "test enable_wildcard flag"
        h = self.handler
        self.assertTrue(h.verify('password','', enable_wildcard=True))
        self.assertFalse(h.verify('password',''))
        for c in ("!*x"):
            self.assertFalse(h.verify('password',c, enable_wildcard=True))
            self.assertFalse(h.verify('password',c))

#=========================================================
#EOF
#=========================================================
