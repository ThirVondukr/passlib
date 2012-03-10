"""passlib.tests.test_handlers - tests for passlib hash algorithms"""
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
from passlib.utils.compat import irange
from passlib.tests.utils import TestCase, HandlerCase, create_backend_case, \
        enable_option, b, catch_warnings, UserHandlerMixin
from passlib.utils.compat import u
#module

#=========================================================
#some
#=========================================================

# some common unicode passwords which used as test cases
UPASS_WAV = u('\u0399\u03c9\u03b1\u03bd\u03bd\u03b7\u03c2')
UPASS_USD = u("\u20AC\u00A5$")
UPASS_TABLE = u("t\u00e1\u0411\u2113\u0259")

#=========================================================
#apr md5 crypt
#=========================================================
class apr_md5_crypt_test(HandlerCase):
    handler = hash.apr_md5_crypt

    known_correct_hashes = [
        #
        # http://httpd.apache.org/docs/2.2/misc/password_encryptions.html
        #
        ('myPassword', '$apr1$r31.....$HqJZimcKQFAMYayBlzkrA/'),

        #
        # custom
        #

        # ensures utf-8 used for unicode
        (UPASS_TABLE, '$apr1$bzYrOHUx$a1FcpXuQDJV3vPY20CS6N1'),
        ]

    known_malformed_hashes = [
        # bad char in otherwise correct hash ----\/
            '$apr1$r31.....$HqJZimcKQFAMYayBlzkrA!'
        ]

#=========================================================
#bcrypt
#=========================================================
class _bcrypt_test(HandlerCase):
    "base for BCrypt test cases"
    handler = hash.bcrypt
    secret_size = 72

    known_correct_hashes = [
        #
        # from JTR 1.7.9
        #
        ('U*U*U*U*', '$2a$05$c92SVSfjeiCD6F2nAD6y0uBpJDjdRkt0EgeC4/31Rf2LUZbDRDE.O'),
        ('U*U***U', '$2a$05$WY62Xk2TXZ7EvVDQ5fmjNu7b0GEzSzUXUh2cllxJwhtOeMtWV3Ujq'),
        ('U*U***U*', '$2a$05$Fa0iKV3E2SYVUlMknirWU.CFYGvJ67UwVKI1E2FP6XeLiZGcH3MJi'),
        ('*U*U*U*U', '$2a$05$.WRrXibc1zPgIdRXYfv.4uu6TD1KWf0VnHzq/0imhUhuxSxCyeBs2'),
        ('', '$2a$05$Otz9agnajgrAe0.kFVF9V.tzaStZ2s1s4ZWi/LY4sw2k/MTVFj/IO'),

        #
        # test vectors from http://www.openwall.com/crypt v1.2
        #
        ('U*U', '$2a$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW'),
        ('U*U*', '$2a$05$CCCCCCCCCCCCCCCCCCCCC.VGOzA784oUp/Z0DY336zx7pLYAy0lwK'),
        ('U*U*U', '$2a$05$XXXXXXXXXXXXXXXXXXXXXOAcXxm9kjPGEMsLznoKqmqw7tc8WCx4a'),
        ('', '$2a$05$CCCCCCCCCCCCCCCCCCCCC.7uG0VCzI2bS7j6ymqJi9CdcdxiRTWNy'),
        ('0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'
         '0123456789chars after 72 are ignored',
                '$2a$05$abcdefghijklmnopqrstuu5s2v8.iXieOjg/.AySBTTZIIVFJeBui'),
        (b('\xa3'),
                '$2a$05$/OK.fbVrR/bpIqNJ5ianF.Sa7shbm4.OzKpvFnX1pQLmQW96oUlCq'),
        (b('\xff\xa3345'),
            '$2a$05$/OK.fbVrR/bpIqNJ5ianF.nRht2l/HRhr6zmCp9vYUvvsqynflf9e'),
        (b('\xa3ab'),
                '$2a$05$/OK.fbVrR/bpIqNJ5ianF.6IflQkJytoRVc1yuaNtHfiuq.FRlSIS'),
        (b('\xaa')*72 + b('chars after 72 are ignored as usual'),
                '$2a$05$/OK.fbVrR/bpIqNJ5ianF.swQOIzjOiJ9GHEPuhEkvqrUyvWhEMx6'),
        (b('\xaa\x55'*36),
                '$2a$05$/OK.fbVrR/bpIqNJ5ianF.R9xrDjiycxMbQE2bp.vgqlYpW5wx2yy'),
        (b('\x55\xaa\xff'*24),
                '$2a$05$/OK.fbVrR/bpIqNJ5ianF.9tQZzcJfm3uj2NvJ/n5xkhpqLrMpWCe'),

        #
        # from py-bcrypt tests
        #
        ('', '$2a$06$DCq7YPn5Rq63x1Lad4cll.TV4S6ytwfsfvkgY8jIucDrjc8deX1s.'),
        ('a', '$2a$10$k87L/MF28Q673VKh8/cPi.SUl7MU/rWuSiIDDFayrKk/1tBsSQu4u'),
        ('abc', '$2a$10$WvvTPHKwdBJ3uk0Z37EMR.hLA2W6N9AEBhEgrAOljy2Ae5MtaSIUi'),
        ('abcdefghijklmnopqrstuvwxyz',
                '$2a$10$fVH8e28OQRj9tqiDXs1e1uxpsjN0c7II7YPKXua2NAKYvM6iQk7dq'),
        ('~!@#$%^&*()      ~!@#$%^&*()PNBFRD',
                '$2a$10$LgfYWkbzEvQ4JakH7rOvHe0y8pHKF9OaFgwUZ2q7W2FFZmZzJYlfS'),
        ]

    known_correct_configs = [
        ('$2a$10$Z17AXnnlpzddNUvnC6cZNO', UPASS_TABLE,
         '$2a$10$Z17AXnnlpzddNUvnC6cZNOl54vBeVTewdrxohbPtcwl.GEZFTGjHe'),
    ]

    known_unidentified_hashes = [
        # invalid minor version
        "$2b$12$EXRkfkdmXnagzds2SSitu.MW9.gAVqa9eLS1//RYtYCmB1eLHg.9q",
        "$2`$12$EXRkfkdmXnagzds2SSitu.MW9.gAVqa9eLS1//RYtYCmB1eLHg.9q",
    ]

    known_malformed_hashes = [
        # bad char in otherwise correct hash
        #                 \/
        "$2a$12$EXRkfkdmXn!gzds2SSitu.MW9.gAVqa9eLS1//RYtYCmB1eLHg.9q",

        # rounds not zero-padded (pybcrypt rejects this, therefore so do we)
        '$2a$6$DCq7YPn5Rq63x1Lad4cll.TV4S6ytwfsfvkgY8jIucDrjc8deX1s.'

        #NOTE: salts with padding bits set are technically malformed,
        #      but we can reliably correct & issue a warning for that.
        ]

    #===============================================================
    # fuzz testing
    #===============================================================
    def get_fuzz_verifiers(self):
        verifiers = super(_bcrypt_test, self).get_fuzz_verifiers()

        # test other backends against pybcrypt if available
        from passlib.utils import to_native_str
        try:
            from bcrypt import hashpw
        except ImportError:
            pass
        else:
            def check_pybcrypt(secret, hash):
                "pybcrypt"
                secret = to_native_str(secret, self.fuzz_password_encoding)
                try:
                    return hashpw(secret, hash) == hash
                except ValueError:
                    raise ValueError("pybcrypt rejected hash: %r" % (hash,))
            verifiers.append(check_pybcrypt)

        # test other backends against bcryptor if available
        try:
            from bcryptor.engine import Engine
        except ImportError:
            pass
        else:
            def check_bcryptor(secret, hash):
                "bcryptor"
                secret = to_native_str(secret, self.fuzz_password_encoding)
                return Engine(False).hash_key(secret, hash) == hash
            verifiers.append(check_bcryptor)

        return verifiers

    def get_fuzz_ident(self):
        ident = super(_bcrypt_test,self).get_fuzz_ident()
        if ident == u("$2$") and self.handler.has_backend("bcryptor"):
            # FIXME: skipping this since bcryptor doesn't support v0 hashes
            return None
        return ident

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

    def test_90_bcrypt_padding(self):
        "test passlib correctly handles bcrypt padding bits"
        bcrypt = self.handler
        corr_desc = ".*incorrectly set padding bits"

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
        for i in irange(6):
            check_padding(bcrypt.genconfig())
        for i in irange(3):
            check_padding(bcrypt.encrypt("bob", rounds=bcrypt.min_rounds))

        # check passing salt to genconfig causes it to be normalized.
        with catch_warnings(record=True) as wlog:
            hash = bcrypt.genconfig(salt="."*21 + "A.", relaxed=True)
            self.consumeWarningList(wlog, ["salt too large", corr_desc])
            self.assertEqual(hash, "$2a$12$" + "." * 22)

            hash = bcrypt.genconfig(salt="."*23, relaxed=True)
            self.consumeWarningList(wlog, ["salt too large"])
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
            self.assertEqual(bcrypt.genhash(PASS1, BAD1), GOOD1)
            self.consumeWarningList(wlog, [corr_desc])

            self.assertEqual(bcrypt.genhash(PASS2, BAD2), GOOD2)
            self.consumeWarningList(wlog, [corr_desc])

            self.assertEqual(bcrypt.genhash(PASS2, GOOD2), GOOD2)
            self.consumeWarningList(wlog)

            self.assertEqual(bcrypt.genhash(PASS3, BAD3), GOOD3)
            self.consumeWarningList(wlog, [corr_desc])

        # make sure verify works on both bad and good hashes
        with catch_warnings(record=True) as wlog:
            self.assertTrue(bcrypt.verify(PASS1, BAD1))
            self.consumeWarningList(wlog, [corr_desc])

            self.assertTrue(bcrypt.verify(PASS1, GOOD1))
            self.consumeWarningList(wlog)

        #===============================================================
        # test normhash cleans things up correctly
        #===============================================================
        with catch_warnings(record=True) as wlog:
            self.assertEqual(bcrypt.normhash(BAD1), GOOD1)
            self.assertEqual(bcrypt.normhash(BAD2), GOOD2)
            self.assertEqual(bcrypt.normhash(GOOD1), GOOD1)
            self.assertEqual(bcrypt.normhash(GOOD2), GOOD2)
            self.assertEqual(bcrypt.normhash("$md5$abc"), "$md5$abc")

hash.bcrypt._no_backends_msg() #call this for coverage purposes

#create test cases for specific backends
pybcrypt_bcrypt_test = create_backend_case(_bcrypt_test, "pybcrypt")
bcryptor_bcrypt_test = create_backend_case(_bcrypt_test, "bcryptor")
os_crypt_bcrypt_test = create_backend_case(_bcrypt_test, "os_crypt")
builtin_bcrypt_test = create_backend_case(_bcrypt_test, "builtin")

#=========================================================
#bigcrypt
#=========================================================
class bigcrypt_test(HandlerCase):
    handler = hash.bigcrypt

    # TODO: find an authoritative source of test vectors
    known_correct_hashes = [

        #
        # various docs & messages on the web.
        #
        ("passphrase",               "qiyh4XPJGsOZ2MEAyLkfWqeQ"),
        ("This is very long passwd", "f8.SVpL2fvwjkAnxn8/rgTkwvrif6bjYB5c"),

        #
        # custom
        #

        # ensures utf-8 used for unicode
        (UPASS_TABLE, 'SEChBAyMbMNhgGLyP7kD1HZU'),
    ]

    known_unidentified_hashes = [
        # one char short
        "qiyh4XPJGsOZ2MEAyLkfWqe"
    ]

    # omit des_crypt from known_other since it's a valid bigcrypt hash too.
    known_other_hashes = [row for row in HandlerCase.known_other_hashes
                          if row[0] != "des_crypt"]

#=========================================================
#bsdi crypt
#=========================================================
class _bsdi_crypt_test(HandlerCase):
    "test BSDiCrypt algorithm"
    handler = hash.bsdi_crypt

    known_correct_hashes = [
        #
        # from JTR 1.7.9
        #
        ('U*U*U*U*', '_J9..CCCCXBrJUJV154M'),
        ('U*U***U', '_J9..CCCCXUhOBTXzaiE'),
        ('U*U***U*', '_J9..CCCC4gQ.mB/PffM'),
        ('*U*U*U*U', '_J9..XXXXvlzQGqpPPdk'),
        ('*U*U*U*U*', '_J9..XXXXsqM/YSSP..Y'),
        ('*U*U*U*U*U*U*U*U', '_J9..XXXXVL7qJCnku0I'),
        ('*U*U*U*U*U*U*U*U*', '_J9..XXXXAj8cFbP5scI'),
        ('ab1234567', '_J9..SDizh.vll5VED9g'),
        ('cr1234567', '_J9..SDizRjWQ/zePPHc'),
        ('zxyDPWgydbQjgq', '_J9..SDizxmRI1GjnQuE'),
        ('726 even', '_K9..SaltNrQgIYUAeoY'),
        ('', '_J9..SDSD5YGyRCr4W4c'),

        #
        # custom
        #
        (" ", "_K1..crsmZxOLzfJH8iw"),
        ("my", '_KR/.crsmykRplHbAvwA'), # <-- to detect old 12-bit rounds bug
        ("my socra", "_K1..crsmf/9NzZr1fLM"),
        ("my socrates", '_K1..crsmOv1rbde9A9o'),
        ("my socrates note", "_K1..crsm/2qeAhdISMA"),

        # ensures utf-8 used for unicode
        (UPASS_TABLE, '_7C/.ABw0WIKy0ILVqo2'),
    ]
    known_unidentified_hashes = [
        # bad char in otherwise correctly formatted hash
        #    \/
        "_K1.!crsmZxOLzfJH8iw"
    ]

os_crypt_bsdi_crypt_test = create_backend_case(_bsdi_crypt_test, "os_crypt")
builtin_bsdi_crypt_test = create_backend_case(_bsdi_crypt_test, "builtin")

#=========================================================
# crypt16
#=========================================================
class crypt16_test(HandlerCase):
    handler = hash.crypt16
    secret_size = 16

    # TODO: find an authortative source of test vectors
    known_correct_hashes = [
        #
        # from messages around the web, including
        # http://seclists.org/bugtraq/1999/Mar/76
        #
        ("passphrase",  "qi8H8R7OM4xMUNMPuRAZxlY."),
        ("printf",      "aaCjFz4Sh8Eg2QSqAReePlq6"),
        ("printf",      "AA/xje2RyeiSU0iBY3PDwjYo"),
        ("LOLOAQICI82QB4IP", "/.FcK3mad6JwYt8LVmDqz9Lc"),
        ("LOLOAQICI",   "/.FcK3mad6JwYSaRHJoTPzY2"),
        ("LOLOAQIC",    "/.FcK3mad6JwYelhbtlysKy6"),
        ("L",           "/.CIu/PzYCkl6elhbtlysKy6"),

        #
        # custom
        #

        # ensures utf-8 used for unicode
        (UPASS_TABLE, 'YeDc9tKkkmDvwP7buzpwhoqQ'),
        ]

#=========================================================
#des crypt
#=========================================================
class _des_crypt_test(HandlerCase):
    "test des-crypt algorithm"
    handler = hash.des_crypt
    secret_size = 8

    known_correct_hashes = [
        #
        # from JTR 1.7.9
        #
        ('U*U*U*U*', 'CCNf8Sbh3HDfQ'),
        ('U*U***U', 'CCX.K.MFy4Ois'),
        ('U*U***U*', 'CC4rMpbg9AMZ.'),
        ('*U*U*U*U', 'XXxzOu6maQKqQ'),
        ('', 'SDbsugeBiC58A'),

        #
        # custom
        #
        ('', 'OgAwTx2l6NADI'),
        (' ', '/Hk.VPuwQTXbc'),
        ('test', 'N1tQbOFcM5fpg'),
        ('Compl3X AlphaNu3meric', 'um.Wguz3eVCx2'),
        ('4lpHa N|_|M3r1K W/ Cur5Es: #$%(*)(*%#', 'sNYqfOyauIyic'),
        ('AlOtBsOl', 'cEpWz5IUCShqM'),

        # ensures utf-8 used for unicode
        (u('hell\u00D6'), 'saykDgk3BPZ9E'),
        ]
    known_unidentified_hashes = [
        # bad char in otherwise correctly formatted hash
        #\/
        '!gAwTx2l6NADI',
        ]

    def test_90_invalid_secret_chars(self):
        self.assertRaises(ValueError, self.do_encrypt, 'sec\x00t')

os_crypt_des_crypt_test = create_backend_case(_des_crypt_test, "os_crypt")
builtin_des_crypt_test = create_backend_case(_des_crypt_test, "builtin")

#=========================================================
#django
#=========================================================
class _DjangoHelper(object):

    def get_fuzz_verifiers(self):
        verifiers = super(_DjangoHelper, self).get_fuzz_verifiers()

        from passlib.tests.test_ext_django import has_django1
        if has_django1:
            from django.contrib.auth.models import check_password
            def verify_django(secret, hash):
                "django check_password()"
                return check_password(secret, hash)
            verifiers.append(verify_django)

        return verifiers

    def test_90_django_reference(self):
        "run known correct hashes through Django's check_password()"
        if not self.known_correct_hashes:
            return self.skipTest("no known correct hashes specified")
        from passlib.tests.test_ext_django import has_django1
        if not has_django1:
            return self.skipTest("Django not installed")
        from django.contrib.auth.models import check_password
        for secret, hash in self.iter_known_hashes():
            self.assertTrue(check_password(secret, hash))
            self.assertFalse(check_password('x' + secret, hash))

class django_disabled_test(HandlerCase):
    "test django_disabled"
    handler = hash.django_disabled
    is_disabled_handler = True

    known_correct_hashes = [
        # *everything* should hash to "!", and nothing should verify
        ("password", "!"),
        ("", "!"),
        (UPASS_TABLE, "!"),
    ]

class django_des_crypt_test(HandlerCase, _DjangoHelper):
    "test django_des_crypt"
    handler = hash.django_des_crypt
    secret_size = 8

    known_correct_hashes = [
        # ensures only first two digits of salt count.
        ("password",         'crypt$c2$c2M87q...WWcU'),
        ("password",         'crypt$c2e86$c2M87q...WWcU'),
        ("passwordignoreme", 'crypt$c2.AZ$c2M87q...WWcU'),

        # ensures utf-8 used for unicode
        (UPASS_USD, 'crypt$c2e86$c2hN1Bxd6ZiWs'),
        (UPASS_TABLE, 'crypt$0.aQs$0.wB.TT0Czvlo'),
        (u("hell\u00D6"), "crypt$sa$saykDgk3BPZ9E"),

        # prevent regression of issue 22
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

class django_salted_md5_test(HandlerCase, _DjangoHelper):
    "test django_salted_md5"
    handler = hash.django_salted_md5

    known_correct_hashes = [
        # test extra large salt
        ("password",    'md5$123abcdef$c8272612932975ee80e8a35995708e80'),

        # ensures utf-8 used for unicode
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

class django_salted_sha1_test(HandlerCase, _DjangoHelper):
    "test django_salted_sha1"
    handler = hash.django_salted_sha1

    known_correct_hashes = [
        # test extra large salt
        ("password",'sha1$123abcdef$e4a1877b0e35c47329e7ed7e58014276168a37ba'),

        # ensures utf-8 used for unicode
        (UPASS_USD,     'sha1$c2e86$0f75c5d7fbd100d587c127ef0b693cde611b4ada'),
        (UPASS_TABLE,   'sha1$6d853$ef13a4d8fb57aed0cb573fe9c82e28dc7fd372d4'),

        # generic password
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
class fshp_test(HandlerCase):
    "test fshp algorithm"
    handler = hash.fshp

    known_correct_hashes = [
        #
        # test vectors from FSHP reference implementation
        # https://github.com/bdd/fshp-is-not-secure-anymore/blob/master/python/test.py
        #
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

        #
        # custom
        #

        # ensures utf-8 used for unicode
        (UPASS_TABLE, '{FSHP1|16|16384}9v6/l3Lu/d9by5nznpOS'
         'cqQo8eKu/b/CKli3RCkgYg4nRTgZu5y659YV8cCZ68UL'),
        ]

    known_unidentified_hashes = [
        # incorrect header
        '{FSHX0|0|1}qUqP5cyxm6YcTAhz05Hph5gvu9M=',
        'FSHP0|0|1}qUqP5cyxm6YcTAhz05Hph5gvu9M=',
        ]

    known_malformed_hashes = [
        # wrong salt size
        '{FSHP0|1|1}qUqP5cyxm6YcTAhz05Hph5gvu9M=',

        # bad rounds
        '{FSHP0|0|A}qUqP5cyxm6YcTAhz05Hph5gvu9M=',
    ]

#=========================================================
#hex digests
#=========================================================
class hex_md4_test(HandlerCase):
    handler = hash.hex_md4
    known_correct_hashes = [
        ("password", '8a9d093f14f8701df17732b2bb182c74'),
        (UPASS_TABLE, '876078368c47817ce5f9115f3a42cf74'),
    ]

class hex_md5_test(HandlerCase):
    handler = hash.hex_md5
    known_correct_hashes = [
        ("password", '5f4dcc3b5aa765d61d8327deb882cf99'),
        (UPASS_TABLE, '05473f8a19f66815e737b33264a0d0b0'),
    ]

class hex_sha1_test(HandlerCase):
    handler = hash.hex_sha1
    known_correct_hashes = [
        ("password", '5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8'),
        (UPASS_TABLE, 'e059b2628e3a3e2de095679de9822c1d1466e0f0'),
    ]

class hex_sha256_test(HandlerCase):
    handler = hash.hex_sha256
    known_correct_hashes = [
        ("password", '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8'),
        (UPASS_TABLE, '6ed729e19bf24d3d20f564375820819932029df05547116cfc2cc868a27b4493'),
    ]

class hex_sha512_test(HandlerCase):
    handler = hash.hex_sha512
    known_correct_hashes = [
        ("password", 'b109f3bbbc244eb82441917ed06d618b9008dd09b3befd1b5e07394c'
         '706a8bb980b1d7785e5976ec049b46df5f1326af5a2ea6d103fd07c95385ffab0cac'
         'bc86'),
        (UPASS_TABLE, 'd91bb0a23d66dca07a1781fd63ae6a05f6919ee5fc368049f350c9f'
         '293b078a18165d66097cf0d89fdfbeed1ad6e7dba2344e57348cd6d51308c843a06f'
         '29caf'),
    ]

#=========================================================
#ldap hashes
#=========================================================
class ldap_md5_test(HandlerCase):
    handler = hash.ldap_md5
    known_correct_hashes = [
        ("helloworld", '{MD5}/F4DjTilcDIIVEHn/nAQsA=='),
        (UPASS_TABLE, '{MD5}BUc/ihn2aBXnN7MyZKDQsA=='),
    ]

class ldap_sha1_test(HandlerCase):
    handler = hash.ldap_sha1
    known_correct_hashes = [
        ("helloworld", '{SHA}at+xg6SiyUovktq1redipHiJpaE='),
        (UPASS_TABLE, '{SHA}4FmyYo46Pi3glWed6YIsHRRm4PA='),
    ]

class ldap_salted_md5_test(HandlerCase):
    handler = hash.ldap_salted_md5
    known_correct_hashes = [
        ("testing1234", '{SMD5}UjFY34os/pnZQ3oQOzjqGu4yeXE='),
        (UPASS_TABLE, '{SMD5}Z0ioJ58LlzUeRxm3K6JPGAvBGIM='),
    ]

class ldap_salted_sha1_test(HandlerCase):
    handler = hash.ldap_salted_sha1
    known_correct_hashes = [
        ("testing123", '{SSHA}0c0blFTXXNuAMHECS4uxrj3ZieMoWImr'),
        ("secret", "{SSHA}0H+zTv8o4MR4H43n03eCsvw1luG8LdB7"),
        (UPASS_TABLE, '{SSHA}3yCSD1nLZXznra4N8XzZgAL+s1sQYsx5'),
    ]

class ldap_plaintext_test(HandlerCase):
    handler = hash.ldap_plaintext
    known_correct_hashes = [
        ("password", 'password'),
        (UPASS_TABLE, 't\xc3\xa1\xd0\x91\xe2\x84\x93\xc9\x99'),
    ]
    known_unidentified_hashes = [
        "{FOO}bar"
    ]

    known_other_hashes = [
        ("ldap_md5", "{MD5}/F4DjTilcDIIVEHn/nAQsA==")
    ]

#NOTE: since the ldap_{crypt} handlers are all wrappers,
# don't need separate test. have just one for end-to-end testing purposes.

class _ldap_md5_crypt_test(HandlerCase):
    handler = hash.ldap_md5_crypt

    known_correct_hashes = [
        #
        # custom
        #
        ('', '{CRYPT}$1$dOHYPKoP$tnxS1T8Q6VVn3kpV8cN6o.'),
        (' ', '{CRYPT}$1$m/5ee7ol$bZn0kIBFipq39e.KDXX8I0'),
        ('test', '{CRYPT}$1$ec6XvcoW$ghEtNK2U1MC5l.Dwgi3020'),
        ('Compl3X AlphaNu3meric', '{CRYPT}$1$nX1e7EeI$ljQn72ZUgt6Wxd9hfvHdV0'),
        ('4lpHa N|_|M3r1K W/ Cur5Es: #$%(*)(*%#', '{CRYPT}$1$jQS7o98J$V6iTcr71CGgwW2laf17pi1'),
        ('test', '{CRYPT}$1$SuMrG47N$ymvzYjr7QcEQjaK5m1PGx1'),

        # ensures utf-8 used for unicode
        (UPASS_TABLE, '{CRYPT}$1$d6/Ky1lU$/xpf8m7ftmWLF.TjHCqel0'),
        ]

    known_malformed_hashes = [
        # bad char in otherwise correct hash
        '{CRYPT}$1$dOHYPKoP$tnxS1T8Q6VVn3kpV8cN6o!',
        ]

os_crypt_ldap_md5_crypt_test = create_backend_case(_ldap_md5_crypt_test, "os_crypt")
builtin_ldap_md5_crypt_test = create_backend_case(_ldap_md5_crypt_test, "builtin")

#=========================================================
#ldap_pbkdf2_{digest}
#=========================================================
#NOTE: since these are all wrappers for the pbkdf2_{digest} hasehs,
# they don't extensive separate testing.

class ldap_pbkdf2_test(TestCase):

    def test_wrappers(self):
        "test ldap pbkdf2 wrappers"

        self.assertTrue(
            hash.ldap_pbkdf2_sha1.verify(
                "password",
                '{PBKDF2}1212$OB.dtnSEXZK8U5cgxU/GYQ$y5LKPOplRmok7CZp/aqVDVg8zGI',
            )
        )

        self.assertTrue(
            hash.ldap_pbkdf2_sha256.verify(
                "password",
                '{PBKDF2-SHA256}1212$4vjV83LKPjQzk31VI4E0Vw$hsYF68OiOUPdDZ1Fg'
                '.fJPeq1h/gXXY7acBp9/6c.tmQ'
            )
        )

        self.assertTrue(
            hash.ldap_pbkdf2_sha512.verify(
                "password",
                '{PBKDF2-SHA512}1212$RHY0Fr3IDMSVO/RSZyb5ow$eNLfBK.eVozomMr.1gYa1'
                '7k9B7KIK25NOEshvhrSX.esqY3s.FvWZViXz4KoLlQI.BzY/YTNJOiKc5gBYFYGww'
            )
        )

#=========================================================
#md5 crypt
#=========================================================
class _md5_crypt_test(HandlerCase):
    handler = hash.md5_crypt

    known_correct_hashes = [
        #
        # from JTR 1.7.9
        #
        ('U*U*U*U*', '$1$dXc3I7Rw$ctlgjDdWJLMT.qwHsWhXR1'),
        ('U*U***U', '$1$dXc3I7Rw$94JPyQc/eAgQ3MFMCoMF.0'),
        ('U*U***U*', '$1$dXc3I7Rw$is1mVIAEtAhIzSdfn5JOO0'),
        ('*U*U*U*U', '$1$eQT9Hwbt$XtuElNJD.eW5MN5UCWyTQ0'),
        ('', '$1$Eu.GHtia$CFkL/nE1BYTlEPiVx1VWX0'),

        #
        # custom
        #

        # NOTE: would need to patch HandlerCase to coerce hashes
        # to native str for this first one to work under py3.
##        ('', b('$1$dOHYPKoP$tnxS1T8Q6VVn3kpV8cN6o.')),
        ('', '$1$dOHYPKoP$tnxS1T8Q6VVn3kpV8cN6o.'),
        (' ', '$1$m/5ee7ol$bZn0kIBFipq39e.KDXX8I0'),
        ('test', '$1$ec6XvcoW$ghEtNK2U1MC5l.Dwgi3020'),
        ('Compl3X AlphaNu3meric', '$1$nX1e7EeI$ljQn72ZUgt6Wxd9hfvHdV0'),
        ('4lpHa N|_|M3r1K W/ Cur5Es: #$%(*)(*%#', '$1$jQS7o98J$V6iTcr71CGgwW2laf17pi1'),
        ('test', '$1$SuMrG47N$ymvzYjr7QcEQjaK5m1PGx1'),
        (b('test'), '$1$SuMrG47N$ymvzYjr7QcEQjaK5m1PGx1'),
        (u('s'), '$1$ssssssss$YgmLTApYTv12qgTwBoj8i/'),

        # ensures utf-8 used for unicode
        (UPASS_TABLE, '$1$d6/Ky1lU$/xpf8m7ftmWLF.TjHCqel0'),
        ]

    known_malformed_hashes = [
        # bad char in otherwise correct hash \/
           '$1$dOHYPKoP$tnxS1T8Q6VVn3kpV8cN6o!',
        ]

os_crypt_md5_crypt_test = create_backend_case(_md5_crypt_test, "os_crypt")
builtin_md5_crypt_test = create_backend_case(_md5_crypt_test, "builtin")

#=========================================================
# mssql 2000 & 2005
#=========================================================
class mssql2000_test(HandlerCase):
    handler = hash.mssql2000
    secret_case_insensitive = "verify-only"

    known_correct_hashes = [
        #
        # http://hkashfi.blogspot.com/2007/08/breaking-sql-server-2005-hashes.html
        #
        ('Test', '0x010034767D5C0CFA5FDCA28C4A56085E65E882E71CB0ED2503412FD54D6119FFF04129A1D72E7C3194F7284A7F3A'),
        ('TEST', '0x010034767D5C2FD54D6119FFF04129A1D72E7C3194F7284A7F3A2FD54D6119FFF04129A1D72E7C3194F7284A7F3A'),

        #
        # http://www.sqlmag.com/forums/aft/68438
        #
        ('x', '0x010086489146C46DD7318D2514D1AC706457CBF6CD3DF8407F071DB4BBC213939D484BF7A766E974F03C96524794'),

        #
        # http://stackoverflow.com/questions/173329/how-to-decrypt-a-password-from-sql-server
        #
        ('AAAA', '0x0100CF465B7B12625EF019E157120D58DD46569AC7BF4118455D12625EF019E157120D58DD46569AC7BF4118455D'),

        #
        # http://msmvps.com/blogs/gladchenko/archive/2005/04/06/41083.aspx
        #
        ('123', '0x01002D60BA07FE612C8DE537DF3BFCFA49CD9968324481C1A8A8FE612C8DE537DF3BFCFA49CD9968324481C1A8A8'),

        #
        # http://www.simple-talk.com/sql/t-sql-programming/temporarily-changing-an-unknown-password-of-the-sa-account-/
        #
        ('12345', '0x01005B20054332752E1BC2E7C5DF0F9EBFE486E9BEE063E8D3B332752E1BC2E7C5DF0F9EBFE486E9BEE063E8D3B3'),

        #
        # XXX: sample is incomplete, password unknown
        # https://anthonystechblog.wordpress.com/2011/04/20/password-encryption-in-sql-server-how-to-tell-if-a-user-is-using-a-weak-password/
        # (????, '0x0100813F782D66EF15E40B1A3FDF7AB88B322F51401A87D8D3E3A8483C4351A3D96FC38499E6CDD2B6F?????????'),
        #

        #
        # from JTR 1.7.9
        #
        ('foo', '0x0100A607BA7C54A24D17B565C59F1743776A10250F581D482DA8B6D6261460D3F53B279CC6913CE747006A2E3254'),
        ('bar', '0x01000508513EADDF6DB7DDD270CCA288BF097F2FF69CC2DB74FBB9644D6901764F999BAB9ECB80DE578D92E3F80D'),
        ('canard', '0x01008408C523CF06DCB237835D701C165E68F9460580132E28ED8BC558D22CEDF8801F4503468A80F9C52A12C0A3'),
        ('lapin', '0x0100BF088517935FC9183FE39FDEC77539FD5CB52BA5F5761881E5B9638641A79DBF0F1501647EC941F3355440A2'),

        #
        # custom
        #

        # ensures utf-8 used for unicode
        (UPASS_USD,   '0x0100624C0961B28E39FEE13FD0C35F57B4523F0DA1861C11D5A5B28E39FEE13FD0C35F57B4523F0DA1861C11D5A5'),
        (UPASS_TABLE, '0x010083104228FAD559BE52477F2131E538BE9734E5C4B0ADEFD7F6D784B03C98585DC634FE2B8CA3A6DFFEC729B4'),

    ]

    known_correct_configs = [
        ('0x010034767D5C00000000000000000000000000000000000000000000000000000000000000000000000000000000',
         'Test', '0x010034767D5C0CFA5FDCA28C4A56085E65E882E71CB0ED2503412FD54D6119FFF04129A1D72E7C3194F7284A7F3A'),
    ]

    known_alternate_hashes = [
        # lower case hex
        ('0x01005b20054332752e1bc2e7c5df0f9ebfe486e9bee063e8d3b332752e1bc2e7c5df0f9ebfe486e9bee063e8d3b3',
         '12345', '0x01005B20054332752E1BC2E7C5DF0F9EBFE486E9BEE063E8D3B332752E1BC2E7C5DF0F9EBFE486E9BEE063E8D3B3'),
    ]

    known_unidentified_hashes = [
        # malformed start
        '0X01005B20054332752E1BC2E7C5DF0F9EBFE486E9BEE063E8D3B332752E1BC2E7C5DF0F9EBFE486E9BEE063E8D3B3',

        # wrong magic value
        '0x02005B20054332752E1BC2E7C5DF0F9EBFE486E9BEE063E8D3B332752E1BC2E7C5DF0F9EBFE486E9BEE063E8D3B3',

        # wrong size
        '0x01005B20054332752E1BC2E7C5DF0F9EBFE486E9BEE063E8D3B332752E1BC2E7C5DF0F9EBFE486E9BEE063E8D3',
        '0x01005B20054332752E1BC2E7C5DF0F9EBFE486E9BEE063E8D3B332752E1BC2E7C5DF0F9EBFE486E9BEE063E8D3B3AF',

        # mssql2005
        '0x01005B20054332752E1BC2E7C5DF0F9EBFE486E9BEE063E8D3B3',
    ]

    known_malformed_hashes = [
        # non-hex char ---\/
        '0x01005B200543327G2E1BC2E7C5DF0F9EBFE486E9BEE063E8D3B332752E1BC2E7C5DF0F9EBFE486E9BEE063E8D3B3',
    ]

class mssql2005_test(HandlerCase):
    handler = hash.mssql2005

    known_correct_hashes = [
        #
        # http://hkashfi.blogspot.com/2007/08/breaking-sql-server-2005-hashes.html
        #
        ('TEST', '0x010034767D5C2FD54D6119FFF04129A1D72E7C3194F7284A7F3A'),

        #
        # http://www.openwall.com/lists/john-users/2009/07/14/2
        #
        ('toto', '0x01004086CEB6BF932BC4151A1AF1F13CD17301D70816A8886908'),

        #
        # http://msmvps.com/blogs/gladchenko/archive/2005/04/06/41083.aspx
        #
        ('123', '0x01004A335DCEDB366D99F564D460B1965B146D6184E4E1025195'),
        ('123', '0x0100E11D573F359629B344990DCD3D53DE82CF8AD6BBA7B638B6'),

        #
        # XXX: password unknown
        # http://www.simple-talk.com/sql/t-sql-programming/temporarily-changing-an-unknown-password-of-the-sa-account-/
        # (???, '0x01004086CEB6301EEC0A994E49E30DA235880057410264030797'),
        #

        #
        # http://therelentlessfrontend.com/2010/03/26/encrypting-and-decrypting-passwords-in-sql-server/
        #
        ('AAAA', '0x010036D726AE86834E97F20B198ACD219D60B446AC5E48C54F30'),

        #
        # from JTR 1.7.9
        #
        ("toto", "0x01004086CEB6BF932BC4151A1AF1F13CD17301D70816A8886908"),
        ("titi", "0x01004086CEB60ED526885801C23B366965586A43D3DEAC6DD3FD"),
        ("foo", "0x0100A607BA7C54A24D17B565C59F1743776A10250F581D482DA8"),
        ("bar", "0x01000508513EADDF6DB7DDD270CCA288BF097F2FF69CC2DB74FB"),
        ("canard", "0x01008408C523CF06DCB237835D701C165E68F9460580132E28ED"),
        ("lapin", "0x0100BF088517935FC9183FE39FDEC77539FD5CB52BA5F5761881"),

        #
        # adapted from mssql2000.known_correct_hashes (above)
        #
        ('Test',  '0x010034767D5C0CFA5FDCA28C4A56085E65E882E71CB0ED250341'),
        ('Test',  '0x0100993BF2315F36CC441485B35C4D84687DC02C78B0E680411F'),
        ('x',     '0x010086489146C46DD7318D2514D1AC706457CBF6CD3DF8407F07'),
        ('AAAA',  '0x0100CF465B7B12625EF019E157120D58DD46569AC7BF4118455D'),
        ('123',   '0x01002D60BA07FE612C8DE537DF3BFCFA49CD9968324481C1A8A8'),
        ('12345', '0x01005B20054332752E1BC2E7C5DF0F9EBFE486E9BEE063E8D3B3'),

        #
        # custom
        #

        # ensures utf-8 used for unicode
        (UPASS_USD,   '0x0100624C0961B28E39FEE13FD0C35F57B4523F0DA1861C11D5A5'),
        (UPASS_TABLE, '0x010083104228FAD559BE52477F2131E538BE9734E5C4B0ADEFD7'),
    ]

    known_correct_configs = [
        ('0x010034767D5C0000000000000000000000000000000000000000',
         'Test', '0x010034767D5C0CFA5FDCA28C4A56085E65E882E71CB0ED250341'),
    ]

    known_alternate_hashes = [
        # lower case hex
        ('0x01005b20054332752e1bc2e7c5df0f9ebfe486e9bee063e8d3b3',
         '12345', '0x01005B20054332752E1BC2E7C5DF0F9EBFE486E9BEE063E8D3B3'),
    ]

    known_unidentified_hashes = [
        # malformed start
        '0X010036D726AE86834E97F20B198ACD219D60B446AC5E48C54F30',

        # wrong magic value
        '0x020036D726AE86834E97F20B198ACD219D60B446AC5E48C54F30',

        # wrong size
        '0x010036D726AE86834E97F20B198ACD219D60B446AC5E48C54F',
        '0x010036D726AE86834E97F20B198ACD219D60B446AC5E48C54F3012',

        # mssql2000
        '0x01005B20054332752E1BC2E7C5DF0F9EBFE486E9BEE063E8D3B332752E1BC2E7C5DF0F9EBFE486E9BEE063E8D3B3',
    ]

    known_malformed_hashes = [
        # non-hex char --\/
        '0x010036D726AE86G34E97F20B198ACD219D60B446AC5E48C54F30',
    ]

#=========================================================
# mysql 323 & 41
#=========================================================
class mysql323_test(HandlerCase):
    handler = hash.mysql323

    known_correct_hashes = [
        #
        # from JTR 1.7.9
        #
        ('drew', '697a7de87c5390b2'),
        ('password', "5d2e19393cc5ef67"),

        #
        # custom
        #
        ('mypass', '6f8c114b58f2ce9e'),

        # ensures utf-8 used for unicode
        (UPASS_TABLE, '4ef327ca5491c8d7'),
    ]

    known_unidentified_hashes = [
        # bad char in otherwise correct hash
        '6z8c114b58f2ce9e',
    ]

    def test_90_whitespace(self):
        "check whitespace is ignored per spec"
        h = self.do_encrypt("mypass")
        h2 = self.do_encrypt("my pass")
        self.assertEqual(h, h2)

class mysql41_test(HandlerCase):
    handler = hash.mysql41
    known_correct_hashes = [
        #
        # from JTR 1.7.9
        #
        ('verysecretpassword', '*2C905879F74F28F8570989947D06A8429FB943E6'),
        ('12345678123456781234567812345678', '*F9F1470004E888963FB466A5452C9CBD9DF6239C'),
        ("' OR 1 /*'", '*97CF7A3ACBE0CA58D5391AC8377B5D9AC11D46D9'),

        #
        # custom
        #
        ('mypass', '*6C8989366EAF75BB670AD8EA7A7FC1176A95CEF4'),

        # ensures utf-8 used for unicode
        (UPASS_TABLE, '*E7AFE21A9CFA2FC9D15D942AE8FB5C240FE5837B'),
    ]
    known_unidentified_hashes = [
        #bad char in otherwise correct hash
        '*6Z8989366EAF75BB670AD8EA7A7FC1176A95CEF4',
    ]

#=========================================================
# NTHASH for unix
#=========================================================
class nthash_test(HandlerCase):
    handler = hash.nthash

    known_correct_hashes = [
        ('passphrase', '$3$$7f8fe03093cc84b267b109625f6bbf4b'),
        ('passphrase', '$NT$7f8fe03093cc84b267b109625f6bbf4b'),
    ]

    known_malformed_hashes = [
        #bad char in otherwise correct hash
        '$3$$7f8fe03093cc84b267b109625f6bbfxb',
    ]

#=========================================================
#oracle 10 & 11
#=========================================================
class oracle10_test(UserHandlerMixin, HandlerCase):
    handler = hash.oracle10
    secret_case_insensitive = True
    user_case_insensitive = True

    # TODO: get more test vectors (especially ones which properly test unicode)
    known_correct_hashes = [
        # ((secret,user),hash)

        #
        # http://www.petefinnigan.com/default/default_password_list.htm
        #
        (('tiger', 'scott'), 'F894844C34402B67'),
        ((u('ttTiGGeR'), u('ScO')), '7AA1A84E31ED7771'),
        (("d_syspw", "SYSTEM"), '1B9F1F9A5CB9EB31'),
        (("strat_passwd", "strat_user"), 'AEBEDBB4EFB5225B'),

        #
        # http://openwall.info/wiki/john/sample-hashes
        #
        (('#95LWEIGHTS', 'USER'), '000EA4D72A142E29'),
        (('CIAO2010', 'ALFREDO'), 'EB026A76F0650F7B'),

        #
        # from JTR 1.7.9
        #
        (('GLOUGlou', 'Bob'), 'CDC6B483874B875B'),
        (('GLOUGLOUTER', 'bOB'), 'EF1F9139DB2D5279'),
        (('LONG_MOT_DE_PASSE_OUI', 'BOB'), 'EC8147ABB3373D53'),

        #
        # custom
        #
        ((UPASS_TABLE, 'System'), 'B915A853F297B281'),
    ]

    known_unidentified_hashes = [
        # bad char in hash --\
             'F894844C34402B6Z',
    ]

class oracle11_test(HandlerCase):
    handler = hash.oracle11
    # TODO: find more test vectors (especially ones which properly test unicode)
    known_correct_hashes = [
        #
        # from JTR 1.7.9
        #
        ("abc123", "S:5FDAB69F543563582BA57894FE1C1361FB8ED57B903603F2C52ED1B4D642"),
        ("SyStEm123!@#", "S:450F957ECBE075D2FA009BA822A9E28709FBC3DA82B44D284DDABEC14C42"),
        ("oracle", "S:3437FF72BD69E3FB4D10C750B92B8FB90B155E26227B9AB62D94F54E5951"),
        ("11g", "S:61CE616647A4F7980AFD7C7245261AF25E0AFE9C9763FCF0D54DA667D4E6"),
        ("11g", "S:B9E7556F53500C8C78A58F50F24439D79962DE68117654B6700CE7CC71CF"),

        #
        # source?
        #
        ("SHAlala", "S:2BFCFDF5895014EE9BB2B9BA067B01E0389BB5711B7B5F82B7235E9E182C"),

        #
        # custom
        #
        (UPASS_TABLE, 'S:51586343E429A6DF024B8F242F2E9F8507B1096FACD422E29142AA4974B0'),
    ]

#=========================================================
#pbkdf2 hashes
#=========================================================
class atlassian_pbkdf2_sha1_test(HandlerCase):
    handler = hash.atlassian_pbkdf2_sha1

    known_correct_hashes = [
        #
        # generated using Jira
        #
        ("admin", '{PKCS5S2}c4xaeTQM0lUieMS3V5voiexyX9XhqC2dBd5ecVy60IPksHChwoTAVYFrhsgoq8/p'),
        (UPASS_WAV,
                  "{PKCS5S2}cE9Yq6Am5tQGdHSHhky2XLeOnURwzaLBG2sur7FHKpvy2u0qDn6GcVGRjlmJoIUy"),
    ]

    known_malformed_hashes = [
        # bad char                                    ---\/
        '{PKCS5S2}c4xaeTQM0lUieMS3V5voiexyX9XhqC2dBd5ecVy!0IPksHChwoTAVYFrhsgoq8/p'

        # bad size, missing padding
        '{PKCS5S2}c4xaeTQM0lUieMS3V5voiexyX9XhqC2dBd5ecVy60IPksHChwoTAVYFrhsgoq8/'

        # bad size, with correct padding
        '{PKCS5S2}c4xaeTQM0lUieMS3V5voiexyX9XhqC2dBd5ecVy60IPksHChwoTAVYFrhsgoq8/='
    ]

class pbkdf2_sha1_test(HandlerCase):
    handler = hash.pbkdf2_sha1
    known_correct_hashes = [
        ("password", '$pbkdf2$1212$OB.dtnSEXZK8U5cgxU/GYQ$y5LKPOplRmok7CZp/aqVDVg8zGI'),
        (UPASS_WAV,
            '$pbkdf2$1212$THDqatpidANpadlLeTeOEg$HV3oi1k5C5LQCgG1BMOL.BX4YZc'),
    ]

class pbkdf2_sha256_test(HandlerCase):
    handler = hash.pbkdf2_sha256
    known_correct_hashes = [
        ("password",
            '$pbkdf2-sha256$1212$4vjV83LKPjQzk31VI4E0Vw$hsYF68OiOUPdDZ1Fg.fJPeq1h/gXXY7acBp9/6c.tmQ'
            ),
        (UPASS_WAV,
            '$pbkdf2-sha256$1212$3SABFJGDtyhrQMVt1uABPw$WyaUoqCLgvz97s523nF4iuOqZNbp5Nt8do/cuaa7AiI'
            ),
    ]

class pbkdf2_sha512_test(HandlerCase):
    handler = hash.pbkdf2_sha512
    known_correct_hashes = [
        ("password",
            '$pbkdf2-sha512$1212$RHY0Fr3IDMSVO/RSZyb5ow$eNLfBK.eVozomMr.1gYa1'
            '7k9B7KIK25NOEshvhrSX.esqY3s.FvWZViXz4KoLlQI.BzY/YTNJOiKc5gBYFYGww'
            ),
        (UPASS_WAV,
            '$pbkdf2-sha512$1212$KkbvoKGsAIcF8IslDR6skQ$8be/PRmd88Ps8fmPowCJt'
            'tH9G3vgxpG.Krjt3KT.NP6cKJ0V4Prarqf.HBwz0dCkJ6xgWnSj2ynXSV7MlvMa8Q'
            ),
    ]

class cta_pbkdf2_sha1_test(HandlerCase):
    handler = hash.cta_pbkdf2_sha1
    known_correct_hashes = [
        #
        # test vectors from original implementation
        #
        (u("hashy the \N{SNOWMAN}"), '$p5k2$1000$ZxK4ZBJCfQg=$jJZVscWtO--p1-xIZl6jhO2LKR0='),

        #
        # custom
        #
        ("password", "$p5k2$1$$h1TDLGSw9ST8UMAPeIE13i0t12c="),
        (UPASS_WAV,
            "$p5k2$4321$OTg3NjU0MzIx$jINJrSvZ3LXeIbUdrJkRpN62_WQ="),
        ]

class dlitz_pbkdf2_sha1_test(HandlerCase):
    handler = hash.dlitz_pbkdf2_sha1
    known_correct_hashes = [
        #
        # test vectors from original implementation
        #
        ('cloadm',  '$p5k2$$exec$r1EWMCMk7Rlv3L/RNcFXviDefYa0hlql'),
        ('gnu',     '$p5k2$c$u9HvcT4d$Sd1gwSVCLZYAuqZ25piRnbBEoAesaa/g'),
        ('dcl',     '$p5k2$d$tUsch7fU$nqDkaxMDOFBeJsTSfABsyn.PYUXilHwL'),
        ('spam',    '$p5k2$3e8$H0NX9mT/$wk/sE8vv6OMKuMaqazCJYDSUhWY9YB2J'),
        (UPASS_WAV,
                    '$p5k2$$KosHgqNo$9mjN8gqjt02hDoP0c2J0ABtLIwtot8cQ'),
        ]

class grub_pbkdf2_sha512_test(HandlerCase):
    handler = hash.grub_pbkdf2_sha512
    known_correct_hashes = [
        #
        # test vectors generated from cmd line tool
        #

        # salt=32 bytes
        (UPASS_WAV,
            'grub.pbkdf2.sha512.10000.BCAC1CEC5E4341C8C511C529'
            '7FA877BE91C2817B32A35A3ECF5CA6B8B257F751.6968526A'
            '2A5B1AEEE0A29A9E057336B48D388FFB3F600233237223C21'
            '04DE1752CEC35B0DD1ED49563398A282C0F471099C2803FBA'
            '47C7919CABC43192C68F60'),

        # salt=64 bytes
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
class phpass_test(HandlerCase):
    handler = hash.phpass

    known_correct_hashes = [
        #
        # from official 0.3 implementation
        # http://www.openwall.com/phpass/
        #
        ('test12345', '$P$9IQRaTwmfeRo7ud9Fh4E2PdI0S3r.L0'), #from the source

        #
        # from JTR 1.7.9
        #
        ('test1', '$H$9aaaaaSXBjgypwqm.JsMssPLiS8YQ00'),
        ('123456', '$H$9PE8jEklgZhgLmZl5.HYJAzfGCQtzi1'),
        ('123456', '$H$9pdx7dbOW3Nnt32sikrjAxYFjX8XoK1'),
        ('thisisalongertestPW', '$P$912345678LIjjb6PhecupozNBmDndU0'),
        ('JohnRipper', '$P$612345678si5M0DDyPpmRCmcltU/YW/'),
        ('JohnRipper', '$H$712345678WhEyvy1YWzT4647jzeOmo0'),
        ('JohnRipper', '$P$B12345678L6Lpt4BxNotVIMILOa9u81'),

        #
        # custom
        #
        ('', '$P$7JaFQsPzJSuenezefD/3jHgt5hVfNH0'),
        ('compL3X!', '$P$FiS0N5L672xzQx1rt1vgdJQRYKnQM9/'),

        # ensures utf-8 used for unicode
        (UPASS_TABLE, '$P$7SMy8VxnfsIy2Sxm7fJxDSdil.h7TW.'),
        ]

    known_malformed_hashes = [
        # bad char in otherwise correct hash
        #                            ---\/
        '$P$9IQRaTwmfeRo7ud9Fh4E2PdI0S3r!L0',
        ]

#=========================================================
#plaintext
#=========================================================
class plaintext_test(HandlerCase):
    handler = hash.plaintext
    accepts_all_hashes = True

    known_correct_hashes = [
        ('',''),
        ('password', 'password'),
    ]

#=========================================================
#postgres_md5
#=========================================================
class postgres_md5_test(UserHandlerMixin, HandlerCase):
    handler = hash.postgres_md5
    known_correct_hashes = [
        # ((secret,user),hash)

        #
        # generated using postgres 8.1
        #
        (('mypass', 'postgres'), 'md55fba2ea04fd36069d2574ea71c8efe9d'),
        (('mypass', 'root'), 'md540c31989b20437833f697e485811254b'),
        (("testpassword",'testuser'), 'md5d4fc5129cc2c25465a5370113ae9835f'),

        #
        # custom
        #

        # verify unicode->utf8
        ((UPASS_TABLE, 'postgres'), 'md5cb9f11283265811ce076db86d18a22d2'),
    ]
    known_unidentified_hashes = [
        # bad 'z' char in otherwise correct hash
        'md54zc31989b20437833f697e485811254b',
    ]

#=========================================================
# scram hash
#=========================================================
class scram_test(HandlerCase):
    handler = hash.scram

    # TODO: need a bunch more reference vectors from some real
    # SCRAM transactions.
    known_correct_hashes = [
        #
        # taken from example in SCRAM specification (rfc 5802)
        #
        ('pencil', '$scram$4096$QSXCR.Q6sek8bf92$'
                   'sha-1=HZbuOlKbWl.eR8AfIposuKbhX30'),

        #
        # custom
        #

        # same as 5802 example hash, but with sha-256 & sha-512 added.
        ('pencil', '$scram$4096$QSXCR.Q6sek8bf92$'
                   'sha-1=HZbuOlKbWl.eR8AfIposuKbhX30,'
                   'sha-256=qXUXrlcvnaxxWG00DdRgVioR2gnUpuX5r.3EZ1rdhVY,'
                   'sha-512=lzgniLFcvglRLS0gt.C4gy.NurS3OIOVRAU1zZOV4P.qFiVFO2/'
                       'edGQSu/kD1LwdX0SNV/KsPdHSwEl5qRTuZQ'),

        # test unicode passwords & saslprep (all the passwords below
        # should normalize to the same value: 'IX \xE0')
        (u('IX \xE0'),             '$scram$6400$0BojBCBE6P2/N4bQ$'
                                   'sha-1=YniLes.b8WFMvBhtSACZyyvxeCc'),
        (u('\u2168\u3000a\u0300'), '$scram$6400$0BojBCBE6P2/N4bQ$'
                                   'sha-1=YniLes.b8WFMvBhtSACZyyvxeCc'),
        (u('\u00ADIX \xE0'),       '$scram$6400$0BojBCBE6P2/N4bQ$'
                                   'sha-1=YniLes.b8WFMvBhtSACZyyvxeCc'),
    ]

    known_malformed_hashes = [
        # zero-padding in rounds
        '$scram$04096$QSXCR.Q6sek8bf92$sha-1=HZbuOlKbWl.eR8AfIposuKbhX30',

        # non-digit in rounds
        '$scram$409A$QSXCR.Q6sek8bf92$sha-1=HZbuOlKbWl.eR8AfIposuKbhX30',

        # bad char in salt       ---\/
        '$scram$4096$QSXCR.Q6sek8bf9-$sha-1=HZbuOlKbWl.eR8AfIposuKbhX30',

        # bad char in digest                                       ---\/
        '$scram$4096$QSXCR.Q6sek8bf92$sha-1=HZbuOlKbWl.eR8AfIposuKbhX3-',

        # missing separator
        '$scram$4096$QSXCR.Q6sek8bf92$sha-1=HZbuOlKbWl.eR8AfIposuKbhX30'
                   'sha-256=qXUXrlcvnaxxWG00DdRgVioR2gnUpuX5r.3EZ1rdhVY',

        # too many chars in alg name
        '$scram$4096$QSXCR.Q6sek8bf92$sha-1=HZbuOlKbWl.eR8AfIposuKbhX30,'
                                 'shaxxx-190=HZbuOlKbWl.eR8AfIposuKbhX30',

        # missing sha-1 alg
        '$scram$4096$QSXCR.Q6sek8bf92$sha-256=HZbuOlKbWl.eR8AfIposuKbhX30',

    ]

    def test_90_algs(self):
        "test parsing of 'algs' setting"
        def parse(algs, **kwds):
            return self.handler(algs=algs, use_defaults=True, **kwds).algs

        # None -> default list
        self.assertEqual(parse(None), ["sha-1","sha-256","sha-512"])

        # strings should be parsed
        self.assertEqual(parse("sha1"), ["sha-1"])
        self.assertEqual(parse("sha1, sha256, md5"), ["md5","sha-1","sha-256"])

        # lists should be normalized
        self.assertEqual(parse(["sha-1","sha256"]), ["sha-1","sha-256"])

        # sha-1 required
        self.assertRaises(ValueError, parse, ["sha-256"])

        # alg names must be < 10 chars
        self.assertRaises(ValueError, parse, ["sha-1","shaxxx-190"])

        # alg & checksum mutually exclusive.
        self.assertRaises(RuntimeError, parse, ['sha-1'],
                          checksum={"sha-1": b("\x00"*20)})

    def test_91_extract_digest_info(self):
        "test scram.extract_digest_info()"
        edi = self.handler.extract_digest_info

        # return appropriate value or throw KeyError
        h = "$scram$10$AAAAAA$sha-1=AQ,bbb=Ag,ccc=Aw"
        s = b('\x00')*4
        self.assertEqual(edi(h,"SHA1"), (s,10, b('\x01')))
        self.assertEqual(edi(h,"bbb"), (s,10, b('\x02')))
        self.assertEqual(edi(h,"ccc"), (s,10, b('\x03')))
        self.assertRaises(KeyError, edi, h, "ddd")

        # config strings should cause value error.
        c = "$scram$10$....$sha-1,bbb,ccc"
        self.assertRaises(ValueError, edi, c, "sha-1")
        self.assertRaises(ValueError, edi, c, "bbb")
        self.assertRaises(ValueError, edi, c, "ddd")

    def test_92_extract_digest_algs(self):
        "test scram.extract_digest_algs()"
        eda = self.handler.extract_digest_algs

        self.assertEqual(eda('$scram$4096$QSXCR.Q6sek8bf92$'
                   'sha-1=HZbuOlKbWl.eR8AfIposuKbhX30'), ["sha-1"])

        self.assertEqual(eda('$scram$4096$QSXCR.Q6sek8bf92$'
                   'sha-1=HZbuOlKbWl.eR8AfIposuKbhX30,'
                   'sha-256=qXUXrlcvnaxxWG00DdRgVioR2gnUpuX5r.3EZ1rdhVY,'
                   'sha-512=lzgniLFcvglRLS0gt.C4gy.NurS3OIOVRAU1zZOV4P.qFiVFO2/'
                       'edGQSu/kD1LwdX0SNV/KsPdHSwEl5qRTuZQ'),
                          ["sha-1","sha-256","sha-512"])

    def test_93_derive_digest(self):
        "test scram.derive_digest()"
        # NOTE: this just does a light test, since derive_digest
        # is used by encrypt / verify, and is tested pretty well via those.

        hash = self.handler.derive_digest

        # check various encodings of password work.
        s1 = b('\x01\x02\x03')
        d1 = b('\xb2\xfb\xab\x82[tNuPnI\x8aZZ\x19\x87\xcen\xe9\xd3')
        self.assertEqual(hash(u("\u2168"), s1, 1000, 'sha-1'), d1)
        self.assertEqual(hash(b("\xe2\x85\xa8"), s1, 1000, 'SHA-1'), d1)
        self.assertEqual(hash(u("IX"), s1, 1000, 'sha1'), d1)
        self.assertEqual(hash(b("IX"), s1, 1000, 'SHA1'), d1)

        # check algs
        self.assertEqual(hash("IX", s1, 1000, 'md5'),
                         b('3\x19\x18\xc0\x1c/\xa8\xbf\xe4\xa3\xc2\x8eM\xe8od'))
        self.assertRaises(ValueError, hash, "IX", s1, 1000, 'sha-666')

        # check rounds
        self.assertRaises(ValueError, hash, "IX", s1, 0, 'sha-1')

    def test_94_saslprep(self):
        "test encrypt/verify use saslprep"
        # NOTE: this just does a light test that saslprep() is being
        # called in various places, relying in saslpreps()'s tests
        # to verify full normalization behavior.

        # encrypt unnormalized
        h = self.do_encrypt(u("I\u00ADX"))
        self.assertTrue(self.do_verify(u("IX"), h))
        self.assertTrue(self.do_verify(u("\u2168"), h))

        # encrypt normalized
        h = self.do_encrypt(u("\xF3"))
        self.assertTrue(self.do_verify(u("o\u0301"), h))
        self.assertTrue(self.do_verify(u("\u200Do\u0301"), h))

        # throws error if forbidden char provided
        self.assertRaises(ValueError, self.do_encrypt, u("\uFDD0"))
        self.assertRaises(ValueError, self.do_verify, u("\uFDD0"), h)

    def test_95_context_algs(self):
        "test handling of 'algs' in context object"
        handler = self.handler
        from passlib.context import CryptContext
        c1 = CryptContext(["scram"], scram__algs="sha1,md5")

        h = c1.encrypt("dummy")
        self.assertEqual(handler.extract_digest_algs(h), ["md5", "sha-1"])
        self.assertFalse(c1.hash_needs_update(h))

        c2 = c1.replace(scram__algs="sha1")
        self.assertFalse(c2.hash_needs_update(h))

        c2 = c1.replace(scram__algs="sha1,sha256")
        self.assertTrue(c2.hash_needs_update(h))

    def test_96_full_verify(self):
        "test full_verify flag"
        def vfull(s, h):
            return self.handler.verify(s, h, full_verify=True)

        # reference
        h = ('$scram$4096$QSXCR.Q6sek8bf92$'
             'sha-1=HZbuOlKbWl.eR8AfIposuKbhX30,'
             'sha-256=qXUXrlcvnaxxWG00DdRgVioR2gnUpuX5r.3EZ1rdhVY,'
             'sha-512=lzgniLFcvglRLS0gt.C4gy.NurS3OIOVRAU1zZOV4P.qFiVFO2/'
                'edGQSu/kD1LwdX0SNV/KsPdHSwEl5qRTuZQ')
        self.assertTrue(vfull('pencil', h))
        self.assertFalse(vfull('tape', h))

        # catch truncated digests.
        h = ('$scram$4096$QSXCR.Q6sek8bf92$'
             'sha-1=HZbuOlKbWl.eR8AfIposuKbhX30,'
             'sha-256=qXUXrlcvnaxxWG00DdRgVioR2gnUpuX5r.3EZ1rdhVY' # -1 char
             'sha-512=lzgniLFcvglRLS0gt.C4gy.NurS3OIOVRAU1zZOV4P.qFiVFO2/'
                'edGQSu/kD1LwdX0SNV/KsPdHSwEl5qRTuZQ')
        self.assertRaises(ValueError, vfull, 'pencil', h)

        # catch padded digests.
        h = ('$scram$4096$QSXCR.Q6sek8bf92$'
             'sha-1=HZbuOlKbWl.eR8AfIposuKbhX30,'
             'sha-256=qXUXrlcvnaxxWG00DdRgVioR2gnUpuX5r.3EZ1rdhVY,a' # +1 char
             'sha-512=lzgniLFcvglRLS0gt.C4gy.NurS3OIOVRAU1zZOV4P.qFiVFO2/'
                'edGQSu/kD1LwdX0SNV/KsPdHSwEl5qRTuZQ')
        self.assertRaises(ValueError, vfull, 'pencil', h)

        # catch digests belonging to diff passwords.
        h = ('$scram$4096$QSXCR.Q6sek8bf92$'
             'sha-1=HZbuOlKbWl.eR8AfIposuKbhX30,'
             'sha-256=R7RJDWIbeKRTFwhE9oxh04kab0CllrQ3kCcpZUcligc' # 'tape'
             'sha-512=lzgniLFcvglRLS0gt.C4gy.NurS3OIOVRAU1zZOV4P.qFiVFO2/'
                'edGQSu/kD1LwdX0SNV/KsPdHSwEl5qRTuZQ')
        self.assertRaises(ValueError, vfull, 'pencil', h)
        self.assertRaises(ValueError, vfull, 'tape', h)

    ndn_values = [
        # normalized name, unnormalized names

        # IANA assigned names
        ("md5", "MD-5"),
        ("sha-1", "SHA1"),
        ("sha-256", "SHA_256", "sha2-256", "sha-2-256"),

        # heuristic for unassigned names
        ("abc6", "aBc-6"),
        ("abc6-256", "aBc-6-256"),
        ("ripemd", "RIPEMD"),
        ("ripemd-160", "RIPEmd160"),
    ]

    def test_97_norm_digest_name(self):
        "test norm_digest_name helper"
        from passlib.handlers.scram import norm_digest_name
        for row in self.ndn_values:
            result = row[0]
            for value in row:
                self.assertEqual(norm_digest_name(value), result)

#=========================================================
# (netbsd's) sha1 crypt
#=========================================================
class _sha1_crypt_test(HandlerCase):
    handler = hash.sha1_crypt

    known_correct_hashes = [
        #
        # custom
        #
        ("password", "$sha1$19703$iVdJqfSE$v4qYKl1zqYThwpjJAoKX6UvlHq/a"),
        ("password", "$sha1$21773$uV7PTeux$I9oHnvwPZHMO0Nq6/WgyGV/tDJIH"),
        (UPASS_TABLE, '$sha1$40000$uJ3Sp7LE$.VEmLO5xntyRFYihC7ggd3297T/D'),
    ]

    known_malformed_hashes = [
        # bad char in otherwise correct hash
        '$sha1$21773$u!7PTeux$I9oHnvwPZHMO0Nq6/WgyGV/tDJIH',

        # zero padded rounds
        '$sha1$01773$uV7PTeux$I9oHnvwPZHMO0Nq6/WgyGV/tDJIH',
    ]

os_crypt_sha1_crypt_test = create_backend_case(_sha1_crypt_test, "os_crypt")
builtin_sha1_crypt_test = create_backend_case(_sha1_crypt_test, "builtin")

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
            hash.ldap_hex_sha1,
            "sekrit",
            '{SHA}8d42e738c7adee551324955458b5e2c0b49ee655')

        self._test_pair(
            hash.ldap_hex_md5,
            "sekrit",
            '{MD5}ccbc53f4464604e714f69dd11138d8b5')

        self._test_pair(
            hash.ldap_des_crypt,
            "sekrit",
            '{CRYPT}nFia0rj2TT59A')

        self._test_pair(
            hash.roundup_plaintext,
            "sekrit",
            '{plaintext}sekrit')

        self._test_pair(
            hash.ldap_pbkdf2_sha1,
            "sekrit",
            '{PBKDF2}5000$7BvbBq.EZzz/O0HuwX3iP.nAG3s$g3oPnFFaga2BJaX5PoPRljl4XIE')

#=========================================================
#sha256-crypt
#=========================================================
class _sha256_crypt_test(HandlerCase):
    handler = hash.sha256_crypt

    known_correct_hashes = [
        #
        # from JTR 1.7.9
        #
        ('U*U*U*U*', '$5$LKO/Ute40T3FNF95$U0prpBQd4PloSGU0pnpM4z9wKn4vZ1.jsrzQfPqxph9'),
        ('U*U***U', '$5$LKO/Ute40T3FNF95$fdgfoJEBoMajNxCv3Ru9LyQ0xZgv0OBMQoq80LQ/Qd.'),
        ('U*U***U*', '$5$LKO/Ute40T3FNF95$8Ry82xGnnPI/6HtFYnvPBTYgOL23sdMXn8C29aO.x/A'),
        ('*U*U*U*U', '$5$9mx1HkCz7G1xho50$O7V7YgleJKLUhcfk9pgzdh3RapEaWqMtEp9UUBAKIPA'),
        ('', '$5$kc7lRD1fpYg0g.IP$d7CMTcEqJyTXyeq8hTdu/jB/I6DGkoo62NXbHIR7S43'),

        #
        # custom tests
        #
        ('', '$5$rounds=10428$uy/jIAhCetNCTtb0$YWvUOXbkqlqhyoPMpN8BMe.ZGsGx2aBvxTvDFI613c3'),
        (' ', '$5$rounds=10376$I5lNtXtRmf.OoMd8$Ko3AI1VvTANdyKhBPavaRjJzNpSatKU6QVN9uwS9MH.'),
        ('test', '$5$rounds=11858$WH1ABM5sKhxbkgCK$aTQsjPkz0rBsH3lQlJxw9HDTDXPKBxC0LlVeV69P.t1'),
        ('Compl3X AlphaNu3meric', '$5$rounds=10350$o.pwkySLCzwTdmQX$nCMVsnF3TXWcBPOympBUUSQi6LGGloZoOsVJMGJ09UB'),
        ('4lpHa N|_|M3r1K W/ Cur5Es: #$%(*)(*%#', '$5$rounds=11944$9dhlu07dQMRWvTId$LyUI5VWkGFwASlzntk1RLurxX54LUhgAcJZIt0pYGT7'),
        (u('with unic\u00D6de'), '$5$rounds=1000$IbG0EuGQXw5EkMdP$LQ5AfPf13KufFsKtmazqnzSGZ4pxtUNw3woQ.ELRDF4'),
        ]

    if enable_option("cover"):
        # builtin alg was changed in 1.6, and had possibility of fencepost
        # errors near rounds that are multiples of 42. these hashes test rounds
        # 1004..1012 (42*24=1008 +/- 4) to ensure no mistakes were made.
        # (also relying on fuzz testing against os_crypt backend).
        known_correct_hashes.extend([
        ("secret", '$5$rounds=1004$nacl$oiWPbm.kQ7.jTCZoOtdv7/tO5mWv/vxw5yTqlBagVR7'),
        ("secret", '$5$rounds=1005$nacl$6Mo/TmGDrXxg.bMK9isRzyWH3a..6HnSVVsJMEX7ud/'),
        ("secret", '$5$rounds=1006$nacl$I46VwuAiUBwmVkfPFakCtjVxYYaOJscsuIeuZLbfKID'),
        ("secret", '$5$rounds=1007$nacl$9fY4j1AV3N/dV/YMUn1enRHKH.7nEL4xf1wWB6wfDD4'),
        ("secret", '$5$rounds=1008$nacl$CiFWCfn8ODmWs0I1xAdXFo09tM8jr075CyP64bu3by9'),
        ("secret", '$5$rounds=1009$nacl$QtpFX.CJHgVQ9oAjVYStxAeiU38OmFILWm684c6FyED'),
        ("secret", '$5$rounds=1010$nacl$ktAwXuT5WbjBW/0ZU1eNMpqIWY1Sm4twfRE1zbZyo.B'),
        ("secret", '$5$rounds=1011$nacl$QJWLBEhO9qQHyMx4IJojSN9sS41P1Yuz9REddxdO721'),
        ("secret", '$5$rounds=1012$nacl$mmf/k2PkbBF4VCtERgky3bEVavmLZKFwAcvxD1p3kV2'),
        ])

    known_malformed_hashes = [
        # bad char in otherwise correct hash
        '$5$rounds=10428$uy/:jIAhCetNCTtb0$YWvUOXbkqlqhyoPMpN8BMeZGsGx2aBvxTvDFI613c3',

        # zero-padded rounds
       '$5$rounds=010428$uy/jIAhCetNCTtb0$YWvUOXbkqlqhyoPMpN8BMe.ZGsGx2aBvxTvDFI613c3',
    ]

    known_correct_configs = [
        # config, secret, result

        #
        # taken from official specification at http://www.akkadia.org/drepper/SHA-crypt.txt
        #
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

    filter_config_warnings = True # rounds too low, salt too small

os_crypt_sha256_crypt_test = create_backend_case(_sha256_crypt_test, "os_crypt")
builtin_sha256_crypt_test = create_backend_case(_sha256_crypt_test, "builtin")

#=========================================================
#test sha512-crypt
#=========================================================
class _sha512_crypt_test(HandlerCase):
    handler = hash.sha512_crypt

    known_correct_hashes = [
        #
        # from JTR 1.7.9
        #
        ('U*U*U*U*', "$6$LKO/Ute40T3FNF95$6S/6T2YuOIHY0N3XpLKABJ3soYcXD9mB7uVbtEZDj/LNscVhZoZ9DEH.sBciDrMsHOWOoASbNLTypH/5X26gN0"),
        ('U*U***U', "$6$LKO/Ute40T3FNF95$wK80cNqkiAUzFuVGxW6eFe8J.fSVI65MD5yEm8EjYMaJuDrhwe5XXpHDJpwF/kY.afsUs1LlgQAaOapVNbggZ1"),
        ('U*U***U*', "$6$LKO/Ute40T3FNF95$YS81pp1uhOHTgKLhSMtQCr2cDiUiN03Ud3gyD4ameviK1Zqz.w3oXsMgO6LrqmIEcG3hiqaUqHi/WEE2zrZqa/"),
        ('*U*U*U*U', "$6$OmBOuxFYBZCYAadG$WCckkSZok9xhp4U1shIZEV7CCVwQUwMVea7L3A77th6SaE9jOPupEMJB.z0vIWCDiN9WLh2m9Oszrj5G.gt330"),
        ('', "$6$ojWH1AiTee9x1peC$QVEnTvRVlPRhcLQCk/HnHaZmlGAAjCfrAN0FtOsOnUk5K5Bn/9eLHHiRzrTzaIKjW9NTLNIBUCtNVOowWS2mN."),

        #
        # custom tests
        #
        ('', '$6$rounds=11021$KsvQipYPWpr93wWP$v7xjI4X6vyVptJjB1Y02vZC5SaSijBkGmq1uJhPr3cvqvvkd42Xvo48yLVPFt8dvhCsnlUgpX.//Cxn91H4qy1'),
        (' ', '$6$rounds=11104$ED9SA4qGmd57Fq2m$q/.PqACDM/JpAHKmr86nkPzzuR5.YpYa8ZJJvI8Zd89ZPUYTJExsFEIuTYbM7gAGcQtTkCEhBKmp1S1QZwaXx0'),
        ('test', '$6$rounds=11531$G/gkPn17kHYo0gTF$Kq.uZBHlSBXyzsOJXtxJruOOH4yc0Is13uY7yK0PvAvXxbvc1w8DO1RzREMhKsc82K/Jh8OquV8FZUlreYPJk1'),
        ('Compl3X AlphaNu3meric', '$6$rounds=10787$wakX8nGKEzgJ4Scy$X78uqaX1wYXcSCtS4BVYw2trWkvpa8p7lkAtS9O/6045fK4UB2/Jia0Uy/KzCpODlfVxVNZzCCoV9s2hoLfDs/'),
        ('4lpHa N|_|M3r1K W/ Cur5Es: #$%(*)(*%#', '$6$rounds=11065$5KXQoE1bztkY5IZr$Jf6krQSUKKOlKca4hSW07MSerFFzVIZt/N3rOTsUgKqp7cUdHrwV8MoIVNCk9q9WL3ZRMsdbwNXpVk0gVxKtz1'),

        # ensures utf-8 used for unicode
        (UPASS_TABLE, '$6$rounds=40000$PEZTJDiyzV28M3.m$GTlnzfzGB44DGd1XqlmC4erAJKCP.rhvLvrYxiT38htrNzVGBnplFOHjejUGVrCfusGWxLQCc3pFO0A/1jYYr0'),
        ]

    known_malformed_hashes = [
        #zero-padded rounds
        '$6$rounds=011021$KsvQipYPWpr93wWP$v7xjI4X6vyVptJjB1Y02vZC5SaSijBkGmq1uJhPr3cvqvvkd42Xvo48yLVPFt8dvhCsnlUgpX.//Cxn91H4qy1',
        #bad char in otherwise correct hash
        '$6$rounds=11021$KsvQipYPWpr9:wWP$v7xjI4X6vyVptJjB1Y02vZC5SaSijBkGmq1uJhPr3cvqvvkd42Xvo48yLVPFt8dvhCsnlUgpX.//Cxn91H4qy1',
    ]

    known_correct_configs = [
        # config, secret, result

        #
        # taken from official specification at http://www.akkadia.org/drepper/SHA-crypt.txt
        #
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

    filter_config_warnings = True # rounds too low, salt too small

os_crypt_sha512_crypt_test = create_backend_case(_sha512_crypt_test, "os_crypt")
builtin_sha512_crypt_test = create_backend_case(_sha512_crypt_test, "builtin")

#=========================================================
#sun md5 crypt
#=========================================================
class sun_md5_crypt_test(HandlerCase):
    handler = hash.sun_md5_crypt

    # TODO: this scheme needs some real test vectors, especially due to
    # the "bare salt" issue which plagued the official parser.
    known_correct_hashes = [
        #
        # http://forums.halcyoninc.com/showthread.php?t=258
        #
        ("Gpcs3_adm", "$md5$zrdhpMlZ$$wBvMOEqbSjU.hu5T2VEP01"),

        #
        # http://www.c0t0d0s0.org/archives/4453-Less-known-Solaris-features-On-passwords-Part-2-Using-stronger-password-hashing.html
        #
        ("aa12345678", "$md5$vyy8.OVF$$FY4TWzuauRl4.VQNobqMY."),

        #
        # http://www.cuddletech.com/blog/pivot/entry.php?id=778
        #
        ("this", "$md5$3UqYqndY$$6P.aaWOoucxxq.l00SS9k0"),

        #
        # http://compgroups.net/comp.unix.solaris/password-file-in-linux-and-solaris-8-9
        #
        ("passwd", "$md5$RPgLF6IJ$WTvAlUJ7MqH5xak2FMEwS/"),

        #
        # source: http://solaris-training.com/301_HTML/docs/deepdiv.pdf page 27
        # FIXME: password unknown
        # "$md5,rounds=8000$kS9FT1JC$$mnUrRO618lLah5iazwJ9m1"

        #
        # source: http://www.visualexams.com/310-303.htm
        # XXX: this has 9 salt chars unlike all other hashes. is that valid?
        # FIXME: password unknown
        # "$md5,rounds=2006$2amXesSj5$$kCF48vfPsHDjlKNXeEw7V."
        #

        #
        # custom
        #

        # ensures utf-8 used for unicode
        (UPASS_TABLE, '$md5,rounds=5000$10VYDzAA$$1arAVtMA3trgE1qJ2V0Ez1'),
        ]

    known_correct_configs = [
        # (config, secret, hash)

        #---------------------------
        # test salt string handling
        #
        # these tests attempt to verify that passlib is handling
        # the "bare salt" issue (see sun md5 crypt docs)
        # in a sane manner
        #---------------------------

        # config with "$" suffix, hash strings with "$$" suffix,
        # should all be treated the same, with one "$" added to salt digest.
        ("$md5$3UqYqndY$",
            "this", "$md5$3UqYqndY$$6P.aaWOoucxxq.l00SS9k0"),
        ("$md5$3UqYqndY$$......................",
            "this", "$md5$3UqYqndY$$6P.aaWOoucxxq.l00SS9k0"),

        # config with no suffix, hash strings with "$" suffix,
        # should all be treated the same, and no suffix added to salt digest.
        # NOTE: this is just a guess re: config w/ no suffix,
        #       but otherwise there's no sane way to encode bare_salt=False
        #       within config string.
        ("$md5$3UqYqndY",
            "this", "$md5$3UqYqndY$HIZVnfJNGCPbDZ9nIRSgP1"),
        ("$md5$3UqYqndY$......................",
            "this", "$md5$3UqYqndY$HIZVnfJNGCPbDZ9nIRSgP1"),
    ]

    known_malformed_hashes = [
        # bad char in otherwise correct hash
        "$md5$RPgL!6IJ$WTvAlUJ7MqH5xak2FMEwS/",

        # digest too short
        "$md5$RPgLa6IJ$WTvAlUJ7MqH5xak2FMEwS",

        # digest too long
        "$md5$RPgLa6IJ$WTvAlUJ7MqH5xak2FMEwS/.",

        # 2+ "$" at end of salt in config
        #NOTE: not sure what correct behavior is, so forbidding format for now.
        "$md5$3UqYqndY$$",

        # 3+ "$" at end of salt in hash
        #NOTE: not sure what correct behavior is, so forbidding format for now.
        "$md5$RPgLa6IJ$$$WTvAlUJ7MqH5xak2FMEwS/",

        ]

    def do_verify(self, secret, hash):
        # override to fake error for "$..." hash strings listed in known_config.
        # these have to be hash strings, in order to test bare salt issue.
        if hash and hash.endswith("$......................"):
            raise ValueError("pretending '$.' hash is config string")
        return self.handler.verify(secret, hash)

#=========================================================
#unix fallback
#=========================================================
class unix_fallback_test(HandlerCase):
    handler = hash.unix_fallback
    accepts_all_hashes = True
    is_disabled_handler = True

    known_correct_hashes = [
        # *everything* should hash to "!", and nothing should verify
        ("password", "!"),
        (UPASS_TABLE, "!"),
    ]

    def test_90_wildcard(self):
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
