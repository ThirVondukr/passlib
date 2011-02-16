"""tests for passlib.pwhash -- (c) Assurance Technologies 2003-2009"""
#=========================================================
#imports
#=========================================================
from __future__ import with_statement
#core
import hashlib
import logging; log = logging.getLogger(__name__)
try:
    from warnings import catch_warnings
except ImportError: #wasn't added until py26
    catch_warnings = None
import warnings
#site
#pkg
from passlib.tests.utils import HandlerCase, create_backend_case, enable_option
#module

#=========================================================
#apr md5 crypt
#=========================================================
from passlib.drivers.md5_crypt import apr_md5_crypt
class AprMd5CryptTest(HandlerCase):
    handler = apr_md5_crypt

    #values taken from http://httpd.apache.org/docs/2.2/misc/password_encryptions.html
    known_correct = (
        ('myPassword', '$apr1$r31.....$HqJZimcKQFAMYayBlzkrA/'),
        )

    known_identified_invalid = [
        #bad char in otherwise correct hash
        '$apr1$r31.....$HqJZimcKQFAMYayBlzkrA!'
        ]

#=========================================================
#bcrypt
#=========================================================
from passlib.drivers.bcrypt import bcrypt

class BCryptTest(HandlerCase):
    handler = bcrypt
    secret_chars = 72

    known_correct = (
        #selected bcrypt test vectors
        ('', '$2a$06$DCq7YPn5Rq63x1Lad4cll.TV4S6ytwfsfvkgY8jIucDrjc8deX1s.'),
        ('a', '$2a$10$k87L/MF28Q673VKh8/cPi.SUl7MU/rWuSiIDDFayrKk/1tBsSQu4u'),
        ('abc', '$2a$10$WvvTPHKwdBJ3uk0Z37EMR.hLA2W6N9AEBhEgrAOljy2Ae5MtaSIUi'),
        ('abcdefghijklmnopqrstuvwxyz', '$2a$10$fVH8e28OQRj9tqiDXs1e1uxpsjN0c7II7YPKXua2NAKYvM6iQk7dq'),
        ('~!@#$%^&*()      ~!@#$%^&*()PNBFRD', '$2a$10$LgfYWkbzEvQ4JakH7rOvHe0y8pHKF9OaFgwUZ2q7W2FFZmZzJYlfS'),
        )

    known_invalid = [
        #unsupported minor version
        "$2b$12$EXRkfkdmXn!gzds2SSitu.MW9.gAVqa9eLS1//RYtYCmB1eLHg.9q",
    ]

    known_identified_invalid = [
        #bad char in otherwise correct hash
        "$2a$12$EXRkfkdmXn!gzds2SSitu.MW9.gAVqa9eLS1//RYtYCmB1eLHg.9q",
        #rounds not zero-padded (pybcrypt rejects this, therefore so do we)
        '$2a$6$DCq7YPn5Rq63x1Lad4cll.TV4S6ytwfsfvkgY8jIucDrjc8deX1s.'
        ]

#NOTE: pybcrypt backend will be chosen as primary if possible, so just check for os crypt and builtin
OsCrypt_BCryptTest = create_backend_case(BCryptTest, "os_crypt")

#this one's unusuablly slow, don't test it unless user asks for it.
Builtin_BCryptTest = create_backend_case(BCryptTest, "builtin") if enable_option("slow") else None

#=========================================================
#bigcrypt
#=========================================================
from passlib.drivers.des_crypt import bigcrypt

class BigCryptTest(HandlerCase):
    handler = bigcrypt

    #TODO: find an authortative source of test vectors
    known_correct = [
        ("passphrase", "qiyh4XPJGsOZ2MEAyLkfWqeQ"),
        ]

    #omit des_crypt from known other, it looks like bigcrypt
    known_other = filter(lambda row: row[0] != "des_crypt", HandlerCase.known_other)

#=========================================================
#bsdi crypt
#=========================================================
from passlib.drivers.des_crypt import bsdi_crypt

class BSDiCryptTest(HandlerCase):
    "test BSDiCrypt algorithm"
    handler = bsdi_crypt
    known_correct = [
        (" ", "_K1..crsmZxOLzfJH8iw"),
        ("my", '_KR/.crsmykRplHbAvwA'), #<- to detect old 12-bit rounds bug
        ("my socra", "_K1..crsmf/9NzZr1fLM"),
        ("my socrates", '_K1..crsmOv1rbde9A9o'),
        ("my socrates note", "_K1..crsm/2qeAhdISMA"),
    ]
    known_invalid = [
        #bad char in otherwise correctly formatted hash
       "_K1.!crsmZxOLzfJH8iw"
    ]

#=========================================================
#crypt16
#=========================================================
from passlib.drivers.des_crypt import crypt16

class Crypt16Test(HandlerCase):
    handler = crypt16
    secret_chars = 16

    #TODO: find an authortative source of test vectors
    known_correct = [
        ("passphrase", "qi8H8R7OM4xMUNMPuRAZxlY."),
        ]

#=========================================================
#des crypt
#=========================================================
from passlib.drivers.des_crypt import des_crypt

class DesCryptTest(HandlerCase):
    "test des-crypt algorithm"
    handler = des_crypt
    secret_chars = 8

    #TODO: test

    known_correct = (
        #secret, example hash which matches secret
        ('', 'OgAwTx2l6NADI'),
        (' ', '/Hk.VPuwQTXbc'),
        ('test', 'N1tQbOFcM5fpg'),
        ('Compl3X AlphaNu3meric', 'um.Wguz3eVCx2'),
        ('4lpHa N|_|M3r1K W/ Cur5Es: #$%(*)(*%#', 'sNYqfOyauIyic'),
        ('AlOtBsOl', 'cEpWz5IUCShqM'),
        (u'hell\u00D6', 'saykDgk3BPZ9E'),
        )
    known_invalid = [
        #bad char in otherwise correctly formatted hash
        '!gAwTx2l6NADI',
        ]

BuiltinDesCryptTest = create_backend_case(DesCryptTest, "builtin")

#=========================================================
#md5 crypt
#=========================================================
from passlib.drivers.md5_crypt import md5_crypt
class Md5CryptTest(HandlerCase):
    handler = md5_crypt

    known_correct = (
        ('', '$1$dOHYPKoP$tnxS1T8Q6VVn3kpV8cN6o.'),
        (' ', '$1$m/5ee7ol$bZn0kIBFipq39e.KDXX8I0'),
        ('test', '$1$ec6XvcoW$ghEtNK2U1MC5l.Dwgi3020'),
        ('Compl3X AlphaNu3meric', '$1$nX1e7EeI$ljQn72ZUgt6Wxd9hfvHdV0'),
        ('4lpHa N|_|M3r1K W/ Cur5Es: #$%(*)(*%#', '$1$jQS7o98J$V6iTcr71CGgwW2laf17pi1'),
        ('test', '$1$SuMrG47N$ymvzYjr7QcEQjaK5m1PGx1'),
        )

    known_identified_invalid = [
        #bad char in otherwise correct hash
        '$1$dOHYPKoP$tnxS1T8Q6VVn3kpV8cN6o!',
        ]

BuiltinMd5CryptTest = create_backend_case(Md5CryptTest, "builtin")

#=========================================================
#mysql 323 & 41
#=========================================================
from passlib.drivers.mysql import mysql323, mysql41

class Mysql323Test(HandlerCase):
    handler = mysql323

    #remove single space from secrets, since mysql-323 ignores all whitespace (?!)
    standard_secrets = [ x for x in HandlerCase.standard_secrets if x != ' ' ]

    known_correct = (
        ('mypass', '6f8c114b58f2ce9e'),
    )
    known_invalid = [
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
    known_correct = (
        ('mypass', '*6C8989366EAF75BB670AD8EA7A7FC1176A95CEF4'),
    )
    known_invalid = [
        #bad char in otherwise correct hash
        '*6Z8989366EAF75BB670AD8EA7A7FC1176A95CEF4',
    ]

#=========================================================
#NTHASH for unix
#=========================================================
from passlib.drivers.nthash import nthash

class NTHashTest(HandlerCase):
    handler = nthash

    known_correct = (
        ('passphrase', '$3$$7f8fe03093cc84b267b109625f6bbf4b'),
        ('passphrase', '$NT$7f8fe03093cc84b267b109625f6bbf4b'),
    )

    known_identified_invalid = [
        #bad char in otherwise correct hash
        '$3$$7f8fe03093cc84b267b109625f6bbfxb',
    ]

#=========================================================
#PHPass Portable Crypt
#=========================================================
from passlib.drivers.phpass import phpass

class PHPassTest(HandlerCase):
    handler = phpass

    known_correct = (
        ('', '$P$7JaFQsPzJSuenezefD/3jHgt5hVfNH0'),
        ('compL3X!', '$P$FiS0N5L672xzQx1rt1vgdJQRYKnQM9/'),
        ('test12345', '$P$9IQRaTwmfeRo7ud9Fh4E2PdI0S3r.L0'), #from the source
        )

    known_identified_invalid = [
        #bad char in otherwise correct hash
        '$P$9IQRaTwmfeRo7ud9Fh4E2PdI0S3r!L0',
        ]

#=========================================================
#postgres_md5
#=========================================================
from passlib.drivers.postgres import postgres_md5, postgres_plaintext

#FIXME: test postgres_plaintext

class PostgresMD5CryptTest(HandlerCase):
    handler = postgres_md5
    known_correct = [
        # ((secret,user),hash)
        (('mypass', 'postgres'), 'md55fba2ea04fd36069d2574ea71c8efe9d'),
        (('mypass', 'root'), 'md540c31989b20437833f697e485811254b'),
        (("testpassword",'testuser'), 'md5d4fc5129cc2c25465a5370113ae9835f'),
    ]
    known_invalid = [
        #bad 'z' char in otherwise correct hash
        'md54zc31989b20437833f697e485811254b',
    ]

    #NOTE: used to support secret=(password, user) format, but removed it for now.
    ##def test_tuple_mode(self):
    ##    "check tuple mode works for encrypt/verify"
    ##    self.assertEquals(self.handler.encrypt(('mypass', 'postgres')),
    ##        'md55fba2ea04fd36069d2574ea71c8efe9d')
    ##    self.assertEquals(self.handler.verify(('mypass', 'postgres'),
    ##        'md55fba2ea04fd36069d2574ea71c8efe9d'), True)

    def test_user(self):
        "check user kwd is required for encrypt/verify"
        self.assertRaises(TypeError, self.handler.encrypt, 'mypass')
        self.assertRaises(TypeError, self.handler.verify, 'mypass', 'md55fba2ea04fd36069d2574ea71c8efe9d')

    def do_concat(self, secret, prefix):
        if isinstance(secret, tuple):
            secret, user = secret
            secret = prefix + secret
            return secret, user
        else:
            return prefix + secret

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

#=========================================================
# (netbsd's) sha1 crypt
#=========================================================
from passlib.drivers.sha1_crypt import sha1_crypt

class SHA1CryptTest(HandlerCase):
    handler = sha1_crypt

    known_correct = (
        ("password", "$sha1$19703$iVdJqfSE$v4qYKl1zqYThwpjJAoKX6UvlHq/a"),
        ("password", "$sha1$21773$uV7PTeux$I9oHnvwPZHMO0Nq6/WgyGV/tDJIH"),
    )

    known_identified_invalid = [
        #bad char in otherwise correct hash
        '$sha1$21773$u!7PTeux$I9oHnvwPZHMO0Nq6/WgyGV/tDJIH',
    ]

#=========================================================
#sha256-crypt
#=========================================================
from passlib.drivers.sha2_crypt import sha256_crypt

class SHA256CryptTest(HandlerCase):
    handler = sha256_crypt
    supports_unicode = True

    known_correct = [
        ('', '$5$rounds=10428$uy/jIAhCetNCTtb0$YWvUOXbkqlqhyoPMpN8BMe.ZGsGx2aBvxTvDFI613c3'),
        (' ', '$5$rounds=10376$I5lNtXtRmf.OoMd8$Ko3AI1VvTANdyKhBPavaRjJzNpSatKU6QVN9uwS9MH.'),
        ('test', '$5$rounds=11858$WH1ABM5sKhxbkgCK$aTQsjPkz0rBsH3lQlJxw9HDTDXPKBxC0LlVeV69P.t1'),
        ('Compl3X AlphaNu3meric', '$5$rounds=10350$o.pwkySLCzwTdmQX$nCMVsnF3TXWcBPOympBUUSQi6LGGloZoOsVJMGJ09UB'),
        ('4lpHa N|_|M3r1K W/ Cur5Es: #$%(*)(*%#', '$5$rounds=11944$9dhlu07dQMRWvTId$LyUI5VWkGFwASlzntk1RLurxX54LUhgAcJZIt0pYGT7'),
        (u'with unic\u00D6de', '$5$rounds=1000$IbG0EuGQXw5EkMdP$LQ5AfPf13KufFsKtmazqnzSGZ4pxtUNw3woQ.ELRDF4'),
        ]

    known_identified_invalid = [
        #bad char in otherwise correct hash
        '$5$rounds=10428$uy/:jIAhCetNCTtb0$YWvUOXbkqlqhyoPMpN8BMeZGsGx2aBvxTvDFI613c3',

        #zero-padded rounds
       '$5$rounds=010428$uy/jIAhCetNCTtb0$YWvUOXbkqlqhyoPMpN8BMe.ZGsGx2aBvxTvDFI613c3',
    ]

BuiltinSHA256CryptTest = create_backend_case(SHA256CryptTest, "builtin")

#=========================================================
#test sha512-crypt
#=========================================================
from passlib.drivers.sha2_crypt import sha512_crypt

class SHA512CryptTest(HandlerCase):
    handler = sha512_crypt
    supports_unicode = True

    known_correct = [
        ('', '$6$rounds=11021$KsvQipYPWpr93wWP$v7xjI4X6vyVptJjB1Y02vZC5SaSijBkGmq1uJhPr3cvqvvkd42Xvo48yLVPFt8dvhCsnlUgpX.//Cxn91H4qy1'),
        (' ', '$6$rounds=11104$ED9SA4qGmd57Fq2m$q/.PqACDM/JpAHKmr86nkPzzuR5.YpYa8ZJJvI8Zd89ZPUYTJExsFEIuTYbM7gAGcQtTkCEhBKmp1S1QZwaXx0'),
        ('test', '$6$rounds=11531$G/gkPn17kHYo0gTF$Kq.uZBHlSBXyzsOJXtxJruOOH4yc0Is13uY7yK0PvAvXxbvc1w8DO1RzREMhKsc82K/Jh8OquV8FZUlreYPJk1'),
        ('Compl3X AlphaNu3meric', '$6$rounds=10787$wakX8nGKEzgJ4Scy$X78uqaX1wYXcSCtS4BVYw2trWkvpa8p7lkAtS9O/6045fK4UB2/Jia0Uy/KzCpODlfVxVNZzCCoV9s2hoLfDs/'),
        ('4lpHa N|_|M3r1K W/ Cur5Es: #$%(*)(*%#', '$6$rounds=11065$5KXQoE1bztkY5IZr$Jf6krQSUKKOlKca4hSW07MSerFFzVIZt/N3rOTsUgKqp7cUdHrwV8MoIVNCk9q9WL3ZRMsdbwNXpVk0gVxKtz1'),
        ]

    known_identified_invalid = [
        #zero-padded rounds
        '$6$rounds=011021$KsvQipYPWpr93wWP$v7xjI4X6vyVptJjB1Y02vZC5SaSijBkGmq1uJhPr3cvqvvkd42Xvo48yLVPFt8dvhCsnlUgpX.//Cxn91H4qy1',
        #bad char in otherwise correct hash
        '$6$rounds=11021$KsvQipYPWpr9:wWP$v7xjI4X6vyVptJjB1Y02vZC5SaSijBkGmq1uJhPr3cvqvvkd42Xvo48yLVPFt8dvhCsnlUgpX.//Cxn91H4qy1',
    ]

    #NOTE: these test cases taken from official specification at http://www.akkadia.org/drepper/SHA-crypt.txt
    cases512 = [
        #salt-hash, secret, result
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

    def test_spec_vectors(self):
        "verify sha512-crypt passes specification test vectors"
        handler = self.handler

        #NOTE: the 'roundstoolow' test vector is known to raise a warning, which we silence here
        if catch_warnings:
            ctx = catch_warnings()
            ctx.__enter__()
        warnings.filterwarnings("ignore", "sha512_crypt does not allow less than 1000 rounds: 10", UserWarning)

        for config, secret, hash in self.cases512:
            #make sure we got expected result back
            result = handler.genhash(secret, config)
            self.assertEqual(result, hash, "hash=%r secret=%r:" % (hash, secret))

            #make sure parser truncated salts
            info = handler.from_string(config)
            self.assert_(len(info.salt) <= 16, "hash=%r secret=%r:" % (hash, secret))

        if catch_warnings:
            ctx.__exit__(None,None,None)

BuiltinSHA512CryptTest = create_backend_case(SHA512CryptTest, "builtin")

#=========================================================
#sun md5 crypt
#=========================================================
from passlib.drivers.sun_md5_crypt import sun_md5_crypt

class SunMD5CryptTest(HandlerCase):
    handler = sun_md5_crypt

    known_correct = [
        #sample hash found at http://compgroups.net/comp.unix.solaris/password-file-in-linux-and-solaris-8-9
        ("passwd", "$md5$RPgLF6IJ$WTvAlUJ7MqH5xak2FMEwS/"),
        ]

    known_identified_invalid = [
        #bad char in otherwise correct hash
        "$md5$RPgL!6IJ$WTvAlUJ7MqH5xak2FMEwS/"
        ]

#=========================================================
#EOF
#=========================================================
