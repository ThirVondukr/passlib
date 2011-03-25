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
from passlib.tests.utils import HandlerCase, create_backend_case, enable_option
#module

#=========================================================
#apr md5 crypt
#=========================================================
from passlib.handlers.md5_crypt import apr_md5_crypt
class AprMd5CryptTest(HandlerCase):
    handler = apr_md5_crypt

    #values taken from http://httpd.apache.org/docs/2.2/misc/password_encryptions.html
    known_correct_hashes = (
        ('myPassword', '$apr1$r31.....$HqJZimcKQFAMYayBlzkrA/'),
        )

    known_malformed_hashes = [
        #bad char in otherwise correct hash
        '$apr1$r31.....$HqJZimcKQFAMYayBlzkrA!'
        ]

#=========================================================
#bcrypt
#=========================================================
from passlib.handlers.bcrypt import bcrypt

class BCryptTest(HandlerCase):
    handler = bcrypt
    secret_chars = 72

    known_correct_hashes = (
        #selected bcrypt test vectors
        ('', '$2a$06$DCq7YPn5Rq63x1Lad4cll.TV4S6ytwfsfvkgY8jIucDrjc8deX1s.'),
        ('a', '$2a$10$k87L/MF28Q673VKh8/cPi.SUl7MU/rWuSiIDDFayrKk/1tBsSQu4u'),
        ('abc', '$2a$10$WvvTPHKwdBJ3uk0Z37EMR.hLA2W6N9AEBhEgrAOljy2Ae5MtaSIUi'),
        ('abcdefghijklmnopqrstuvwxyz', '$2a$10$fVH8e28OQRj9tqiDXs1e1uxpsjN0c7II7YPKXua2NAKYvM6iQk7dq'),
        ('~!@#$%^&*()      ~!@#$%^&*()PNBFRD', '$2a$10$LgfYWkbzEvQ4JakH7rOvHe0y8pHKF9OaFgwUZ2q7W2FFZmZzJYlfS'),
        )

    known_unidentified_hashes = [
        #unsupported minor version
        "$2b$12$EXRkfkdmXn!gzds2SSitu.MW9.gAVqa9eLS1//RYtYCmB1eLHg.9q",
    ]

    known_malformed_hashes = [
        #bad char in otherwise correct hash
        "$2a$12$EXRkfkdmXn!gzds2SSitu.MW9.gAVqa9eLS1//RYtYCmB1eLHg.9q",
        #rounds not zero-padded (pybcrypt rejects this, therefore so do we)
        '$2a$6$DCq7YPn5Rq63x1Lad4cll.TV4S6ytwfsfvkgY8jIucDrjc8deX1s.'
        ]

    def test_idents(self):
        handler = self.handler

        kwds = dict(checksum='8CIhhFCj15KqqFvo/n.Jatx8dJ92f82', salt='VlsfIX9.apXuQBr6tego0M', rounds=12, ident="2a", strict=True)
        handler(**kwds)

        kwds['ident'] = None
        self.assertRaises(ValueError, handler, **kwds)

        del kwds['strict']
        kwds['ident'] = 'Q'
        self.assertRaises(ValueError, handler, **kwds)

    #this method is added in order to maximize test coverage on systems
    #where os_crypt is missing or doesn't support bcrypt
    if enable_option("cover") and not bcrypt.has_backend("os_crypt") and bcrypt.has_backend("pybcrypt"):
        def test_backend(self):
            from passlib.handlers import bcrypt as bcrypt_mod
            orig = bcrypt_mod.os_crypt
            bcrypt_mod.os_crypt = bcrypt_mod.pybcrypt_hashpw
            orig = bcrypt.get_backend()
            try:
                bcrypt.set_backend("os_crypt")
                bcrypt.encrypt(u"test", rounds=4)
            finally:
                bcrypt.set_backend(orig)
                bcrypt_mod.os_crypt = orig

bcrypt._no_backends_msg()

try:
    bcrypt.get_backend()
except EnvironmentError:
    #no bcrypt backends available!
    BCryptTest = None

#NOTE: pybcrypt backend will be chosen as primary if possible, so just check for os crypt and builtin
OsCrypt_BCryptTest = create_backend_case(BCryptTest, "os_crypt")

###this one's unusuablly slow, don't test it unless user asks for it.
##Builtin_BCryptTest = create_backend_case(BCryptTest, "builtin") if enable_option("slow") else None

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
    known_other_hashes = filter(lambda row: row[0] != "des_crypt", HandlerCase.known_other_hashes)

#=========================================================
#bsdi crypt
#=========================================================
from passlib.handlers.des_crypt import bsdi_crypt

class BSDiCryptTest(HandlerCase):
    "test BSDiCrypt algorithm"
    handler = bsdi_crypt
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

class DesCryptTest(HandlerCase):
    "test des-crypt algorithm"
    handler = des_crypt
    secret_chars = 8

    known_correct_hashes = (
        #secret, example hash which matches secret
        ('', 'OgAwTx2l6NADI'),
        (' ', '/Hk.VPuwQTXbc'),
        ('test', 'N1tQbOFcM5fpg'),
        ('Compl3X AlphaNu3meric', 'um.Wguz3eVCx2'),
        ('4lpHa N|_|M3r1K W/ Cur5Es: #$%(*)(*%#', 'sNYqfOyauIyic'),
        ('AlOtBsOl', 'cEpWz5IUCShqM'),
        (u'hell\u00D6', 'saykDgk3BPZ9E'),
        )
    known_unidentified_hashes = [
        #bad char in otherwise correctly formatted hash
        '!gAwTx2l6NADI',
        ]

    def test_invalid_secret_chars(self):
        self.assertRaises(ValueError, self.do_encrypt, 'sec\x00t')

BuiltinDesCryptTest = create_backend_case(DesCryptTest, "builtin")

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

# helloworld -> '{CRYPT}dQ58WW.1980Ig'

#=========================================================
#md5 crypt
#=========================================================
from passlib.handlers.md5_crypt import md5_crypt, raw_md5_crypt
class Md5CryptTest(HandlerCase):
    handler = md5_crypt

    known_correct_hashes = (
        ('', '$1$dOHYPKoP$tnxS1T8Q6VVn3kpV8cN6o.'),
        (' ', '$1$m/5ee7ol$bZn0kIBFipq39e.KDXX8I0'),
        ('test', '$1$ec6XvcoW$ghEtNK2U1MC5l.Dwgi3020'),
        ('Compl3X AlphaNu3meric', '$1$nX1e7EeI$ljQn72ZUgt6Wxd9hfvHdV0'),
        ('4lpHa N|_|M3r1K W/ Cur5Es: #$%(*)(*%#', '$1$jQS7o98J$V6iTcr71CGgwW2laf17pi1'),
        ('test', '$1$SuMrG47N$ymvzYjr7QcEQjaK5m1PGx1'),
        )

    known_malformed_hashes = [
        #bad char in otherwise correct hash
        '$1$dOHYPKoP$tnxS1T8Q6VVn3kpV8cN6o!',
        ]

    def test_raw(self):
        self.assertEquals(raw_md5_crypt('s','s'*16), 'YgmLTApYTv12qgTwBoj8i/')

BuiltinMd5CryptTest = create_backend_case(Md5CryptTest, "builtin")

#=========================================================
#mysql 323 & 41
#=========================================================
from passlib.handlers.mysql import mysql323, mysql41

class Mysql323Test(HandlerCase):
    handler = mysql323

    known_correct_hashes = (
        ('mypass', '6f8c114b58f2ce9e'),
    )
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
    known_correct_hashes = (
        ('mypass', '*6C8989366EAF75BB670AD8EA7A7FC1176A95CEF4'),
    )
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

    known_correct_hashes = (
        ('passphrase', '$3$$7f8fe03093cc84b267b109625f6bbf4b'),
        ('passphrase', '$NT$7f8fe03093cc84b267b109625f6bbf4b'),
    )

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
#PHPass Portable Crypt
#=========================================================
from passlib.handlers.phpass import phpass

class PHPassTest(HandlerCase):
    handler = phpass

    known_correct_hashes = (
        ('', '$P$7JaFQsPzJSuenezefD/3jHgt5hVfNH0'),
        ('compL3X!', '$P$FiS0N5L672xzQx1rt1vgdJQRYKnQM9/'),
        ('test12345', '$P$9IQRaTwmfeRo7ud9Fh4E2PdI0S3r.L0'), #from the source
        )

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

    known_correct_hashes = (
        ('',''),
        ('password', 'password'),
    )

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
    ##    self.assertEquals(self.handler.encrypt(('mypass', 'postgres')),
    ##        'md55fba2ea04fd36069d2574ea71c8efe9d')
    ##    self.assertEquals(self.handler.verify(('mypass', 'postgres'),
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
from passlib.handlers.sha1_crypt import sha1_crypt

class SHA1CryptTest(HandlerCase):
    handler = sha1_crypt

    known_correct_hashes = (
        ("password", "$sha1$19703$iVdJqfSE$v4qYKl1zqYThwpjJAoKX6UvlHq/a"),
        ("password", "$sha1$21773$uV7PTeux$I9oHnvwPZHMO0Nq6/WgyGV/tDJIH"),
    )

    known_malformed_hashes = [
        #bad char in otherwise correct hash
        '$sha1$21773$u!7PTeux$I9oHnvwPZHMO0Nq6/WgyGV/tDJIH',

        #zero padded rounds
        '$sha1$01773$uV7PTeux$I9oHnvwPZHMO0Nq6/WgyGV/tDJIH',
    ]

#=========================================================
#sha256-crypt
#=========================================================
from passlib.handlers.sha2_crypt import sha256_crypt, raw_sha_crypt

class SHA256CryptTest(HandlerCase):
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
             raw_sha_crypt('secret', 'salt'*10, 1, hashlib.md5),
             ('\x1f\x96\x1cO\x11\xa9h\x12\xc4\xf3\x9c\xee\xf5\x93\xf3\xdd',
            'saltsaltsaltsalt',
            1000)
            )
        self.assertRaises(ValueError, raw_sha_crypt, 'secret', '$', 1, hashlib.md5)

BuiltinSHA256CryptTest = create_backend_case(SHA256CryptTest, "builtin")

#=========================================================
#test sha512-crypt
#=========================================================
from passlib.handlers.sha2_crypt import sha512_crypt

class SHA512CryptTest(HandlerCase):
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

BuiltinSHA512CryptTest = create_backend_case(SHA512CryptTest, "builtin")

#=========================================================
#sun md5 crypt
#=========================================================
from passlib.handlers.sun_md5_crypt import sun_md5_crypt, raw_sun_md5_crypt

class SunMD5CryptTest(HandlerCase):
    handler = sun_md5_crypt

    known_correct_hashes = [
        #sample hash found at http://compgroups.net/comp.unix.solaris/password-file-in-linux-and-solaris-8-9
        ("passwd", "$md5$RPgLF6IJ$WTvAlUJ7MqH5xak2FMEwS/"),
        ]

    known_malformed_hashes = [
        #bad char in otherwise correct hash
        "$md5$RPgL!6IJ$WTvAlUJ7MqH5xak2FMEwS/"
        ]

    def test_raw(self):
        #check raw func handles salt clipping right
        self.assertEqual(raw_sun_md5_crypt("s",1,"s"*10),'oV9bYatWWWc8S7qSpMKU2.')

#=========================================================
#unix fallback
#=========================================================
from passlib.handlers.misc import unix_fallback

class UnixFallbackTest(HandlerCase):
    #NOTE: this class behaves VERY differently from a normal password hash,
    #so we subclass & disable a number of the default tests.

    handler = unix_fallback

    known_correct_hashes = [ ("password",""), ]
    known_other_hashes = []
    accepts_empty_hash = True

    def test_50_encrypt_plain(self):
        "test encrypt() basic behavior"
        if self.supports_unicode:
            secret = u"unic\u00D6de"
        else:
            secret = "too many secrets"
        result = self.do_encrypt(secret)
        self.assertEquals(result, "!")
        self.assert_(not self.do_verify(secret, result))

#=========================================================
#EOF
#=========================================================
