"""tests for passlib.pwhash -- (c) Assurance Technologies 2003-2009"""
#=========================================================
#imports
#=========================================================
from __future__ import with_statement
#core
import re
import hashlib
from logging import getLogger
import warnings
#site
#pkg
from passlib.utils import rng, getrandstr
from passlib.utils.handlers import MultiBackendHandler, ExtendedHandler, SimpleHandler
from passlib.tests.utils import HandlerCase, TestCase, catch_warnings
#module
log = getLogger(__name__)

#=========================================================
#test support classes - SimpleHandler, etc
#=========================================================
class SkeletonTest(TestCase):
    "test hash support classes"

    #=========================================================
    #base hash
    #=========================================================
    def test_00_base_hash(self):

        class d1(SimpleHandler):
            name = "d1"
            setting_kwds = ('dummy',)

            @classmethod
            def genhash(cls, secret, hash):
                if hash != 'a':
                    raise ValueError
                return 'a'

        #check internal properties
        self.assertRaises(RuntimeError, getattr, SimpleHandler, "_has_settings")

        #check identify method
        self.assertTrue(d1.identify('a'))
        self.assertFalse(d1.identify('b'))
        self.assertFalse(d1.identify(''))
        self.assertFalse(d1.identify(None))

        #check default genconfig
        self.assertRaises(NotImplementedError, d1.genconfig, dummy='xxx')

        class d3(SimpleHandler):
            name = 'd3'
            setting_kwds = ()
        self.assertRaises(TypeError, d3.genconfig, dummy='xxx')

        #check default genhash
        class d2(SimpleHandler):
            name = "d2"
            setting_kwds = ("dummy",)
        self.assertRaises(NotImplementedError, d2.genhash, 'stub', 'hash')

    #=========================================================
    #ext hash
    #=========================================================
    def test_10_ext_hash(self):
        class d1(ExtendedHandler):
            setting_kwds = ()
            max_salt_chars = 2

            @classmethod
            def from_string(cls, hash):
                if hash == 'a':
                    return cls('a')
                else:
                    raise ValueError

        #check internal properties
        self.assertRaises(RuntimeError, getattr, ExtendedHandler, "_has_settings")
        self.assertRaises(RuntimeError, getattr, ExtendedHandler, "_has_salt")
        self.assertRaises(RuntimeError, getattr, ExtendedHandler, "_has_rounds")

        #check min salt chars
        self.assertEqual(d1.min_salt_chars, 2)

        #check identify
        self.assertFalse(d1.identify(None))
        self.assertFalse(d1.identify(''))
        self.assertTrue(d1.identify('a'))
        self.assertFalse(d1.identify('b'))

    def test_11_norm_checksum(self):
        class d1(ExtendedHandler):
            checksum_chars = 4
            checksum_charset = 'x'
        self.assertRaises(ValueError, d1.norm_checksum, 'xxx')
        self.assertEqual(d1.norm_checksum('xxxx'), 'xxxx')
        self.assertRaises(ValueError, d1.norm_checksum, 'xxxxx')
        self.assertRaises(ValueError, d1.norm_checksum, 'xxyx')

    def test_12_norm_salt(self):
        class d1(ExtendedHandler):
            name = 'd1'
            setting_kwds = ('salt',)
            min_salt_chars = 1
            max_salt_chars = 3
            default_salt_chars = 2
            salt_charset = 'a'

        #check salt=None
        self.assertEqual(d1.norm_salt(None), 'aa')
        self.assertRaises(ValueError, d1.norm_salt, None, strict=True)

        #check small & large salts
        with catch_warnings():
            warnings.filterwarnings("ignore", ".* salt string must be at (least|most) .*", UserWarning)
            self.assertEqual(d1.norm_salt('aaaa'), 'aaa')
        self.assertRaises(ValueError, d1.norm_salt, '')
        self.assertRaises(ValueError, d1.norm_salt, 'aaaa', strict=True)

        #check no salt kwd
        class d2(ExtendedHandler):
            name = "d2"
            setting_kwds = ("dummy",)
        self.assertRaises(TypeError, d2.norm_salt, 1)
        self.assertIs(d2.norm_salt(None), None)

    def test_13_norm_rounds(self):
        class d1(ExtendedHandler):
            name = 'd1'
            setting_kwds = ('rounds',)
            min_rounds = 1
            max_rounds = 3
            default_rounds = 2

        #check rounds=None
        self.assertEqual(d1.norm_rounds(None), 2)
        self.assertRaises(ValueError, d1.norm_rounds, None, strict=True)

        #check small & large rounds
        with catch_warnings():
            warnings.filterwarnings("ignore", ".* does not allow (less|more) than \d rounds: .*", UserWarning)
            self.assertEqual(d1.norm_rounds(0), 1)
            self.assertEqual(d1.norm_rounds(4), 3)
        self.assertRaises(ValueError, d1.norm_rounds, 0, strict=True)
        self.assertRaises(ValueError, d1.norm_rounds, 4, strict=True)

        #check no default rounds
        d1.default_rounds = None
        self.assertRaises(ValueError, d1.norm_rounds, None)

        #check no rounds keyword
        class d2(ExtendedHandler):
            name = "d2"
            setting_kwds = ("dummy",)
        self.assertRaises(TypeError, d2.norm_rounds, 1)
        self.assertIs(d2.norm_rounds(None), None)

    #=========================================================
    #backend ext hash
    #=========================================================
    def test_20_backend_ext_hash(self):
        class d1(MultiBackendHandler):
            name = 'd1'
            setting_kwds = ()

            backends = ("a", "b")

            _has_backend_a = False
            _has_backend_b = False

            def _calc_checksum_a(self, secret):
                return 'a'

            def _calc_checksum_b(self, secret):
                return 'b'

        #test no backends
        self.assertRaises(EnvironmentError, d1.set_backend, 'default')
        self.assertFalse(d1.has_backend())

        #enable 'b' backend
        d1._has_backend_b = True

        #test lazy load
        obj = d1()
        self.assertEquals(obj.calc_checksum('s'), 'b')

        #test repeat load
        d1.set_backend('b')
        d1.set_backend(None)
        self.assertEquals(obj.calc_checksum('s'), 'b')

        #test unavailable
        self.assertRaises(ValueError, d1.set_backend, 'a')

        #enable 'a' backend also
        d1._has_backend_a = True

        #test explicit
        self.assertTrue(d1.has_backend())
        d1.set_backend('a')
        self.assertEquals(obj.calc_checksum('s'), 'a')

    #=========================================================
    #eoc
    #=========================================================

#=========================================================
#sample algorithms - these serve as known quantities
# to test the unittests themselves, as well as other
# parts of passlib. they shouldn't be used as actual password schemes.
#=========================================================
class UnsaltedHash(ExtendedHandler):
    "test algorithm which lacks a salt"
    name = "unsalted_test_hash"
    setting_kwds = ()

    @classmethod
    def identify(cls, hash):
        return bool(hash and re.match("^[0-9a-f]{40}$", hash))

    @classmethod
    def from_string(cls, hash):
        if not cls.identify(hash):
            raise ValueError, "not a unsalted-example hash"
        return cls(checksum=hash, strict=True)

    def to_string(self):
        return self.checksum

    def calc_checksum(self, secret):
        if isinstance(secret, unicode):
            secret = secret.encode("utf-8")
        return hashlib.sha1("boblious" + secret).hexdigest()

class SaltedHash(ExtendedHandler):
    "test algorithm with a salt"
    name = "salted_test_hash"
    setting_kwds = ("salt",)

    min_salt_chars = max_salt_chars = 2
    checksum_chars = 40
    salt_charset = checksum_charset = "0123456789abcdef"

    @classmethod
    def identify(cls, hash):
        return bool(hash and re.match("^@salt[0-9a-f]{42}$", hash))

    @classmethod
    def from_string(cls, hash):
        if not cls.identify(hash):
            raise ValueError, "not a salted-example hash"
        return cls(salt=hash[5:7], checksum=hash[7:], strict=True)

    _stub_checksum = '0' * 40

    def to_string(self):
        return "@salt%s%s" % (self.salt, self.checksum or self._stub_checksum)

    def calc_checksum(self, secret):
        if isinstance(secret, unicode):
            secret = secret.encode("utf-8")
        return hashlib.sha1(self.salt + secret + self.salt).hexdigest()

#=========================================================
#test sample algorithms - really a self-test of HandlerCase
#=========================================================

#TODO: provide data samples for algorithms
# (positive knowns, negative knowns, invalid identify)

class UnsaltedHashTest(HandlerCase):
    handler = UnsaltedHash

    known_correct_hashes = [
        ("password", "61cfd32684c47de231f1f982c214e884133762c0"),

    ]

    def test_bad_kwds(self):
        self.assertRaises(TypeError, UnsaltedHash, salt='x')
        self.assertRaises(ValueError, SaltedHash, checksum=SaltedHash._stub_checksum, salt=None, strict=True)
        self.assertRaises(ValueError, SaltedHash, checksum=SaltedHash._stub_checksum, salt='xxx', strict=True)

        self.assertRaises(TypeError, UnsaltedHash.genconfig, rounds=1)

class SaltedHashTest(HandlerCase):
    handler = SaltedHash

    known_correct_hashes = [
        ("password", '@salt77d71f8fe74f314dac946766c1ac4a2a58365482c0'),
    ]

#=========================================================
#EOF
#=========================================================
