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
from passlib.hash import ldap_md5
from passlib.registry import _unload_handler_name as unload_handler_name, \
    register_crypt_handler, get_crypt_handler
from passlib.utils import rng, getrandstr, handlers as uh, bytes, b, \
    to_hash_str, to_unicode, MissingBackendError, jython_vm
from passlib.tests.utils import HandlerCase, TestCase, catch_warnings, \
    dummy_handler_in_registry
#module
log = getLogger(__name__)

#=========================================================
#test support classes - StaticHandler, GenericHandler, etc
#=========================================================
class SkeletonTest(TestCase):
    "test hash support classes"

    #=========================================================
    #StaticHandler
    #=========================================================
    def test_00_static_handler(self):
        "test StaticHandler helper class"

        class d1(uh.StaticHandler):
            name = "d1"
            context_kwds = ("flag",)

            @classmethod
            def genhash(cls, secret, hash, flag=False):
                if isinstance(hash, bytes):
                    hash = hash.decode("ascii")
                if hash not in (u'a',u'b'):
                    raise ValueError
                return to_hash_str(u'b' if flag else u'a')

        #check default identify method
        self.assertTrue(d1.identify(u'a'))
        self.assertTrue(d1.identify(b('a')))
        self.assertTrue(d1.identify(u'b'))
        self.assertFalse(d1.identify(u'c'))
        self.assertFalse(d1.identify(b('c')))
        self.assertFalse(d1.identify(u''))
        self.assertFalse(d1.identify(None))

        #check default genconfig method
        self.assertIs(d1.genconfig(), None)
        d1._stub_config = u'b'
        self.assertEqual(d1.genconfig(), to_hash_str('b'))

        #check default verify method
        self.assertTrue(d1.verify('s','a'))
        self.assertTrue(d1.verify('s',u'a'))
        self.assertFalse(d1.verify('s','b'))
        self.assertFalse(d1.verify('s',u'b'))
        self.assertTrue(d1.verify('s', 'b', flag=True))
        self.assertRaises(ValueError, d1.verify, 's', 'c')

        #check default encrypt method
        self.assertEqual(d1.encrypt('s'), to_hash_str('a'))
        self.assertEqual(d1.encrypt('s'), to_hash_str('a'))
        self.assertEqual(d1.encrypt('s', flag=True), to_hash_str('b'))

    #=========================================================
    #GenericHandler & mixins
    #=========================================================
    def test_10_identify(self):
        "test GenericHandler.identify()"
        class d1(uh.GenericHandler):

            @classmethod
            def from_string(cls, hash):
                if hash == 'a':
                    return cls(checksum='a')
                else:
                    raise ValueError

        #check fallback
        self.assertFalse(d1.identify(None))
        self.assertFalse(d1.identify(''))
        self.assertTrue(d1.identify('a'))
        self.assertFalse(d1.identify('b'))

        #check ident-based
        d1.ident = u'!'
        self.assertFalse(d1.identify(None))
        self.assertFalse(d1.identify(''))
        self.assertTrue(d1.identify('!a'))
        self.assertFalse(d1.identify('a'))

    def test_11_norm_checksum(self):
        "test GenericHandler.norm_checksum()"
        class d1(uh.GenericHandler):
            name = 'd1'
            checksum_size = 4
            checksum_chars = 'x'
        self.assertRaises(ValueError, d1.norm_checksum, 'xxx')
        self.assertEqual(d1.norm_checksum('xxxx'), 'xxxx')
        self.assertRaises(ValueError, d1.norm_checksum, 'xxxxx')
        self.assertRaises(ValueError, d1.norm_checksum, 'xxyx')

    def test_20_norm_salt(self):
        "test GenericHandler+HasSalt: .norm_salt(), .generate_salt()"
        class d1(uh.HasSalt, uh.GenericHandler):
            name = 'd1'
            setting_kwds = ('salt',)
            min_salt_size = 1
            max_salt_size = 3
            default_salt_size = 2
            salt_chars = 'a'

        #check salt=None
        self.assertEqual(d1.norm_salt(None), 'aa')
        self.assertRaises(ValueError, d1.norm_salt, None, strict=True)

        #check small & large salts
        with catch_warnings():
            warnings.filterwarnings("ignore", ".* salt string must be at (least|most) .*", UserWarning)
            self.assertEqual(d1.norm_salt('aaaa'), 'aaa')
        self.assertRaises(ValueError, d1.norm_salt, '')
        self.assertRaises(ValueError, d1.norm_salt, 'aaaa', strict=True)

        #check generate salt (indirectly)
        self.assertEqual(len(d1.norm_salt(None)), 2)
        self.assertEqual(len(d1.norm_salt(None,salt_size=1)), 1)
        self.assertEqual(len(d1.norm_salt(None,salt_size=3)), 3)
        self.assertEqual(len(d1.norm_salt(None,salt_size=5)), 3)
        self.assertRaises(ValueError, d1.norm_salt, None, salt_size=5, strict=True)

    def test_21_norm_salt(self):
        "test GenericHandler+HasSalt: .norm_salt(), .generate_salt() - with no max_salt_size"
        class d1(uh.HasSalt, uh.GenericHandler):
            name = 'd1'
            setting_kwds = ('salt',)
            min_salt_size = 1
            max_salt_size = None
            default_salt_size = 2
            salt_chars = 'a'

        #check salt=None
        self.assertEqual(d1.norm_salt(None), 'aa')
        self.assertRaises(ValueError, d1.norm_salt, None, strict=True)

        #check small & large salts
        self.assertRaises(ValueError, d1.norm_salt, '')
        self.assertEqual(d1.norm_salt('aaaa', strict=True), 'aaaa')

        #check generate salt (indirectly)
        self.assertEqual(len(d1.norm_salt(None)), 2)
        self.assertEqual(len(d1.norm_salt(None,salt_size=1)), 1)
        self.assertEqual(len(d1.norm_salt(None,salt_size=3)), 3)
        self.assertEqual(len(d1.norm_salt(None,salt_size=5)), 5)

    def test_30_norm_rounds(self):
        "test GenericHandler+HasRounds: .norm_rounds()"
        class d1(uh.HasRounds, uh.GenericHandler):
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

    def test_40_backends(self):
        "test GenericHandler+HasManyBackends"
        class d1(uh.HasManyBackends, uh.GenericHandler):
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
        self.assertRaises(MissingBackendError, d1.get_backend)
        self.assertRaises(MissingBackendError, d1.set_backend)
        self.assertRaises(MissingBackendError, d1.set_backend, 'any')
        self.assertRaises(MissingBackendError, d1.set_backend, 'default')
        self.assertFalse(d1.has_backend())

        #enable 'b' backend
        d1._has_backend_b = True

        #test lazy load
        obj = d1()
        self.assertEqual(obj.calc_checksum('s'), 'b')

        #test repeat load
        d1.set_backend('b')
        d1.set_backend('any')
        self.assertEqual(obj.calc_checksum('s'), 'b')

        #test unavailable
        self.assertRaises(MissingBackendError, d1.set_backend, 'a')
        self.assertTrue(d1.has_backend('b'))
        self.assertFalse(d1.has_backend('a'))

        #enable 'a' backend also
        d1._has_backend_a = True

        #test explicit
        self.assertTrue(d1.has_backend())
        d1.set_backend('a')
        self.assertEqual(obj.calc_checksum('s'), 'a')
        
        #test unknown backend
        self.assertRaises(ValueError, d1.set_backend, 'c')
        self.assertRaises(ValueError, d1.has_backend, 'c')

    def test_50_bh_norm_ident(self):
        "test GenericHandler+HasManyIdents: .norm_ident() & .identify()"
        class d1(uh.HasManyIdents, uh.GenericHandler):
            name = 'd1'
            setting_kwds = ('ident',)
            ident_values = [ u"!A", u"!B" ]
            ident_aliases = { u"A": u"!A"}

        #check ident=None w/ no default
        self.assertIs(d1.norm_ident(None), None)
        self.assertRaises(ValueError, d1.norm_ident, None, strict=True)

        #check ident=None w/ default
        d1.default_ident = u"!A"
        self.assertEqual(d1.norm_ident(None), u'!A')
        self.assertRaises(ValueError, d1.norm_ident, None, strict=True)

        #check explicit
        self.assertEqual(d1.norm_ident(u'!A'), u'!A')
        self.assertEqual(d1.norm_ident(u'!B'), u'!B')
        self.assertRaises(ValueError, d1.norm_ident, u'!C')

        #check aliases
        self.assertEqual(d1.norm_ident(u'A'), u'!A')
        self.assertRaises(ValueError, d1.norm_ident, u'B')

        #check identify
        self.assertTrue(d1.identify(u"!Axxx"))
        self.assertTrue(d1.identify(u"!Bxxx"))
        self.assertFalse(d1.identify(u"!Cxxx"))
        self.assertFalse(d1.identify(u"A"))
        self.assertFalse(d1.identify(u""))
        self.assertFalse(d1.identify(None))

    #=========================================================
    #eoc
    #=========================================================

#=========================================================
#PrefixWrapper
#=========================================================
class PrefixWrapperTest(TestCase):
    "test PrefixWrapper class"

    def test_00_lazy_loading(self):
        "test PrefixWrapper lazy loading of handler"
        d1 = uh.PrefixWrapper("d1", "ldap_md5", "{XXX}", "{MD5}", lazy=True)

        #check base state
        self.assertEqual(d1._wrapped_name, "ldap_md5")
        self.assertIs(d1._wrapped_handler, None)

        #check loading works
        self.assertIs(d1.wrapped, ldap_md5)
        self.assertIs(d1._wrapped_handler, ldap_md5)

        #replace w/ wrong handler, make sure doesn't reload w/ dummy
        with dummy_handler_in_registry("ldap_md5") as dummy:
            self.assertIs(d1.wrapped, ldap_md5)

    def test_01_active_loading(self):
        "test PrefixWrapper active loading of handler"
        d1 = uh.PrefixWrapper("d1", "ldap_md5", "{XXX}", "{MD5}")

        #check base state
        self.assertEqual(d1._wrapped_name, "ldap_md5")
        self.assertIs(d1._wrapped_handler, ldap_md5)
        self.assertIs(d1.wrapped, ldap_md5)

        #replace w/ wrong handler, make sure doesn't reload w/ dummy
        with dummy_handler_in_registry("ldap_md5") as dummy:
            self.assertIs(d1.wrapped, ldap_md5)

    def test_02_explicit(self):
        "test PrefixWrapper with explicitly specified handler"

        d1 = uh.PrefixWrapper("d1", ldap_md5, "{XXX}", "{MD5}")

        #check base state
        self.assertEqual(d1._wrapped_name, None)
        self.assertIs(d1._wrapped_handler, ldap_md5)
        self.assertIs(d1.wrapped, ldap_md5)

        #replace w/ wrong handler, make sure doesn't reload w/ dummy
        with dummy_handler_in_registry("ldap_md5") as dummy:
            self.assertIs(d1.wrapped, ldap_md5)

    def test_10_wrapped_attributes(self):
        d1 = uh.PrefixWrapper("d1", "ldap_md5", "{XXX}", "{MD5}")
        self.assertEqual(d1.name, "d1")
        self.assertIs(d1.setting_kwds, ldap_md5.setting_kwds)

    def test_11_wrapped_methods(self):
        d1 = uh.PrefixWrapper("d1", "ldap_md5", "{XXX}", "{MD5}")
        dph = "{XXX}X03MO1qnZdYdgyfeuILPmQ=="
        lph = "{MD5}X03MO1qnZdYdgyfeuILPmQ=="

        #genconfig
        self.assertIs(d1.genconfig(), None)

        #genhash
        self.assertEqual(d1.genhash("password", None), dph)
        self.assertEqual(d1.genhash("password", dph), dph)
        self.assertRaises(ValueError, d1.genhash, "password", lph)

        #encrypt
        self.assertEqual(d1.encrypt("password"), dph)

        #identify
        self.assertTrue(d1.identify(dph))
        self.assertFalse(d1.identify(lph))

        #verify
        self.assertRaises(ValueError, d1.verify, "password", lph)
        self.assertTrue(d1.verify("password", dph))

#=========================================================
#sample algorithms - these serve as known quantities
# to test the unittests themselves, as well as other
# parts of passlib. they shouldn't be used as actual password schemes.
#=========================================================
class UnsaltedHash(uh.StaticHandler):
    "test algorithm which lacks a salt"
    name = "unsalted_test_hash"
    _stub_config = "0" * 40

    @classmethod
    def identify(cls, hash):
        return uh.identify_regexp(hash, re.compile(u"^[0-9a-f]{40}$"))

    @classmethod
    def genhash(cls, secret, hash):
        if not cls.identify(hash):
            raise ValueError("not a unsalted-example hash")
        if isinstance(secret, unicode):
            secret = secret.encode("utf-8")
        data = b("boblious") + secret
        return to_hash_str(hashlib.sha1(data).hexdigest())

class SaltedHash(uh.HasSalt, uh.GenericHandler):
    "test algorithm with a salt"
    name = "salted_test_hash"
    setting_kwds = ("salt",)

    min_salt_size = 2
    max_salt_size = 4
    checksum_size = 40
    salt_chars = checksum_chars = uh.LC_HEX_CHARS

    @classmethod
    def identify(cls, hash):
        return uh.identify_regexp(hash, re.compile(u"^@salt[0-9a-f]{42,44}$"))

    @classmethod
    def from_string(cls, hash):
        if not cls.identify(hash):
            raise ValueError("not a salted-example hash")
        if isinstance(hash, bytes):
            hash = hash.decode("ascii")
        return cls(salt=hash[5:-40], checksum=hash[-40:], strict=True)

    _stub_checksum = '0' * 40

    def to_string(self):
        hash = u"@salt%s%s" % (self.salt, self.checksum or self._stub_checksum)
        return to_hash_str(hash)

    def calc_checksum(self, secret):
        if isinstance(secret, unicode):
            secret = secret.encode("utf-8")
        data = self.salt.encode("ascii") + secret + self.salt.encode("ascii")
        return to_unicode(hashlib.sha1(data).hexdigest(), "latin-1")

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
        if not jython_vm:
            #FIXME: annoyingly, the object() constructor of Jython (as of 2.5.2)
            #       silently drops any extra kwds (old 2.4 behavior)
            #       instead of raising TypeError (new 2.5 behavior).
            #       we *could* use a custom base object to restore correct
            #       behavior, but that's a lot of effort for a non-critical
            #       border case. so just skipping this test instead...
            self.assertRaises(TypeError, UnsaltedHash, salt='x')
        self.assertRaises(ValueError, SaltedHash, checksum=SaltedHash._stub_checksum, salt=None, strict=True)
        self.assertRaises(ValueError, SaltedHash, checksum=SaltedHash._stub_checksum, salt='xxx', strict=True)

        self.assertRaises(TypeError, UnsaltedHash.genconfig, rounds=1)

class SaltedHashTest(HandlerCase):
    handler = SaltedHash

    known_correct_hashes = [
        ("password", '@salt77d71f8fe74f314dac946766c1ac4a2a58365482c0'),
        (u'\u0399\u03c9\u03b1\u03bd\u03bd\u03b7\u03c2',
                     '@salt9f978a9bfe360d069b0c13f2afecd570447407fa7e48'),
    ]

#=========================================================
#EOF
#=========================================================
