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
from passlib.hash import ldap_md5, sha256_crypt
from passlib.registry import _unload_handler_name as unload_handler_name, \
    register_crypt_handler, get_crypt_handler
from passlib.exc import MissingBackendError, PasslibHashWarning
from passlib.utils import getrandstr, JYTHON, rng
from passlib.utils.compat import b, bytes, bascii_to_str, str_to_uascii, \
                                 uascii_to_str, unicode, PY_MAX_25
import passlib.utils.handlers as uh
from passlib.tests.utils import HandlerCase, TestCase, catch_warnings
from passlib.utils.compat import u
#module
log = getLogger(__name__)

#=========================================================
# utils
#=========================================================
def _makelang(alphabet, size):
    "generate all strings of given size using alphabet"
    def helper(size):
        if size < 2:
            for char in alphabet:
                yield char
        else:
            for char in alphabet:
                for tail in helper(size-1):
                    yield char+tail
    return set(helper(size))

#=========================================================
#test GenericHandler & associates mixin classes
#=========================================================
class SkeletonTest(TestCase):
    "test hash support classes"

    #=========================================================
    # StaticHandler
    #=========================================================
    def test_00_static_handler(self):
        "test StaticHandler class"

        class d1(uh.StaticHandler):
            name = "d1"
            context_kwds = ("flag",)
            _hash_prefix = u("_")
            checksum_chars = u("ab")
            checksum_size = 1

            def __init__(self, flag=False, **kwds):
                super(d1, self).__init__(**kwds)
                self.flag = flag

            def _calc_checksum(self, secret):
                return u('b') if self.flag else u('a')

        # check default identify method
        self.assertTrue(d1.identify(u('_a')))
        self.assertTrue(d1.identify(b('_a')))
        self.assertTrue(d1.identify(u('_b')))

        self.assertFalse(d1.identify(u('_c')))
        self.assertFalse(d1.identify(b('_c')))
        self.assertFalse(d1.identify(u('a')))
        self.assertFalse(d1.identify(u('b')))
        self.assertFalse(d1.identify(u('c')))
        self.assertRaises(TypeError, d1.identify, None)
        self.assertRaises(TypeError, d1.identify, 1)

        # check default genconfig method
        self.assertIs(d1.genconfig(), None)

        # check default verify method
        self.assertTrue(d1.verify('s', b('_a')))
        self.assertTrue(d1.verify('s',u('_a')))
        self.assertFalse(d1.verify('s', b('_b')))
        self.assertFalse(d1.verify('s',u('_b')))
        self.assertTrue(d1.verify('s', b('_b'), flag=True))
        self.assertRaises(ValueError, d1.verify, 's', b('_c'))
        self.assertRaises(ValueError, d1.verify, 's', u('_c'))

        # check default encrypt method
        self.assertEqual(d1.encrypt('s'), '_a')
        self.assertEqual(d1.encrypt('s', flag=True), '_b')

    #=========================================================
    #GenericHandler & mixins
    #=========================================================
    def test_10_identify(self):
        "test GenericHandler.identify()"
        class d1(uh.GenericHandler):

            @classmethod
            def from_string(cls, hash):
                if isinstance(hash, bytes):
                    hash = hash.decode("ascii")
                if hash == u('a'):
                    return cls(checksum=hash)
                else:
                    raise ValueError

        # check fallback
        self.assertRaises(TypeError, d1.identify, None)
        self.assertRaises(TypeError, d1.identify, 1)
        self.assertFalse(d1.identify(''))
        self.assertTrue(d1.identify('a'))
        self.assertFalse(d1.identify('b'))

        # check regexp
        d1._hash_regex = re.compile(u('@.'))
        self.assertRaises(TypeError, d1.identify, None)
        self.assertRaises(TypeError, d1.identify, 1)
        self.assertTrue(d1.identify('@a'))
        self.assertFalse(d1.identify('a'))
        del d1._hash_regex

        # check ident-based
        d1.ident = u('!')
        self.assertRaises(TypeError, d1.identify, None)
        self.assertRaises(TypeError, d1.identify, 1)
        self.assertTrue(d1.identify('!a'))
        self.assertFalse(d1.identify('a'))
        del d1.ident

    def test_11_norm_checksum(self):
        "test GenericHandler checksum handling"
        # setup helpers
        class d1(uh.GenericHandler):
            name = 'd1'
            checksum_size = 4
            checksum_chars = u('xz')
            _stub_checksum = u('z')*4

        def norm_checksum(*a, **k):
            return d1(*a, **k).checksum

        # too small
        self.assertRaises(ValueError, norm_checksum, u('xxx'))

        # right size
        self.assertEqual(norm_checksum(u('xxxx')), u('xxxx'))
        self.assertEqual(norm_checksum(u('xzxz')), u('xzxz'))

        # too large
        self.assertRaises(ValueError, norm_checksum, u('xxxxx'))

        # wrong chars
        self.assertRaises(ValueError, norm_checksum, u('xxyx'))

        # wrong type
        self.assertRaises(TypeError, norm_checksum, b('xxyx'))

        # test _stub_checksum behavior
        self.assertIs(norm_checksum(u('zzzz')), None)

    # TODO: test HasRawChecksum mixin

    def test_20_norm_salt(self):
        "test GenericHandler + HasSalt mixin"
        # setup helpers
        class d1(uh.HasSalt, uh.GenericHandler):
            name = 'd1'
            setting_kwds = ('salt',)
            min_salt_size = 2
            max_salt_size = 4
            default_salt_size = 3
            salt_chars = 'ab'

        def norm_salt(**k):
            return d1(**k).salt

        def gen_salt(sz, **k):
            return d1(use_defaults=True, salt_size=sz, **k).salt

        salts2 = _makelang('ab', 2)
        salts3 = _makelang('ab', 3)
        salts4 = _makelang('ab', 4)

        # check salt=None
        self.assertRaises(TypeError, norm_salt)
        self.assertRaises(TypeError, norm_salt, salt=None)
        self.assertIn(norm_salt(use_defaults=True), salts3)

        # check explicit salts
        with catch_warnings(record=True) as wlog:

            # check too-small salts
            self.assertRaises(ValueError, norm_salt, salt='')
            self.assertRaises(ValueError, norm_salt, salt='a')
            self.consumeWarningList(wlog)

            # check correct salts
            self.assertEqual(norm_salt(salt='ab'), 'ab')
            self.assertEqual(norm_salt(salt='aba'), 'aba')
            self.assertEqual(norm_salt(salt='abba'), 'abba')
            self.consumeWarningList(wlog)

            # check too-large salts
            self.assertRaises(ValueError, norm_salt, salt='aaaabb')
            self.consumeWarningList(wlog)

            self.assertEqual(norm_salt(salt='aaaabb', relaxed=True), 'aaaa')
            self.consumeWarningList(wlog, PasslibHashWarning)

        #check generated salts
        with catch_warnings(record=True) as wlog:

            # check too-small salt size
            self.assertRaises(ValueError, gen_salt, 0)
            self.assertRaises(ValueError, gen_salt, 1)
            self.consumeWarningList(wlog)

            # check correct salt size
            self.assertIn(gen_salt(2), salts2)
            self.assertIn(gen_salt(3), salts3)
            self.assertIn(gen_salt(4), salts4)
            self.consumeWarningList(wlog)

            # check too-large salt size
            self.assertRaises(ValueError, gen_salt, 5)
            self.consumeWarningList(wlog)

            self.assertIn(gen_salt(5, relaxed=True), salts4)
            self.consumeWarningList(wlog, ["salt too large"])

        # test with max_salt_size=None
        del d1.max_salt_size
        with catch_warnings(record=True) as wlog:
            self.assertEqual(len(gen_salt(None)), 3)
            self.assertEqual(len(gen_salt(5)), 5)
            self.consumeWarningList(wlog)

    # TODO: test HasRawSalt mixin

    def test_30_norm_rounds(self):
        "test GenericHandler + HasRounds mixin"
        # setup helpers
        class d1(uh.HasRounds, uh.GenericHandler):
            name = 'd1'
            setting_kwds = ('rounds',)
            min_rounds = 1
            max_rounds = 3
            default_rounds = 2

        def norm_rounds(**k):
            return d1(**k).rounds

        # check rounds=None
        self.assertRaises(TypeError, norm_rounds)
        self.assertRaises(TypeError, norm_rounds, rounds=None)
        self.assertEqual(norm_rounds(use_defaults=True), 2)

        # check explicit rounds
        with catch_warnings(record=True) as wlog:
            # too small
            self.assertRaises(ValueError, norm_rounds, rounds=0)
            self.consumeWarningList(wlog)

            self.assertEqual(norm_rounds(rounds=0, relaxed=True), 1)
            self.consumeWarningList(wlog, PasslibHashWarning)

            # just right
            self.assertEqual(norm_rounds(rounds=1), 1)
            self.assertEqual(norm_rounds(rounds=2), 2)
            self.assertEqual(norm_rounds(rounds=3), 3)
            self.consumeWarningList(wlog)

            # too large
            self.assertRaises(ValueError, norm_rounds, rounds=4)
            self.consumeWarningList(wlog)

            self.assertEqual(norm_rounds(rounds=4, relaxed=True), 3)
            self.consumeWarningList(wlog, PasslibHashWarning)

        # check no default rounds
        d1.default_rounds = None
        self.assertRaises(TypeError, norm_rounds, use_defaults=True)

    def test_40_backends(self):
        "test GenericHandler + HasManyBackends mixin"
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
        self.assertEqual(obj._calc_checksum('s'), 'b')

        #test repeat load
        d1.set_backend('b')
        d1.set_backend('any')
        self.assertEqual(obj._calc_checksum('s'), 'b')

        #test unavailable
        self.assertRaises(MissingBackendError, d1.set_backend, 'a')
        self.assertTrue(d1.has_backend('b'))
        self.assertFalse(d1.has_backend('a'))

        #enable 'a' backend also
        d1._has_backend_a = True

        #test explicit
        self.assertTrue(d1.has_backend())
        d1.set_backend('a')
        self.assertEqual(obj._calc_checksum('s'), 'a')

        #test unknown backend
        self.assertRaises(ValueError, d1.set_backend, 'c')
        self.assertRaises(ValueError, d1.has_backend, 'c')

    def test_50_norm_ident(self):
        "test GenericHandler + HasManyIdents"
        # setup helpers
        class d1(uh.HasManyIdents, uh.GenericHandler):
            name = 'd1'
            setting_kwds = ('ident',)
            default_ident = u("!A")
            ident_values = [ u("!A"), u("!B") ]
            ident_aliases = { u("A"): u("!A")}

        def norm_ident(**k):
            return d1(**k).ident

        # check ident=None
        self.assertRaises(TypeError, norm_ident)
        self.assertRaises(TypeError, norm_ident, ident=None)
        self.assertEqual(norm_ident(use_defaults=True), u('!A'))

        # check valid idents
        self.assertEqual(norm_ident(ident=u('!A')), u('!A'))
        self.assertEqual(norm_ident(ident=u('!B')), u('!B'))
        self.assertRaises(ValueError, norm_ident, ident=u('!C'))

        # check aliases
        self.assertEqual(norm_ident(ident=u('A')), u('!A'))

        # check invalid idents
        self.assertRaises(ValueError, norm_ident, ident=u('B'))

        # check identify is honoring ident system
        self.assertTrue(d1.identify(u("!Axxx")))
        self.assertTrue(d1.identify(u("!Bxxx")))
        self.assertFalse(d1.identify(u("!Cxxx")))
        self.assertFalse(d1.identify(u("A")))
        self.assertFalse(d1.identify(u("")))
        self.assertRaises(TypeError, d1.identify, None)
        self.assertRaises(TypeError, d1.identify, 1)

        # check default_ident missing is detected.
        d1.default_ident = None
        self.assertRaises(AssertionError, norm_ident, use_defaults=True)

    #=========================================================
    #eoc
    #=========================================================

#=========================================================
#PrefixWrapper
#=========================================================
class dummy_handler_in_registry(object):
    "context manager that inserts dummy handler in registry"
    def __init__(self, name):
        self.name = name
        self.dummy = type('dummy_' + name, (uh.GenericHandler,), dict(
            name=name,
            setting_kwds=(),
        ))

    def __enter__(self):
        from passlib import registry
        registry._unload_handler_name(self.name, locations=False)
        registry.register_crypt_handler(self.dummy)
        assert registry.get_crypt_handler(self.name) is self.dummy
        return self.dummy

    def __exit__(self, *exc_info):
        from passlib import registry
        registry._unload_handler_name(self.name, locations=False)

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
        self.assertFalse('max_rounds' in dir(d1))

        d2 = uh.PrefixWrapper("d2", "sha256_crypt", "{XXX}")
        self.assertIs(d2.setting_kwds, sha256_crypt.setting_kwds)
        if PY_MAX_25: # __dir__() support not added until py 2.6
            self.assertFalse('max_rounds' in dir(d2))
        else:
            self.assertTrue('max_rounds' in dir(d2))

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

    def test_12_ident(self):
        # test ident is proxied
        h = uh.PrefixWrapper("h2", "ldap_md5", "{XXX}")
        self.assertEqual(h.ident, u("{XXX}{MD5}"))
        self.assertIs(h.ident_values, None)

        # test orig_prefix disabled ident proxy
        h = uh.PrefixWrapper("h1", "ldap_md5", "{XXX}", "{MD5}")
        self.assertIs(h.ident, None)
        self.assertIs(h.ident_values, None)

        # test custom ident overrides default
        h = uh.PrefixWrapper("h3", "ldap_md5", "{XXX}", ident="{X")
        self.assertEqual(h.ident, u("{X"))
        self.assertIs(h.ident_values, None)

        # test custom ident must match
        h = uh.PrefixWrapper("h3", "ldap_md5", "{XXX}", ident="{XXX}A")
        self.assertRaises(ValueError, uh.PrefixWrapper, "h3", "ldap_md5",
                          "{XXX}", ident="{XY")
        self.assertRaises(ValueError, uh.PrefixWrapper, "h3", "ldap_md5",
                          "{XXX}", ident="{XXXX")

        # test ident_values is proxied
        h = uh.PrefixWrapper("h4", "phpass", "{XXX}")
        self.assertIs(h.ident, None)
        self.assertEqual(h.ident_values, [ u("{XXX}$P$"), u("{XXX}$H$") ])

#=========================================================
#sample algorithms - these serve as known quantities
# to test the unittests themselves, as well as other
# parts of passlib. they shouldn't be used as actual password schemes.
#=========================================================
class UnsaltedHash(uh.StaticHandler):
    "test algorithm which lacks a salt"
    name = "unsalted_test_hash"
    checksum_chars = uh.LOWER_HEX_CHARS
    checksum_size = 40

    def _calc_checksum(self, secret):
        if isinstance(secret, unicode):
            secret = secret.encode("utf-8")
        data = b("boblious") + secret
        return str_to_uascii(hashlib.sha1(data).hexdigest())

class SaltedHash(uh.HasSalt, uh.GenericHandler):
    "test algorithm with a salt"
    name = "salted_test_hash"
    setting_kwds = ("salt",)

    min_salt_size = 2
    max_salt_size = 4
    checksum_size = 40
    salt_chars = checksum_chars = uh.LOWER_HEX_CHARS

    _hash_regex = re.compile(u("^@salt[0-9a-f]{42,44}$"))

    @classmethod
    def from_string(cls, hash):
        if not cls.identify(hash):
            raise uh.exc.InvalidHashError(cls)
        if isinstance(hash, bytes):
            hash = hash.decode("ascii")
        return cls(salt=hash[5:-40], checksum=hash[-40:])

    _stub_checksum = u('0') * 40

    def to_string(self):
        hash = u("@salt%s%s") % (self.salt, self.checksum or self._stub_checksum)
        return uascii_to_str(hash)

    def _calc_checksum(self, secret):
        if isinstance(secret, unicode):
            secret = secret.encode("utf-8")
        data = self.salt.encode("ascii") + secret + self.salt.encode("ascii")
        return str_to_uascii(hashlib.sha1(data).hexdigest())

#=========================================================
#test sample algorithms - really a self-test of HandlerCase
#=========================================================

#TODO: provide data samples for algorithms
# (positive knowns, negative knowns, invalid identify)

UPASS_TEMP = u('\u0399\u03c9\u03b1\u03bd\u03bd\u03b7\u03c2')

class UnsaltedHashTest(HandlerCase):
    handler = UnsaltedHash

    known_correct_hashes = [
        ("password", "61cfd32684c47de231f1f982c214e884133762c0"),
        (UPASS_TEMP, '96b329d120b97ff81ada770042e44ba87343ad2b'),
    ]

    def test_bad_kwds(self):
        if not PY_MAX_25:
            # annoyingly, py25's ``super().__init__()`` doesn't throw TypeError
            # when passing unknown keywords to object. just ignoring
            # this issue for now, since it's a minor border case.
            self.assertRaises(TypeError, UnsaltedHash, salt='x')
        self.assertRaises(TypeError, UnsaltedHash.genconfig, rounds=1)

class SaltedHashTest(HandlerCase):
    handler = SaltedHash

    known_correct_hashes = [
        ("password", '@salt77d71f8fe74f314dac946766c1ac4a2a58365482c0'),
        (UPASS_TEMP, '@salt9f978a9bfe360d069b0c13f2afecd570447407fa7e48'),
    ]

    def test_bad_kwds(self):
        self.assertRaises(TypeError, SaltedHash,
                          checksum=SaltedHash._stub_checksum, salt=None)
        self.assertRaises(ValueError, SaltedHash,
                          checksum=SaltedHash._stub_checksum, salt='xxx')

#=========================================================
#EOF
#=========================================================
