"""helpers for passlib unittests"""
#=========================================================
#imports
#=========================================================
#core
import atexit
import logging; log = logging.getLogger(__name__)
import re
import os
import tempfile
import unittest
import warnings
try:
    from warnings import catch_warnings
except ImportError:
    #catch_warnings wasn't added until py26
    #put stub in place
    class catch_warnings(object):
        def __enter__(self):
            return None
        def __exit__(self, *exc_info):
            return None
        __name__ = 'stub'
#site
from nose.plugins.skip import SkipTest
#pkg
from passlib.utils import classproperty
from passlib.utils.handlers import SimpleHandler, ExtendedHandler, MultiBackendHandler
#local
__all__ = [
    #util funcs
    'enable_option',
    'Params',

    #unit testing
    'TestCase',
    'HandlerCase',
    'enable_backend_case',
    'create_backend_case',
]

#=========================================================
#option flags
#=========================================================
DEFAULT_TESTS = "active-backends"

tests = set(
    v.strip()
    for v
    in os.environ.get("PASSLIB_TESTS", DEFAULT_TESTS).lower().split(",")
    )
if 'all-backends' in tests:
    tests.add("backends")

def enable_option(*names):
    """check if a given test should be included based on the env var.

    test flags:
        active-backends     test active backends
        all-backends        test ALL backends, even the inactive ones
        cover               enable minor tweaks to maximize coverage testing
        all                 run ALL tests
    """
    return 'all' in tests or any(name in tests for name in names)

#=========================================================
#misc utility funcs
#=========================================================
class Params(object):
    "helper to represent params for function call"

    @classmethod
    def norm(cls, value):
        if isinstance(value, cls):
            return value
        if isinstance(value, (list,tuple)):
            return cls(*value)
        return cls(**value)

    def __init__(self, *args, **kwds):
        self.args = args
        self.kwds = kwds

    def render(self, offset=0):
        """render parenthesized parameters"""
        txt = ''
        for a in self.args[offset:]:
            txt += "%r, " % (a,)
        kwds = self.kwds
        for k in sorted(kwds):
            txt += "%s=%r, " % (k, kwds[k])
        if txt.endswith(", "):
            txt = txt[:-2]
        return txt

#=========================================================
#custom test base
#=========================================================
class TestCase(unittest.TestCase):
    """passlib-specific test case class

    this class mainly overriddes many of the common assert methods
    so to give a default message which includes the values
    as well as the class-specific case_prefix string.
    this latter bit makes the output of various test cases
    easier to distinguish from eachother.
    """

    case_prefix = None

    def __init__(self, *a, **k):
        #set the doc strings for all test messages to begin w/ case_prefix
        #yes, this is incredibly hacked.
        prefix = self.case_prefix
        if prefix:
            if callable(prefix):
                prefix = prefix()
            for attr in dir(self):
                if not attr.startswith("test"):
                    continue
                v = getattr(self, attr)
                if not hasattr(v, "im_func"):
                    continue
                d = v.im_func.__doc__ or v.im_func.__name__
                idx = d.find(": ")
                if idx > -1:
                    d = d[idx+1:]
                v.im_func.__doc__ = d = "%s: %s" % (prefix, d.lstrip())
                assert v.__doc__ == d
        unittest.TestCase.__init__(self, *a, **k)

    def assertEquals(self, real, correct, msg=None):
        #NOTE: overriding this to get msg formatting capability
        msg = self._format_msg(msg, "got %r, expected would equal %r", real, correct)
        return self.assert_(real == correct, msg)

    def assertEqual(self, *a, **k):
        return self.assertEquals(*a, **k)

    def assertNotEquals(self, real, correct, msg=None):
        #NOTE: overriding this to get msg formatting capability
        msg = self._format_msg(msg, "got %r, expected would equal %r", real, correct)
        return self.assert_(real != correct, msg)

    def assertNotEqual(self, *a, **k):
        return self.assertNotEquals(*a, **k)

    def assertIs(self, real, correct, msg=None):
        msg = self._format_msg(msg, "got %r, expected would be %r", real, correct)
        return self.assert_(real is correct, msg)

    def assertIsNot(self, real, correct, msg=None):
        msg = self._format_msg(msg, "expected would not be %r", real)
        return self.assert_(real is not correct, msg)

    def assertIsInstance(self, obj, klass, msg=None):
        msg = self._format_msg(msg, "got %r, expected instance of %r", obj, klass)
        return self.assert_(isinstance(obj, klass), msg)

    def assertRaises(self, type, func, *args, **kwds):
        msg = kwds.pop("__msg__", None)
        err = None
        try:
            result = func(*args, **kwds)
        except Exception, err:
            pass
        if err is None:
            msg = self._format_msg(msg, "function returned %r, expected it to raise %r", result, type)
            raise AssertionError(msg)
        elif not isinstance(err, type):
            msg = self._format_msg(msg, "function raised %r, expected %r", err, type)
            raise AssertionError(msg)

    def assertFunctionResults(self, func, cases):
        """helper for running through function calls.

        func should be the function to call.
        cases should be list of Param instances,
        where first position argument is expected return value,
        and remaining args and kwds are passed to function.
        """
        for elem in cases:
            elem = Params.norm(elem)
            correct = elem.args[0]
            result = func(*elem.args[1:], **elem.kwds)
            self.assertEqual(result, correct,
                    "error for case %s: got %r, expected would equal %r" % (elem.render(1), result, correct)
                    )

    def _format_msg(self, msg, template, *args, **kwds):
        "helper for generating default message"
        if msg and not msg.endswith(":"):
            return msg
        if args:
            template %= args
        if kwds:
            template %= kwds
        if msg:
            return msg + " " + template
        return template

#=========================================================
#other unittest helpers
#=========================================================
class HandlerCase(TestCase):
    """base class for testing password hash handlers (esp passlib.utils.handlers.SimpleHandler subclasses)

    .. todo::
        write directions on how to use this class.
        for now, see examples in test_handlers
    """
    #=========================================================
    #attrs to be filled in by subclass for testing specific handler
    #=========================================================

    #specify handler object here (required)
    handler = None

    #this option is available for hashes which can't handle unicode
    supports_unicode = True

    #maximum number of chars which hash will include in checksum
    #override this only if hash doesn't use all chars (the default)
    secret_chars = -1

    #list of (secret,hash) pairs which handler should verify as matching
    known_correct_hashes = []

    #list of (config, secret, hash) triples which handler should genhash & verify
    known_correct_configs = []

    # hashes so malformed they aren't even identified properly
    known_unidentified_hashes = []

    # hashes which are malformed - they should identify() as True, but cause error when passed to genhash/verify
    known_malformed_hashes = []

    #list of (handler name, hash) pairs for other algorithm's hashes, that handler shouldn't identify as belonging to it
    #this list should generally be sufficient (if handler name in list, that entry will be skipped)
    known_other_hashes = [
        ('des_crypt', '6f8c114b58f2c'),
        ('md5_crypt', '$1$dOHYPKoP$tnxS1T8Q6VVn3kpV8cN6o.'),
        ('sha512_crypt', "$6$rounds=123456$asaltof16chars..$BtCwjqMJGx5hrJhZywWvt0RLE8uZ4oPwc"
            "elCjmw2kSYu.Ec6ycULevoBK25fs2xXgMNrCzIMVcgEJAstJeonj1"),
    ]

    #flag if scheme accepts empty string as hash (rare)
    accepts_empty_hash = False

    #=========================================================
    #alg interface helpers - allows subclass to overide how
    # default tests invoke the handler (eg for context_kwds)
    #=========================================================

    def do_encrypt(self, secret, **kwds):
        "call handler's encrypt method with specified options"
        return self.handler.encrypt(secret, **kwds)

    def do_verify(self, secret, hash):
        "call handler's verify method"
        return self.handler.verify(secret, hash)

    def do_identify(self, hash):
        "call handler's identify method"
        return self.handler.identify(hash)

    def do_genconfig(self, **kwds):
        "call handler's genconfig method with specified options"
        return self.handler.genconfig(**kwds)

    def do_genhash(self, secret, config):
        "call handler's genhash method with specified options"
        return self.handler.genhash(secret, config)

    def create_mismatch(self, secret):
        "return other secret which won't match"
        #NOTE: this is subclassable mainly for some algorithms
        #which accept non-strings in secret
        return 'x' + secret

    #=========================================================
    #internal class attrs
    #=========================================================
    @classproperty
    def __test__(cls):
        #so nose won't auto run *this* cls, but it will for subclasses
        return cls is not HandlerCase

    #optional prefix to prepend to name of test method as it's called,
    #useful when multiple handler test classes being run.
    #default behavior should be sufficient
    def case_prefix(self):
        name = self.handler.name if self.handler else self.__class__.__name__
        backend = getattr(self.handler, "get_backend", None) #set by some of the builtin handlers
        if backend:
            name += " (%s backend)" % (backend(),)
        return name

    @classproperty
    def has_salt_info(cls):
        return 'salt' in cls.handler.setting_kwds and getattr(cls.handler, "max_salt_chars", None) > 0

    @classproperty
    def has_rounds_info(cls):
        return 'rounds' in cls.handler.setting_kwds and getattr(cls.handler, "max_rounds", None) > 0

    backend = "default"

    def setUp(self):
        h = self.handler
        if hasattr(h, "set_backend"):
            self.orig_backend = h.get_backend()
            h.set_backend(self.backend)

    def tearDown(self):
        h = self.handler
        if hasattr(h, "set_backend"):
            h.set_backend(self.orig_backend)

    #=========================================================
    #attributes
    #=========================================================
    def test_00_required_attributes(self):
        "test required handler attributes are defined"
        handler = self.handler
        def ga(name):
            return getattr(handler, name, None)

        name = ga("name")
        self.assert_(name, "name not defined:")
        self.assert_(name.lower() == name, "name not lower-case:")
        self.assert_(re.match("^[a-z0-9_]+$", name), "name must be alphanum + underscore: %r" % (name,))

        settings = ga("setting_kwds")
        self.assert_(settings is not None, "setting_kwds must be defined:")
        self.assertIsInstance(settings, tuple, "setting_kwds must be a tuple:")

        context = ga("context_kwds")
        self.assert_(context is not None, "context_kwds must be defined:")
        self.assertIsInstance(context, tuple, "context_kwds must be a tuple:")

    #TODO: check optional rounds attributes & salt attributes

    def test_04_base_handler(self):
        "check configuration of SimpleHandler-derived classes"
        cls = self.handler
        if not isinstance(cls, type) or not issubclass(cls, SimpleHandler):
            raise SkipTest

        if not cls.name:
            raise AssertionError, "class must have .name attribute set"

        if cls.setting_kwds is None:
            raise AssertionError, "class must have .setting_kwds attribute set"

    def test_05_ext_handler(self):
        "check configuration of ExtendedHandler-derived classes"
        cls = self.handler
        if not isinstance(cls, type) or not issubclass(cls, ExtendedHandler):
            raise SkipTest

        if any(k not in cls.setting_kwds for k in cls._extra_init_settings):
            raise AssertionError, "_extra_init_settings must be subset of setting_kwds"

        if 'salt' in cls.setting_kwds:

            if cls.min_salt_chars > cls.max_salt_chars:
                raise AssertionError, "min salt chars too large"

            if cls.default_salt_chars < cls.min_salt_chars:
                raise AssertionError, "default salt chars too small"
            if cls.default_salt_chars > cls.max_salt_chars:
                raise AssertionError, "default salt chars too large"

            if any(c not in cls.salt_charset for c in cls.default_salt_charset):
                raise AssertionError, "default salt charset not subset of salt charset"

        if 'rounds' in cls.setting_kwds:

            if cls.max_rounds is None:
                raise AssertionError, "max rounds not specified"

            if cls.min_rounds > cls.max_rounds:
                raise AssertionError, "min rounds too large"

            if cls.default_rounds is not None:
                if cls.default_rounds < cls.min_rounds:
                    raise AssertionError, "default rounds too small"
                if cls.default_rounds > cls.max_rounds:
                    raise AssertionError, "default rounds too large"

            if cls.rounds_cost not in ("linear", "log2"):
                raise AssertionError, "unknown rounds cost function"

    def test_06_backend_handler(self):
        "check configuration of MultiBackendHandler-derived classes"
        h = self.handler
        if not hasattr(h, "get_backend"):
            raise SkipTest
        #preserve current backend
        orig = h.get_backend()
        try:
            #run through all backends handler supports
            for backend in h.backends:
                #check has_backend() returns bool value
                r = h.has_backend(backend)
                if r is True:
                    #check backend can be loaded
                    h.set_backend(backend)
                    self.assertEquals(h.get_backend(), backend)
                elif r is False:
                    #check backend CAN'T be loaded
                    self.assertRaises(ValueError, h.set_backend, backend)
                else:
                    #failure eg: used classmethod instead of classproperty in _has_backend_xxx
                    raise TypeError, "has_backend(%r) returned invalid value: %r" % (backend, r,)
        finally:
            h.set_backend(orig)

    #=========================================================
    #identify()
    #=========================================================
    def test_10_identify_hash(self):
        "test identify() against scheme's own hashes"
        for secret, hash in self.known_correct_hashes:
            self.assertEqual(self.do_identify(hash), True, "hash=%r:" % (hash,))

        for config, secret, hash in self.known_correct_configs:
            self.assertEqual(self.do_identify(hash), True, "hash=%r:" % (hash,))

    def test_11_identify_config(self):
        "test identify() against scheme's own config strings"
        if not self.known_correct_configs:
            raise SkipTest
        for config, secret, hash in self.known_correct_configs:
            self.assertEqual(self.do_identify(config), True, "config=%r:" % (config,))

    def test_12_identify_unidentified(self):
        "test identify() against scheme's own hashes that are mangled beyond identification"
        if not self.known_unidentified_hashes:
            raise SkipTest
        for hash in self.known_unidentified_hashes:
            self.assertEqual(self.do_identify(hash), False, "hash=%r:" % (hash,))

    def test_13_identify_malformed(self):
        "test identify() against scheme's own hashes that are mangled but identifiable"
        if not self.known_malformed_hashes:
            raise SkipTest
        for hash in self.known_malformed_hashes:
            self.assertEqual(self.do_identify(hash), True, "hash=%r:" % (hash,))

    def test_14_identify_other(self):
        "test identify() against other schemes' hashes"
        for name, hash in self.known_other_hashes:
            self.assertEqual(self.do_identify(hash), name == self.handler.name, "scheme=%r, hash=%r:" % (name, hash))

    def test_15_identify_none(self):
        "test identify() against None / empty string"
        self.assertEqual(self.do_identify(None), False)
        self.assertEqual(self.do_identify(''), self.accepts_empty_hash)

    #=========================================================
    #verify()
    #=========================================================
    def test_20_verify_positive(self):
        "test verify() against known-correct secret/hash pairs"
        self.assert_(self.known_correct_hashes or self.known_correct_configs,
                     "test must define at least one of known_correct_hashes or known_correct_configs")

        for secret, hash in self.known_correct_hashes:
            self.assertEqual(self.do_verify(secret, hash), True,
                             "known correct hash (secret=%r, hash=%r):" % (secret,hash))

        for config, secret, hash in self.known_correct_configs:
            self.assertEqual(self.do_verify(secret, hash), True,
                             "known correct hash (secret=%r, hash=%r):" % (secret,hash))

    def test_21_verify_other(self):
        "test verify() throws error against other algorithm's hashes"
        for name, hash in self.known_other_hashes:
            if name == self.handler.name:
                continue
            self.assertRaises(ValueError, self.do_verify, 'stub', hash, __msg__="scheme=%r, hash=%r:" % (name, hash))

    def test_22_verify_invalid(self):
        "test verify() throws error against known-invalid hashes"
        if not self.known_unidentified_hashes and not self.known_malformed_hashes:
            raise SkipTest
        for hash in self.known_unidentified_hashes:
            self.assertRaises(ValueError, self.do_verify, 'stub', hash, __msg__="hash=%r:" % (hash,))
        for hash in self.known_malformed_hashes:
            self.assertRaises(ValueError, self.do_verify, 'stub', hash, __msg__="hash=%r:" % (hash,))

    def test_23_verify_none(self):
        "test verify() throws error against hash=None/empty string"
        #find valid hash so that doesn't mask error
        self.assertRaises(ValueError, self.do_verify, 'stub', None, __msg__="hash=None:")
        if self.accepts_empty_hash:
            self.do_verify("stub", "")
        else:
            self.assertRaises(ValueError, self.do_verify, 'stub', '', __msg__="hash='':")

    #=========================================================
    #genconfig()
    #=========================================================
    def test_30_genconfig_salt(self):
        "test genconfig() generates new salt"
        if 'salt' not in self.handler.setting_kwds:
            raise SkipTest
        c1 = self.do_genconfig()
        c2 = self.do_genconfig()
        self.assertNotEquals(c1,c2)

    def test_31_genconfig_minsalt(self):
        "test genconfig() honors min salt chars"
        if not self.has_salt_info:
            raise SkipTest
        handler = self.handler
        cs = handler.salt_charset
        mn = handler.min_salt_chars
        c1 = self.do_genconfig(salt=cs[0] * mn)
        if mn > 0:
            self.assertRaises(ValueError, self.do_genconfig, salt=cs[0]*(mn-1))

    def test_32_genconfig_maxsalt(self):
        "test genconfig() honors max salt chars"
        if not self.has_salt_info:
            raise SkipTest
        handler = self.handler
        cs = handler.salt_charset
        mx = handler.max_salt_chars
        c1 = self.do_genconfig(salt=cs[0] * mx)
        c2 = self.do_genconfig(salt=cs[0] * (mx+1))
        self.assertEquals(c1,c2)

    def test_33_genconfig_saltcharset(self):
        "test genconfig() honors salt charset"
        if not self.has_salt_info:
            raise SkipTest
        handler = self.handler
        mx = handler.max_salt_chars
        mn = handler.min_salt_chars
        cs = handler.salt_charset

        #make sure all listed chars are accepted
        for i in xrange(0,len(cs),mx):
            salt = cs[i:i+mx]
            if len(salt) < mn:
                salt = (salt*(mn//len(salt)+1))[:mx]
            self.do_genconfig(salt=salt)

        #check some invalid salt chars are rejected
        for c in '\x00\xff':
            if c not in cs:
                self.assertRaises(ValueError, self.do_genconfig, salt=c*mx)

    #=========================================================
    #genhash()
    #=========================================================
    filter_known_config_warnings = None

    def test_40_genhash_config(self):
        "test genhash() against known config strings"
        if not self.known_correct_configs:
            raise SkipTest
        fk = self.filter_known_config_warnings
        if fk:
            ctx = catch_warnings()
            ctx.__enter__()
            fk()
        for config, secret, hash in self.known_correct_configs:
            result = self.do_genhash(secret, config)
            self.assertEquals(result, hash, "config=%r,secret=%r:" % (config,secret))
        if fk:
            ctx.__exit__(None,None,None)

    def test_41_genhash_hash(self):
        "test genhash() against known hash strings"
        if not self.known_correct_hashes:
            raise SkipTest
        handler = self.handler
        for secret, hash in self.known_correct_hashes:
            result = self.do_genhash(secret, hash)
            self.assertEquals(result, hash, "secret=%r:" % (secret,))

    def test_42_genhash_genconfig(self):
        "test genhash() against genconfig() output"
        handler = self.handler
        config = handler.genconfig()
        hash = self.do_genhash("stub", config)
        self.assert_(handler.identify(hash))

    def test_43_genhash_none(self):
        "test genhash() against empty hash"
        handler = self.handler
        config = handler.genconfig()
        if config is None:
            raise SkipTest
        self.assertRaises(ValueError, handler.genhash, 'secret', None)

    #=========================================================
    #encrypt()
    #=========================================================
    def test_50_encrypt_plain(self):
        "test encrypt() basic behavior"
        if self.supports_unicode:
            secret = u"unic\u00D6de"
        else:
            secret = "too many secrets"
        result = self.do_encrypt(secret)
        self.assert_(self.do_identify(result))
        self.assert_(self.do_verify(secret, result))

    def test_51_encrypt_none(self):
        "test encrypt() refused secret=None"
        self.assertRaises(TypeError, self.do_encrypt, None)

    def test_52_encrypt_salt(self):
        "test encrypt() generates new salt"
        if 'salt' not in self.handler.setting_kwds:
            raise SkipTest
        #test encrypt()
        h1 = self.do_encrypt("stub")
        h2 = self.do_encrypt("stub")
        self.assertNotEquals(h1, h2)

    #=========================================================
    #test max password size
    #=========================================================
    def test_60_secret_chars(self):
        "test secret_chars limit"
        sc = self.secret_chars

        base = "too many secrets" #16 chars
        alt = 'x' #char that's not in base string

        if sc > 0:
            #hash only counts the first <sc> characters
            #eg: bcrypt, des-crypt

            #create & hash something of exactly sc+1 chars
            secret = (base * (1+sc//16))[:sc+1]
            assert len(secret) == sc+1
            hash = self.do_encrypt(secret)

            #check sc value isn't too large
            #by verifying that sc-1'th char affects hash
            self.assert_(not self.do_verify(secret[:-2] + alt + secret[-1], hash), "secret_chars value is too large")

            #check sc value isn't too small
            #by verifying adding sc'th char doesn't affect hash
            self.assert_(self.do_verify(secret[:-1] + alt, hash))

        else:
            #hash counts all characters
            #eg: md5-crypt
            self.assertEquals(sc, -1)

            #NOTE: this doesn't do an exhaustive search to verify algorithm
            #doesn't have some cutoff point, it just tries
            #1024-character string, and alters the last char.
            #as long as algorithm doesn't clip secret at point <1024,
            #the new secret shouldn't verify.
            secret = base * 64
            hash = self.do_encrypt(secret)
            self.assert_(not self.do_verify(secret[:-1] + alt, hash))

    #=========================================================
    #eoc
    #=========================================================

#=========================================================
#backend test helpers
#=========================================================
def enable_backend_case(handler, name):
    "helper to check if a separate test is needed for the specified backend"
    assert issubclass(handler, MultiBackendHandler), "handler must derived from MultiBackendHandler"
    assert name in handler.backends, "unknown backend: %r" % (name,)
    return enable_option("all-backends") and handler.get_backend() != name and handler.has_backend(name)

def create_backend_case(base_test, name):
    "create a test case (subclassing); if test doesn't need to be enabled, returns None"
    if base_test is None:
        return None
    handler = base_test.handler

    if not enable_backend_case(handler, name):
        return None

    class dummy(base_test):
        case_prefix = "%s (%s backend)" % (handler.name, name)
        backend = name

    dummy.__name__ = name.title() + base_test.__name__
    return dummy

#=========================================================
#helper for creating temp files - all cleaned up when prog exits
#=========================================================
tmp_files = []

def _clean_tmp_files():
    for path in tmp_files:
        if os.path.exists(path):
            os.remove(path)
atexit.register(_clean_tmp_files)

def mktemp(*args, **kwds):
    fd, path = tempfile.mkstemp(*args, **kwds)
    tmp_files.append(path)
    os.close(fd)
    return path

#=========================================================
#EOF
#=========================================================
