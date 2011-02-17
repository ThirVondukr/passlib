"""helpers for bps unittests"""
#=========================================================
#imports
#=========================================================
#core
import logging; log = logging.getLogger(__name__)
import re
import os
import unittest
#site
from nose.plugins.skip import SkipTest
#pkg
from passlib.utils import classproperty
from passlib.utils.drivers import BaseHash, BackendMixin
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

tests = [
    v.strip()
    for v
    in os.environ.get("PASSLIB_TESTS", DEFAULT_TESTS).lower().split(",")
    ]

def enable_option(*names):
    """check if a given test should be included based on the env var.

    test flags:
        all                 run ALL tests
        active-backends     test active backends
        all-backends        test ALL backends, even the inactive ones

        slow                required to enable really slow tests (eg builtin bcrypt backend)
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
    """base class for testing password hash drivers (esp passlib.utils.drivers.BaseHash subclasses)

    .. todo::
        write directions on how to use this class.
        for now, see examples in places such as test_unix_crypt
    """
    @classproperty
    def __test__(cls):
        #so nose won't auto run *this* cls, but it will for subclasses
        return cls is not HandlerCase

    #=========================================================
    #attrs to be filled in by subclass for testing specific handler
    #=========================================================

    #specify handler object here
    handler = None

    #this option is available for hashes which can't handle unicode
    supports_unicode = False

    #maximum number of chars which hash will include in checksum
    #override this only if hash doesn't use all chars (the default)
    secret_chars = -1

    #list of (secret,hash) pairs which handler should verify as matching
    known_correct = []

    #list of (secret,hash) pairs which handler should verify as NOT matching
    known_incorrect = []

    # list of handler's hashes with crucial invalidating typos, that handler shouldn't identify as belonging to it
    known_invalid = []

    # list of handler's hashes that it *will* identify as it's own, but genhash will raise error due to invalid internal requirements
    known_identified_invalid = []

    #list of (name, hash) pairs for other algorithm's hashes, that handler shouldn't identify as belonging to it
    #this list should generally be sufficient (if handler name in list, that entry will be skipped)
    known_other = [
        ('des_crypt', '6f8c114b58f2c'),
        ('md5_crypt', '$1$dOHYPKoP$tnxS1T8Q6VVn3kpV8cN6o.'),
        ('sha512_crypt', "$6$rounds=123456$asaltof16chars..$BtCwjqMJGx5hrJhZywWvt0RLE8uZ4oPwc"
            "elCjmw2kSYu.Ec6ycULevoBK25fs2xXgMNrCzIMVcgEJAstJeonj1"),
    ]

    #list of various secrets all algs are tested with to make sure they work
    standard_secrets = [
        '',
        ' ',
        'my socrates note',
        'Compl3X AlphaNu3meric',
        '4lpHa N|_|M3r1K W/ Cur51|\\|g: #$%(*)(*%#',
        'Really Long Password (tm), which is all the rage nowadays. Maybe some Shakespeare?',
        ]

    unicode_secrets = [
        u'test with unic\u00D6de',
    ]

    #optional prefix to prepend to name of test method as it's called,
    #useful when multiple handler test classes being run.
    #default behavior should be sufficient
    def case_prefix(self):
        name = self.handler.name if self.handler else self.__class__.__name__
        backend = getattr(self.handler, "get_backend", None) #set by some of the builtin handlers
        if backend:
            name += " (%s backend)" % (backend(),)
        return name

    #=========================================================
    #alg interface helpers - allows subclass to overide how
    # default tests invoke the handler (eg for context_kwds)
    #=========================================================
    def do_concat(self, secret, prefix):
        "concatenate prefix onto secret"
        #NOTE: this is subclassable mainly for some algorithms
        #which accept non-strings in secret
        return prefix + secret

    def do_encrypt(self, secret, **kwds):
        "call handler's encrypt method with specified options"
        return self.handler.encrypt(secret, **kwds)

    def do_verify(self, secret, hash):
        "call handler's verify method"
        return self.handler.verify(secret, hash)

    def do_identify(self, hash):
        "call handler's identify method"
        return self.handler.identify(hash)

    #=========================================================
    #attributes
    #=========================================================
    def test_00_attributes(self):
        "test handler attributes are all defined"
        handler = self.handler
        def ga(name):
            return getattr(handler, name, None)

        name = ga("name")
        self.assert_(name, "name not defined:")
        self.assert_(name.lower() == name, "name not lower-case:")
        self.assert_(re.match("^[a-z0-9_]+$", name), "name must be alphanum + underscore: %r" % (name,))

    def test_01_base_handler(self):
        "check configuration of BaseHash-derived classes"
        h = self.handler
        if not isinstance(h, type) or not issubclass(h, BaseHash):
            raise SkipTest
        h.validate_class() #should raise AssertionError if something's wrong.

    #=========================================================
    #identify
    #=========================================================
    def test_10_identify_other(self):
        "test identify() against other schemes' hashes"
        for name, hash in self.known_other:
            self.assertEqual(self.do_identify(hash), name == self.handler.name)

    def test_11_identify_positive(self):
        "test identify() against scheme's own hashes"
        for secret, hash in self.known_correct:
            self.assertEqual(self.do_identify(hash), True)

        for secret, hash in self.known_incorrect:
            self.assertEqual(self.do_identify(hash), True)

        for hash in self.known_identified_invalid:
            self.assertEqual(self.do_identify(hash), True)

    def test_12_identify_invalid(self):
        "test identify() against malformed instances of scheme's own hashes"
        if not self.known_invalid:
            raise SkipTest
        for hash in self.known_invalid:
            self.assertEqual(self.do_identify(hash), False, "hash=%r:" % (hash,))

    def test_13_identify_none(self):
        "test identify() against None / empty string"
        self.assertEqual(self.do_identify(None), False)
        self.assertEqual(self.do_identify(''), False)

    #=========================================================
    #verify
    #=========================================================
    def test_20_verify_positive(self):
        "test verify() against known-correct secret/hash pairs"
        self.assert_(self.known_correct, "test must define known_correct hashes")
        for secret, hash in self.known_correct:
            self.assertEqual(self.do_verify(secret, hash), True, "known correct hash (secret=%r, hash=%r):" % (secret,hash))

    def test_21_verify_negative(self):
        "test verify() against known-incorrect secret/hash pairs"
        if not self.known_incorrect:
            raise SkipTest
        for secret, hash in self.known_incorrect:
            self.assertEqual(self.do_verify(secret, hash), False)

    #XXX: is this needed if known_incorrect is defined?
    def test_22_verify_derived_negative(self):
        "test verify() against derived incorrect secret/hash pairs"
        for secret, hash in self.known_correct:
            self.assertEqual(self.do_verify(self.do_concat(secret,'x'), hash), False)

    def test_23_verify_other(self):
        "test verify() throws error against other algorithm's hashes"
        for name, hash in self.known_other:
            if name == self.handler.name:
                continue
            self.assertRaises(ValueError, self.do_verify, 'stub', hash, __msg__="verify other %r %r:" % (name, hash))

    def test_24_verify_invalid(self):
        "test verify() throws error against known-invalid hashes"
        if not self.known_invalid and not self.known_identified_invalid:
            raise SkipTest
        for hash in self.known_invalid + self.known_identified_invalid:
            self.assertRaises(ValueError, self.do_verify, 'stub', hash, __msg__="verify invalid %r:" % (hash,))

    def test_25_verify_none(self):
        "test verify() throws error against hash=None/empty string"
        #find valid hash so that doesn't mask error
        self.assertRaises(ValueError, self.do_verify, 'stub', None, __msg__="verify None:")
        self.assertRaises(ValueError, self.do_verify, 'stub', '', __msg__="verify empty:")

    #=========================================================
    #encrypt
    #=========================================================

    #---------------------------------------------------------
    #test encryption against various secrets
    #---------------------------------------------------------
    def test_30_encrypt_standard(self):
        "test encrypt() against standard secrets"
        for secret in self.standard_secrets:
            self.check_encrypt(secret)

    def test_31_encrypt_unicode(self):
        "test encrypt() against unicode secrets"
        if not self.supports_unicode:
            raise SkipTest
        for secret in self.unicode_secrets:
            self.check_encrypt(secret)

    #this is probably excessive
    ##def test_32_encrypt_positive(self):
    ##    "test encrypt() against known-correct secret/hash pairs"
    ##    for secret, hash in self.known_correct:
    ##        self.check_encrypt(secret)

    def check_encrypt(self, secret):
        "check encrypt() behavior for a given secret"
        #hash the secret
        hash = self.do_encrypt(secret)

        #test identification
        self.assertEqual(self.do_identify(hash), True, "identify hash %r from secret %r:" % (hash, secret))

        #test positive verification
        self.assertEqual(self.do_verify(secret, hash), True, "verify hash %r from secret %r:" % (hash, secret))

        #test negative verification
        for other in ['', 'test', self.do_concat(secret,'x')]:
            if other != secret:
                self.assertEqual(self.do_verify(other, hash), False,
                    "hash collision: %r and %r => %r" % (secret, other, hash))

    #---------------------------------------------------------
    #test salt handling
    #---------------------------------------------------------
    def test_33_encrypt_gensalt(self):
        "test encrypt() generates new salt each time"
        if 'salt' not in self.handler.setting_kwds:
            raise SkipTest
        for secret, hash in self.known_correct:
            hash2 = self.do_encrypt(secret)
            self.assertNotEqual(hash, hash2)

    #TODO: test too-short user-provided salts
    #TODO: test too-long user-provided salts
    #TODO: test invalid char in user-provided salts

    #---------------------------------------------------------
    #test secret handling
    #---------------------------------------------------------
    def test_37_secret_chars(self):
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

    def test_38_encrypt_none(self):
        "test encrypt() refused secret=None"
        self.assertRaises(TypeError, self.do_encrypt, None)

    #=========================================================
    #
    #=========================================================

    #TODO: check genhash works
    #TODO: check genconfig works

    #TODO: check parse method works
    #TODO: check render method works
    #TODO: check default/min/max_rounds valid if present

    #=========================================================
    #eoc
    #=========================================================

#=========================================================
#backend test helpers
#=========================================================
def enable_backend_case(handler, name):
    "helper to check if a separate test is needed for the specified backend"
    assert issubclass(handler, BackendMixin), "handler must derived from BackendMixin"
    assert name in handler.backends, "unknown backend: %r" % (name,)
    return enable_option("all-backends") and handler.get_backend() != name and handler.has_backend(name)

def create_backend_case(base_test, name):
    "create a test case (subclassing); if test doesn't need to be enabled, returns None"
    handler = base_test.handler

    if not enable_backend_case(handler, name):
        return None

    assert getattr(base_test, "setUp", None) is None #just haven't implemented this
    assert getattr(base_test, "cleanUp", None) is None #ditto

    class dummy(base_test):
        case_prefix = "%s (%s backend)" % (handler.name, name)

        def setUp(self):
            self.orig_backend = self.handler.get_backend()
            self.handler.set_backend(name)

        def cleanUp(self):
            self.handler.set_backend(self.orig_backend)

    dummy.__name__ = name.title() + base_test.__name__
    return dummy

#=========================================================
#EOF
#=========================================================
