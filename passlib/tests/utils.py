"""helpers for passlib unittests"""
#=========================================================
#imports
#=========================================================
from __future__ import with_statement
#core
import atexit
import logging; log = logging.getLogger(__name__)
import re
import os
import sys
import tempfile

try:
    import unittest2 as unittest
    ut_version = 2
except ImportError:
    import unittest
    # Py2k #
    if sys.version_info < (2,7):
    # Py3k #
    #if sys.version_info < (3,2):
    # end Py3k #
        ut_version = 1
    else:
        ut_version = 2

import warnings
from warnings import warn

#site
if ut_version < 2:
    #used to provide replacement skipTest() method
    from nose.plugins.skip import SkipTest
#pkg
from passlib import registry, utils
from passlib.utils import classproperty, handlers as uh, \
        has_rounds_info, has_salt_info, MissingBackendError, \
        rounds_cost_values, b, bytes, native_str, NoneType
#local
__all__ = [
    #util funcs
    'enable_option',
    'Params',
    'set_file', 'get_file',

    #unit testing
    'TestCase',
    'HandlerCase',
    'enable_backend_case',
    'create_backend_case',

    #flags
    'gae_env',
]

#figure out if we're running under GAE...
#some tests (eg FS related) should be skipped.
    #XXX: is there better way to do this?
try:
    import google.appengine
except ImportError:
    gae_env = False
else:
    gae_env = True

#=========================================================
#option flags
#=========================================================
DEFAULT_TESTS = ""

tests = set(
    v.strip()
    for v
    in os.environ.get("PASSLIB_TESTS", DEFAULT_TESTS).lower().split(",")
    )

def enable_option(*names):
    """check if a given test should be included based on the env var.

    test flags:
        all-backends    test all backends, even the inactive ones
        cover           enable minor tweaks to maximize coverage testing
        all             run all tests
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

def set_file(path, content):
    "set file to specified bytes"
    if isinstance(content, unicode):
        content = content.encode("utf-8")
    with open(path, "wb") as fh:
        fh.write(content)

def get_file(path):
    "read file as bytes"
    with open(path, "rb") as fh:
        return fh.read()

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

    #=============================================================
    #make it ease for test cases to add common prefix to all descs
    #=============================================================
    #: string or method returning string - prepended to all tests in TestCase
    case_prefix = None

    #: flag to disable feature
    longDescription = True

    def shortDescription(self):
        "wrap shortDescription() method to prepend case_prefix"
        desc = super(TestCase, self).shortDescription()
        if desc is None:
            #would still like to add prefix, but munges things up.
            return None
        prefix = self.case_prefix
        if prefix and self.longDescription:
            if callable(prefix):
                prefix = prefix()
            desc = "%s: %s" % (prefix, desc)
        return desc

    #============================================================
    #hack to set UT2 private skip attrs to mirror nose's __test__ attr
    #============================================================
    if ut_version >= 2:

        @classproperty
        def __unittest_skip__(cls):
            return not getattr(cls, "__test__", True)

    @classproperty
    def __test__(cls):
        #so nose won't auto run *this* cls, but it will for subclasses
        return cls is not TestCase and not cls.__name__.startswith("_")

    #============================================================
    # tweak msg formatting for some assert methods
    #============================================================
    longMessage = True #override python default (False)

    def _formatMessage(self, msg, std):
        "override UT2's _formatMessage - only use longMessage if msg ends with ':'"
        if not msg:
            return std
        if not self.longMessage or not msg.endswith(":"):
            return msg.rstrip(":")
        return '%s %s' % (msg, std)

    #============================================================
    #override some unittest1 methods to support _formatMessage
    #============================================================
    if ut_version < 2:

        def assertEqual(self, real, correct, msg=None):
            if real != correct:
                std = "got %r, expected would equal %r" % (real, correct)
                msg = self._formatMessage(msg, std)
                raise self.failureException(msg)

        def assertNotEqual(self, real, correct, msg=None):
            if real == correct:
                std = "got %r, expected would not equal %r" % (real, correct)
                msg = self._formatMessage(msg, std)
                raise self.failureException(msg)

        assertEquals = assertEqual
        assertNotEquals = assertNotEqual

    #NOTE: overriding this even under UT2.
    #FIXME: this doesn't support the fancy context manager UT2 provides.
    def assertRaises(self, type, func, *args, **kwds):
        #NOTE: overriding this for format ability,
        #      but ALSO adding "__msg__" kwd so we can set custom msg
        msg = kwds.pop("__msg__", None)
        try:
            result = func(*args, **kwds)
        except Exception, err:
            if isinstance(err, type):
                return True
            ##import traceback, sys
            ##print >>sys.stderr, traceback.print_exception(*sys.exc_info())
            std = "function raised %r, expected %r" % (err, type)
            msg = self._formatMessage(msg, std)
            raise self.failureException(msg)
        std = "function returned %r, expected it to raise %r" % (result, type)
        msg = self._formatMessage(msg, std)
        raise self.failureException(msg)

    #===============================================================
    #backport some methods from unittest2
    #===============================================================
    if ut_version < 2:

        def assertIs(self, real, correct, msg=None):
            if real is not correct:
                std = "got %r, expected would be %r" % (real, correct)
                msg = self._formatMessage(msg, std)
                raise self.failureException(msg)

        def assertIsNot(self, real, correct, msg=None):
            if real is correct:
                std = "got %r, expected would not be %r" % (real, correct)
                msg = self._formatMessage(msg, std)
                raise self.failureException(msg)

        def assertIsInstance(self, obj, klass, msg=None):
            if not isinstance(obj, klass):
                std = "got %r, expected instance of %r" % (obj, klass)
                msg = self._formatMessage(msg, std)
                raise self.failureException(msg)

        def skipTest(self, reason):
            raise SkipTest(reason)

        def assertAlmostEqual(self, first, second, places=None, msg=None, delta=None):
            """Fail if the two objects are unequal as determined by their
               difference rounded to the given number of decimal places
               (default 7) and comparing to zero, or by comparing that the
               between the two objects is more than the given delta.

               Note that decimal places (from zero) are usually not the same
               as significant digits (measured from the most signficant digit).

               If the two objects compare equal then they will automatically
               compare almost equal.
            """
            if first == second:
                # shortcut
                return
            if delta is not None and places is not None:
                raise TypeError("specify delta or places not both")

            if delta is not None:
                if abs(first - second) <= delta:
                    return

                standardMsg = '%s != %s within %s delta' % (repr(first),
                                                            repr(second),
                                                            repr(delta))
            else:
                if places is None:
                    places = 7

                if round(abs(second-first), places) == 0:
                    return

                standardMsg = '%s != %s within %r places' % (repr(first),
                                                              repr(second),
                                                              places)
            msg = self._formatMessage(msg, standardMsg)
            raise self.failureException(msg)

    if not hasattr(unittest.TestCase, "assertRegexpMatches"):
        #added in 2.7/UT2 and 3.1
        def assertRegexpMatches(self, text, expected_regex, msg=None):
            """Fail the test unless the text matches the regular expression."""
            if isinstance(expected_regex, basestring):
                assert expected_regex, "expected_regex must not be empty."
                expected_regex = re.compile(expected_regex)
            if not expected_regex.search(text):
                msg = msg or "Regex didn't match"
                msg = '%s: %r not found in %r' % (msg, expected_regex.pattern, text)
                raise self.failureException(msg)

    #============================================================
    #add some custom methods
    #============================================================
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
            msg = "error for case %r:" % (elem.render(1),)
            self.assertEqual(result, correct, msg)

    def assertWarningMatches(self, warning,
                             message=None, message_re=None,
                             category=None,
                             ##filename=None, filename_re=None,
                             ##lineno=None,
                             msg=None,
                             ):
        "check if WarningMessage instance (as returned by catch_warnings) matches parameters"

        #determine if we have WarningMessage object,
        #and ensure 'warning' contains only warning instances.
        if hasattr(warning, "category"):
            wmsg = warning
            warning = warning.message
        else:
            wmsg = None

        #tests that can use a warning instance or WarningMessage object
        if message:
            self.assertEqual(str(warning), message, msg)
        if message_re:
            self.assertRegexpMatches(str(warning), message_re, msg)
        if category:
            self.assertIsInstance(warning, category, msg)

        #commented out until needed...
        ###tests that require a WarningMessage object
        ##if filename or filename_re:
        ##    if not wmsg:
        ##        raise TypeError("can't read filename from warning object")
        ##    real = wmsg.filename
        ##    if real.endswith(".pyc") or real.endswith(".pyo"):
        ##        #FIXME: should use a stdlib call to resolve this back
        ##        #       to original module's path
        ##        real = real[:-1]
        ##    if filename:
        ##        self.assertEqual(real, filename, msg)
        ##    if filename_re:
        ##        self.assertRegexpMatches(real, filename_re, msg)
        ##if lineno:
        ##    if not wmsg:
        ##        raise TypeError("can't read lineno from warning object")
        ##    self.assertEqual(wmsg.lineno, lineno, msg)

    #============================================================
    #eoc
    #============================================================

#=========================================================
#other unittest helpers
#=========================================================
class HandlerCase(TestCase):
    """base class for testing password hash handlers (esp passlib.utils.handlers subclasses)

    In order to use this to test a handler,
    create a subclass will all the appropriate attributes
    filled as listed in the example below,
    and run the subclass via unittest.

    .. todo::

        Document all of the options HandlerCase offers.

    .. note::

        This is subclass of :class:`unittest.TestCase`
        (or :class:`unittest2.TestCase` if available).
    """
    #=========================================================
    #attrs to be filled in by subclass for testing specific handler
    #=========================================================

    #: specify handler object here (required)
    handler = None

    #: maximum number of chars which hash will include in checksum
    #  override this only if hash doesn't use all chars (the default)
    secret_chars = -1

    #: list of (secret,hash) pairs which handler should verify as matching
    known_correct_hashes = []

    #: list of (config, secret, hash) triples which handler should genhash & verify
    known_correct_configs = []

    #: hashes so malformed they aren't even identified properly
    known_unidentified_hashes = []

    #: hashes which are malformed - they should identify() as True, but cause error when passed to genhash/verify
    known_malformed_hashes = []

    #: list of (handler name, hash) pairs for other algorithm's hashes, that handler shouldn't identify as belonging to it
    #  this list should generally be sufficient (if handler name in list, that entry will be skipped)
    known_other_hashes = [
        ('des_crypt', '6f8c114b58f2c'),
        ('md5_crypt', '$1$dOHYPKoP$tnxS1T8Q6VVn3kpV8cN6o.'),
        ('sha512_crypt', "$6$rounds=123456$asaltof16chars..$BtCwjqMJGx5hrJhZywWvt0RLE8uZ4oPwc"
            "elCjmw2kSYu.Ec6ycULevoBK25fs2xXgMNrCzIMVcgEJAstJeonj1"),
    ]

    #: flag if scheme accepts empty string as hash (rare)
    accepts_empty_hash = False

    #: if handler uses multiple backends, explicitly set this one when running tests.
    backend = None

    #: hack used by create_backend() to signal we should monkeypatch
    #  safe_os_crypt() to use handler+this backend,
    #  only used when backend == "os_crypt"
    _patch_crypt_backend = None

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
        if isinstance(secret, unicode):
            return u'x' + secret
        else:
            return b('x') + secret

    #=========================================================
    #internal class attrs
    #=========================================================
    @classproperty
    def __test__(cls):
        #so nose won't auto run *this* cls, but it will for subclasses
        return cls is not HandlerCase and not cls.__name__.startswith("_")

    #optional prefix to prepend to name of test method as it's called,
    #useful when multiple handler test classes being run.
    #default behavior should be sufficient
    def case_prefix(self):
        name = self.handler.name if self.handler else self.__class__.__name__
        get_backend = getattr(self.handler, "get_backend", None) #set by some of the builtin handlers
        if get_backend:
            name += " (%s backend)" % (get_backend(),)
        return name

    @classproperty
    def all_correct_hashes(cls):
        hashes = cls.known_correct_hashes
        configs = cls.known_correct_configs
        if configs:
            hashes = hashes + [
                (secret,hash)
                for config,secret,hash
                in configs
                if (secret,hash) not in hashes
            ]
        return hashes

    #=========================================================
    #setup / cleanup
    #=========================================================
    _orig_backend = None #backup of original backend
    _orig_os_crypt = None #backup of original utils.os_crypt

    def setUp(self):
        h = self.handler
        backend = self.backend
        if backend:
            if not hasattr(h, "set_backend"):
                raise RuntimeError("handler doesn't support multiple backends")
            self._orig_backend = h.get_backend()
            alt_backend = None
            if (backend == "os_crypt" and not h.has_backend("os_crypt")):
                alt_backend = _has_other_backends(h, "os_crypt")
            if alt_backend:
                #monkeypatch utils.safe_os_crypt to use specific handler+backend
                #this allows use to test as much of the hash's code path
                #as possible, even if current OS doesn't provide crypt() support
                #for the hash.
                self._orig_os_crypt = utils.os_crypt
                def crypt_stub(secret, hash):
                    tmp = h.get_backend()
                    try:
                        h.set_backend(alt_backend)
                        hash = h.genhash(secret, hash)
                    finally:
                        h.set_backend(tmp)
                    # Py2k #
                    if isinstance(hash, unicode):
                        hash = hash.encode("ascii")
                    # end Py2k #
                    return hash
                utils.os_crypt = crypt_stub
            h.set_backend(backend)

    def tearDown(self):
        if self._orig_os_crypt:
            utils.os_crypt = self._orig_os_crypt
        if self._orig_backend:
            self.handler.set_backend(self._orig_backend)

    #=========================================================
    #attributes
    #=========================================================
    def test_00_required_attributes(self):
        "test required handler attributes are defined"
        handler = self.handler
        def ga(name):
            return getattr(handler, name, None)

        name = ga("name")
        self.assertTrue(name, "name not defined:")
        self.assertIsInstance(name, native_str, "name must be native str")
        self.assertTrue(name.lower() == name, "name not lower-case:")
        self.assertTrue(re.match("^[a-z0-9_]+$", name), "name must be alphanum + underscore: %r" % (name,))

        settings = ga("setting_kwds")
        self.assertTrue(settings is not None, "setting_kwds must be defined:")
        self.assertIsInstance(settings, tuple, "setting_kwds must be a tuple:")

        context = ga("context_kwds")
        self.assertTrue(context is not None, "context_kwds must be defined:")
        self.assertIsInstance(context, tuple, "context_kwds must be a tuple:")

    def test_01_optional_salt_attributes(self):
        "validate optional salt attributes"
        cls = self.handler
        if not has_salt_info(cls):
            raise self.skipTest("handler doesn't provide salt info")

        AssertionError = self.failureException

        #check max_salt_size
        mx_set = (cls.max_salt_size is not None)
        if mx_set and cls.max_salt_size < 1:
            raise AssertionError("max_salt_chars must be >= 1")

        #check min_salt_size
        if cls.min_salt_size < 0:
            raise AssertionError("min_salt_chars must be >= 0")
        if mx_set and cls.min_salt_size > cls.max_salt_size:
            raise AssertionError("min_salt_chars must be <= max_salt_chars")

        #check default_salt_size
        if cls.default_salt_size < cls.min_salt_size:
            raise AssertionError("default_salt_size must be >= min_salt_size")
        if mx_set and cls.default_salt_size > cls.max_salt_size:
            raise AssertionError("default_salt_size must be <= max_salt_size")

        #check for 'salt_size' keyword
        if 'salt_size' not in cls.setting_kwds and \
                (not mx_set or cls.min_salt_size < cls.max_salt_size):
            #NOTE: for now, only bothering to issue warning if default_salt_size isn't maxed out
            if (not mx_set or cls.default_salt_size < cls.max_salt_size):
                warn("%s: hash handler supports range of salt sizes, but doesn't offer 'salt_size' setting" % (cls.name,))

        #check salt_chars & default_salt_chars
        if cls.salt_chars:
            if not cls.default_salt_chars:
                raise AssertionError("default_salt_chars must not be empty")
            if any(c not in cls.salt_chars for c in cls.default_salt_chars):
                raise AssertionError("default_salt_chars must be subset of salt_chars: %r not in salt_chars" % (c,))
        else:
            if not cls.default_salt_chars:
                raise AssertionError("default_salt_chars MUST be specified if salt_chars is empty")

    def test_02_optional_rounds_attributes(self):
        "validate optional rounds attributes"
        cls = self.handler
        if not has_rounds_info(cls):
            raise self.skipTest("handler lacks rounds attributes")

        AssertionError = self.failureException

        #check max_rounds
        if cls.max_rounds is None:
            raise AssertionError("max_rounds not specified")
        if cls.max_rounds < 1:
            raise AssertionError("max_rounds must be >= 1")

        #check min_rounds
        if cls.min_rounds < 0:
            raise AssertionError("min_rounds must be >= 0")
        if cls.min_rounds > cls.max_rounds:
            raise AssertionError("min_rounds must be <= max_rounds")

        #check default_rounds
        if cls.default_rounds is not None:
            if cls.default_rounds < cls.min_rounds:
                raise AssertionError("default_rounds must be >= min_rounds")
            if cls.default_rounds > cls.max_rounds:
                raise AssertionError("default_rounds must be <= max_rounds")

        #check rounds_cost
        if cls.rounds_cost not in rounds_cost_values:
            raise AssertionError("unknown rounds cost constant: %r" % (cls.rounds_cost,))

    def test_03_HasManyIdents(self):
        "check configuration of HasManyIdents-derived classes"
        cls = self.handler
        if not isinstance(cls, type) or not issubclass(cls, uh.HasManyIdents):
            raise self.skipTest("handler doesn't derive from HasManyIdents")

        #check settings
        self.assertTrue('ident' in cls.setting_kwds)

        #check ident_values list
        for value in cls.ident_values:
            self.assertIsInstance(value, unicode,
                                  "cls.ident_values must be unicode:")
        self.assertTrue(len(cls.ident_values)>1,
                        "cls.ident_values must have 2+ elements:")

        #check default_ident value
        self.assertIsInstance(cls.default_ident, unicode,
                              "cls.default_ident must be unicode:")
        self.assertTrue(cls.default_ident in cls.ident_values,
                        "cls.default_ident must specify member of cls.ident_values")

        #check optional aliases list
        if cls.ident_aliases:
            for alias, ident in cls.ident_aliases.iteritems():
                self.assertIsInstance(alias, unicode,
                                      "cls.ident_aliases keys must be unicode:") #XXX: allow ints?
                self.assertIsInstance(ident, unicode,
                                      "cls.ident_aliases values must be unicode:")
                self.assertTrue(ident in cls.ident_values,
                                "cls.ident_aliases must map to cls.ident_values members: %r" % (ident,))

    RESERVED_BACKEND_NAMES = [ "any", "default", None ]

    def test_04_backend_handler(self):
        "check behavior of multiple-backend handlers"
        h = self.handler
        if not hasattr(h, "set_backend"):
            raise self.skipTest("handler has single backend")

        #preserve current backend
        orig = h.get_backend()
        try:
            #run through all backends handler supports
            for backend in h.backends:
                self.assertFalse(backend in self.RESERVED_BACKEND_NAMES,
                                 "invalid backend name: %r" % (backend,))
                #check has_backend() returns bool value
                r = h.has_backend(backend)
                if r is True:
                    #check backend can be loaded
                    h.set_backend(backend)
                    self.assertEqual(h.get_backend(), backend)
                elif r is False:
                    #check backend CAN'T be loaded
                    self.assertRaises(MissingBackendError, h.set_backend, backend)
                else:
                    #failure eg: used classmethod instead of classproperty in _has_backend_xxx
                    raise TypeError("has_backend(%r) returned invalid value: %r" % (backend, r,))
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
            raise self.skipTest("no config strings provided")
        for config, secret, hash in self.known_correct_configs:
            self.assertEqual(self.do_identify(config), True, "config=%r:" % (config,))

    def test_12_identify_unidentified(self):
        "test identify() against scheme's own hashes that are mangled beyond identification"
        if not self.known_unidentified_hashes:
            raise self.skipTest("no unidentified hashes provided")
        for hash in self.known_unidentified_hashes:
            self.assertEqual(self.do_identify(hash), False, "hash=%r:" % (hash,))

    def test_13_identify_malformed(self):
        "test identify() against scheme's own hashes that are mangled but identifiable"
        if not self.known_malformed_hashes:
            raise self.skipTest("no malformed hashes provided")
        for hash in self.known_malformed_hashes:
            self.assertEqual(self.do_identify(hash), True, "hash=%r:" % (hash,))

    def test_14_identify_other(self):
        "test identify() against other schemes' hashes"
        for name, hash in self.known_other_hashes:
            self.assertEqual(self.do_identify(hash), name == self.handler.name, "scheme=%r, hash=%r:" % (name, hash))

    def test_15_identify_none(self):
        "test identify() against None / empty string"
        self.assertEqual(self.do_identify(None), False)
        self.assertEqual(self.do_identify(b('')), self.accepts_empty_hash)
        self.assertEqual(self.do_identify(u''), self.accepts_empty_hash)

    #=========================================================
    #verify()
    #=========================================================
    def test_20_verify_positive(self):
        "test verify() against known-correct secret/hash pairs"
        self.assertTrue(self.known_correct_hashes or self.known_correct_configs,
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
            self.assertRaises(ValueError, self.do_verify, 'fakesecret', hash, __msg__="scheme=%r, hash=%r:" % (name, hash))

    def test_22_verify_unidentified(self):
        "test verify() throws error against known-unidentified hashes"
        if not self.known_unidentified_hashes:
            raise self.skipTest("no unidentified hashes provided")
        for hash in self.known_unidentified_hashes:
            self.assertRaises(ValueError, self.do_verify, 'stub', hash, __msg__="hash=%r:" % (hash,))

    def test_23_verify_malformed(self):
        "test verify() throws error against known-malformed hashes"
        if not self.known_malformed_hashes:
            raise self.skipTest("no malformed hashes provided")
        for hash in self.known_malformed_hashes:
            self.assertRaises(ValueError, self.do_verify, 'stub', hash, __msg__="hash=%r:" % (hash,))

    def test_24_verify_none(self):
        "test verify() throws error against hash=None/empty string"
        #find valid hash so that doesn't mask error
        self.assertRaises(ValueError, self.do_verify, 'stub', None, __msg__="hash=None:")
        if self.accepts_empty_hash:
            self.do_verify("stub", u"")
            self.do_verify("stub", b(""))
        else:
            self.assertRaises(ValueError, self.do_verify, 'stub', u'', __msg__="hash='':")
            self.assertRaises(ValueError, self.do_verify, 'stub', b(''), __msg__="hash='':")

    #=========================================================
    #genconfig()
    #=========================================================
    def test_30_genconfig_salt(self):
        "test genconfig() generates new salt"
        if 'salt' not in self.handler.setting_kwds:
            raise self.skipTest("handler doesn't have salt")
        c1 = self.do_genconfig()
        c2 = self.do_genconfig()
        self.assertIsInstance(c1, native_str, "genconfig() must return native str:")
        self.assertIsInstance(c2, native_str, "genconfig() must return native str:")
        self.assertNotEqual(c1,c2)

    def test_31_genconfig_minsalt(self):
        "test genconfig() honors min salt chars"
        handler = self.handler
        if not has_salt_info(handler):
            raise self.skipTest("handler doesn't provide salt info")
        cs = handler.salt_chars
        cc = cs[0:1]
        mn = handler.min_salt_size
        c1 = self.do_genconfig(salt=cc * mn)
        if mn > 0:
            self.assertRaises(ValueError, self.do_genconfig, salt=cc*(mn-1))

    def test_32_genconfig_maxsalt(self):
        "test genconfig() honors max salt chars"
        handler = self.handler
        if not has_salt_info(handler):
            raise self.skipTest("handler doesn't provide salt info")
        cs = handler.salt_chars
        cc = cs[0:1]
        mx = handler.max_salt_size
        if mx is None:
            #make sure salt is NOT truncated,
            #use a really large salt for testing
            salt = cc * 1024
            c1 = self.do_genconfig(salt=salt)
            c2 = self.do_genconfig(salt=salt + cc)
            self.assertNotEqual(c1,c2)
        else:
            #make sure salt is truncated exactly where it should be.
            salt = cc * mx
            c1 = self.do_genconfig(salt=salt)
            c2 = self.do_genconfig(salt=salt + cc)
            self.assertEqual(c1,c2)

            #if min_salt supports it, check smaller than mx is NOT truncated
            if handler.min_salt_size < mx:
                c3 = self.do_genconfig(salt=salt[:-1])
                self.assertNotEqual(c1,c3)

    def test_33_genconfig_saltchars(self):
        "test genconfig() honors salt_chars"
        handler = self.handler
        if not has_salt_info(handler):
            raise self.skipTest("handler doesn't provide salt info")
        mx = handler.max_salt_size
        mn = handler.min_salt_size
        cs = handler.salt_chars
        raw = isinstance(cs, bytes)

        #make sure all listed chars are accepted
        chunk = 32 if mx is None else mx
        for i in xrange(0,len(cs),chunk):
            salt = cs[i:i+chunk]
            if len(salt) < mn:
                salt = (salt*(mn//len(salt)+1))[:chunk]
            self.do_genconfig(salt=salt)

        #check some invalid salt chars, make sure they're rejected
        source = u'\x00\xff'
        if raw:
            source = source.encode("latin-1")
        chunk = max(mn, 1)
        for c in source:
            if c not in cs:
                self.assertRaises(ValueError, self.do_genconfig, salt=c*chunk, __msg__="invalid salt char %r:" % (c,))

    #=========================================================
    #genhash()
    #=========================================================
    filter_known_config_warnings = None

    def test_40_genhash_config(self):
        "test genhash() against known config strings"
        if not self.known_correct_configs:
            raise self.skipTest("no config strings provided")
        fk = self.filter_known_config_warnings
        if fk:
            ctx = catch_warnings()
            ctx.__enter__()
            fk()
        for config, secret, hash in self.known_correct_configs:
            result = self.do_genhash(secret, config)
            self.assertEqual(result, hash, "config=%r,secret=%r:" % (config,secret))
        if fk:
            ctx.__exit__(None,None,None)

    def test_41_genhash_hash(self):
        "test genhash() against known hash strings"
        if not self.known_correct_hashes:
            raise self.skipTest("no correct hashes provided")
        handler = self.handler
        for secret, hash in self.known_correct_hashes:
            result = self.do_genhash(secret, hash)
            self.assertEqual(result, hash, "secret=%r:" % (secret,))

    def test_42_genhash_genconfig(self):
        "test genhash() against genconfig() output"
        handler = self.handler
        config = handler.genconfig()
        hash = self.do_genhash("stub", config)
        self.assertTrue(handler.identify(hash))

    def test_43_genhash_none(self):
        "test genhash() against hash=None"
        handler = self.handler
        config = handler.genconfig()
        if config is None:
            raise self.skipTest("handler doesnt use config strings")
        self.assertRaises(ValueError, handler.genhash, 'secret', None)

    #=========================================================
    #encrypt()
    #=========================================================
    def test_50_encrypt_plain(self):
        "test encrypt() basic behavior"
        #check it handles unicode password
        secret = u"\u20AC\u00A5$"
        result = self.do_encrypt(secret)
        self.assertIsInstance(result, native_str, "encrypt must return native str:")
        self.assertTrue(self.do_identify(result))
        self.assertTrue(self.do_verify(secret, result))

        #check it handles bytes password as well
        secret = b('\xe2\x82\xac\xc2\xa5$')
        result = self.do_encrypt(secret)
        self.assertIsInstance(result, native_str, "encrypt must return native str:")
        self.assertTrue(self.do_identify(result))
        self.assertTrue(self.do_verify(secret, result))

    def test_51_encrypt_none(self):
        "test encrypt() refused secret=None"
        self.assertRaises(TypeError, self.do_encrypt, None)

    def test_52_encrypt_salt(self):
        "test encrypt() generates new salt"
        if 'salt' not in self.handler.setting_kwds:
            raise self.skipTest("handler doesn't have salt")
        #test encrypt()
        h1 = self.do_encrypt("stub")
        h2 = self.do_encrypt("stub")
        self.assertNotEqual(h1, h2)

    # optional helper used by test_53_external_verifiers
    iter_external_verifiers = None

    def test_53_external_verifiers(self):
        "test encrypt() output verifies against external libs"
        # this makes sure our output can be verified by external libs,
        # to avoid repeat of things like issue 25.

        handler = self.handler
        possible = False
        if self.iter_external_verifiers:
            helpers = list(self.iter_external_verifiers())
            possible = True
        else:
            helpers = []

        # provide default "os_crypt" helper
        if hasattr(handler, "has_backend") and \
                'os_crypt' in handler.backends and \
                not hasattr(handler, "orig_prefix"):
            possible = True
            if handler.has_backend("os_crypt"):
                def check_crypt(secret, hash):
                    self.assertEqual(utils.os_crypt(secret, hash), hash,
                                     "os_crypt(%r,%r):" % (secret, hash))
                helpers.append(check_crypt)

        if not helpers:
            if possible:
                raise self.skipTest("no external libs available")
            else:
                raise self.skipTest("not applicable")

        # generate a single hash, and verify it using all helpers.
        secret = 't\xc3\xa1\xd0\x91\xe2\x84\x93\xc9\x99'
        hash = self.do_encrypt(secret)
        for helper in helpers:
            helper(secret, hash)

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
            self.assertTrue(not self.do_verify(secret[:-2] + alt + secret[-1], hash), "secret_chars value is too large")

            #check sc value isn't too small
            #by verifying adding sc'th char doesn't affect hash
            self.assertTrue(self.do_verify(secret[:-1] + alt, hash))

        else:
            #hash counts all characters
            #eg: md5-crypt
            self.assertEqual(sc, -1)

            #NOTE: this doesn't do an exhaustive search to verify algorithm
            #doesn't have some cutoff point, it just tries
            #1024-character string, and alters the last char.
            #as long as algorithm doesn't clip secret at point <1024,
            #the new secret shouldn't verify.
            secret = base * 64
            hash = self.do_encrypt(secret)
            self.assertTrue(not self.do_verify(secret[:-1] + alt, hash))

    #=========================================================
    #eoc
    #=========================================================

#=========================================================
#backend test helpers
#=========================================================
def _enable_backend_case(handler, backend):
    "helper to check if testcase should be enabled for the specified backend"
    assert backend in handler.backends, "unknown backend: %r" % (backend,)
    if enable_option("all-backends") or _is_default_backend(handler, backend):
        if handler.has_backend(backend):
            return True, None
        if backend == "os_crypt" and utils.safe_os_crypt:
            if enable_option("cover") and _has_other_backends(handler, "os_crypt"):
                #in this case, HandlerCase will monkeypatch os_crypt
                #to use another backend, just so we can test os_crypt fully.
                return True, None
            else:
                return False, "hash not supported by os crypt()"
        else:
            return False, "backend not available"
    else:
        return False, "only default backend being tested"

def _is_default_backend(handler, name):
    "check if backend is the default for handler"
    try:
        orig = handler.get_backend()
    except MissingBackendError:
        return False
    try:
        return handler.set_backend("default") == name
    finally:
        handler.set_backend(orig)

def _has_other_backends(handler, ignore):
    "helper to check if alternate backend is available"
    for name in handler.backends:
        if name != ignore and handler.has_backend(name):
            return name
    return None

def create_backend_case(base, name, module="passlib.tests.test_drivers"):
    "create a test case for specific backend of a multi-backend handler"
    #get handler, figure out if backend should be tested
    handler = base.handler
    assert hasattr(handler, "backends"), "handler must support uh.HasManyBackends protocol"
    enable, reason = _enable_backend_case(handler, name)

    #UT1 doesn't support skipping whole test cases,
    #so we just return None.
    if not enable and ut_version < 2:
        return None

    #make classname match what it's stored under, to be tidy
    cname = name.title().replace("_","") + "_" + base.__name__.lstrip("_")

    #create subclass of 'base' which uses correct backend
    subcase = type(
        cname,
        (base,),
        dict(
            case_prefix = "%s (%s backend)" % (handler.name, name),
            backend = name,
            __module__=module,
        )
    )

    if not enable:
        subcase = unittest.skip(reason)(subcase)

    return subcase

#=========================================================
#misc helpers
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
        registry._unload_handler_name(self.name, locations=False)
        registry.register_crypt_handler(self.dummy)
        assert registry.get_crypt_handler(self.name) is self.dummy
        return self.dummy

    def __exit__(self, *exc_info):
        registry._unload_handler_name(self.name, locations=False)

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
#make sure catch_warnings() is available
#=========================================================
try:
    from warnings import catch_warnings
except ImportError:
    #catch_warnings wasn't added until py26.
    #this adds backported copy from py26's stdlib
    #so we can use it under py25.

    class WarningMessage(object):

        """Holds the result of a single showwarning() call."""

        _WARNING_DETAILS = ("message", "category", "filename", "lineno", "file",
                            "line")

        def __init__(self, message, category, filename, lineno, file=None,
                        line=None):
            local_values = locals()
            for attr in self._WARNING_DETAILS:
                setattr(self, attr, local_values[attr])
            self._category_name = category.__name__ if category else None

        def __str__(self):
            return ("{message : %r, category : %r, filename : %r, lineno : %s, "
                        "line : %r}" % (self.message, self._category_name,
                                        self.filename, self.lineno, self.line))


    class catch_warnings(object):

        """A context manager that copies and restores the warnings filter upon
        exiting the context.

        The 'record' argument specifies whether warnings should be captured by a
        custom implementation of warnings.showwarning() and be appended to a list
        returned by the context manager. Otherwise None is returned by the context
        manager. The objects appended to the list are arguments whose attributes
        mirror the arguments to showwarning().

        The 'module' argument is to specify an alternative module to the module
        named 'warnings' and imported under that name. This argument is only useful
        when testing the warnings module itself.

        """

        def __init__(self, record=False, module=None):
            """Specify whether to record warnings and if an alternative module
            should be used other than sys.modules['warnings'].

            For compatibility with Python 3.0, please consider all arguments to be
            keyword-only.

            """
            self._record = record
            self._module = sys.modules['warnings'] if module is None else module
            self._entered = False

        def __repr__(self):
            args = []
            if self._record:
                args.append("record=True")
            if self._module is not sys.modules['warnings']:
                args.append("module=%r" % self._module)
            name = type(self).__name__
            return "%s(%s)" % (name, ", ".join(args))

        def __enter__(self):
            if self._entered:
                raise RuntimeError("Cannot enter %r twice" % self)
            self._entered = True
            self._filters = self._module.filters
            self._module.filters = self._filters[:]
            self._showwarning = self._module.showwarning
            if self._record:
                log = []
                def showwarning(*args, **kwargs):
                    log.append(WarningMessage(*args, **kwargs))
                self._module.showwarning = showwarning
                return log
            else:
                return None

        def __exit__(self, *exc_info):
            if not self._entered:
                raise RuntimeError("Cannot exit %r without entering first" % self)
            self._module.filters = self._filters
            self._module.showwarning = self._showwarning

#=========================================================
#EOF
#=========================================================
