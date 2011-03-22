"""tests for passlib.pwhash -- (c) Assurance Technologies 2003-2009"""
#=========================================================
#imports
#=========================================================
from __future__ import with_statement
#core
import hashlib
from logging import getLogger
import os
import time
import warnings
import sys
#site
#pkg
from passlib import hash, registry
from passlib.registry import register_crypt_handler, register_crypt_handler_path, \
    get_crypt_handler, list_crypt_handlers
from passlib.utils.handlers import SimpleHandler
from passlib.tests.utils import TestCase, mktemp, catch_warnings
#module
log = getLogger(__name__)

#=========================================================
#test registry
#=========================================================
class dummy_0(SimpleHandler):
    name = "dummy_0"
    setting_kwds = ()

class alt_dummy_0(SimpleHandler):
    name = "dummy_0"
    setting_kwds = ()

dummy_x = 1

def unload_handler_name(name):
    if hasattr(hash, name):
        delattr(hash, name)

    #NOTE: this messes w/ internals of registry, shouldn't be used publically.
    paths = registry._handler_locations
    if name in paths:
        del paths[name]

class RegistryTest(TestCase):

    case_prefix = "passlib registry"

    def tearDown(self):
        for name in ("dummy_0", "dummy_1", "dummy_x", "dummy_bad"):
            unload_handler_name(name)

    def test_hash_proxy(self):
        "test passlib.hash proxy object"
        dir(hash)
        repr(hash)
        self.assertRaises(AttributeError, getattr, hash, 'fooey')

    def test_register_crypt_handler_path(self):
        "test register_crypt_handler_path()"

        #NOTE: this messes w/ internals of registry, shouldn't be used publically.
        paths = registry._handler_locations

        #check namespace is clear
        self.assertTrue('dummy_0' not in paths)
        self.assertFalse(hasattr(hash, 'dummy_0'))

        #try lazy load
        register_crypt_handler_path('dummy_0', 'passlib.tests.test_registry')
        self.assertTrue('dummy_0' in list_crypt_handlers())
        self.assertTrue('dummy_0' not in list_crypt_handlers(loaded_only=True))
        self.assertIs(hash.dummy_0, dummy_0)
        self.assertTrue('dummy_0' in list_crypt_handlers(loaded_only=True))
        unload_handler_name('dummy_0')

        #try lazy load w/ alt
        register_crypt_handler_path('dummy_0', 'passlib.tests.test_registry:alt_dummy_0')
        self.assertIs(hash.dummy_0, alt_dummy_0)
        unload_handler_name('dummy_0')

        #check lazy load w/ wrong type fails
        register_crypt_handler_path('dummy_x', 'passlib.tests.test_registry')
        self.assertRaises(TypeError, get_crypt_handler, 'dummy_x')

        #check lazy load w/ wrong name fails
        register_crypt_handler_path('alt_dummy_0', 'passlib.tests.test_registry')
        self.assertRaises(ValueError, get_crypt_handler, "alt_dummy_0")

        #TODO: check lazy load which calls register_crypt_handler (warning should be issued)
        sys.modules.pop("passlib.tests._test_bad_register", None)
        register_crypt_handler_path("dummy_bad", "passlib.tests._test_bad_register")
        with catch_warnings():
            warnings.filterwarnings("ignore", "xxxxxxxxxx", DeprecationWarning)
            h = get_crypt_handler("dummy_bad")
        from passlib.tests import _test_bad_register as tbr
        self.assertIs(h, tbr.alt_dummy_bad)

    def test_register_crypt_handler(self):
        "test register_crypt_handler()"

        self.assertRaises(TypeError, register_crypt_handler, {})

        self.assertRaises(ValueError, register_crypt_handler, SimpleHandler)
        self.assertRaises(ValueError, register_crypt_handler, type('x', (SimpleHandler,), dict(name="AB_CD")))
        self.assertRaises(ValueError, register_crypt_handler, type('x', (SimpleHandler,), dict(name="ab-cd")))

        class dummy_1(SimpleHandler):
            name = "dummy_1"

        class dummy_1b(SimpleHandler):
            name = "dummy_1"

        self.assertTrue('dummy_1' not in list_crypt_handlers())

        register_crypt_handler(dummy_1)
        register_crypt_handler(dummy_1)
        self.assertIs(get_crypt_handler("dummy_1"), dummy_1)

        self.assertRaises(KeyError, register_crypt_handler, dummy_1b)
        self.assertIs(get_crypt_handler("dummy_1"), dummy_1)

        register_crypt_handler(dummy_1b, force=True)
        self.assertIs(get_crypt_handler("dummy_1"), dummy_1b)

        self.assertTrue('dummy_1' in list_crypt_handlers())

    def test_get_crypt_handler(self):
        "test get_crypt_handler()"

        class dummy_1(SimpleHandler):
            name = "dummy_1"

        self.assertRaises(KeyError, get_crypt_handler, "dummy_1")

        register_crypt_handler(dummy_1)
        self.assertIs(get_crypt_handler("dummy_1"), dummy_1)

        with catch_warnings():
            warnings.filterwarnings("ignore", "handler names be lower-case, and use underscores instead of hyphens:.*", UserWarning)
            self.assertIs(get_crypt_handler("DUMMY-1"), dummy_1)

#=========================================================
#EOF
#=========================================================
