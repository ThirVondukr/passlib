"""tests for passlib.pwhash -- (c) Assurance Technologies 2003-2009"""
#=========================================================
#imports
#=========================================================
from __future__ import with_statement
#core
import hashlib
from logging import getLogger
#site
#pkg
import passlib as mod
from passlib.tests.utils import TestCase
#module
log = getLogger(__name__)

#NOTE: this is commented out until frontend added back (if ever)
###=========================================================
###pull crypt tests
###=========================================================
##def get_crypt_cases():
##
##    #this test suite uses info stored in the specific hash algs' test suites,
##    #so we have to import them here.
##    from passlib.tests.test_drivers import Sha256CryptTest, Sha512CryptTest, DesCryptTest, BCryptTest, Md5CryptTest
##
##    crypt_cases = [ DesCryptTest, Md5CryptTest, Sha256CryptTest]
##    if BCryptTest:
##        crypt_cases.append(BCryptTest)
##    crypt_cases.extend([ Sha512CryptTest ])
##
##    return crypt_cases
##
###=========================================================
###quick access functions
###=========================================================
##class QuickAccessTest(TestCase):
##    "test quick access functions"
##
##    crypt_cases = get_crypt_cases()
##
##    def test_00_identify(self):
##        "test pwhash.identify()"
##        identify = mod.identify
##        for cc in self.crypt_cases:
##            name = cc.handler.name
##            for _, hash in cc.known_correct_hashes:
##                self.assertEqual(identify(hash), name)
##            for other, hash in cc.known_other_hashes:
##                if other == name:
##                    self.assertEqual(identify(hash), name)
##                else:
##                    self.assertNotEqual(identify(hash), name)
##            for hash in cc.known_unidentified_hashes:
##                self.assertEqual(identify(hash), None)
##
##    def test_01_verify(self):
##        "test pwhash.verify()"
##        verify = mod.verify
##        for cc in self.crypt_cases:
##            name = cc.handler.name
##            for secret, hash in cc.known_correct_hashes[:3]:
##                self.assert_(verify(secret, hash))
##                self.assert_(verify(secret, hash, alg=name))
##            for hash in cc.known_unidentified_hashes[:3]:
##                #context should raise ValueError because can't be identified
##                self.assertRaises(ValueError, verify, secret, hash)
##
##    def test_02_encrypt(self):
##        "test pwhash.encrypt()"
##        identify = mod.identify
##        verify = mod.verify
##        encrypt = mod.encrypt
##        for cc in self.crypt_cases:
##            handler = cc.handler
##            name = handler.name
##            s = 'test'
##            h = encrypt(s, alg=name)
##            self.assertEqual(identify(h), name)
##            self.assertEqual(verify(s, h), True)
##            if hasattr(handler, "parse"):
##                info = handler.parse(h)
##                del info['checksum']
##                h2 = encrypt(s, alg=name, **info)
##                self.assertEqual(identify(h2), name, "failed to identify %r rehash %r of hash %r from secret %r:" % (name, h2, h, s))
##                self.assertEqual(verify(s, h2, alg=name), True)
##
##    def test_04_default_context(self):
##        "test pwhash.default_context contents"
##        dc = mod.default_context
##        for case in self.crypt_cases:
##            self.assert_(dc.lookup(case.handler.name) is case.handler)
##
##        last = 'sha512-crypt'
##        self.assertEqual(dc.lookup().name, last)
##        h = dc.encrypt("test")
##        self.assertEqual(dc.identify(h).name, last)
##        self.assertEqual(dc.verify('test', h, alg=last), True)

#=========================================================
#EOF
#=========================================================
