"""tests for passlib.apache -- (c) Assurance Technologies 2008-2011"""
#=========================================================
#imports
#=========================================================
from __future__ import with_statement
#core
import hashlib
from logging import getLogger
import os
import time
#site
#pkg
from passlib import apache
from passlib.utils.compat import irange, unicode
from passlib.tests.utils import TestCase, mktemp, gae_env, get_file, set_file
from passlib.utils.compat import b, bytes, u
#module
log = getLogger(__name__)

def backdate_file_mtime(path, offset=10):
    "backdate file's mtime by specified amount"
    #NOTE: this is used so we can test code which detects mtime changes,
    # without having to actually *pause* for that long.
    atime = os.path.getatime(path)
    mtime = os.path.getmtime(path)-offset
    os.utime(path, (atime, mtime))

#=========================================================
#htpasswd
#=========================================================
class HtpasswdFileTest(TestCase):
    "test HtpasswdFile class"
    descriptionPrefix = "HtpasswdFile"

    # sample with 4 users
    sample_01 = b('user2:2CHkkwa2AtqGs\n'
                  'user3:{SHA}3ipNV1GrBtxPmHFC21fCbVCSXIo=\n'
                  'user4:pass4\n'
                  'user1:$apr1$t4tc7jTh$GPIWVUo8sQKJlUdV8V5vu0\n')

    # sample 1 with user 1, 2 deleted; 4 changed
    sample_02 = b('user3:{SHA}3ipNV1GrBtxPmHFC21fCbVCSXIo=\nuser4:pass4\n')

    # sample 1 with user2 updated, user 1 first entry removed, and user 5 added
    sample_03 = b('user2:pass2x\n'
                  'user3:{SHA}3ipNV1GrBtxPmHFC21fCbVCSXIo=\n'
                  'user4:pass4\n'
                  'user1:$apr1$t4tc7jTh$GPIWVUo8sQKJlUdV8V5vu0\n'
                  'user5:pass5\n')

    # standalone sample with 8-bit username
    sample_04_utf8 = b('user\xc3\xa6:2CHkkwa2AtqGs\n')
    sample_04_latin1 = b('user\xe6:2CHkkwa2AtqGs\n')

    sample_dup = b('user1:pass1\nuser1:pass2\n')

    def test_00_constructor_autoload(self):
        "test constructor autoload"
        if gae_env:
            return self.skipTest("GAE doesn't offer read/write filesystem access")

        # check with existing file
        path = mktemp()
        set_file(path, self.sample_01)
        ht = apache.HtpasswdFile(path)
        self.assertEqual(ht.to_string(), self.sample_01)

        # check without autoload
        ht = apache.HtpasswdFile(path, new=True)
        self.assertEqual(ht.to_string(), b(""))

        # check missing file
        os.remove(path)
        self.assertRaises(IOError, apache.HtpasswdFile, path)

        #NOTE: "default_scheme" option checked via set_password() test, among others

    def test_01_delete(self):
        "test delete()"
        ht = apache.HtpasswdFile.from_string(self.sample_01)
        self.assertTrue(ht.delete("user1")) # should delete both entries
        self.assertTrue(ht.delete("user2"))
        self.assertFalse(ht.delete("user5")) # user not present
        self.assertEqual(ht.to_string(), self.sample_02)

        # invalid user
        self.assertRaises(ValueError, ht.delete, "user:")

    def test_01_delete_autosave(self):
        if gae_env:
            return self.skipTest("GAE doesn't offer read/write filesystem access")
        path = mktemp()
        sample = b('user1:pass1\nuser2:pass2\n')
        set_file(path, sample)

        ht = apache.HtpasswdFile(path)
        ht.delete("user1")
        self.assertEqual(get_file(path), sample)

        ht = apache.HtpasswdFile(path, autosave=True)
        ht.delete("user1")
        self.assertEqual(get_file(path), b("user2:pass2\n"))

    def test_02_set_password(self):
        "test set_password()"
        ht = apache.HtpasswdFile.from_string(
            self.sample_01, default_scheme="plaintext")
        self.assertTrue(ht.set_password("user2", "pass2x"))
        self.assertFalse(ht.set_password("user5", "pass5"))
        self.assertEqual(ht.to_string(), self.sample_03)

        # invalid user
        self.assertRaises(ValueError, ht.set_password, "user:", "pass")

    def test_02_set_password_autosave(self):
        if gae_env:
            return self.skipTest("GAE doesn't offer read/write filesystem access")
        path = mktemp()
        sample = b('user1:pass1\n')
        set_file(path, sample)

        ht = apache.HtpasswdFile(path)
        ht.set_password("user1", "pass2")
        self.assertEqual(get_file(path), sample)

        ht = apache.HtpasswdFile(path, default_scheme="plaintext", autosave=True)
        ht.set_password("user1", "pass2")
        self.assertEqual(get_file(path), b("user1:pass2\n"))

    def test_03_users(self):
        "test users()"
        ht = apache.HtpasswdFile.from_string(self.sample_01)
        ht.set_password("user5", "pass5")
        ht.delete("user3")
        ht.set_password("user3", "pass3")
        self.assertEqual(ht.users(), ["user2", "user4", "user1", "user5",
                                      "user3"])

    def test_04_check_password(self):
        "test check_password()"
        ht = apache.HtpasswdFile.from_string(self.sample_01)
        self.assertTrue(ht.check_password("user5","pass5") is None)
        for i in irange(1,5):
            i = str(i)
            self.assertTrue(ht.check_password("user"+i, "pass"+i))
            self.assertTrue(ht.check_password("user"+i, "pass5") is False)

        self.assertRaises(ValueError, ht.check_password, "user:", "pass")

    def test_05_load(self):
        "test load()"
        if gae_env:
            return self.skipTest("GAE doesn't offer read/write filesystem access")

        #setup empty file
        path = mktemp()
        set_file(path, "")
        backdate_file_mtime(path, 5)
        ha = apache.HtpasswdFile(path, default_scheme="plaintext")
        self.assertEqual(ha.to_string(), b(""))

        #make changes, check load_if_changed() does nothing
        ha.set_password("user1", "pass1")
        ha.load_if_changed()
        self.assertEqual(ha.to_string(), b("user1:pass1\n"))

        #change file
        set_file(path, self.sample_01)
        ha.load_if_changed()
        self.assertEqual(ha.to_string(), self.sample_01)

        #make changes, check load() overwrites them
        ha.set_password("user5", "pass5")
        ha.load()
        self.assertEqual(ha.to_string(), self.sample_01)

        #test load w/ no path
        hb = apache.HtpasswdFile()
        self.assertRaises(RuntimeError, hb.load)
        self.assertRaises(RuntimeError, hb.load_if_changed)

        #test load w/ dups and explicit path
        set_file(path, self.sample_dup)
        hc = apache.HtpasswdFile()
        hc.load(path)
        self.assertTrue(hc.check_password('user1','pass1'))

    # NOTE: load_string() tested via from_string(), which is used all over this file

    def test_06_save(self):
        "test save()"
        if gae_env:
            return self.skipTest("GAE doesn't offer read/write filesystem access")

        #load from file
        path = mktemp()
        set_file(path, self.sample_01)
        ht = apache.HtpasswdFile(path)

        #make changes, check they saved
        ht.delete("user1")
        ht.delete("user2")
        ht.save()
        self.assertEqual(get_file(path), self.sample_02)

        #test save w/ no path
        hb = apache.HtpasswdFile(default_scheme="plaintext")
        hb.set_password("user1", "pass1")
        self.assertRaises(RuntimeError, hb.save)

        # test save w/ explicit path
        hb.save(path)
        self.assertEqual(get_file(path), b("user1:pass1\n"))

    def test_07_encodings(self):
        "test 'encoding' kwd"
        # test bad encodings cause failure in constructor
        self.assertRaises(ValueError, apache.HtpasswdFile, encoding="utf-16")

        # check sample utf-8
        ht = apache.HtpasswdFile.from_string(self.sample_04_utf8, encoding="utf-8",
                                             return_unicode=True)
        self.assertEqual(ht.users(), [ u("user\u00e6") ])

        # check sample latin-1
        ht = apache.HtpasswdFile.from_string(self.sample_04_latin1,
                                              encoding="latin-1", return_unicode=True)
        self.assertEqual(ht.users(), [ u("user\u00e6") ])

    def test_08_to_string(self):
        "test to_string"

        # check with known sample
        ht = apache.HtpasswdFile.from_string(self.sample_01)
        self.assertEqual(ht.to_string(), self.sample_01)

        # test blank
        ht = apache.HtpasswdFile()
        self.assertEqual(ht.to_string(), b(""))

    #=========================================================
    #eoc
    #=========================================================

#=========================================================
#htdigest
#=========================================================
class HtdigestFileTest(TestCase):
    "test HtdigestFile class"
    descriptionPrefix = "HtdigestFile"

    # sample with 4 users
    sample_01 = b('user2:realm:549d2a5f4659ab39a80dac99e159ab19\n'
                  'user3:realm:a500bb8c02f6a9170ae46af10c898744\n'
                  'user4:realm:ab7b5d5f28ccc7666315f508c7358519\n'
                  'user1:realm:2a6cf53e7d8f8cf39d946dc880b14128\n')

    # sample 1 with user 1, 2 deleted; 4 changed
    sample_02 = b('user3:realm:a500bb8c02f6a9170ae46af10c898744\n'
                  'user4:realm:ab7b5d5f28ccc7666315f508c7358519\n')

    # sample 1 with user2 updated, user 1 first entry removed, and user 5 added
    sample_03 = b('user2:realm:5ba6d8328943c23c64b50f8b29566059\n'
                  'user3:realm:a500bb8c02f6a9170ae46af10c898744\n'
                  'user4:realm:ab7b5d5f28ccc7666315f508c7358519\n'
                  'user1:realm:2a6cf53e7d8f8cf39d946dc880b14128\n'
                  'user5:realm:03c55fdc6bf71552356ad401bdb9af19\n')

    # standalone sample with 8-bit username & realm
    sample_04_utf8 = b('user\xc3\xa6:realm\xc3\xa6:549d2a5f4659ab39a80dac99e159ab19\n')
    sample_04_latin1 = b('user\xe6:realm\xe6:549d2a5f4659ab39a80dac99e159ab19\n')

    def test_00_constructor_autoload(self):
        "test constructor autoload"
        if gae_env:
            return self.skipTest("GAE doesn't offer read/write filesystem access")

        # check with existing file
        path = mktemp()
        set_file(path, self.sample_01)
        ht = apache.HtdigestFile(path)
        self.assertEqual(ht.to_string(), self.sample_01)

        # check without autoload
        ht = apache.HtdigestFile(path, new=True)
        self.assertEqual(ht.to_string(), b(""))

        # check missing file
        os.remove(path)
        self.assertRaises(IOError, apache.HtdigestFile, path)

        # NOTE: default_realm option checked via other tests.

    def test_01_delete(self):
        "test delete()"
        ht = apache.HtdigestFile.from_string(self.sample_01)
        self.assertTrue(ht.delete("user1", "realm"))
        self.assertTrue(ht.delete("user2", "realm"))
        self.assertFalse(ht.delete("user5", "realm"))
        self.assertFalse(ht.delete("user3", "realm5"))
        self.assertEqual(ht.to_string(), self.sample_02)

        # invalid user
        self.assertRaises(ValueError, ht.delete, "user:", "realm")

        # invalid realm
        self.assertRaises(ValueError, ht.delete, "user", "realm:")

    def test_01_delete_autosave(self):
        if gae_env:
            return self.skipTest("GAE doesn't offer read/write filesystem access")
        path = mktemp()
        set_file(path, self.sample_01)

        ht = apache.HtdigestFile(path)
        self.assertTrue(ht.delete("user1", "realm"))
        self.assertFalse(ht.delete("user3", "realm5"))
        self.assertFalse(ht.delete("user5", "realm"))
        self.assertEqual(get_file(path), self.sample_01)

        ht.autosave = True
        self.assertTrue(ht.delete("user2", "realm"))
        self.assertEqual(get_file(path), self.sample_02)

    def test_02_set_password(self):
        "test update()"
        ht = apache.HtdigestFile.from_string(self.sample_01)
        self.assertTrue(ht.set_password("user2", "realm", "pass2x"))
        self.assertFalse(ht.set_password("user5", "realm", "pass5"))
        self.assertEqual(ht.to_string(), self.sample_03)

        # default realm
        self.assertRaises(TypeError, ht.set_password, "user2", "pass3")
        ht.default_realm = "realm2"
        ht.set_password("user2", "pass3")
        ht.check_password("user2", "realm2", "pass3")

        # invalid user
        self.assertRaises(ValueError, ht.set_password, "user:", "realm", "pass")
        self.assertRaises(ValueError, ht.set_password, "u"*256, "realm", "pass")

        # invalid realm
        self.assertRaises(ValueError, ht.set_password, "user", "realm:", "pass")
        self.assertRaises(ValueError, ht.set_password, "user", "r"*256, "pass")

    # TODO: test set_password autosave

    def test_03_users(self):
        "test users()"
        ht = apache.HtdigestFile.from_string(self.sample_01)
        ht.set_password("user5", "realm", "pass5")
        ht.delete("user3", "realm")
        ht.set_password("user3", "realm", "pass3")
        self.assertEqual(ht.users("realm"), ["user2", "user4", "user1", "user5", "user3"])

    def test_04_check_password(self):
        "test check_password()"
        ht = apache.HtdigestFile.from_string(self.sample_01)
        self.assertIs(ht.check_password("user5", "realm","pass5"), None)
        for i in irange(1,5):
            i = str(i)
            self.assertTrue(ht.check_password("user"+i, "realm", "pass"+i))
            self.assertIs(ht.check_password("user"+i, "realm", "pass5"), False)

        # default realm
        self.assertRaises(TypeError, ht.check_password, "user5", "pass5")
        ht.default_realm = "realm"
        self.assertTrue(ht.check_password("user1", "pass1"))
        self.assertIs(ht.check_password("user5", "pass5"), None)

        # invalid user
        self.assertRaises(ValueError, ht.check_password, "user:", "realm", "pass")

    def test_05_load(self):
        "test load()"
        if gae_env:
            return self.skipTest("GAE doesn't offer read/write filesystem access")

        #setup empty file
        path = mktemp()
        set_file(path, "")
        backdate_file_mtime(path, 5)
        ha = apache.HtdigestFile(path)
        self.assertEqual(ha.to_string(), b(""))

        #make changes, check load_if_changed() does nothing
        ha.set_password("user1", "realm", "pass1")
        ha.load_if_changed()
        self.assertEqual(ha.to_string(), b('user1:realm:2a6cf53e7d8f8cf39d946dc880b14128\n'))

        #change file
        set_file(path, self.sample_01)
        ha.load_if_changed()
        self.assertEqual(ha.to_string(), self.sample_01)

        #make changes, check force=True overwrites them
        ha.set_password("user5", "realm", "pass5")
        ha.load()
        self.assertEqual(ha.to_string(), self.sample_01)

        #test load w/ no path
        hb = apache.HtdigestFile()
        self.assertRaises(RuntimeError, hb.load)
        self.assertRaises(RuntimeError, hb.load_if_changed)

        # test load w/ explicit path
        hc = apache.HtdigestFile()
        hc.load(path)
        self.assertEqual(hc.to_string(), self.sample_01)

    def test_06_save(self):
        "test save()"
        if gae_env:
            return self.skipTest("GAE doesn't offer read/write filesystem access")

        #load from file
        path = mktemp()
        set_file(path, self.sample_01)
        ht = apache.HtdigestFile(path)

        #make changes, check they saved
        ht.delete("user1", "realm")
        ht.delete("user2", "realm")
        ht.save()
        self.assertEqual(get_file(path), self.sample_02)

        #test save w/ no path
        hb = apache.HtdigestFile()
        hb.set_password("user1", "realm", "pass1")
        self.assertRaises(RuntimeError, hb.save)

        # test save w/ explicit path
        hb.save(path)
        self.assertEqual(get_file(path), hb.to_string())

    def test_07_realms(self):
        "test realms() & delete_realm()"
        ht = apache.HtdigestFile.from_string(self.sample_01)

        self.assertEqual(ht.delete_realm("x"), 0)
        self.assertEqual(ht.realms(), ['realm'])

        self.assertEqual(ht.delete_realm("realm"), 4)
        self.assertEqual(ht.realms(), [])
        self.assertEqual(ht.to_string(), b(""))

    def test_08_get_hash(self):
        "test get_hash()"
        ht = apache.HtdigestFile.from_string(self.sample_01)
        self.assertEqual(ht.get_hash("user3", "realm"), "a500bb8c02f6a9170ae46af10c898744")
        self.assertEqual(ht.get_hash("user4", "realm"), "ab7b5d5f28ccc7666315f508c7358519")
        self.assertEqual(ht.get_hash("user5", "realm"), None)

    def test_09_encodings(self):
        "test encoding parameter"
        # test bad encodings cause failure in constructor
        self.assertRaises(ValueError, apache.HtdigestFile, encoding="utf-16")

        # check sample utf-8
        ht = apache.HtdigestFile.from_string(self.sample_04_utf8, encoding="utf-8", return_unicode=True)
        self.assertEqual(ht.realms(), [ u("realm\u00e6") ])
        self.assertEqual(ht.users(u("realm\u00e6")), [ u("user\u00e6") ])

        # check sample latin-1
        ht = apache.HtdigestFile.from_string(self.sample_04_latin1, encoding="latin-1", return_unicode=True)
        self.assertEqual(ht.realms(), [ u("realm\u00e6") ])
        self.assertEqual(ht.users(u("realm\u00e6")), [ u("user\u00e6") ])

    def test_10_to_string(self):
        "test to_string()"

        # check sample
        ht = apache.HtdigestFile.from_string(self.sample_01)
        self.assertEqual(ht.to_string(), self.sample_01)

        # check blank
        ht = apache.HtdigestFile()
        self.assertEqual(ht.to_string(), b(""))

    #=========================================================
    #eoc
    #=========================================================

#=========================================================
#EOF
#=========================================================
