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
from passlib.tests.utils import TestCase, mktemp
#module
log = getLogger(__name__)

def set_file(path, content):
    with file(path, "wb") as fh:
        fh.write(content)

def get_file(path):
    with file(path, "rb") as fh:
        return fh.read()

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
    case_prefix = "HtpasswdFile"

    sample_01 = 'user2:2CHkkwa2AtqGs\nuser3:{SHA}3ipNV1GrBtxPmHFC21fCbVCSXIo=\nuser4:pass4\nuser1:$apr1$t4tc7jTh$GPIWVUo8sQKJlUdV8V5vu0\n'
    sample_02 = 'user3:{SHA}3ipNV1GrBtxPmHFC21fCbVCSXIo=\nuser4:pass4\n'
    sample_03 = 'user2:pass2x\nuser3:{SHA}3ipNV1GrBtxPmHFC21fCbVCSXIo=\nuser4:pass4\nuser1:$apr1$t4tc7jTh$GPIWVUo8sQKJlUdV8V5vu0\nuser5:pass5\n'

    sample_dup = 'user1:pass1\nuser1:pass2\n'

    def test_00_constructor(self):
        "test constructor & to_string()"
        #check with existing file
        path = mktemp()
        set_file(path, self.sample_01)
        ht = apache.HtpasswdFile(path)
        self.assertEqual(ht.to_string(), self.sample_01)

        #check autoload=False
        ht = apache.HtpasswdFile(path, autoload=False)
        self.assertEqual(ht.to_string(), "")

        #check missing file
        os.remove(path)
        self.assertRaises(IOError, apache.HtpasswdFile, path)

        #check no path
        ht = apache.HtpasswdFile()
        self.assertEqual(ht.to_string(), "")

        #NOTE: "default" option checked via update() test, among others

    def test_01_delete(self):
        "test delete()"
        path = mktemp()
        set_file(path, self.sample_01)
        ht = apache.HtpasswdFile(path)
        self.assert_(ht.delete("user1"))
        self.assert_(ht.delete("user2"))
        self.assert_(not ht.delete("user5"))
        self.assertEqual(ht.to_string(), self.sample_02)

        self.assertRaises(ValueError, ht.delete, "user:")

    def test_02_update(self):
        "test update()"
        path = mktemp()
        set_file(path, self.sample_01)
        ht = apache.HtpasswdFile(path, default="plaintext")
        self.assert_(ht.update("user2", "pass2x"))
        self.assert_(not ht.update("user5", "pass5"))
        self.assertEqual(ht.to_string(), self.sample_03)

        self.assertRaises(ValueError, ht.update, "user:", "pass")

    def test_03_users(self):
        "test users()"
        path = mktemp()
        set_file(path, self.sample_01)
        ht = apache.HtpasswdFile(path)
        ht.update("user5", "pass5")
        ht.delete("user3")
        ht.update("user3", "pass3")
        self.assertEqual(ht.users(), ["user2", "user4", "user1", "user5", "user3"])

    def test_03_verify(self):
        "test verify()"
        path = mktemp()
        set_file(path, self.sample_01)
        ht = apache.HtpasswdFile(path)
        self.assert_(ht.verify("user5","pass5") is None)
        for i in xrange(1,5):
            i = str(i)
            self.assert_(ht.verify("user"+i, "pass"+i))
            self.assert_(ht.verify("user"+i, "pass5") is False)

        self.assertRaises(ValueError, ht.verify, "user:", "pass")

    def test_04_load(self):
        "test load()"

        #setup empty file
        path = mktemp()
        set_file(path, "")
        backdate_file_mtime(path, 5)
        ha = apache.HtpasswdFile(path, default="plaintext")
        self.assertEqual(ha.to_string(), "")

        #make changes, check force=False does nothing
        ha.update("user1", "pass1")
        ha.load(force=False)
        self.assertEqual(ha.to_string(), "user1:pass1\n")

        #change file
        set_file(path, self.sample_01)
        ha.load(force=False)
        self.assertEqual(ha.to_string(), self.sample_01)

        #make changes, check force=True overwrites them
        ha.update("user5", "pass5")
        ha.load()
        self.assertEqual(ha.to_string(), self.sample_01)

        #test load w/ no path
        hb = apache.HtpasswdFile()
        self.assertRaises(RuntimeError, hb.load)
        self.assertRaises(RuntimeError, hb.load, force=False)

        #test load w/ dups
        set_file(path, self.sample_dup)
        hc = apache.HtpasswdFile(path)
        self.assert_(hc.verify('user1','pass1'))

    def test_05_save(self):
        "test save()"
        #load from file
        path = mktemp()
        set_file(path, self.sample_01)
        ht = apache.HtpasswdFile(path)

        #make changes, check they saved
        ht.delete("user1")
        ht.delete("user2")
        ht.save()
        self.assertEquals(get_file(path), self.sample_02)

        #test save w/ no path
        hb = apache.HtpasswdFile()
        hb.update("user1", "pass1")
        self.assertRaises(RuntimeError, hb.save)

    #=========================================================
    #eoc
    #=========================================================

#=========================================================
#htdigest
#=========================================================
class HtdigestFileTest(TestCase):
    "test HtdigestFile class"
    case_prefix = "HtdigestFile"

    sample_01 = 'user2:realm:549d2a5f4659ab39a80dac99e159ab19\nuser3:realm:a500bb8c02f6a9170ae46af10c898744\nuser4:realm:ab7b5d5f28ccc7666315f508c7358519\nuser1:realm:2a6cf53e7d8f8cf39d946dc880b14128\n'
    sample_02 = 'user3:realm:a500bb8c02f6a9170ae46af10c898744\nuser4:realm:ab7b5d5f28ccc7666315f508c7358519\n'
    sample_03 = 'user2:realm:5ba6d8328943c23c64b50f8b29566059\nuser3:realm:a500bb8c02f6a9170ae46af10c898744\nuser4:realm:ab7b5d5f28ccc7666315f508c7358519\nuser1:realm:2a6cf53e7d8f8cf39d946dc880b14128\nuser5:realm:03c55fdc6bf71552356ad401bdb9af19\n'

    def test_00_constructor(self):
        "test constructor & to_string()"
        #check with existing file
        path = mktemp()
        set_file(path, self.sample_01)
        ht = apache.HtdigestFile(path)
        self.assertEqual(ht.to_string(), self.sample_01)

        #check autoload=False
        ht = apache.HtdigestFile(path, autoload=False)
        self.assertEqual(ht.to_string(), "")

        #check missing file
        os.remove(path)
        self.assertRaises(IOError, apache.HtdigestFile, path)

        #check no path
        ht = apache.HtdigestFile()
        self.assertEqual(ht.to_string(), "")

    def test_01_delete(self):
        "test delete()"
        path = mktemp()
        set_file(path, self.sample_01)
        ht = apache.HtdigestFile(path)
        self.assert_(ht.delete("user1", "realm"))
        self.assert_(ht.delete("user2", "realm"))
        self.assert_(not ht.delete("user5", "realm"))
        self.assertEqual(ht.to_string(), self.sample_02)

        self.assertRaises(ValueError, ht.delete, "user:", "realm")

    def test_02_update(self):
        "test update()"
        path = mktemp()
        set_file(path, self.sample_01)
        ht = apache.HtdigestFile(path)
        self.assert_(ht.update("user2", "realm", "pass2x"))
        self.assert_(not ht.update("user5", "realm", "pass5"))
        self.assertEqual(ht.to_string(), self.sample_03)

        self.assertRaises(ValueError, ht.update, "user:", "realm", "pass")
        self.assertRaises(ValueError, ht.update, "u"*256, "realm", "pass")

        self.assertRaises(ValueError, ht.update, "user", "realm:", "pass")
        self.assertRaises(ValueError, ht.update, "user", "r"*256, "pass")

    def test_03_users(self):
        "test users()"
        path = mktemp()
        set_file(path, self.sample_01)
        ht = apache.HtdigestFile(path)
        ht.update("user5", "realm", "pass5")
        ht.delete("user3", "realm")
        ht.update("user3", "realm", "pass3")
        self.assertEqual(ht.users("realm"), ["user2", "user4", "user1", "user5", "user3"])

    def test_03_verify(self):
        "test verify()"
        path = mktemp()
        set_file(path, self.sample_01)
        ht = apache.HtdigestFile(path)
        self.assert_(ht.verify("user5", "realm","pass5") is None)
        for i in xrange(1,5):
            i = str(i)
            self.assert_(ht.verify("user"+i, "realm", "pass"+i))
            self.assert_(ht.verify("user"+i, "realm", "pass5") is False)

        self.assertRaises(ValueError, ht.verify, "user:", "realm", "pass")

    def test_04_load(self):
        "test load()"

        #setup empty file
        path = mktemp()
        set_file(path, "")
        backdate_file_mtime(path, 5)
        ha = apache.HtdigestFile(path)
        self.assertEqual(ha.to_string(), "")

        #make changes, check force=False does nothing
        ha.update("user1", "realm", "pass1")
        ha.load(force=False)
        self.assertEqual(ha.to_string(), 'user1:realm:2a6cf53e7d8f8cf39d946dc880b14128\n')

        #change file
        set_file(path, self.sample_01)
        ha.load(force=False)
        self.assertEqual(ha.to_string(), self.sample_01)

        #make changes, check force=True overwrites them
        ha.update("user5", "realm", "pass5")
        ha.load()
        self.assertEqual(ha.to_string(), self.sample_01)

        #test load w/ no path
        hb = apache.HtdigestFile()
        self.assertRaises(RuntimeError, hb.load)
        self.assertRaises(RuntimeError, hb.load, force=False)

    def test_05_save(self):
        "test save()"
        #load from file
        path = mktemp()
        set_file(path, self.sample_01)
        ht = apache.HtdigestFile(path)

        #make changes, check they saved
        ht.delete("user1", "realm")
        ht.delete("user2", "realm")
        ht.save()
        self.assertEquals(get_file(path), self.sample_02)

        #test save w/ no path
        hb = apache.HtdigestFile()
        hb.update("user1", "realm", "pass1")
        self.assertRaises(RuntimeError, hb.save)

    def test_06_realms(self):
        "test realms() & delete_realm()"
        path = mktemp()
        set_file(path, self.sample_01)
        ht = apache.HtdigestFile(path)

        self.assertEquals(ht.delete_realm("x"), 0)
        self.assertEquals(ht.realms(), ['realm'])

        self.assertEquals(ht.delete_realm("realm"), 4)
        self.assertEquals(ht.realms(), [])
        self.assertEquals(ht.to_string(), "")

    def test_07_find(self):
        "test find()"
        path = mktemp()
        set_file(path, self.sample_01)
        ht = apache.HtdigestFile(path)
        self.assertEquals(ht.find("user3", "realm"), "a500bb8c02f6a9170ae46af10c898744")
        self.assertEquals(ht.find("user4", "realm"), "ab7b5d5f28ccc7666315f508c7358519")
        self.assertEquals(ht.find("user5", "realm"), None)

    #=========================================================
    #eoc
    #=========================================================

#=========================================================
#EOF
#=========================================================
