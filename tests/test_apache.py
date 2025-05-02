import os
import subprocess
import unittest

import pytest

from passlib import apache
from passlib._logging import logger
from passlib.utils.handlers import to_unicode_for_identify
from tests.utils import TestCase, get_file, set_file
from tests.utils_ import backdate_file_mtime

htpasswd_path = os.environ.get("PASSLIB_TEST_HTPASSWD_PATH") or "htpasswd"


def _call_htpasswd(args, stdin=None):
    """
    helper to run htpasswd cmd
    """
    if stdin is not None:
        stdin = stdin.encode("utf-8")
    proc = subprocess.Popen(
        [htpasswd_path] + args,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        stdin=subprocess.PIPE if stdin else None,
    )
    out, err = proc.communicate(stdin)
    rc = proc.wait()
    out = to_unicode_for_identify(out or "")
    return out, rc


def _call_htpasswd_verify(path, user, password):
    """
    wrapper for htpasswd verify
    """
    out, rc = _call_htpasswd(["-vi", path, user], password)
    return not rc


def _detect_htpasswd():
    """
    helper to check if htpasswd is present
    """
    try:
        out, rc = _call_htpasswd([])
    except OSError:
        # TODO: under py3, could trap the more specific FileNotFoundError
        # cmd not found
        return False, False
    # when called w/o args, it should print usage to stderr & return rc=2
    if not rc:
        logger.warning("htpasswd test returned with rc=0")
    have_bcrypt = " -B " in out
    return True, have_bcrypt


HAVE_HTPASSWD, HAVE_HTPASSWD_BCRYPT = _detect_htpasswd()

requires_htpasswd_cmd = unittest.skipUnless(
    HAVE_HTPASSWD, "requires `htpasswd` cmdline tool"
)


class HtdigestFileTest(TestCase):
    """test HtdigestFile class"""

    descriptionPrefix = "HtdigestFile"

    # sample with 4 users
    sample_01 = (
        b"user2:realm:549d2a5f4659ab39a80dac99e159ab19\n"
        b"user3:realm:a500bb8c02f6a9170ae46af10c898744\n"
        b"user4:realm:ab7b5d5f28ccc7666315f508c7358519\n"
        b"user1:realm:2a6cf53e7d8f8cf39d946dc880b14128\n"
    )

    # sample 1 with user 1, 2 deleted; 4 changed
    sample_02 = (
        b"user3:realm:a500bb8c02f6a9170ae46af10c898744\n"
        b"user4:realm:ab7b5d5f28ccc7666315f508c7358519\n"
    )

    # sample 1 with user2 updated, user 1 first entry removed, and user 5 added
    sample_03 = (
        b"user2:realm:5ba6d8328943c23c64b50f8b29566059\n"
        b"user3:realm:a500bb8c02f6a9170ae46af10c898744\n"
        b"user4:realm:ab7b5d5f28ccc7666315f508c7358519\n"
        b"user1:realm:2a6cf53e7d8f8cf39d946dc880b14128\n"
        b"user5:realm:03c55fdc6bf71552356ad401bdb9af19\n"
    )

    # standalone sample with 8-bit username & realm
    sample_04_utf8 = b"user\xc3\xa6:realm\xc3\xa6:549d2a5f4659ab39a80dac99e159ab19\n"
    sample_04_latin1 = b"user\xe6:realm\xe6:549d2a5f4659ab39a80dac99e159ab19\n"

    def test_00_constructor_autoload(self):
        """test constructor autoload"""
        # check with existing file
        path = self.mktemp()
        set_file(path, self.sample_01)
        ht = apache.HtdigestFile(path)
        assert ht.to_string() == self.sample_01

        # check without autoload
        ht = apache.HtdigestFile(path, new=True)
        assert ht.to_string() == b""

        # check missing file
        os.remove(path)
        with pytest.raises(IOError):
            apache.HtdigestFile(path)

    def test_01_delete(self):
        """test delete()"""
        ht = apache.HtdigestFile.from_string(self.sample_01)
        assert ht.delete("user1", "realm")
        assert ht.delete("user2", "realm")
        assert not ht.delete("user5", "realm")
        assert not ht.delete("user3", "realm5")
        assert ht.to_string() == self.sample_02

        # invalid user
        with pytest.raises(ValueError):
            ht.delete("user:", "realm")

        # invalid realm
        with pytest.raises(ValueError):
            ht.delete("user", "realm:")

    def test_01_delete_autosave(self):
        path = self.mktemp()
        set_file(path, self.sample_01)

        ht = apache.HtdigestFile(path)
        assert ht.delete("user1", "realm")
        assert not ht.delete("user3", "realm5")
        assert not ht.delete("user5", "realm")
        assert get_file(path) == self.sample_01

        ht.autosave = True
        assert ht.delete("user2", "realm")
        assert get_file(path) == self.sample_02

    def test_02_set_password(self):
        """test update()"""
        ht = apache.HtdigestFile.from_string(self.sample_01)
        assert ht.set_password("user2", "realm", "pass2x")
        assert not ht.set_password("user5", "realm", "pass5")
        assert ht.to_string() == self.sample_03

        # default realm
        with pytest.raises(TypeError):
            ht.set_password("user2", "pass3")
        ht.default_realm = "realm2"
        ht.set_password("user2", "pass3")
        ht.check_password("user2", "realm2", "pass3")

        # invalid user
        with pytest.raises(ValueError):
            ht.set_password("user:", "realm", "pass")
        with pytest.raises(ValueError):
            ht.set_password("u" * 256, "realm", "pass")

        # invalid realm
        with pytest.raises(ValueError):
            ht.set_password("user", "realm:", "pass")
        with pytest.raises(ValueError):
            ht.set_password("user", "r" * 256, "pass")

    # TODO: test set_password autosave

    def test_03_users(self):
        """test users()"""
        ht = apache.HtdigestFile.from_string(self.sample_01)
        ht.set_password("user5", "realm", "pass5")
        ht.delete("user3", "realm")
        ht.set_password("user3", "realm", "pass3")
        assert sorted(ht.users("realm")) == [
            "user1",
            "user2",
            "user3",
            "user4",
            "user5",
        ]

        with pytest.raises(TypeError):
            ht.users(1)

    def test_04_check_password(self):
        """test check_password()"""
        ht = apache.HtdigestFile.from_string(self.sample_01)
        with pytest.raises(TypeError):
            ht.check_password(1, "realm", "pass5")
        with pytest.raises(TypeError):
            ht.check_password("user", 1, "pass5")
        assert ht.check_password("user5", "realm", "pass5") is None
        for i in range(1, 5):
            i = str(i)
            assert ht.check_password("user" + i, "realm", "pass" + i)
            assert ht.check_password("user" + i, "realm", "pass5") is False

        # default realm
        with pytest.raises(TypeError):
            ht.check_password("user5", "pass5")
        ht.default_realm = "realm"
        assert ht.check_password("user1", "pass1")
        assert ht.check_password("user5", "pass5") is None

        # invalid user
        with pytest.raises(ValueError):
            ht.check_password("user:", "realm", "pass")

    def test_05_load(self):
        """test load()"""
        # setup empty file
        path = self.mktemp()
        set_file(path, "")
        backdate_file_mtime(path, 5)
        ha = apache.HtdigestFile(path)
        assert ha.to_string() == b""

        # make changes, check load_if_changed() does nothing
        ha.set_password("user1", "realm", "pass1")
        ha.load_if_changed()
        assert ha.to_string() == b"user1:realm:2a6cf53e7d8f8cf39d946dc880b14128\n"

        # change file
        set_file(path, self.sample_01)
        ha.load_if_changed()
        assert ha.to_string() == self.sample_01

        # make changes, check load_if_changed overwrites them
        ha.set_password("user5", "realm", "pass5")
        ha.load()
        assert ha.to_string() == self.sample_01

        # test load w/ no path
        hb = apache.HtdigestFile()
        with pytest.raises(RuntimeError):
            hb.load()
        with pytest.raises(RuntimeError):
            hb.load_if_changed()

        # test load w/ explicit path
        hc = apache.HtdigestFile()
        hc.load(path)
        assert hc.to_string() == self.sample_01

    def test_06_save(self):
        """test save()"""
        # load from file
        path = self.mktemp()
        set_file(path, self.sample_01)
        ht = apache.HtdigestFile(path)

        # make changes, check they saved
        ht.delete("user1", "realm")
        ht.delete("user2", "realm")
        ht.save()
        assert get_file(path) == self.sample_02

        # test save w/ no path
        hb = apache.HtdigestFile()
        hb.set_password("user1", "realm", "pass1")
        with pytest.raises(RuntimeError):
            hb.save()

        # test save w/ explicit path
        hb.save(path)
        assert get_file(path) == hb.to_string()

    def test_07_realms(self):
        """test realms() & delete_realm()"""
        ht = apache.HtdigestFile.from_string(self.sample_01)

        assert ht.delete_realm("x") == 0
        assert ht.realms() == ["realm"]

        assert ht.delete_realm("realm") == 4
        assert ht.realms() == []
        assert ht.to_string() == b""

    def test_08_get_hash(self):
        """test get_hash()"""
        ht = apache.HtdigestFile.from_string(self.sample_01)
        assert ht.get_hash("user3", "realm") == "a500bb8c02f6a9170ae46af10c898744"
        assert ht.get_hash("user4", "realm") == "ab7b5d5f28ccc7666315f508c7358519"
        assert ht.get_hash("user5", "realm") is None

    def test_09_encodings(self):
        """test encoding parameter"""
        # test bad encodings cause failure in constructor
        with pytest.raises(ValueError):
            apache.HtdigestFile(encoding="utf-16")

        # check sample utf-8
        ht = apache.HtdigestFile.from_string(
            self.sample_04_utf8, encoding="utf-8", return_unicode=True
        )
        assert ht.realms() == ["realmæ"]
        assert ht.users("realmæ") == ["useræ"]

        # check sample latin-1
        ht = apache.HtdigestFile.from_string(
            self.sample_04_latin1, encoding="latin-1", return_unicode=True
        )
        assert ht.realms() == ["realmæ"]
        assert ht.users("realmæ") == ["useræ"]

    def test_10_to_string(self):
        """test to_string()"""

        # check sample
        ht = apache.HtdigestFile.from_string(self.sample_01)
        assert ht.to_string() == self.sample_01

        # check blank
        ht = apache.HtdigestFile()
        assert ht.to_string() == b""

    def test_11_malformed(self):
        with pytest.raises(ValueError):
            apache.HtdigestFile.from_string(b"realm:user1:pass1:other\n")
        with pytest.raises(ValueError):
            apache.HtdigestFile.from_string(b"user1:pass1\n")
