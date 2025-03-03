from __future__ import annotations

import dataclasses
import os
import subprocess
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Generic, TypeVar

import pytest

from passlib import apache
from passlib.apache import HtdigestFile, HtpasswdFile
from passlib.utils import to_bytes
from passlib.utils.handlers import to_unicode_for_identify
from tests.utils_ import backdate_file_mtime

htpasswd_path = os.environ.get("PASSLIB_TEST_HTPASSWD_PATH") or "htpasswd"
if TYPE_CHECKING:
    from collections.abc import Sequence
    from pathlib import Path


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
    except FileNotFoundError:
        return False, False
    have_bcrypt = " -B " in out
    return True, have_bcrypt


HAS_HTPASSWD, HAS_HTPASSWD_BCRYPT = _detect_htpasswd()

requires_htpasswd = pytest.mark.skipif(
    not HAS_HTPASSWD, reason="requires `htpasswd` cmdline tool"
)

# sample with 4 users
SAMPLE_01 = (
    b"user2:2CHkkwa2AtqGs\n"
    b"user3:{SHA}3ipNV1GrBtxPmHFC21fCbVCSXIo=\n"
    b"user4:pass4\n"
    b"user1:$apr1$t4tc7jTh$GPIWVUo8sQKJlUdV8V5vu0\n"
)

# sample 1 with user 1, 2 deleted; 4 changed
SAMPLE_02 = b"user3:{SHA}3ipNV1GrBtxPmHFC21fCbVCSXIo=\nuser4:pass4\n"

# sample 1 with user2 updated, user 1 first entry removed, and user 5 added
SAMPLE_03 = (
    b"user2:pass2x\n"
    b"user3:{SHA}3ipNV1GrBtxPmHFC21fCbVCSXIo=\n"
    b"user4:pass4\n"
    b"user1:$apr1$t4tc7jTh$GPIWVUo8sQKJlUdV8V5vu0\n"
    b"user5:pass5\n"
)

# standalone sample with 8-bit username
SAMPLE_04_utf8 = b"user\xc3\xa6:2CHkkwa2AtqGs\n"
SAMPLE_04_latin1 = b"user\xe6:2CHkkwa2AtqGs\n"

sample_dup = b"user1:pass1\nuser1:pass2\n"

# sample with bcrypt & sha256_crypt hashes
SAMPLE_05 = (
    b"user2:2CHkkwa2AtqGs\n"
    b"user3:{SHA}3ipNV1GrBtxPmHFC21fCbVCSXIo=\n"
    b"user4:pass4\n"
    b"user1:$apr1$t4tc7jTh$GPIWVUo8sQKJlUdV8V5vu0\n"
    b"user5:$2a$12$yktDxraxijBZ360orOyCOePFGhuis/umyPNJoL5EbsLk.s6SWdrRO\n"
    b"user6:$5$rounds=110000$cCRp/xUUGVgwR4aP$"
    b"p0.QKFS5qLNRqw1/47lXYiAcgIjJK.WjCO8nrEKuUK.\n"
)


@pytest.fixture
def password_file_path(tmp_path: Path) -> Path:
    return tmp_path.joinpath("file")


TApacheFile = TypeVar("TApacheFile", HtpasswdFile, HtdigestFile)


@dataclasses.dataclass
class _TestCaseParams(Generic[TApacheFile]):
    sample_01: bytes
    sample_02: bytes
    sample_03: bytes
    cls: type[TApacheFile]

    load_with_user: bytes


class _BaseTest(ABC, Generic[TApacheFile]):
    @property
    @abstractmethod
    def params(self) -> _TestCaseParams[TApacheFile]:
        raise NotImplementedError

    def _delete(self, file: TApacheFile, user: str) -> bool:
        return file.delete(user)

    def _set_password(self, file: TApacheFile, user: str, password: str) -> bool:
        return file.set_password(user, password)

    def _users(self, file: TApacheFile) -> Sequence[str | bytes]:
        return file.users()

    @pytest.fixture
    def sample_file(self, password_file_path) -> Path:
        password_file_path.write_bytes(self.params.sample_01)
        return password_file_path

    def test_create(self, sample_file: Path) -> None:
        ht = self.params.cls(sample_file)
        assert ht.to_string() == self.params.sample_01
        assert ht.path == sample_file
        assert ht.mtime

    def test_change_path(self, sample_file: Path) -> None:
        ht = self.params.cls(sample_file)
        # check changing path
        ht.path = sample_file / "x"
        assert ht.path == sample_file / "x"
        assert not ht.mtime

    def test_create_new(self, tmp_path: Path) -> None:
        path = tmp_path.joinpath(htpasswd_path)
        ht = self.params.cls(path, new=True)
        assert ht.to_string() == b""
        assert ht.path == path
        assert not ht.mtime

    def test_file_not_found(self, tmp_path: Path) -> None:
        with pytest.raises(IOError):
            self.params.cls(tmp_path.joinpath(htpasswd_path))

    def test_from_file(self, sample_file: Path) -> None:
        htpasswd = self.params.cls.from_path(sample_file)
        assert htpasswd.to_string() == sample_file.read_bytes()
        assert htpasswd.path is None
        assert not htpasswd.mtime

    def test_delete(self, sample_file: Path) -> None:
        ht = self.params.cls.from_string(self.params.sample_01)
        assert self._delete(ht, "user1")
        assert self._delete(ht, "user2")
        assert not self._delete(ht, "user5")
        assert ht.to_string() == self.params.sample_02

    def test_invalid_username(self) -> None:
        err_msg = "user contains invalid characters: b'user:'"
        ht = self.params.cls.from_string("")

        with pytest.raises(ValueError) as exc_info:
            ht.delete("user:")
        assert str(exc_info.value) == err_msg

        with pytest.raises(ValueError) as exc_info:
            self._set_password(ht, "user:", "password")
        assert str(exc_info.value) == err_msg

        with pytest.raises(ValueError) as exc_info:
            ht.check_password("user:", "password")
        assert str(exc_info.value) == err_msg

    def test_users(self) -> None:
        ht = self.params.cls.from_string(self.params.sample_01)
        assert sorted(self._users(ht)) == [f"user{i}" for i in range(1, 4 + 1)]

        self._set_password(ht, "user5", "password")
        assert sorted(self._users(ht)) == [f"user{i}" for i in range(1, 5 + 1)]

    @pytest.fixture
    def ht_from_path(self, password_file_path: Path) -> HtpasswdFile | HtdigestFile:
        password_file_path.touch()
        backdate_file_mtime(password_file_path, 5)

        if issubclass(self.params.cls, HtdigestFile):
            return self.params.cls(password_file_path)
        return self.params.cls(password_file_path, default_scheme="plaintext")

    def test_load(self, password_file_path: Path, ht_from_path: TApacheFile) -> None:
        ht = ht_from_path
        assert ht.to_string() == b""

        # Make changes, check load_if_changed() does nothing
        self._set_password(ht, "user1", "pass1")
        ht.load_if_changed()
        assert ht.to_string() == self.params.load_with_user

        password_file_path.write_bytes(self.params.sample_01)
        ht.load_if_changed()
        assert ht.to_string() == self.params.sample_01

        # Make changes, check load() overwrites them
        self._set_password(ht, "user5", "pass5")
        ht.load()
        assert ht.to_string() == self.params.sample_01

    def test_save(self, sample_file: Path) -> None:
        ht = self.params.cls(sample_file)

        self._delete(ht, "user1")
        self._delete(ht, "user2")
        ht.save()
        assert sample_file.read_bytes() == self.params.sample_02


class TestHtpasswdFile(_BaseTest[HtpasswdFile]):
    params = _TestCaseParams(
        sample_01=SAMPLE_01,
        sample_02=SAMPLE_02,
        sample_03=SAMPLE_03,
        load_with_user=b"user1:pass1\n",
        cls=HtpasswdFile,
    )

    def test_set_password(self):
        ht = self.params.cls.from_string(
            self.params.sample_01, default_scheme="plaintext"
        )
        assert self._set_password(ht, "user2", "pass2x")
        assert not self._set_password(ht, "user5", "pass5")
        assert ht.to_string() == self.params.sample_03

    @pytest.mark.parametrize("autosave", [True, False])
    def test_set_password_autosave(
        self, password_file_path: Path, autosave: bool
    ) -> None:
        sample = b"user1:pass1\n"
        password_file_path.write_bytes(sample)

        expected_file_contents = b"user1:pass2\n" if autosave else sample

        ht = self.params.cls(
            password_file_path, autosave=autosave, default_scheme="plaintext"
        )
        self._set_password(ht, "user1", "pass2")
        assert password_file_path.read_bytes() == expected_file_contents

    @pytest.mark.parametrize("autosave", [True, False])
    def test_delete_autosave(self, password_file_path: Path, autosave: bool) -> None:
        sample = b"user1:pass1\nuser2:pass2\n"
        expected_file_contents = b"user2:pass2\n" if autosave else sample

        password_file_path.write_bytes(b"user1:pass1\nuser2:pass2\n")

        ht = self.params.cls(password_file_path, autosave=autosave)
        self._delete(ht, "user1")
        assert password_file_path.read_bytes() == expected_file_contents

    @pytest.mark.parametrize("scheme", ["sha256_crypt", "des_crypt"])
    def test_set_password_default_scheme(self, scheme: str) -> None:
        ht = self.params.cls(default_scheme=scheme)
        self._set_password(ht, "user1", "pass1")
        assert ht.context.identify(ht.get_hash("user1"))

    def test_check_password(self) -> None:
        ht = apache.HtpasswdFile.from_string(SAMPLE_05)
        with pytest.raises(TypeError):
            ht.check_password(1, "pass")

        for i in range(1, 6 + 1):
            assert ht.check_password(f"user{i}", f"pass{i}")
            assert not ht.check_password(f"user{i}", "pass9")


class TestHtdigestFile(_BaseTest[HtdigestFile]):
    params = _TestCaseParams(
        sample_01=(
            b"user2:realm:549d2a5f4659ab39a80dac99e159ab19\n"
            b"user3:realm:a500bb8c02f6a9170ae46af10c898744\n"
            b"user4:realm:ab7b5d5f28ccc7666315f508c7358519\n"
            b"user1:realm:2a6cf53e7d8f8cf39d946dc880b14128\n"
        ),
        sample_02=(
            b"user3:realm:a500bb8c02f6a9170ae46af10c898744\n"
            b"user4:realm:ab7b5d5f28ccc7666315f508c7358519\n"
        ),
        sample_03=(
            b"user2:realm:5ba6d8328943c23c64b50f8b29566059\n"
            b"user3:realm:a500bb8c02f6a9170ae46af10c898744\n"
            b"user4:realm:ab7b5d5f28ccc7666315f508c7358519\n"
            b"user1:realm:2a6cf53e7d8f8cf39d946dc880b14128\n"
            b"user5:realm:03c55fdc6bf71552356ad401bdb9af19\n"
        ),
        load_with_user=b"user1:realm:2a6cf53e7d8f8cf39d946dc880b14128\n",
        cls=HtdigestFile,
    )
    realm = "realm"

    def _delete(self, file: HtdigestFile, user: str) -> bool:
        return file.delete(user, realm=self.realm)

    def _set_password(self, file: HtdigestFile, user: str, password: str) -> bool:
        return file.set_password(user, realm=self.realm, password=password)

    def _users(self, file: HtdigestFile) -> Sequence[str]:
        return file.users(realm=self.realm)


@pytest.mark.parametrize(
    ("scheme", "alias"),
    [
        ("portable", "portable"),
        ("portable_apache_22", "portable_apache_22"),
        ("host_apache_22", "host_apache_22"),
        (None, "portable_apache_22"),
    ],
)
def test_set_password_default_scheme_alias(scheme: str, alias: str):
    ht = apache.HtpasswdFile(default_scheme=scheme)
    ht.set_password("user1", "pass1")
    assert ht.context.identify(ht.get_hash("user1")) == apache.htpasswd_defaults[alias]


def test_set_password_default_scheme_unknown() -> None:
    with pytest.raises(KeyError) as exc_info:
        apache.HtpasswdFile(default_scheme="unknown")
    assert str(exc_info.value) == "'default scheme not found in policy'"


def test_save_without_path(password_file_path: Path) -> None:
    ht = apache.HtpasswdFile(default_scheme="plaintext")
    ht.set_password("user1", "pass1")
    with pytest.raises(RuntimeError) as exc_info:
        ht.save()
    assert str(exc_info.value) == "HtpasswdFile().path is not set, cannot autosave"

    ht.save(password_file_path)
    assert password_file_path.read_bytes() == b"user1:pass1\n"


def test_encoding_err_incompatible() -> None:
    with pytest.raises(ValueError):
        apache.HtpasswdFile(encoding="utf-16")


def test_encoding_err_none() -> None:
    with pytest.raises(TypeError):
        apache.HtpasswdFile.from_string(
            SAMPLE_04_utf8,
            encoding=None,
        )


@pytest.mark.parametrize(
    ("encoding", "sample"), [("utf-8", SAMPLE_04_utf8), ("latin1", SAMPLE_04_latin1)]
)
def test_encoding_ok(encoding: str, sample: bytes):
    ht = apache.HtpasswdFile.from_string(sample, encoding=encoding, return_unicode=True)
    assert ht.users() == ["user\u00e6"]


def test_get_hash() -> None:
    ht = apache.HtpasswdFile.from_string(SAMPLE_01)
    assert ht.get_hash("user3") == b"{SHA}3ipNV1GrBtxPmHFC21fCbVCSXIo="
    assert ht.get_hash("user4") == b"pass4"
    assert ht.get_hash("user5") is None


def test_to_string() -> None:
    # check with known sample
    ht = apache.HtpasswdFile.from_string(SAMPLE_01)
    assert ht.to_string() == SAMPLE_01

    # test blank
    ht = apache.HtpasswdFile()
    assert ht.to_string() == b""


def test_repr() -> None:
    ht = apache.HtpasswdFile("fakepath", autosave=True, new=True, encoding="latin-1")
    repr(ht)


@pytest.mark.parametrize("sample", [b"realm:user1:pass1\n", b"pass1\n"])
def test_from_string_err_malformed(sample: str):
    with pytest.raises(ValueError):
        apache.HtpasswdFile.from_string(sample)


def test_from_string_err_path_keyword():
    with pytest.raises(TypeError):
        apache.HtpasswdFile.from_string(b"", path=None)


def test_whitespace_handling():
    """whitespace & comment handling"""

    # per htpasswd source (https://github.com/apache/httpd/blob/trunk/support/htpasswd.c),
    # lines that match "^\s*(#.*)?$" should be ignored
    source = to_bytes(
        "\n"
        "user2:pass2\n"
        "user4:pass4\n"
        "user7:pass7\r\n"
        " \t \n"
        "user1:pass1\n"
        " # legacy users\n"
        "#user6:pass6\n"
        "user5:pass5\n\n"
    )

    # loading should see all users (except user6, who was commented out)
    ht = apache.HtpasswdFile.from_string(source)
    assert sorted(ht.users()) == ["user1", "user2", "user4", "user5", "user7"]

    # update existing user
    ht.set_hash("user4", "althash4")
    assert sorted(ht.users()) == ["user1", "user2", "user4", "user5", "user7"]

    # add a new user
    ht.set_hash("user6", "althash6")
    assert sorted(ht.users()) == ["user1", "user2", "user4", "user5", "user6", "user7"]

    # delete existing user
    ht.delete("user7")
    assert sorted(ht.users()) == ["user1", "user2", "user4", "user5", "user6"]

    # re-serialization should preserve whitespace
    target = to_bytes(
        "\n"
        "user2:pass2\n"
        "user4:althash4\n"
        " \t \n"
        "user1:pass1\n"
        " # legacy users\n"
        "#user6:pass6\n"
        "user5:pass5\n"
        "user6:althash6\n"
    )
    assert ht.to_string() == target


@requires_htpasswd
def test_htpasswd_cmd_verify(password_file_path: Path):
    ht = apache.HtpasswdFile(path=password_file_path, new=True)

    def hash_scheme(pwd, scheme):
        return ht.context.handler(scheme).hash(pwd)

    ht.set_hash("user1", hash_scheme("password", "apr_md5_crypt"))

    # 2.2-compat scheme
    host_no_bcrypt = apache.htpasswd_defaults["host_apache_22"]
    ht.set_hash("user2", hash_scheme("password", host_no_bcrypt))

    # 2.4-compat scheme
    host_best = apache.htpasswd_defaults["host"]
    ht.set_hash("user3", hash_scheme("password", host_best))

    # unsupported scheme -- should always fail to verify
    ht.set_hash("user4", "$xxx$foo$bar$baz")

    # make sure htpasswd properly recognizes hashes
    ht.save()

    assert not _call_htpasswd_verify(password_file_path, "user1", "wrong")
    assert not _call_htpasswd_verify(password_file_path, "user2", "wrong")
    assert not _call_htpasswd_verify(password_file_path, "user3", "wrong")
    assert not _call_htpasswd_verify(password_file_path, "user4", "wrong")

    assert _call_htpasswd_verify(password_file_path, "user1", "password")
    assert _call_htpasswd_verify(password_file_path, "user2", "password")
    assert _call_htpasswd_verify(password_file_path, "user3", "password")


@requires_htpasswd
def test_htpasswd_cmd_verify_bcrypt(password_file_path: Path):
    """
    verify "htpasswd" command can read bcrypt format

    this tests for regression of issue 95, where we output "$2b$" instead of "$2y$";
    fixed in v1.7.2.
    """
    ht = apache.HtpasswdFile(path=password_file_path, new=True)

    def hash_scheme(pwd, scheme):
        return ht.context.handler(scheme).hash(pwd)

    ht.set_hash("user1", hash_scheme("password", "bcrypt"))
    ht.save()
    assert not _call_htpasswd_verify(password_file_path, "user1", "wrong")

    assert (
        _call_htpasswd_verify(password_file_path, "user1", "password")
        is HAS_HTPASSWD_BCRYPT
    )
