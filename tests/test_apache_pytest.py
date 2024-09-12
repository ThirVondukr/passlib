import os
import subprocess
from pathlib import Path

import pytest

from passlib import apache
from passlib.utils import to_bytes
from passlib.utils.handlers import to_unicode_for_identify
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


@pytest.fixture
def sample_file(password_file_path) -> Path:
    password_file_path.write_bytes(SAMPLE_01)
    return password_file_path


def test_create(sample_file: Path) -> None:
    ht = apache.HtpasswdFile(sample_file)
    assert ht.to_string() == SAMPLE_01
    assert ht.path == sample_file
    assert ht.mtime


def test_change_path(sample_file: Path) -> None:
    ht = apache.HtpasswdFile(sample_file)
    # check changing path
    ht.path = sample_file / "x"
    assert ht.path == sample_file / "x"
    assert not ht.mtime


def test_create_new(tmp_path: Path) -> None:
    path = tmp_path.joinpath(htpasswd_path)
    ht = apache.HtpasswdFile(path, new=True)
    assert ht.to_string() == b""
    assert ht.path == path
    assert not ht.mtime


def test_file_not_found(tmp_path: Path) -> None:
    with pytest.raises(IOError):
        apache.HtpasswdFile(tmp_path.joinpath(htpasswd_path))


def test_from_file(sample_file: Path) -> None:
    htpasswd = apache.HtpasswdFile.from_path(sample_file)
    assert htpasswd.to_string() == sample_file.read_bytes()
    assert htpasswd.path is None
    assert not htpasswd.mtime


def test_delete(sample_file: Path) -> None:
    ht = apache.HtpasswdFile.from_string(SAMPLE_01)
    assert ht.delete("user1")
    assert ht.delete("user2")
    assert not ht.delete("user5")
    assert ht.to_string() == SAMPLE_02


def test_invalid_username() -> None:
    err_msg = "user contains invalid characters: b'user:'"
    ht = apache.HtpasswdFile.from_string("")

    with pytest.raises(ValueError) as exc_info:
        ht.delete("user:")
    assert str(exc_info.value) == err_msg

    with pytest.raises(ValueError) as exc_info:
        ht.set_password("user:", "password")
    assert str(exc_info.value) == err_msg

    with pytest.raises(ValueError) as exc_info:
        ht.check_password("user:", "password")
    assert str(exc_info.value) == err_msg


@pytest.mark.parametrize("autosave", [True, False])
def test_delete_autosave(password_file_path: Path, autosave: bool) -> None:
    sample = b"user1:pass1\nuser2:pass2\n"
    expected_file_contents = b"user2:pass2\n" if autosave else sample

    password_file_path.write_bytes(b"user1:pass1\nuser2:pass2\n")

    ht = apache.HtpasswdFile(password_file_path, autosave=autosave)
    ht.delete("user1")
    assert password_file_path.read_bytes() == expected_file_contents


def test_set_password():
    ht = apache.HtpasswdFile.from_string(SAMPLE_01, default_scheme="plaintext")
    assert ht.set_password("user2", "pass2x")
    assert not ht.set_password("user5", "pass5")
    assert ht.to_string() == SAMPLE_03


@pytest.mark.parametrize("autosave", [True, False])
def test_set_password_autosave(password_file_path: Path, autosave: bool) -> None:
    sample = b"user1:pass1\n"
    password_file_path.write_bytes(sample)

    expected_file_contents = b"user1:pass2\n" if autosave else sample

    ht = apache.HtpasswdFile(
        password_file_path, autosave=autosave, default_scheme="plaintext"
    )
    ht.set_password("user1", "pass2")
    assert password_file_path.read_bytes() == expected_file_contents


@pytest.mark.parametrize("scheme", ["sha256_crypt", "des_crypt"])
def test_set_password_default_scheme(scheme: str) -> None:
    ht = apache.HtpasswdFile(default_scheme=scheme)
    ht.set_password("user1", "pass1")
    assert ht.context.identify(ht.get_hash("user1"))


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


def test_users() -> None:
    ht = apache.HtpasswdFile.from_string(SAMPLE_01)
    assert sorted(ht.users()) == [f"user{i}" for i in range(1, 4 + 1)]

    ht.set_password("user5", "password")
    assert sorted(ht.users()) == [f"user{i}" for i in range(1, 5 + 1)]


def test_check_password() -> None:
    ht = apache.HtpasswdFile.from_string(SAMPLE_05)
    with pytest.raises(TypeError):
        ht.check_password(1, "pass")

    for i in range(1, 6 + 1):
        assert ht.check_password(f"user{i}", f"pass{i}")
        assert not ht.check_password(f"user{i}", "pass9")


def test_load(password_file_path: Path) -> None:
    password_file_path.touch()
    backdate_file_mtime(password_file_path, 5)

    ht = apache.HtpasswdFile(password_file_path, default_scheme="plaintext")
    assert ht.to_string() == b""

    # Make changes, check load_if_changed() does nothing
    ht.set_password("user1", "pass1")
    ht.load_if_changed()
    ht.to_string(), b"user1:pass1\n"

    password_file_path.write_bytes(SAMPLE_01)
    ht.load_if_changed()
    assert ht.to_string() == SAMPLE_01

    # Make changes, check load() overwrites them
    ht.set_password("user5", "pass5")
    ht.load()
    assert ht.to_string() == SAMPLE_01


def test_load_with_no_path() -> None:
    ht = apache.HtpasswdFile()
    with pytest.raises(RuntimeError):
        ht.load()
    with pytest.raises(RuntimeError):
        ht.load_if_changed()


def test_load_from_exclicit_path(password_file_path: Path):
    password_file_path.write_bytes(SAMPLE_01)

    ht = apache.HtpasswdFile()
    ht.load(password_file_path)
    assert ht.check_password("user1", "pass1")


def test_save(sample_file: Path) -> None:
    ht = apache.HtpasswdFile(sample_file)

    ht.delete("user1")
    ht.delete("user2")
    ht.save()
    assert sample_file.read_bytes() == SAMPLE_02


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
def test_htpasswd_cmd_verify_bcrypt(self):
    """
    verify "htpasswd" command can read bcrypt format

    this tests for regression of issue 95, where we output "$2b$" instead of "$2y$";
    fixed in v1.7.2.
    """
    path = self.mktemp()
    ht = apache.HtpasswdFile(path=path, new=True)

    def hash_scheme(pwd, scheme):
        return ht.context.handler(scheme).hash(pwd)

    ht.set_hash("user1", hash_scheme("password", "bcrypt"))
    ht.save()
    assert not _call_htpasswd_verify(path, "user1", "wrong")

    assert _call_htpasswd_verify(path, "user1", "password") is HAS_HTPASSWD_BCRYPT
