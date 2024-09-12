import os
from pathlib import Path

import pytest

from passlib import apache
from tests.utils_ import backdate_file_mtime

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

htpasswd_path = os.environ.get("PASSLIB_TEST_HTPASSWD_PATH") or "htpasswd"


@pytest.fixture
def password_file_path(tmp_path: Path) -> Path:
    return tmp_path.joinpath(htpasswd_path)


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
