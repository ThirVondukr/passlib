import pytest

from libpass.context import CryptContext
from libpass.hashers.bcrypt import BcryptHasher, BcryptSHA256Hasher
from libpass.hashers.sha_crypt import SHA256Hasher
from libpass.inspect.bcrypt import inspect_bcrypt_hash
from libpass.inspect.phc import inspect_phc
from libpass.inspect.phc.defs import BcryptSHA256PHCV2


def test_no_schemes_provided():
    with pytest.raises(ValueError, match="At least one scheme must be supplied"):
        CryptContext(schemes=[])


@pytest.mark.parametrize(
    ("secret", "hash", "expected"),
    [
        (
            "U*U*U*U*",
            "$2a$05$c92SVSfjeiCD6F2nAD6y0uBpJDjdRkt0EgeC4/31Rf2LUZbDRDE.O",
            True,
        ),
        (
            "password",
            "$bcrypt-sha256$v=2,t=2b,r=5$5Hg1DKFqPE8C2aflZ5vVoe$wOK1VFFtS8IGTrGa7.h5fs0u84qyPbS",
            True,
        ),
        (
            "passwor1",
            "$bcrypt-sha256$v=2,t=2b,r=5$5Hg1DKFqPE8C2aflZ5vVoe$wOK1VFFtS8IGTrGa7.h5fs0u84qyPbS",
            False,
        ),
    ],
)
def test_verify(secret: str, hash: str, expected: bool) -> None:
    context = CryptContext(
        schemes=[
            BcryptSHA256Hasher(),
            BcryptHasher(),
        ]
    )
    assert context.verify(secret=secret, hash=hash) is expected


def test_uses_most_recent_hasher() -> None:
    context = CryptContext(
        schemes=[
            BcryptSHA256Hasher(),
            BcryptHasher(),
        ]
    )
    hash = context.hash("Secret")
    assert inspect_phc(hash=hash, definition=BcryptSHA256PHCV2)
    assert not inspect_bcrypt_hash(hash=hash)


def test_needs_update() -> None:
    default_hasher = BcryptSHA256Hasher()
    deprecated_hasher = BcryptHasher()
    unknown_hasher = SHA256Hasher()

    default_hash = default_hasher.hash("Secret")
    deprecated_hash = deprecated_hasher.hash("Secret")
    unknown_hash = unknown_hasher.hash("Secret")

    context = CryptContext(
        schemes=[default_hasher, deprecated_hasher],
    )
    assert context.needs_update(default_hash) is False
    assert context.needs_update(deprecated_hash) is True
    assert context.needs_update(unknown_hash) is True
    assert context.needs_update("Random String") is True
