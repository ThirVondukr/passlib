import bcrypt
import pytest

from libpass.hashers.bcrypt import BcryptSHA256Hasher
from libpass.inspect.phc import inspect_phc
from libpass.inspect.phc.defs import BcryptSHA256PHCV2
from passlib.utils import repeat_string
from tests_libpass.hashers.test_bcrypt import UPASS_TABLE


@pytest.fixture
def hasher() -> BcryptSHA256Hasher:
    return BcryptSHA256Hasher()


def test_password_truncation(hasher: BcryptSHA256Hasher):
    secret = "a" * 72
    secret1 = secret + "a"

    salt = bcrypt.gensalt()
    assert hasher.hash(secret, salt=salt) != hasher.hash(secret1, salt=salt)


@pytest.mark.parametrize(
    "secret",
    [
        "a",
        "a" * 72,
        "a" * 73,
    ],
)
def test_hash_and_validate(hasher: BcryptSHA256Hasher, secret: str) -> None:
    hash = hasher.hash(secret)
    assert hasher.verify(hash, secret)


@pytest.mark.parametrize("rounds", [4, 8, 12])
def test_rounds(rounds: int) -> None:
    hasher = BcryptSHA256Hasher(rounds=rounds)
    hash = hasher.hash("Secret")

    info = inspect_phc(hash, BcryptSHA256PHCV2)
    assert info
    assert info.rounds == rounds
    assert info.type == "2b"


@pytest.mark.parametrize(
    ("secret", "hash"),
    [
        (
            "",
            "$bcrypt-sha256$v=2,t=2b,r=5$E/e/2AOhqM5W/KJTFQzLce$WFPIZKtDDTriqWwlmRFfHiOTeheAZWe",
        ),
        # ascii
        (
            "password",
            "$bcrypt-sha256$v=2,t=2b,r=5$5Hg1DKFqPE8C2aflZ5vVoe$wOK1VFFtS8IGTrGa7.h5fs0u84qyPbS",
        ),
        # unicode / utf8
        (
            UPASS_TABLE,
            "$bcrypt-sha256$v=2,t=2b,r=5$.US1fQ4TQS.ZTz/uJ5Kyn.$pzzgp40k8reM1CuQb03PvE0IDPQSdV6",
        ),
        (
            UPASS_TABLE.encode("utf-8"),
            "$bcrypt-sha256$v=2,t=2b,r=5$.US1fQ4TQS.ZTz/uJ5Kyn.$pzzgp40k8reM1CuQb03PvE0IDPQSdV6",
        ),
        # test >72 chars is hashed correctly -- under bcrypt these hash the same.
        # NOTE: test_60_truncate_size() handles this already, this is just for overkill :)
        (
            repeat_string("abc123", 72),
            "$bcrypt-sha256$v=2,t=2b,r=5$X1g1nh3g0v4h6970O68cxe$zu1cloESVFIOsUIo7fCEgkdHaI9SSue",
        ),
        (
            repeat_string("abc123", 72) + "qwr",
            "$bcrypt-sha256$v=2,t=2b,r=5$X1g1nh3g0v4h6970O68cxe$CBF9csfEdW68xv3DwE6xSULXMtqEFP.",
        ),
        (
            repeat_string("abc123", 72) + "xyz",
            "$bcrypt-sha256$v=2,t=2b,r=5$X1g1nh3g0v4h6970O68cxe$zC/1UDUG2ofEXB6Onr2vvyFzfhEOS3S",
        ),
    ],
)
def test_known_hashes(
    secret: str,
    hash: str,
    hasher: BcryptSHA256Hasher,
):
    assert hasher.verify(hash, secret)
