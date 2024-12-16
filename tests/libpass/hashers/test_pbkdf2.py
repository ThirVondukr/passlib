import pytest

from libpass._utils.bytes import as_bytes
from libpass._utils.deprecated import ab64_decode
from libpass.hashers.pbkdf2 import (
    PBKDF2SHA256Handler,
    PBKDF2SHA512Handler,
    PBKDF2SHAHandler,
)
from libpass.inspect.pbkdf2 import (
    PBKDF2SHA256CryptInfo,
    PBKDF2SHA512CryptInfo,
    inspect_pbkdf2_hash,
)
from tests.test_handlers import UPASS_WAV


@pytest.mark.parametrize(
    ("secret", "hash"),
    [
        (
            "password",
            "$pbkdf2-sha256$1212$4vjV83LKPjQzk31VI4E0Vw$hsYF68OiOUPdDZ1Fg.fJPeq1h/gXXY7acBp9/6c.tmQ",
        ),
        (
            UPASS_WAV,
            "$pbkdf2-sha256$1212$3SABFJGDtyhrQMVt1uABPw$WyaUoqCLgvz97s523nF4iuOqZNbp5Nt8do/cuaa7AiI",
        ),
    ],
)
def test_pbkdf2_sha256_known_hashes(secret: str, hash: str) -> None:
    hash_info = inspect_pbkdf2_hash(hash=hash, cls=PBKDF2SHA256CryptInfo)
    assert hash_info

    hasher = PBKDF2SHA256Handler()

    assert (
        hasher.hash(
            secret, salt=ab64_decode(as_bytes(hash_info.salt)), rounds=hash_info.rounds
        )
        == hash
    )
    assert hasher.verify(hash=hash, secret=secret)


def test_pbkdf2_sha256_needs_update():
    rounds = 1_000

    hasher = PBKDF2SHA256Handler(rounds=rounds)
    hash = hasher.hash("password", rounds=rounds + 1)
    assert hasher.needs_update(hash)
    assert not hasher.needs_update(hasher.hash("password"))
    # SHA512 hash
    assert hasher.needs_update(
        "$pbkdf2-sha512$1212$RHY0Fr3IDMSVO/RSZyb5ow$eNLfBK.eVozomMr.1gYa1"
    )


@pytest.mark.parametrize(
    ("secret", "hash"),
    [
        (
            "password",
            "$pbkdf2-sha512$1212$RHY0Fr3IDMSVO/RSZyb5ow$eNLfBK.eVozomMr.1gYa1"
            "7k9B7KIK25NOEshvhrSX.esqY3s.FvWZViXz4KoLlQI.BzY/YTNJOiKc5gBYFYGww",
        ),
        (
            UPASS_WAV,
            "$pbkdf2-sha512$1212$KkbvoKGsAIcF8IslDR6skQ$8be/PRmd88Ps8fmPowCJt"
            "tH9G3vgxpG.Krjt3KT.NP6cKJ0V4Prarqf.HBwz0dCkJ6xgWnSj2ynXSV7MlvMa8Q",
        ),
    ],
)
def test_pbkdf2_sha512_known_hashes(secret: str, hash: str) -> None:
    hash_info = inspect_pbkdf2_hash(hash=hash, cls=PBKDF2SHA512CryptInfo)
    assert hash_info

    hasher = PBKDF2SHA512Handler()

    assert (
        hasher.hash(
            secret, salt=ab64_decode(as_bytes(hash_info.salt)), rounds=hash_info.rounds
        )
        == hash
    )
    assert hasher.verify(hash=hash, secret=secret)


def test_pbkdf2_sha512_needs_update():
    rounds = 1_000
    hasher = PBKDF2SHA512Handler(rounds=rounds)
    hash = hasher.hash("password", rounds=rounds + 1)
    assert hasher.needs_update(hash)
    assert not hasher.needs_update(hasher.hash("password"))

    # SHA256 hash
    assert hasher.needs_update(
        "$pbkdf2-sha256$1212$4vjV83LKPjQzk31VI4E0Vw$hsYF68OiOUPdDZ1Fg.fJPeq1h/gXXY7acBp9/6c.tmQ"
    )


def test_dklen_needs_update():
    hasher = PBKDF2SHA512Handler(rounds=1000, dklen=20)
    hash = hasher.hash("password", dklen=40)
    assert hasher.needs_update(hash)


@pytest.mark.parametrize(
    ("hasher_cls", "hash", "expected"),
    [
        (
            PBKDF2SHA256Handler,
            "$pbkdf2-sha256$1212$4vjV83LKPjQzk31VI4E0Vw$hsYF68OiOUPdDZ1Fg.fJPeq1h/gXXY7acBp9/6c.tmQ",
            True,
        ),
        (
            PBKDF2SHA512Handler,
            "$pbkdf2-sha256$1212$4vjV83LKPjQzk31VI4E0Vw$hsYF68OiOUPdDZ1Fg.fJPeq1h/gXXY7acBp9/6c.tmQ",
            False,
        ),
        (
            PBKDF2SHA256Handler,
            "$pbkdf2-sha512$1212$4vjV83LKPjQzk31VI4E0Vw$hsYF68OiOUPdDZ1Fg.fJPeq1h/gXXY7acBp9/6c.tmQ",
            False,
        ),
        (
            PBKDF2SHA512Handler,
            "$pbkdf2-sha512$1212$4vjV83LKPjQzk31VI4E0Vw$hsYF68OiOUPdDZ1Fg.fJPeq1h/gXXY7acBp9/6c.tmQ",
            True,
        ),
    ],
)
def test_identify(
    hasher_cls: type[PBKDF2SHAHandler],
    hash: str,
    expected: bool,
) -> None:
    hasher = hasher_cls()
    assert hasher.identify(hash=hash) is expected
