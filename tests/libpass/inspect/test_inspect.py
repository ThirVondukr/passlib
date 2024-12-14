import pytest

from libpass.inspect.bcrypt import BcryptHashInfo, inspect_bcrypt_hash
from libpass.inspect.phc import inspect_phc
from libpass.inspect.phc.defs import Argon2PHC
from libpass.inspect.sha_crypt import SHA256CryptInfo, inspect_sha_crypt


@pytest.mark.parametrize(
    ("hash", "expected"),
    [
        (
            "$2a$12$R9h/cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ss7KIUgO2t0jWMUW",
            BcryptHashInfo(
                prefix="2a",
                rounds=12,
                salt="R9h/cIPz0gi.URNNX3kh2O",
                hash="PST9/PgBkqquzi.Ss7KIUgO2t0jWMUW",
            ),
        )
    ],
)
def test_bcrypt_inspect(hash: str, expected: BcryptHashInfo) -> None:
    assert inspect_bcrypt_hash(hash) == expected


@pytest.mark.parametrize(
    ("hash", "expected"),
    [
        (
            "$argon2id$v=19$m=65536,t=2,p=1$gZiV/M1gPc22ElAH/Jh1Hw$CWOrkoo7oJBQ/iyh7uJ0LO2aLEfrHwTWllSAxT0zRno",
            Argon2PHC(
                id="argon2id",
                memory_cost=65536,
                time_cost=2,
                parallelism_cost=1,
                salt="gZiV/M1gPc22ElAH/Jh1Hw",
                hash="CWOrkoo7oJBQ/iyh7uJ0LO2aLEfrHwTWllSAxT0zRno",
            ),
        )
    ],
)
def test_argon_inspect(hash: str, expected: Argon2PHC) -> None:
    parsed = inspect_phc(hash, Argon2PHC)
    assert parsed == expected
    assert parsed.as_str() == hash


@pytest.mark.parametrize(
    ("hash", "expected"),
    [
        (
            "$5$rounds=80000$wnsT7Yr92oJoP28r$cKhJImk5mfuSKV9b3mumNzlbstFUplKtQXXMo4G6Ep5",
            SHA256CryptInfo(
                rounds=80000,
                salt="wnsT7Yr92oJoP28r",
                hash="cKhJImk5mfuSKV9b3mumNzlbstFUplKtQXXMo4G6Ep5",
            ),
        ),
        (
            "$5$wnsT7Yr92oJoP28r$cKhJImk5mfuSKV9b3mumNzlbstFUplKtQXXMo4G6Ep5",
            SHA256CryptInfo(
                rounds=5000,
                salt="wnsT7Yr92oJoP28r",
                hash="cKhJImk5mfuSKV9b3mumNzlbstFUplKtQXXMo4G6Ep5",
            ),
        ),
        (
            # SHA512 hash
            "$6$wnsT7Yr92oJoP28r$cKhJImk5mfuSKV9b3mumNzlbstFUplKtQXXMo4G6Ep5",
            None,
        ),
    ],
)
def test_sha_crypt(hash: str, expected: SHA256CryptInfo) -> None:
    info = inspect_sha_crypt(hash, SHA256CryptInfo)
    assert info == expected
