import pytest

from libpass.inspect.bcrypt import BcryptHashInfo, inspect_bcrypt_hash
from libpass.inspect.phc import Argon2PHC, inspect_phc


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
