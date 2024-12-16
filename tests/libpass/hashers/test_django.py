from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from libpass.hashers.django import (
    DjangoPBKDF2SHA1Handler,
    DjangoPBKDF2SHA256Handler,
    _django_b64_encoder,
)
from libpass.inspect.pbkdf2 import inspect_pbkdf2_hash

if TYPE_CHECKING:
    from libpass.hashers.pbkdf2 import PBKDF2SHAHandler


@pytest.mark.parametrize(
    ("hasher_cls", "secret", "salt", "rounds", "dklen", "expected"),
    [
        (
            DjangoPBKDF2SHA1Handler,
            "password",
            b"salt",
            1,
            20,
            "0c60c80f961f0e71f3a9b524af6012062fe037a6",
        ),
        (
            DjangoPBKDF2SHA1Handler,
            "password",
            b"salt",
            2,
            20,
            "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957",
        ),
        (
            DjangoPBKDF2SHA1Handler,
            "password",
            b"salt",
            4096,
            20,
            "4b007901b765489abead49d926f721d065a429c1",
        ),
        (
            DjangoPBKDF2SHA1Handler,
            "passwordPASSWORDpassword",
            b"saltSALTsaltSALTsaltSALTsaltSALTsalt",
            4096,
            25,
            "3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038",
        ),
        (
            DjangoPBKDF2SHA1Handler,
            "pass\0word",
            b"sa\0lt",
            4096,
            16,
            "56fa6aa75548099dcc37d7f03425e0c3",
        ),
        (
            DjangoPBKDF2SHA256Handler,
            "password",
            b"salt",
            1,
            20,
            "120fb6cffcf8b32c43e7225256c4f837a86548c9",
        ),
    ],
)
def test_known_hex(
    hasher_cls: type[PBKDF2SHAHandler],
    secret: str,
    salt: bytes,
    rounds: int,
    dklen: int | None,
    expected: bool,
) -> None:
    hasher = hasher_cls()
    hash = hasher.hash(secret=secret, salt=salt, rounds=rounds, dklen=dklen)
    info = inspect_pbkdf2_hash(hash, hasher.HASH_INFO_CLS)
    assert info

    original_hash = _django_b64_encoder.decode(info.hash.encode())
    assert original_hash.hex() == expected

    assert hasher.verify(hash=hash, secret=secret)


@pytest.mark.parametrize(
    ("secret", "salt", "rounds", "dklen", "expected"),
    [
        (
            "lètmein",
            b"seasalt",
            1000000,
            None,
            "pbkdf2_sha256$1000000$seasalt$r1uLUxoxpP2Ued/qxvmje7UH9PUJBkRrvf9gGPL7Cps=",
        ),
    ],
)
def test_known(
    secret: str,
    salt: bytes,
    rounds: int,
    dklen: int | None,
    expected: bool,
) -> None:
    hasher = DjangoPBKDF2SHA256Handler()
    hash = hasher.hash(secret=secret, salt=salt, rounds=rounds, dklen=dklen)
    assert hash == expected
