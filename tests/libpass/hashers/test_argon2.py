from __future__ import annotations

from typing import Literal

import pytest

from libpass.errors import Panic
from libpass.hashers.argon2 import Argon2Hasher
from libpass.inspect.phc import inspect_phc
from libpass.inspect.phc.defs import (
    Argon2PHC,
)
from tests.test_handlers import PASS_TABLE_UTF8, UPASS_TABLE


@pytest.fixture
def hasher() -> Argon2Hasher:
    return Argon2Hasher()


@pytest.mark.parametrize(
    ("secret", "salt", "hash"),
    [
        (
            "password",
            "somesalt",
            "$argon2i$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$wWKIMhR9lyDFvRz9YTZweHKfbftvj+qf+YFY4NeBbtA",
        ),
        (
            "password",
            "somesalt",
            "$argon2i$v=19$m=1048576,t=2,p=1$c29tZXNhbHQ$0Vh6ygkiw7XWqD7asxvuPE667zQu1hJ6VdGbI1GtH0E",
        ),
        (
            "password",
            "somesalt",
            "$argon2i$v=19$m=262144,t=2,p=1$c29tZXNhbHQ$KW266AuAfNzqrUSudBtQbxTbCVkmexg7EY+bJCKbx8s",
        ),
        (
            "password",
            "somesalt",
            "$argon2i$v=19$m=256,t=2,p=1$c29tZXNhbHQ$iekCn0Y3spW+sCcFanM2xBT63UP2sghkUoHLIUpWRS8",
        ),
        (
            "password",
            "somesalt",
            "$argon2i$v=19$m=256,t=2,p=2$c29tZXNhbHQ$T/XOJ2mh1/TIpJHfCdQan76Q5esCFVoT5MAeIM1Oq2E",
        ),
        (
            "password",
            "somesalt",
            "$argon2i$v=19$m=65536,t=1,p=1$c29tZXNhbHQ$0WgHXE2YXhPr6uVgz4uUw7XYoWxRkWtvSsLaOsEbvs8",
        ),
        (
            "password",
            "somesalt",
            "$argon2i$v=19$m=65536,t=4,p=1$c29tZXNhbHQ$qqlT1YrzcGzj3xrv1KZKhOMdf1QXUjHxKFJZ+IF0zls",
        ),
        (
            "differentpassword",
            "somesalt",
            "$argon2i$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$FK6NoBr+qHAMI1jc73xTWNkCEoK9iGY6RWL1n7dNIu4",
        ),
        (
            "password",
            "diffsalt",
            "$argon2i$v=19$m=65536,t=2,p=1$ZGlmZnNhbHQ$sDV8zPvvkfOGCw26RHsjSMvv7K2vmQq/6cxAcmxSEnE",
        ),
    ],
)
def test_hash_version_19(
    secret: str,
    salt: str,
    hash: str,
) -> None:
    info: Argon2PHC | None = inspect_phc(hash=hash, definition=Argon2PHC)
    if not info:
        raise Panic
    hasher = Argon2Hasher(
        parallelism=info.parallelism_cost,
        time_cost=info.time_cost,
        memory_cost=info.memory_cost,
        type=info.type,
    )
    hashed = hasher.hash(secret=secret, salt=salt)
    assert hashed == hash
    assert hasher.verify(secret=secret, hash=hash)


@pytest.mark.parametrize(
    ("secret", "hash"),
    [
        ("password", "$argon2i$v=19$m=256,t=1,p=1$c29tZXNhbHQ$AJFIsNZTMKTAewB4+ETN1A"),
        # sample w/ all parameters different
        ("password", "$argon2i$v=19$m=380,t=2,p=2$c29tZXNhbHQ$SrssP8n7m/12VWPM8dvNrw"),
        # ensures utf-8 used for unicode
        (
            UPASS_TABLE,
            "$argon2i$v=19$m=512,t=2,p=2$1sV0O4PWLtc12Ypv1f7oGw$"
            "z+yqzlKtrq3SaNfXDfIDnQ",
        ),
        (
            PASS_TABLE_UTF8,
            "$argon2i$v=19$m=512,t=2,p=2$1sV0O4PWLtc12Ypv1f7oGw$"
            "z+yqzlKtrq3SaNfXDfIDnQ",
        ),
        (
            "password\x00",
            "$argon2i$v=19$m=512,t=2,p=2$c29tZXNhbHQ$Fb5+nPuLzZvtqKRwqUEtUQ",
        ),
        (
            "password",
            "$argon2d$v=19$m=102400,t=2,p=8$g2RodLh8j8WbSdCp+lUy/A$zzAJqL/HSjm809PYQu6qkA",
        ),
    ],
)
def test_verify(secret: str, hash: str, hasher: Argon2Hasher) -> None:
    assert hasher.verify(hash=hash, secret=secret)


@pytest.mark.parametrize("argon2_type", ["id", "i", "d"])
def test_type(argon2_type: Literal["id", "i", "d"]) -> None:
    hasher = Argon2Hasher(type=argon2_type)

    hash = hasher.hash("secret")

    info = inspect_phc(hash, Argon2PHC)
    assert info
    assert info.type == argon2_type
    assert info.id == f"argon2{argon2_type}"


@pytest.mark.parametrize(
    ("memory_cost", "time_cost", "parallelism", "hash", "expected"),
    [
        (
            512,
            2,
            2,
            "$argon2id$v=19$m=512,t=2,p=2$aaaaaaaaaaaaaaaaaaaaaa$aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            False,
        ),
        (
            512 + 1,
            2,
            2,
            "$argon2id$v=19$m=512,t=2,p=2$aaaaaaaaaaaaaaaaaaaaaa$aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            True,
        ),
        (
            512 - 1,
            2,
            2,
            "$argon2id$v=19$m=512,t=2,p=2$aaaaaaaaaaaaaaaaaaaaaa$aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            True,
        ),
        (
            512,
            3,
            2,
            "$argon2id$v=19$m=512,t=2,p=2$aaaaaaaaaaaaaaaaaaaaaa$aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            True,
        ),
        (
            512,
            2,
            3,
            "$argon2id$v=19$m=512,t=2,p=2$aaaaaaaaaaaaaaaaaaaaaa$aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            True,
        ),
    ],
)
def test_needs_update(
    memory_cost: int,
    time_cost: int,
    parallelism: int,
    hash: str,
    expected: bool,
) -> None:
    # TODO: Test hash/salt lengths and hash type
    hasher = Argon2Hasher(
        memory_cost=memory_cost,
        time_cost=time_cost,
        parallelism=parallelism,
    )
    assert hasher.needs_update(hash=hash) is expected
