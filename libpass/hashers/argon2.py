from __future__ import annotations

import contextlib
from typing import Literal

import argon2
from argon2.exceptions import InvalidHashError, VerifyMismatchError

from libpass._utils.bytes import StrOrBytes, as_bytes, as_str
from libpass.hashers.abc import PasswordHasher
from libpass.inspect.phc import inspect_phc
from libpass.inspect.phc.defs import any_argon_phc


class Argon2Hasher(PasswordHasher):
    def __init__(
        self,
        time_cost: int = argon2.DEFAULT_TIME_COST,
        memory_cost: int = argon2.DEFAULT_MEMORY_COST,
        parallelism: int = argon2.DEFAULT_PARALLELISM,
        hash_len: int = argon2.DEFAULT_HASH_LENGTH,
        salt_len: int = argon2.DEFAULT_RANDOM_SALT_LENGTH,
        type: Literal["d", "i", "id"] = "id",
    ):
        self._hasher = argon2.PasswordHasher(
            time_cost=time_cost,
            memory_cost=memory_cost,
            parallelism=parallelism,
            hash_len=hash_len,
            salt_len=salt_len,
            type=argon2.Type[type.upper()],
        )

    def hash(self, secret: StrOrBytes, salt: str | None = None) -> str:
        return self._hasher.hash(
            password=secret, salt=as_bytes(salt) if salt is not None else None
        )

    def verify(self, hash: StrOrBytes, secret: StrOrBytes) -> bool:
        with contextlib.suppress(InvalidHashError, VerifyMismatchError):
            return self._hasher.verify(hash=hash, password=secret)
        return False

    def identify(self, hash: StrOrBytes) -> bool:
        return inspect_phc(hash=as_str(hash), definition=any_argon_phc) is not None
