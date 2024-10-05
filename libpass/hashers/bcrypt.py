from __future__ import annotations

import base64
import hashlib
import hmac
from typing import ClassVar, Literal

import bcrypt

from libpass._utils.bytes import StrOrBytes, as_bytes, as_str
from libpass.errors import MalformedHashError, Panic
from libpass.hashers.abc import PasswordHasher
from libpass.inspect.bcrypt import (
    BcryptHashInfo,
    inspect_bcrypt_hash,
)
from libpass.inspect.phc import inspect_phc
from libpass.inspect.phc.defs import BcryptSHA256PHCV2

BcryptPrefix = Literal["2b", "2a"]
_bcrypt_prefixes = (b"2b", b"2a")

__all__ = ["BcryptHasher", "BcryptSHA256Hasher"]


class BcryptHasher(PasswordHasher):
    prefixes: ClassVar[tuple[bytes, ...]] = _bcrypt_prefixes

    def __init__(
        self,
        rounds: int = 12,
        prefix: BcryptPrefix = "2b",
    ) -> None:
        self._rounds = rounds
        self.prefix = prefix.encode()

    def hash(
        self,
        secret: StrOrBytes,
        *,
        salt: bytes | None = None,
    ) -> str:
        """
        :param secret: Secret to hash
        :param salt: Salt, as returned by "bcrypt" library
        :return: Hash
        """
        salt = salt or bcrypt.gensalt(rounds=self._rounds, prefix=self.prefix)
        return as_str(bcrypt.hashpw(as_bytes(secret), salt))

    def verify(self, hash: StrOrBytes, secret: StrOrBytes) -> bool:
        prepared_secret = as_bytes(secret)
        return bcrypt.checkpw(password=prepared_secret, hashed_password=as_bytes(hash))

    def identify(self, hash: StrOrBytes) -> bool:
        return inspect_bcrypt_hash(as_str(hash)) is not None


class BcryptSHA256Hasher(PasswordHasher):
    prefixes: ClassVar[tuple[bytes, ...]] = _bcrypt_prefixes

    def __init__(
        self,
        rounds: int = 12,
    ) -> None:
        self._rounds = rounds

    def hash(
        self,
        secret: StrOrBytes,
        *,
        salt: bytes | None = None,
    ) -> str:
        salt = salt or bcrypt.gensalt(rounds=self._rounds, prefix=self.prefixes[0])
        prepared_secret = self._prepare_secret(secret, salt=salt.rsplit(b"$")[-1])
        hash = as_str(bcrypt.hashpw(prepared_secret, salt))
        info = inspect_bcrypt_hash(hash)
        if not info:
            raise Panic

        return BcryptSHA256PHCV2(
            version_=2,
            type=info.prefix,
            rounds=info.rounds,
            hash=info.hash,
            salt=info.salt,
        ).as_str()

    def verify(self, hash: StrOrBytes, secret: StrOrBytes) -> bool:
        info = inspect_phc(as_str(hash), BcryptSHA256PHCV2)
        if not info:
            raise MalformedHashError

        hashed_password = (
            BcryptHashInfo(
                prefix=info.type,
                salt=info.salt,
                hash=info.hash,
                rounds=info.rounds,
            )
            .as_str()
            .encode()
        )
        return bcrypt.checkpw(
            password=self._prepare_secret(secret, info.salt),
            hashed_password=hashed_password,
        )

    def identify(self, hash: StrOrBytes) -> bool:
        return bool(inspect_phc(as_str(hash), BcryptSHA256PHCV2))

    @classmethod
    def _prepare_secret(cls, secret: StrOrBytes, salt: StrOrBytes) -> bytes:
        return base64.b64encode(
            hmac.new(
                key=as_bytes(salt),
                msg=as_bytes(secret),
                digestmod=hashlib.sha256,
            ).digest()
        )
