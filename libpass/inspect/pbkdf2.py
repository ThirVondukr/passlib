from __future__ import annotations

import abc
import dataclasses
import re
from typing import TypeVar


@dataclasses.dataclass
class BasePBKDF2CryptInfo:
    rounds: int
    salt: str
    hash: str

    def as_str(self) -> str:
        return f"${self.DIGEST_NAME}${self.rounds}${self.salt}${self.hash}"

    @property
    @abc.abstractmethod
    def DIGEST_NAME(self) -> str:
        raise NotImplementedError

    REGEX = re.compile(
        r"^\$(?P<digest_name>[a-z0-9-]+)\$(?P<rounds>\d+)\$(?P<salt>.+)\$(?P<hash>.+)$"
    )


@dataclasses.dataclass
class PBKDF2SHA256CryptInfo(BasePBKDF2CryptInfo):
    DIGEST_NAME = "pbkdf2-sha256"


@dataclasses.dataclass
class PBKDF2SHA512CryptInfo(BasePBKDF2CryptInfo):
    DIGEST_NAME = "pbkdf2-sha512"


_TBaseBKDF2CryptInfo = TypeVar("_TBaseBKDF2CryptInfo", bound=BasePBKDF2CryptInfo)


def inspect_pbkdf2_hash(
    hash: str, cls: type[_TBaseBKDF2CryptInfo]
) -> _TBaseBKDF2CryptInfo | None:
    match = cls.REGEX.fullmatch(hash)
    if match is None:
        return None

    digest_name = match.group("digest_name")
    if digest_name != cls.DIGEST_NAME:
        return None

    return cls(
        rounds=int(match.group("rounds")),
        salt=match.group("salt"),
        hash=match.group("hash"),
    )
