from __future__ import annotations

import abc
import dataclasses
import re
from typing import ClassVar, TypeVar

from libpass._utils.const import SHA_CRYPT_DEFAULT_ROUNDS

_TShaCryptInfo = TypeVar("_TShaCryptInfo", bound="SHACryptInfo")


@dataclasses.dataclass
class SHACryptInfo:
    rounds: int
    salt: str
    hash: str

    def as_str(self) -> str:
        if self.rounds == SHA_CRYPT_DEFAULT_ROUNDS:
            return f"{self._prefix}{self.salt}${self.hash}"

        return f"{self._prefix}rounds={self.rounds}${self.salt}${self.hash}"

    @property
    @abc.abstractmethod
    def _prefix(self) -> str:
        raise NotImplementedError

    REGEX: ClassVar[re.Pattern[str]]


@dataclasses.dataclass
class SHA256CryptInfo(SHACryptInfo):
    _prefix = "$5$"
    REGEX = re.compile(
        r"^\$5(\$rounds=(?P<rounds>\d+))?\$(?P<salt>.{1,16})\$(?P<hash>.{43})$"
    )


@dataclasses.dataclass
class SHA512CryptInfo(SHACryptInfo):
    _prefix = "$6$"
    REGEX = re.compile(
        r"^\$6(\$rounds=(?P<rounds>\d+))?\$(?P<salt>.{1,16})\$(?P<hash>.{86})$"
    )


def inspect_sha_crypt(hash: str, cls: type[_TShaCryptInfo]) -> _TShaCryptInfo | None:
    match = cls.REGEX.fullmatch(hash)
    if match is None:
        return None

    rounds = match.group("rounds")
    return cls(
        rounds=int(rounds) if rounds is not None else SHA_CRYPT_DEFAULT_ROUNDS,
        salt=match.group("salt"),
        hash=match.group("hash"),
    )
