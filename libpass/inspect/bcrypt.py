from __future__ import annotations

import dataclasses
import re

BCRYPT_HASH_REGEX = re.compile(
    r"^\$(?P<prefix>(2a|2b|2y))\$(?P<rounds>\d+)\$(?P<salt>.{22})(?P<hash>.{31})$"
)


@dataclasses.dataclass
class BcryptHashInfo:
    prefix: str
    rounds: int
    salt: str
    hash: str

    @property
    def bcrypt_salt(self) -> bytes:
        return f"${self.prefix}${self.rounds:02}${self.salt}".encode()

    def as_str(self) -> str:
        return f"${self.prefix}${self.rounds:02}${self.salt}{self.hash}"


def inspect_bcrypt_hash(hash: str) -> BcryptHashInfo | None:
    result = BCRYPT_HASH_REGEX.match(hash)
    if not result:
        return None

    return BcryptHashInfo(
        prefix=result.group("prefix"),
        rounds=int(result.group("rounds")),
        salt=result.group("salt"),
        hash=result.group("hash"),
    )
