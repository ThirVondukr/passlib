from __future__ import annotations

import dataclasses
import re

SHA256_CRYPT_HASH_REGEX = re.compile(
    r"^\$5\$rounds=(?P<rounds>\d+)\$(?P<salt>.{0,16})\$(?P<hash>.{43})$"
)


@dataclasses.dataclass
class SHA256CryptInfo:
    rounds: int
    salt: str
    hash: str

    def as_str(self):
        return f"$5$rounds={self.rounds}${self.salt}${self.hash}"


def inspect_sha_crypt(hash: str) -> SHA256CryptInfo | None:
    match = SHA256_CRYPT_HASH_REGEX.fullmatch(hash)
    if match is None:
        return None

    return SHA256CryptInfo(
        rounds=int(match.group("rounds")),
        salt=match.group("salt"),
        hash=match.group("hash"),
    )
