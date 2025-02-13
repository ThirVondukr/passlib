from __future__ import annotations

import hashlib
import hmac
from hashlib import pbkdf2_hmac
from typing import TYPE_CHECKING

from libpass._salt import generate_salt_by_entropy
from libpass._utils.base64 import Base64Encoder
from libpass._utils.bytes import as_bytes, as_str
from libpass._utils.deprecated import ab64_decode, ab64_encode
from libpass.hashers.abc import PasswordHasher
from libpass.inspect.pbkdf2 import (
    BasePBKDF2CryptInfo,
    PBKDF2SHA256CryptInfo,
    PBKDF2SHA512CryptInfo,
    inspect_pbkdf2_hash,
)

if TYPE_CHECKING:
    from libpass._utils.bytes import StrOrBytes

_ab64_encoder = Base64Encoder(
    encode=lambda v: ab64_encode(v).decode("ascii"),
    decode=ab64_decode,
)


class PBKDF2SHAHandler(PasswordHasher):
    DEFAULT_ROUNDS: int
    HASH_NAME: str
    HASH_INFO_CLS: type[BasePBKDF2CryptInfo]
    B64_ENCODER: Base64Encoder

    def __init__(
        self,
        rounds: int | None = None,
        salt_entropy_bits: int = 128,
        dklen: int | None = None,
    ) -> None:
        self._rounds = rounds or self.DEFAULT_ROUNDS
        self._salt_entropy_bits = salt_entropy_bits
        self._dklen = dklen

    def hash(
        self,
        secret: StrOrBytes,
        *,
        salt: bytes | None = None,
        rounds: int | None = None,
        dklen: int | None = None,
    ) -> str:
        salt = salt or self._salt()
        rounds = rounds or self._rounds
        dklen = dklen or self._dklen

        hash = pbkdf2_hmac(
            self.HASH_NAME,
            password=as_bytes(secret),
            salt=salt,
            iterations=rounds,
            dklen=dklen,
        )
        return self.HASH_INFO_CLS(
            rounds=rounds,
            hash=self.B64_ENCODER.encode(hash),
            salt=self.B64_ENCODER.encode_salt(salt),
        ).as_str()

    def identify(self, hash: StrOrBytes) -> bool:
        return (
            inspect_pbkdf2_hash(hash=as_str(hash), cls=self.HASH_INFO_CLS) is not None
        )

    def verify(self, hash: StrOrBytes, secret: StrOrBytes) -> bool:
        hash = as_str(hash)
        hash_info = inspect_pbkdf2_hash(hash=hash, cls=self.HASH_INFO_CLS)
        if not hash_info:
            return False

        new_hash = self.hash(
            secret=secret,
            salt=self.B64_ENCODER.decode_salt(hash_info.salt.encode()),
            rounds=hash_info.rounds,
            dklen=len(self.B64_ENCODER.decode(hash_info.hash.encode())),
        )
        return hmac.compare_digest(hash, new_hash)

    def _salt(self) -> bytes:
        return generate_salt_by_entropy(entropy_bits=self._salt_entropy_bits).encode()

    def needs_update(self, hash: StrOrBytes) -> bool:
        hash_info = inspect_pbkdf2_hash(hash=as_str(hash), cls=self.HASH_INFO_CLS)
        if not hash_info:
            return True
        key_length_matches = (
            self._dklen is None
            or len(self.B64_ENCODER.decode(hash_info.hash.encode())) == self._dklen
        )
        return not (hash_info.rounds == self._rounds and key_length_matches)


# PBKDF2 Recommended rounds:
# https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#pbkdf2


class PBKDF2SHA256Handler(PBKDF2SHAHandler):
    HASH_NAME = hashlib.sha256().name
    DEFAULT_ROUNDS = 600_000
    HASH_INFO_CLS = PBKDF2SHA256CryptInfo
    B64_ENCODER = _ab64_encoder


class PBKDF2SHA512Handler(PBKDF2SHAHandler):
    HASH_NAME = hashlib.sha512().name
    DEFAULT_ROUNDS = 210_000
    HASH_INFO_CLS = PBKDF2SHA512CryptInfo
    B64_ENCODER = _ab64_encoder
