from __future__ import annotations

import base64
import dataclasses
import hashlib

from libpass._utils.base64 import Base64Encoder
from libpass.hashers.pbkdf2 import PBKDF2SHAHandler
from libpass.inspect.django import (
    DjangoPBKDF2SHA1CryptInfo,
    DjangoPBKDF2SHA256CryptInfo,
)


def _b64_encode(value: bytes) -> str:
    return base64.b64encode(value).decode()


@dataclasses.dataclass
class _DjangoB64Encoder(Base64Encoder):
    def encode_salt(self, value: bytes) -> str:
        return value.decode()

    def decode_salt(self, value: bytes) -> bytes:
        return value


_django_b64_encoder = _DjangoB64Encoder(decode=base64.b64decode, encode=_b64_encode)


class DjangoPBKDF2SHA256Handler(PBKDF2SHAHandler):
    HASH_NAME = hashlib.sha256().name
    HASH_INFO_CLS = DjangoPBKDF2SHA256CryptInfo
    B64_ENCODER = _django_b64_encoder
    DEFAULT_ROUNDS = 720_000  # As per Django 5.0


class DjangoPBKDF2SHA1Handler(PBKDF2SHAHandler):
    HASH_NAME = hashlib.sha1().name
    HASH_INFO_CLS = DjangoPBKDF2SHA1CryptInfo
    B64_ENCODER = _django_b64_encoder
    DEFAULT_ROUNDS = 720_000  # As per Django 5.0
