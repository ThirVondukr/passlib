from typing import Protocol, Union

StrOrBytes = Union[str, bytes]


class PasswordHasher(Protocol):
    def hash(self, secret: StrOrBytes) -> str: ...

    def verify(self, hash: StrOrBytes, secret: StrOrBytes) -> bool: ...

    def identify(self, hash: StrOrBytes) -> bool: ...


def as_bytes(value: StrOrBytes) -> bytes:
    return value.encode("utf8") if isinstance(value, str) else value


def as_str(value: StrOrBytes) -> str:
    return value.decode("utf8") if isinstance(value, bytes) else value
