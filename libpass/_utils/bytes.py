from typing import Union

StrOrBytes = Union[str, bytes]


def as_bytes(value: StrOrBytes) -> bytes:
    return value.encode("utf8") if isinstance(value, str) else value


def as_str(value: StrOrBytes) -> str:
    return value.decode("utf8") if isinstance(value, bytes) else value
