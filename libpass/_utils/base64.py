import dataclasses
from typing import Callable


@dataclasses.dataclass
class Base64Encoder:
    encode: Callable[[bytes], str]
    decode: Callable[[bytes], bytes]

    def encode_salt(self, value: bytes) -> str:
        return self.encode(value)

    def decode_salt(self, value: bytes) -> bytes:
        return self.decode(value)
