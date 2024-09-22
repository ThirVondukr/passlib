from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from hashlib import _Hash

    from _typeshed import ReadableBuffer


class HashFunction(Protocol):
    def __call__(
        self, string: "ReadableBuffer", *, usedforsecurity: bool = True
    ) -> "_Hash": ...
