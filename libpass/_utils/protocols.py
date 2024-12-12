from __future__ import annotations

from typing import Callable, Protocol

from typing_extensions import Buffer, Self


class HashLike(Protocol):
    """Lifted from hashlib.pyi"""

    @property
    def digest_size(self) -> int: ...

    @property
    def block_size(self) -> int: ...

    @property
    def name(self) -> str: ...

    def __init__(self, data: Buffer = ...) -> None: ...

    def copy(self) -> Self: ...

    def digest(self) -> bytes: ...

    def hexdigest(self) -> str: ...

    def update(self, data: Buffer, /) -> None: ...


SHAFunc = Callable[[bytes], HashLike]
