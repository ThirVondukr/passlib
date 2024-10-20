from typing import Protocol

from libpass._utils.bytes import StrOrBytes

__all__ = ["PasswordHasher"]


class PasswordHasher(Protocol):
    def hash(self, secret: StrOrBytes) -> str: ...

    def verify(self, hash: StrOrBytes, secret: StrOrBytes) -> bool: ...

    def identify(self, hash: StrOrBytes) -> bool: ...

    def needs_update(self, hash: StrOrBytes) -> bool:
        """Checks if hash needs to be updated, returns True if password is not recognized."""
        ...
