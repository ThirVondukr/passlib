from __future__ import annotations

import functools
from typing import TYPE_CHECKING, Literal

import typing_extensions

if TYPE_CHECKING:
    from collections.abc import Sequence

    from libpass.hashers.abc import PasswordHasher


class CryptContext:
    def __init__(
        self,
        schemes: Sequence[PasswordHasher],
        deprecated: Literal["auto"] = "auto",
    ) -> None:
        self._schemes = schemes
        self._deprecated = deprecated

        self._validate_init()

    def hash(self, secret: str) -> str:
        scheme = self._default_scheme
        return scheme.hash(secret=secret)

    def verify(self, secret: str, hash: str) -> bool:
        return any(scheme.verify(secret=secret, hash=hash) for scheme in self._schemes)

    def needs_update(self, hash: str) -> bool:
        # Todo: Don't filter list in place
        schemes = list(
            scheme for scheme in self._schemes if scheme not in self._deprecated_schemes
        )
        return all(not scheme.identify(hash) for scheme in schemes)

    def _validate_init(self):
        if not self._schemes:
            raise ValueError("At least one scheme must be supplied")

    @functools.cached_property
    def _default_scheme(self) -> PasswordHasher:
        return self._schemes[0]

    @functools.cached_property
    def _deprecated_schemes(self) -> Sequence[PasswordHasher]:
        if self._deprecated == "auto":
            return self._schemes[1:]

        typing_extensions.assert_never(self._deprecated)
