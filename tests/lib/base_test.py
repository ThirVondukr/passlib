from __future__ import annotations

import abc
import contextlib
import math
import warnings
from typing import TYPE_CHECKING, Callable

import pytest

from passlib.exc import MissingBackendError, PasslibHashWarning
from passlib.utils import has_salt_info
from passlib.utils.handlers import BackendMixin, HasSalt
from tests.utils import RESERVED_BACKEND_NAMES, has_relaxed_setting

if TYPE_CHECKING:
    from collections.abc import Iterator

    from passlib.ifc import PasswordHash


@contextlib.contextmanager
def ignore_deprecation_warnings() -> Iterator[None]:
    with warnings.catch_warnings():
        warnings.filterwarnings("ignore", category=DeprecationWarning)
        yield


def as_bytes(string: str | bytes) -> bytes:
    return string.encode() if isinstance(string, str) else string


def as_str(string: str | bytes) -> str:
    return string.decode() if isinstance(string, bytes) else string


@contextlib.contextmanager
def restore_backend(handler: type[BackendMixin]) -> Iterator[None]:
    backend = handler.get_backend()
    try:
        yield
    finally:
        handler.set_backend(backend)


class BaseHandlerTestCase:
    known_correct_hashes: list[tuple[str | bytes, str]] = []
    # list of (config, secret, hash) tuples are known to be correct
    known_correct_configs: list[tuple[str, str, str]] = []

    # passwords used to test basic hash behavior - generally
    # don't need to be overidden.
    stock_passwords: list[str | bytes] = [
        "test",
        "\u20ac\u00a5$",
        b"\xe2\x82\xac\xc2\xa5$",
    ]

    @property
    @abc.abstractmethod
    def handler(self) -> type[PasswordHash]:
        raise NotImplementedError

    def _genconfig(self, **kwargs: object) -> str:
        return self.handler.genconfig(**kwargs)

    @property
    def _known_hashes(self) -> Iterator[tuple[str | bytes, str]]:
        yield from self.known_correct_hashes
        for config, secret, hash in self.known_correct_configs:
            yield secret, hash

    @property
    def _salt_bits(self):
        """calculate number of salt bits in hash"""
        # XXX: replace this with bitsize() method?
        handler = self.handler
        assert has_salt_info(handler), "need explicit bit-size for " + handler.name

        # FIXME: this may be off for case-insensitive hashes, but that accounts
        # for ~1 bit difference, which is good enough for test_unique_salt()
        return int(
            handler.default_salt_size * math.log2(len(handler.default_salt_chars))
        )

    def test_known_hashes(self) -> None:
        for secret, hash in self._known_hashes:
            assert self.handler.identify(hash)
            assert self.handler.verify(secret=secret, hash=hash)
            with ignore_deprecation_warnings():
                assert self.handler.genhash(secret=secret, config=hash) == hash

            # Test bytes

            assert self.handler.identify(as_bytes(hash))
            assert self.handler.verify(secret=as_bytes(secret), hash=as_bytes(hash))
            with ignore_deprecation_warnings():
                assert (
                    self.handler.genhash(secret=as_bytes(secret), config=as_bytes(hash))
                    == hash
                )

    def test_known_configs(self) -> None:
        for config, secret, hash in self.known_correct_configs:
            with pytest.raises(ValueError):
                self.handler.verify(secret=secret, hash=config)
            with ignore_deprecation_warnings():
                result = self.handler.genhash(secret, config)
            assert result == hash

    def test_handler_attributes(self) -> None:
        assert self.handler.name is not None  # type: ignore[attr-defined]
        assert self.handler.setting_kwds is not None  # type: ignore[attr-defined]
        assert self.handler.context_kwds is not None  # type: ignore[attr-defined]

    def test_config_workflow(self) -> None:
        with ignore_deprecation_warnings():
            config = self._genconfig()
        assert isinstance(config, str)

        with ignore_deprecation_warnings():
            hash = self.handler.genhash("stlb", config)
        assert isinstance(hash, str)

        self.handler.verify("", config)
        assert self.handler.identify(config)

    def test_using(self) -> None:
        handler = self.handler
        subclass = handler.using()
        assert subclass is not handler
        assert subclass.name == handler.name  # type: ignore[attr-defined]

    @pytest.mark.parametrize("transform", [as_bytes, as_str])
    def test_hash(self, transform: Callable[[str | bytes], str | bytes]) -> None:
        wrong_password = "stub"
        for secret in self.stock_passwords:
            result = self.handler.hash(secret=transform(secret))
            assert isinstance(result, str)

            assert self.handler.verify(secret=secret, hash=transform(result))
            assert self.handler.verify(secret=transform(secret), hash=transform(result))
            assert not self.handler.verify(secret=wrong_password, hash=result)

            # genhash() should reproduce original hash
            with ignore_deprecation_warnings():
                recreated_hash = self.handler.genhash(
                    secret=secret, config=transform(result)
                )
            assert isinstance(recreated_hash, str)
            assert recreated_hash == result
            assert self.handler.identify(recreated_hash)

            # genhash() should NOT reproduce original hash for wrong password
            with ignore_deprecation_warnings():
                recreated_hash = self.handler.genhash(
                    secret=wrong_password, config=transform(result)
                )
            assert isinstance(recreated_hash, str)
            assert recreated_hash != result
            assert self.handler.identify(recreated_hash)

    def test_backends(self) -> None:
        handler = self.handler
        assert hasattr(handler, "backends")
        assert hasattr(handler, "set_backend")

        assert issubclass(handler, BackendMixin)

        assert handler.backends is not None

        with restore_backend(handler):
            # run through each backend, make sure it works
            for backend in handler.backends:
                assert isinstance(backend, str)
                assert backend not in RESERVED_BACKEND_NAMES, (
                    f"invalid backend name: {backend!r}"
                )

                has_backend = handler.has_backend(backend)
                if has_backend:
                    # verify backend can be loaded
                    handler.set_backend(backend)
                    assert handler.get_backend() == backend

                else:
                    # verify backend CAN'T be loaded
                    with pytest.raises(MissingBackendError):
                        handler.set_backend(backend)

    def test_optional_salt_attributes(self) -> None:
        handler = self.handler
        assert issubclass(handler, HasSalt)
        assert handler.setting_kwds
        assert "salt" in handler.setting_kwds

        max_salt_size_is_set = handler.max_salt_size is not None
        if max_salt_size_is_set:
            assert handler.max_salt_size
            assert handler.max_salt_size >= 1
            assert (
                handler.min_salt_size
                <= handler.default_salt_size
                <= handler.max_salt_size
            )

        assert handler.min_salt_size >= 0

        if "salt_size" not in handler.setting_kwds and (
            not max_salt_size_is_set
            or handler.default_salt_size < handler.max_salt_size
        ):
            raise AssertionError

        if handler.salt_chars:
            assert handler.default_salt_chars
            for char in handler.default_salt_chars:
                assert char in handler.salt_chars
        else:
            assert handler.default_salt_chars

    def test_unique_salt(self) -> None:
        samples = max(1, 4 + 12 - self._salt_bits)

        with ignore_deprecation_warnings():
            salts = set(self.handler.genconfig() for _ in range(samples))
            assert len(salts) == samples

        hashes = set(self.handler.hash(secret="stub") for _ in range(samples))
        assert len(hashes) == samples

    def test_min_salt_size(self) -> None:
        handler = self.handler
        assert issubclass(handler, HasSalt)

        assert handler.salt_chars
        salt_char = handler.salt_chars[0:1]
        min_size = handler.min_salt_size

        salt = salt_char * min_size
        with ignore_deprecation_warnings():
            handler.genconfig(salt=salt)

        handler.using(salt_size=min_size).hash("stub")

        #
        # check min-1 is rejected
        #
        if min_size > 0:
            with pytest.raises(ValueError), ignore_deprecation_warnings():
                handler.genconfig(salt=salt[:-1])

        with pytest.raises(ValueError):
            handler.using(salt_size=min_size - 1).hash("stub")

    def test_max_salt_size(self) -> None:
        handler = self.handler
        assert issubclass(handler, HasSalt)

        max_size = handler.max_salt_size
        assert handler.salt_chars
        salt_char = handler.salt_chars[0:1]

        secret = ""
        # NOTE: skipping this for hashes like argon2 since max_salt_size takes WAY too much memory
        if max_size is None or max_size > 2**20:
            #
            # if it's not set, salt should never be truncated; so test it
            # with an unreasonably large salt.

            s1 = salt_char * 1024

            c1 = handler.using(salt=s1).hash(secret)
            c2 = handler.using(salt=s1 + salt_char).hash(secret)  # type: ignore[operator]
            assert c1 != c2

            handler.using(salt_size=1024).hash(secret)

        else:
            # check max size is accepted
            s1 = salt_char * max_size
            c1 = handler.using(salt=s1).hash(secret)

            handler.using(salt_size=max_size).hash(secret)

            # check max size + 1 is rejected
            s2 = s1 + salt_char  # type: ignore[operator]
            with pytest.raises(ValueError):
                handler.using(salt=s2).hash(secret)

            with pytest.raises(ValueError):
                handler.using(salt_size=max_size + 1).hash(secret)

            if has_relaxed_setting(handler):
                with warnings.catch_warnings():
                    warnings.filterwarnings("ignore", category=PasslibHashWarning)

                    c2 = handler.using(salt=s2, relaxed=True).hash(secret)
                assert c2 == c1

            if handler.min_salt_size < max_size:
                c3 = handler.using(salt=s1[:-1]).hash(secret)
                assert c3 != c1
