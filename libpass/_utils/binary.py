from __future__ import annotations

from typing import TYPE_CHECKING, Callable, Protocol

if TYPE_CHECKING:
    from collections.abc import Iterator

B64_CHARS = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"


class EncodeBytes(Protocol):
    def __call__(
        self, next_value: Callable[[], int], chunks: int, tail: int
    ) -> Iterator[int]: ...


def _encode_bytes_big(
    next_value: Callable[[], int], chunks: int, tail: int
) -> Iterator[int]:
    """helper used by encode_bytes() to handle big-endian encoding"""
    #
    # output bit layout:
    #
    # first byte:   v1 765432
    #
    # second byte:  v1 10....
    #              +v2 ..7654
    #
    # third byte:   v2 3210..
    #              +v3 ....76
    #
    # fourth byte:  v3 543210
    #
    idx = 0
    while idx < chunks:
        v1 = next_value()
        v2 = next_value()
        v3 = next_value()
        yield v1 >> 2
        yield ((v1 & 0x03) << 4) | (v2 >> 4)
        yield ((v2 & 0x0F) << 2) | (v3 >> 6)
        yield v3 & 0x3F
        idx += 1
    if tail:
        v1 = next_value()
        if tail == 1:
            # note: 4 lsb of last byte are padding
            yield v1 >> 2
            yield (v1 & 0x03) << 4
        else:
            assert tail == 2
            # note: 2 lsb of last byte are padding
            v2 = next_value()
            yield v1 >> 2
            yield ((v1 & 0x03) << 4) | (v2 >> 4)
            yield ((v2 & 0x0F) << 2)


def _encode_bytes_little(
    next_value: Callable[[], int], chunks: int, tail: int
) -> Iterator[int]:
    """helper used by encode_bytes() to handle little-endian encoding"""
    #
    # output bit layout:
    #
    # first byte:   v1 543210
    #
    # second byte:  v1 ....76
    #              +v2 3210..
    #
    # third byte:   v2 ..7654
    #              +v3 10....
    #
    # fourth byte:  v3 765432
    #
    idx = 0
    while idx < chunks:
        v1 = next_value()
        v2 = next_value()
        v3 = next_value()
        yield v1 & 0x3F
        yield ((v2 & 0x0F) << 2) | (v1 >> 6)
        yield ((v3 & 0x03) << 4) | (v2 >> 4)
        yield v3 >> 2
        idx += 1
    if tail:
        v1 = next_value()
        if tail == 1:
            # note: 4 msb of last byte are padding
            yield v1 & 0x3F
            yield v1 >> 6
        else:
            assert tail == 2
            # note: 2 msb of last byte are padding
            v2 = next_value()
            yield v1 & 0x3F
            yield ((v2 & 0x0F) << 2) | (v1 >> 6)
            yield v2 >> 4


class Base64Engine:
    def __init__(
        self,
        charmap: str,
        big: bool,
    ) -> None:
        if len(charmap) != 64:
            raise ValueError

        self._charmap = charmap.encode("latin-1")
        self._big = big

    def _encode64(self, i: int) -> int:
        return self._charmap[i]

    @property
    def _encode_bytes(self) -> EncodeBytes:
        if self._big:
            return _encode_bytes_big
        return _encode_bytes_little

    def encode_bytes(self, source: bytes) -> bytes:
        """encode bytes to base64 string.

        :arg source: byte string to encode.
        :returns: byte string containing encoded data.
        """
        chunks, tail = divmod(len(source), 3)
        next_value = iter(source).__next__
        gen = self._encode_bytes(next_value, chunks, tail)
        return bytes(map(self._encode64, gen))

    def encode_transposed_bytes(self, source: bytes, offsets: tuple[int, ...]) -> bytes:
        """encode byte string, first transposing source using offset list"""
        tmp = bytes(source[off] for off in offsets)
        return self.encode_bytes(tmp)


h64_engine = Base64Engine(B64_CHARS, big=False)
