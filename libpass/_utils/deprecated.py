from __future__ import annotations

import binascii

_BASE64_STRIP = b"=\n"
_BASE64_PAD1 = b"="
_BASE64_PAD2 = b"=="


def b64s_encode(data: bytes) -> bytes:
    """
    encode using shortened base64 format which omits padding & whitespace.
    uses default ``+/`` altchars.
    """
    return binascii.b2a_base64(data).rstrip(_BASE64_STRIP)


def b64s_decode(data: bytes | str) -> bytes:
    """
    decode from shortened base64 format which omits padding & whitespace.
    uses default ``+/`` altchars.
    """
    if isinstance(data, str):
        # needs bytes for replace() call, but want to accept ascii-unicode ala a2b_base64()
        data = data.encode("ascii")
    offset = len(data) % 4
    if offset == 0:
        pass
    elif offset == 2:
        data += _BASE64_PAD2
    elif offset == 3:
        data += _BASE64_PAD1
    else:
        raise ValueError("invalid base64 input")
    try:
        return binascii.a2b_base64(data)
    except binascii.Error as err:
        raise TypeError(err) from err


def ab64_encode(data: bytes) -> bytes:
    """
    encode using shortened base64 format which omits padding & whitespace.
    uses custom ``./`` altchars.

    it is primarily used by Passlib's custom pbkdf2 hashes.
    """
    return b64s_encode(data).replace(b"+", b".")


def ab64_decode(data: bytes | str) -> bytes:
    """
    decode from shortened base64 format which omits padding & whitespace.
    uses custom ``./`` altchars, but supports decoding normal ``+/`` altchars as well.

    it is primarily used by Passlib's custom pbkdf2 hashes.
    """
    if isinstance(data, str):
        # needs bytes for replace() call, but want to accept ascii-unicode ala a2b_base64()
        try:
            data = data.encode("ascii")
        except UnicodeEncodeError:
            raise ValueError(
                "string argument should contain only ASCII characters"
            ) from None
    return b64s_decode(data.replace(b".", b"+"))
