from typing import AnyStr


def repeat_string(source: AnyStr, size: int) -> AnyStr:
    """
    repeat or truncate <source> string, so it has length <size>
    """
    mult = (size - 1) // len(source) + 1
    return (source * mult)[:size]
