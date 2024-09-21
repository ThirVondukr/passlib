import contextlib
import os
import warnings
from collections.abc import Iterator
from os import PathLike


def backdate_file_mtime(path: PathLike, offset: int = 10) -> None:
    atime = os.path.getatime(path)
    mtime = os.path.getmtime(path) - offset
    os.utime(path, (atime, mtime))


WARN_SETTINGS_ARG = "passing settings to.*is deprecated"


@contextlib.contextmanager
def no_warnings() -> Iterator[None]:
    with warnings.catch_warnings(record=True) as result:
        yield
    assert not result
