import os
from os import PathLike


def backdate_file_mtime(path: PathLike, offset: int = 10) -> None:
    atime = os.path.getatime(path)
    mtime = os.path.getmtime(path) - offset
    os.utime(path, (atime, mtime))
