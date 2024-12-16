import re

from libpass.inspect.pbkdf2 import BasePBKDF2CryptInfo


class _DjangoPBKDF2SHA(BasePBKDF2CryptInfo):
    REGEX = re.compile(
        r"^(?P<digest_name>[a-z0-9-_]+)\$(?P<rounds>\d+)\$(?P<salt>.+)\$(?P<hash>.+)$"
    )

    def as_str(self) -> str:
        return super().as_str().removeprefix("$")


class DjangoPBKDF2SHA256CryptInfo(_DjangoPBKDF2SHA):
    DIGEST_NAME = "pbkdf2_sha256"


class DjangoPBKDF2SHA1CryptInfo(_DjangoPBKDF2SHA):
    DIGEST_NAME = "pbkdf2_sha1"
