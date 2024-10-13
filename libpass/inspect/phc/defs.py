import dataclasses
from typing import Annotated, Literal

from libpass.inspect.phc import PHC, Param

__all__ = [
    "Argon2IdPHC",
    "Argon2DPHC",
    "Argon2IPHC",
    "any_argon_phc",
    "BcryptSHA256PHCV2",
    "BaseArgon2PHC",
]


@dataclasses.dataclass
class BaseArgon2PHC(PHC):
    id = ""
    version = 19

    memory_cost: Annotated[int, Param("m")]
    time_cost: Annotated[int, Param("t")]
    parallelism_cost: Annotated[int, Param("p")]

    @property
    def type(self) -> Literal["i", "d", "id"]:
        return self.id.split("argon2")[1]  # type: ignore[return-value]


@dataclasses.dataclass
class Argon2IdPHC(BaseArgon2PHC):
    id = "argon2id"


@dataclasses.dataclass
class Argon2IPHC(BaseArgon2PHC):
    id = "argon2i"


@dataclasses.dataclass
class Argon2DPHC(BaseArgon2PHC):
    id = "argon2d"


any_argon_phc = (Argon2IdPHC, Argon2IPHC, Argon2DPHC)


@dataclasses.dataclass
class BcryptSHA256PHCV2(PHC):
    id = "bcrypt-sha256"
    version = None

    version_: Annotated[int, Param("v")]
    type: Annotated[str, Param("t")]
    rounds: Annotated[int, Param("r")]
