import dataclasses
from typing import Annotated

from libpass.inspect.phc import PHC, Param

__all__ = ["Argon2PHC", "BcryptSHA256PHCV2"]


@dataclasses.dataclass
class Argon2PHC(PHC):
    id = "argon2id"
    version = 19

    memory_cost: Annotated[int, Param("m")]
    time_cost: Annotated[int, Param("t")]
    parallelism_cost: Annotated[int, Param("p")]


@dataclasses.dataclass
class BcryptSHA256PHCV2(PHC):
    id = "bcrypt-sha256"
    version = None

    version_: Annotated[int, Param("v")]
    type: Annotated[str, Param("t")]
    rounds: Annotated[int, Param("r")]
