import dataclasses
from typing import Annotated, Literal

from libpass.inspect.phc import PHC, Param

__all__ = [
    "BcryptSHA256PHCV2",
    "Argon2PHC",
]


@dataclasses.dataclass
class Argon2PHC(PHC):
    id: Literal["argon2id", "argon2i", "argon2d"]
    version = 19

    memory_cost: Annotated[int, Param("m")]
    time_cost: Annotated[int, Param("t")]
    parallelism_cost: Annotated[int, Param("p")]

    @property
    def type(self) -> Literal["i", "d", "id"]:
        return self.id.split("argon2")[1]  # type: ignore[return-value]


@dataclasses.dataclass
class BcryptSHA256PHCV2(PHC):
    id: Literal["bcrypt-sha256"]
    version = None

    version_: Annotated[int, Param("v")]
    type: Annotated[str, Param("t")]
    rounds: Annotated[int, Param("r")]
