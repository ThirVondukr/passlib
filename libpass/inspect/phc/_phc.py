from __future__ import annotations

import base64
import dataclasses
import functools
import re
import typing
from collections.abc import Sequence
from typing import TYPE_CHECKING, ClassVar, Optional, TypeVar

if TYPE_CHECKING:
    from collections.abc import Mapping

PHC_REGEX = re.compile(
    r"\$(?P<id>[a-z0-9-]{1,32})"
    r"(\$v=(?P<version>[0-9]+))?"
    r"\$(?P<params>[a-z0-9-]{1,32}=[a-zA-Z0-9/+.-]+(,([a-z0-9-]{1,32}=[a-zA-Z0-9/+.-]+))*)"
    r"\$(?P<salt>[a-zA-Z0-9/+.-]{11,64})"
    r"\$(?P<hash>[a-zA-Z0-9/+.-]{16,86})"
)


@dataclasses.dataclass
class Param:
    name: str


@dataclasses.dataclass
class ParsedParameter:
    param: Param
    type: type


@dataclasses.dataclass
class PHC:
    id: ClassVar[str]
    version: ClassVar[Optional[int]]

    salt: str
    hash: str

    def as_str(self) -> str:
        parts: list[str] = [f"${self.id}"]
        if self.version is not None:
            parts.append(f"v={self.version}")
        params = ",".join(
            f"{value.param.name}={getattr(self, key)}"
            for key, value in _parse_phc_def(self.__class__).parameters.items()
        )
        parts.extend((params, self.salt, self.hash))
        return "$".join(parts)


TPHC = TypeVar("TPHC", bound=PHC)


@dataclasses.dataclass
class _PHCDefinitionInfo:
    parameters: Mapping[str, ParsedParameter]


def _parse_phc_def(definition: type[TPHC]) -> _PHCDefinitionInfo:
    result = {}
    for key, value in typing.get_type_hints(definition, include_extras=True).items():
        args = typing.get_args(value)
        for arg in args:
            if isinstance(arg, Param):
                result[key] = ParsedParameter(param=arg, type=args[0])
    return _PHCDefinitionInfo(parameters=result)


if not TYPE_CHECKING:
    _parse_phc_def = functools.cache(_parse_phc_def)


def _choose_definition(
    definitions: Sequence[type[TPHC]] | type[TPHC], id: str | None, version: int | None
) -> type[TPHC] | None:
    if not isinstance(definitions, Sequence):
        definitions = (definitions,)

    for definition in definitions:
        if definition.id == id and definition.version == version:
            return definition
    return None


def inspect_phc(
    hash: str,
    definition: Sequence[type[TPHC]] | type[TPHC],
) -> TPHC | None:
    """
    Parses PHC-style formatted string

    https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md
    """

    match = PHC_REGEX.fullmatch(hash)
    if match is None:
        return None

    groups = match.groupdict()
    id_ = groups["id"]
    version = int(groups["version"]) if groups["version"] is not None else None

    chosen_definition = _choose_definition(definition, id=id_, version=version)
    if chosen_definition is None:
        return None

    salt = groups["salt"]
    hash = groups["hash"]
    params = {
        key: value for key, value in (p.split("=") for p in groups["params"].split(","))
    }

    definition_info = _parse_phc_def(chosen_definition)
    return chosen_definition(
        salt=salt,
        hash=hash,
        **{
            name: param.type(params[param.param.name])
            for name, param in definition_info.parameters.items()
        },
    )


def phc_b64_encode(string: str) -> str:
    return base64.urlsafe_b64encode(string.encode()).decode().rstrip("=")


def phc_b64_decode(string: str) -> str:
    if len(string) % 4 != 0:
        string += "=" * (4 - (len(string) % 4))
    return base64.urlsafe_b64decode(string.encode()).decode()
