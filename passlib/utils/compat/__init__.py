"""passlib.utils.compat - python 2/3 compatibility helpers"""

import logging
import sys
from contextlib import nullcontext
from types import ModuleType
from typing import Callable


def add_doc(obj: object, doc: str) -> None:
    """add docstring to an object"""
    obj.__doc__ = doc


__all__ = [
    # type detection
    ##    'is_mapping',
    "numeric_types",
    "unicode_or_bytes",
    # unicode/bytes types & helpers
    "bascii_to_str",
    "str_to_bascii",
    "join_unicode",
    "join_bytes",
    # context helpers
    "nullcontext",
    # introspection
    "get_method_function",
    "add_doc",
]

# begin accumulating mapping of lazy-loaded attrs,
# 'merged' into module at bottom
_lazy_attrs: dict[str, object] = dict()


#: alias for isinstance() tests to detect any string type
unicode_or_bytes = (str, bytes)

join_unicode = "".join
join_bytes = b"".join


def bascii_to_str(s):
    assert isinstance(s, bytes)
    return s.decode("ascii")


def str_to_bascii(s):
    assert isinstance(s, str)
    return s.encode("ascii")


def iter_byte_chars(s):
    assert isinstance(s, bytes)
    # FIXME: there has to be a better way to do this
    return (bytes([c]) for c in s)


# TODO: move docstrings to funcs...
add_doc(bascii_to_str, "helper to convert ascii bytes -> native str")
add_doc(str_to_bascii, "helper to convert ascii native str -> bytes")

# byte_elem_value -- function to convert byte element to integer -- a noop under PY3

add_doc(iter_byte_chars, "iterate over byte string as sequence of 1-byte strings")

numeric_types = (int, float)


def get_method_function(func: Callable) -> Callable:
    """given (potential) method, return underlying function"""
    return getattr(func, "__func__", func)


def _import_object(source):
    """helper to import object from module; accept format `path.to.object`"""
    modname, modattr = source.rsplit(".", 1)
    mod = __import__(modname, fromlist=[modattr], level=0)
    return getattr(mod, modattr)


class _LazyOverlayModule(ModuleType):
    """proxy module which overlays original module,
    and lazily imports specified attributes.

    this is mainly used to prevent importing of resources
    that are only needed by certain password hashes,
    yet allow them to be imported from a single location.

    used by :mod:`passlib.utils`, :mod:`passlib.crypto`,
    and :mod:`passlib.utils.compat`.
    """

    @classmethod
    def replace_module(cls, name, attrmap):
        orig = sys.modules[name]
        self = cls(name, attrmap, orig)
        sys.modules[name] = self
        return self

    def __init__(self, name, attrmap, proxy=None):
        ModuleType.__init__(self, name)
        self.__attrmap = attrmap
        self.__proxy = proxy
        self.__log = logging.getLogger(name)

    def __getattr__(self, attr):
        proxy = self.__proxy
        if proxy and hasattr(proxy, attr):
            return getattr(proxy, attr)
        attrmap = self.__attrmap
        if attr in attrmap:
            source = attrmap[attr]
            if callable(source):  # noqa: SIM108
                value = source()
            else:
                value = _import_object(source)
            setattr(self, attr, value)
            self.__log.debug("loaded lazy attr %r: %r", attr, value)
            return value
        raise AttributeError(f"'module' object has no attribute '{attr}'")

    def __repr__(self):
        proxy = self.__proxy
        if proxy:
            return repr(proxy)
        return ModuleType.__repr__(self)

    def __dir__(self):
        attrs = set(dir(self.__class__))
        attrs.update(self.__dict__)
        attrs.update(self.__attrmap)
        proxy = self.__proxy
        if proxy is not None:
            attrs.update(dir(proxy))
        return list(attrs)


# replace this module with overlay that will lazily import attributes.
_LazyOverlayModule.replace_module(__name__, _lazy_attrs)
