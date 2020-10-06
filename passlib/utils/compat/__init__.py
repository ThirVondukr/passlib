"""passlib.utils.compat - python 2/3 compatibility helpers"""
#=============================================================================
# figure out what we're running
#=============================================================================

#------------------------------------------------------------------------
# python version
#------------------------------------------------------------------------
import sys

# make sure it's not an unsupported version, even if we somehow got this far
if sys.version_info < (3, 5):
    raise RuntimeError("Passlib requires Python >= 3.5 (as of passlib 1.8)")

#------------------------------------------------------------------------
# python implementation
#------------------------------------------------------------------------
JYTHON = sys.platform.startswith('java')

PYPY = hasattr(sys, "pypy_version_info")

if PYPY and sys.pypy_version_info < (2,0):
    raise RuntimeError("passlib requires pypy >= 2.0 (as of passlib 1.7)")

# e.g. '2.7.7\n[Pyston 0.5.1]'
# NOTE: deprecated support 2019-11
PYSTON = "Pyston" in sys.version

#=============================================================================
# common imports
#=============================================================================
import logging; log = logging.getLogger(__name__)
import builtins

def add_doc(obj, doc):
    """add docstring to an object"""
    obj.__doc__ = doc

#=============================================================================
# the default exported vars
#=============================================================================
__all__ = [
    # type detection
##    'is_mapping',
    'int_types',
    'num_types',
    'unicode_or_bytes_types',
    'native_string_types',

    # unicode/bytes types & helpers
    'u',
    'unicode',
    'uascii_to_str', 'bascii_to_str',
    'str_to_uascii', 'str_to_bascii',
    'join_unicode', 'join_bytes',
    'join_byte_values', 'join_byte_elems',
    'byte_elem_value',
    'iter_byte_values',

    # context helpers
    'nullcontext',

    # introspection
    'get_method_function', 'add_doc',
]

# begin accumulating mapping of lazy-loaded attrs,
# 'merged' into module at bottom
_lazy_attrs = dict()

#=============================================================================
# unicode & bytes types
#=============================================================================

if True:  # legacy PY3 indent
    unicode = str

    # NOTE: don't need to use this for general u'xxx' case,
    #       but DO need it as wrapper for u(r'xxx') case (mainly when compiling regexen)
    def u(s):
        assert isinstance(s, str)
        return s

    unicode_or_bytes_types = (str, bytes)
    native_string_types = (unicode,)


# shorter preferred aliases
# TODO: align compat module w/ crowbar.compat naming
unicode_or_bytes = unicode_or_bytes_types
unicode_or_str = native_string_types

# unicode -- unicode type, regardless of python version
# bytes -- bytes type, regardless of python version
# unicode_or_bytes_types -- types that text can occur in, whether encoded or not
# native_string_types -- types that native python strings (dict keys etc) can occur in.

#=============================================================================
# unicode & bytes helpers
#=============================================================================
# function to join list of unicode strings
join_unicode = u''.join

# function to join list of byte strings
join_bytes = b''.join

if True:  # legacy PY3 indent
    def uascii_to_str(s):
        assert isinstance(s, unicode)
        return s

    def bascii_to_str(s):
        assert isinstance(s, bytes)
        return s.decode("ascii")

    def str_to_uascii(s):
        assert isinstance(s, str)
        return s

    def str_to_bascii(s):
        assert isinstance(s, str)
        return s.encode("ascii")

    join_byte_values = join_byte_elems = bytes

    def byte_elem_value(elem):
        assert isinstance(elem, int)
        return elem

    def iter_byte_values(s):
        assert isinstance(s, bytes)
        return s

    def iter_byte_chars(s):
        assert isinstance(s, bytes)
        # FIXME: there has to be a better way to do this
        return (bytes([c]) for c in s)

# TODO: move docstrings to funcs...
add_doc(uascii_to_str, "helper to convert ascii unicode -> native str")
add_doc(bascii_to_str, "helper to convert ascii bytes -> native str")
add_doc(str_to_uascii, "helper to convert ascii native str -> unicode")
add_doc(str_to_bascii, "helper to convert ascii native str -> bytes")

# join_byte_values -- function to convert list of ordinal integers to byte string.

# join_byte_elems --  function to convert list of byte elements to byte string;
#                 i.e. what's returned by ``b('a')[0]``...
#                 this is 97 under PY3.

# byte_elem_value -- function to convert byte element to integer -- a noop under PY3

add_doc(iter_byte_values, "iterate over byte string as sequence of ints 0-255")
add_doc(iter_byte_chars, "iterate over byte string as sequence of 1-byte strings")

#=============================================================================
# numeric
#=============================================================================

int_types = (int,)
num_types = (int, float)

#=============================================================================
# typing
#=============================================================================
##def is_mapping(obj):
##    # non-exhaustive check, enough to distinguish from lists, etc
##    return hasattr(obj, "items")

#=============================================================================
# introspection
#=============================================================================

def get_method_function(func):
    """given (potential) method, return underlying function"""
    return getattr(func, "__func__", func)

#=============================================================================
# context managers
#=============================================================================

try:
    # new in py37
    from contextlib import nullcontext
except ImportError:

    class nullcontext(object):
        """
        Context manager that does no additional processing.
        """
        def __init__(self, enter_result=None):
            self.enter_result = enter_result

        def __enter__(self):
            return self.enter_result

        def __exit__(self, *exc_info):
            pass

#=============================================================================
# lazy overlay module
#=============================================================================
from types import ModuleType

def _import_object(source):
    """helper to import object from module; accept format `path.to.object`"""
    modname, modattr = source.rsplit(".",1)
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
            if callable(source):
                value = source()
            else:
                value = _import_object(source)
            setattr(self, attr, value)
            self.__log.debug("loaded lazy attr %r: %r", attr, value)
            return value
        raise AttributeError("'module' object has no attribute '%s'" % (attr,))

    def __repr__(self):
        proxy = self.__proxy
        if proxy:
            return repr(proxy)
        else:
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
_lazy_attrs = dict()
_LazyOverlayModule.replace_module(__name__, _lazy_attrs)

#=============================================================================
# eof
#=============================================================================
