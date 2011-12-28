"""passlib.utils.compat - python 2/3 compatibility helpers"""
#=============================================================================
# figure out what version we're running
#=============================================================================
import sys
PY3 = sys.version_info >= (3,0)
PY_MAX_25 = sys.version_info < (2,6) # py 2.5 or earlier
PY27 = sys.version_info[:2] == (2,7) # supports last 2.x release
PY_MIN_32 = sys.version_info >= (3,2) # py 3.2 or later

#=============================================================================
# common imports
#=============================================================================
if PY3:
    import builtins
else:
    import __builtin__ as builtins

#=============================================================================
# the default exported vars
#=============================================================================
__all__ = [
    "u", "b",
    "irange", "srange", ##"lrange",
    "lmap",
    "iteritems",
]

#=============================================================================
# host/vm configuration info
#=============================================================================
from math import log as logb
if PY3:
    sys_bits = int(logb(sys.maxsize,2)+1.5)
else:
    sys_bits = int(logb(sys.maxint,2)+1.5)
del logb
assert sys_bits in (32,64), "unexpected system bitsize: %r" % (sys_bits,)

# VM identification
PYPY = hasattr(sys, "pypy_version_info")
JYTHON = sys.platform.startswith('java')

#=============================================================================
# lazy import aliases
#=============================================================================
if PY3:
    _aliases = dict(
        BytesIO="io.BytesIO",
        StringIO="io.StringIO",
        SafeConfigParser="configparser.SafeConfigParser",
    )
    if PY_MIN_32:
        # py32 renamed this, removing old ConfigParser
        _aliases["SafeConfigParser"] = "configparser.ConfigParser"
else:
    _aliases = dict(
        BytesIO="cStringIO.StringIO",
        StringIO="StringIO.StringIO",
        SafeConfigParser="ConfigParser.SafeConfigParser",
    )

from types import ModuleType
class _AliasesModule(ModuleType):
    "fake module that does lazy importing of attributes"

    def __init__(self, name, **source):
        ModuleType.__init__(self, name)
        self._source = source

    def __getattr__(self, attr):
        source = self._source
        if attr in source:
            modname, modattr = source[attr].rsplit(".",1)
            mod = __import__(modname, fromlist=[modattr], level=0)
            value = getattr(mod, modattr)
            setattr(self, attr, value)
            return value
        return ModuleType.__getattr__(self, attr)

    def __dir__(self):
        attrs = set(dir(self.__class__))
        attrs.update(self.__dict__)
        attrs.update(self._source)
        return list(attrs)

aliases = _AliasesModule(__name__ + ".aliases", **_aliases)
sys.modules[aliases.__name__] = aliases

#=============================================================================
# typing
#=============================================================================
def is_mapping(obj):
    # non-exhaustive check, enough to distinguish from lists, etc
    return hasattr(obj, "items")

if (3,0) <= sys.version_info < (3,2):
    # callable isn't dead, it's just resting
    from collections import Callable
    def callable(obj):
        return isinstance(obj, Callable)
    __all__.append("callable")
else:
    callable = builtins.callable

if PY3:
    int_types = (int,)
    num_types = (int, float)
else:
    int_types = (int, long)
    num_types = (int, long, float)

#=============================================================================
# unicode / bytes helpers
#=============================================================================
if PY3:
    def u(s):
        return s
    def b(s):
        assert isinstance(s, str)
        return s.encode("latin-1")
    unicode = str
    bytes = builtins.bytes
    __all__.append("unicode")
#    string_types = (unicode,)

else:
    def u(s):
        return s.decode("unicode_escape")
    def b(s):
        assert isinstance(s, str)
        return s
    if PY_MAX_25:
        bytes = str
        __all__.append("bytes")
    else:
        bytes = builtins.bytes
    unicode = builtins.unicode
#    string_types = (unicode, bytes)

sb_types = (unicode, bytes)

# bytes format

#=============================================================================
# iteration helpers
#
# irange - range iterator
# trange - immutable range sequence (list under py2, range object under py3)
# lrange - range list
#
# lmap - map to list
#=============================================================================
if PY3:
    irange = trange = range
    ##def lrange(*a,**k):
    ##    return list(range(*a,**k))

    def lmap(*a, **k):
        return list(map(*a,**k))
    # imap = map

else:
    irange = xrange
    trange = range
    ##lrange = range

    lmap = map
    # from itertools import imap

if PY3:
    def iteritems(d):
        return d.items()
else:
    def iteritems(d):
        return d.iteritems()

#=============================================================================
# introspection
#=============================================================================
def exc_err():
    "return current error object (to avoid try/except syntax change)"
    return sys.exc_info()[1]

if PY3:
    def get_method_function(method):
        return method.__func__
else:
    def get_method_function(method):
        return method.im_func

def _add_doc(obj, doc):
    """add docstring to an object"""
    obj.__doc__ = doc

#=============================================================================
# input/output
#=============================================================================
if PY3:
    print_ = getattr(builtins, "print")
else:
    def print_(*args, **kwds):
        """The new-style print function."""
        # extract kwd args
        fp = kwds.pop("file", sys.stdout)
        sep = kwds.pop("sep", None)
        end = kwds.pop("end", None)
        if kwds:
            raise TypeError("invalid keyword arguments")

        # short-circuit if no target
        if fp is None:
            return

        # use unicode or bytes ?
        want_unicode = isinstance(sep, unicode) or isinstance(end, unicode) or \
                       any(isinstance(arg, unicode) for arg in args)

        # pick default end sequence
        if end is None:
            end = u("\n") if want_unicode else "\n"
        elif not isinstance(end, sb_types):
            raise TypeError("end must be None or a string")

        # pick default separator
        if sep is None:
            sep = u(" ") if want_unicode else " "
        elif not isinstance(sep, sb_types):
            raise TypeError("sep must be None or a string")

        # write to buffer
        first = True
        write = fp.write
        for arg in args:
            if first:
                first = False
            else:
                write(sep)
            if not isinstance(arg, basestring):
                arg = str(arg)
            write(arg)
        write(end)

#=============================================================================
# eof
#=============================================================================
