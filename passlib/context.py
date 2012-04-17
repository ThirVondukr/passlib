"""passlib.context - CryptContext implementation"""
#=========================================================
#imports
#=========================================================
from __future__ import with_statement
#core
from functools import update_wrapper
import inspect
import re
import hashlib
from math import log as logb, ceil
import logging; log = logging.getLogger(__name__)
import os
import re
from time import sleep
from warnings import warn
#site
#libs
from passlib.exc import PasslibConfigWarning, ExpectedStringError, ExpectedTypeError
from passlib.registry import get_crypt_handler, _validate_handler_name
from passlib.utils import is_crypt_handler, rng, saslprep, tick, to_bytes, \
                          to_unicode
from passlib.utils.compat import bytes, iteritems, num_types, \
                                 PY3, PY_MIN_32, unicode, SafeConfigParser, \
                                 NativeStringIO, BytesIO, base_string_types
#pkg
#local
__all__ = [
    'CryptContext',
    'LazyCryptContext',
    'CryptPolicy',
]

#=========================================================
# support
#=========================================================

# private object to detect unset params
_UNSET = object()

def _coerce_vary_rounds(value):
    "parse vary_rounds string to percent as [0,1) float, or integer"
    if value.endswith("%"):
        # XXX: deprecate this in favor of raw float?
        return float(value.rstrip("%"))*.01
    try:
        return int(value)
    except ValueError:
        return float(value)

# set of options which aren't allowed to be set via policy
_forbidden_scheme_options = set(["salt"])
    # 'salt' - not allowed since a fixed salt would defeat the purpose.

# dict containing funcs used to coerce strings to correct type
# for scheme option keys.
_coerce_scheme_options = dict(
    min_rounds=int,
    max_rounds=int,
    default_rounds=int,
    vary_rounds=_coerce_vary_rounds,
    salt_size=int,
)

# dict mapping passprep policy name -> implementation
_passprep_funcs = dict(
    saslprep=saslprep,
    raw=lambda s: s,
)

def _splitcomma(source):
    "split comma-separated string into list of strings"
    source = source.strip()
    if source.endswith(","):
        source = source[:-1]
    if not source:
        return []
    return [ elem.strip() for elem in source.split(",") ]

def _is_handler_registered(handler):
    """detect if handler is registered or a custom handler"""
    return get_crypt_handler(handler.name, None) is handler

#=========================================================
# crypt policy
#=========================================================
_preamble = ("The CryptPolicy class has been deprecated as of "
             "Passlib 1.6, and will be removed in Passlib 1.8. ")

class CryptPolicy(object):
    """This class has been deprecated, and will be removed in Passlib 1.8.

    This class previously stored the configuration options for the
    CryptContext class. In the interest of interface simplification,
    all of this class' functionality has been rolled into the CryptContext
    class itself.

    The documentation for this class is now focused on  documenting how to
    migrate to the new api. Additionally, where possible, the deprecation
    warnings issued by the CryptPolicy methods will list the replacement call
    that should be used.

    Constructors
    ============
    CryptPolicy objects can be constructed directly using any of
    the keywords accepted by :class:`CryptContext`. Direct uses of the
    :class:`!CryptPolicy` constructor should either pass the keywords
    directly into the CryptContext constructor, or to :meth:`CryptContext.update`
    if the policy object was being used to update an existing context object.

    In addition to passing in keywords directly,
    CryptPolicy objects can be constructed by the following methods:

    .. automethod:: from_path
    .. automethod:: from_string
    .. automethod:: from_source
    .. automethod:: from_sources
    .. automethod:: replace

    Introspection
    =============
    All of the informational methods provided by this class have been deprecated
    by identical or similar methods in the :class:`CryptContext` class:

    .. automethod:: has_schemes
    .. automethod:: schemes
    .. automethod:: iter_handlers
    .. automethod:: get_handler
    .. automethod:: get_options
    .. automethod:: handler_is_deprecated
    .. automethod:: get_min_verify_time

    Exporting
    =========
    .. automethod:: iter_config
    .. automethod:: to_dict
    .. automethod:: to_file
    .. automethod:: to_string

    .. note::
        CryptPolicy are immutable.
        Use the :meth:`replace` method to mutate existing instances.

    .. deprecated:: 1.6
    """
    #=========================================================
    #class methods
    #=========================================================
    @classmethod
    def from_path(cls, path, section="passlib", encoding="utf-8"):
        """create a CryptPolicy instance from a local file.

        .. deprecated:: 1.6

        Creating a new CryptContext from a file, which was previously done via
        ``CryptContext(policy=CryptPolicy.from_path(path))``, can now be
        done via ``CryptContext.from_path(path)``.
        See :meth:`CryptContext.from_path` for details.

        Updating an existing CryptContext from a file, which was previously done
        ``context.policy = CryptPolicy.from_path(path)``, can now be
        done via ``context.load_path(path)``.
        See :meth:`CryptContext.load_path` for details.
        """
        warn(_preamble +
             "Instead of ``CryptPolicy.from_path(path)``, "
             "use ``CryptContext.from_path(path)`` "
             " or ``context.load_path(path)`` for an existing CryptContext.",
             DeprecationWarning, stacklevel=2)
        return cls(_internal_context=CryptContext.from_path(path, section,
                                                            encoding))

    @classmethod
    def from_string(cls, source, section="passlib", encoding="utf-8"):
        """create a CryptPolicy instance from a string.

        .. deprecated:: 1.6

        Creating a new CryptContext from a string, which was previously done via
        ``CryptContext(policy=CryptPolicy.from_string(data))``, can now be
        done via ``CryptContext.from_string(data)``.
        See :meth:`CryptContext.from_string` for details.

        Updating an existing CryptContext from a string, which was previously done
        ``context.policy = CryptPolicy.from_string(data)``, can now be
        done via ``context.load(data)``.
        See :meth:`CryptContext.load` for details.
        """
        warn(_preamble +
             "Instead of ``CryptPolicy.from_string(source)``, "
             "use ``CryptContext.from_string(source)`` or "
             "``context.load(source)`` for an existing CryptContext.",
             DeprecationWarning, stacklevel=2)
        return cls(_internal_context=CryptContext.from_string(source, section,
                                                              encoding))

    @classmethod
    def from_source(cls, source, _warn=True):
        """create a CryptPolicy instance from some source.

        this method autodetects the source type, and invokes
        the appropriate constructor automatically. it attempts
        to detect whether the source is a configuration string, a filepath,
        a dictionary, or an existing CryptPolicy instance.

        .. deprecated:: 1.6

        Create a new CryptContext, which could previously be done via
        ``CryptContext(policy=CryptPolicy.from_source(source))``, should
        now be done using an explicit method: the :class:`CryptContext`
        constructor itself, :meth:`CryptContext.from_path`,
        or :meth:`CryptContext.from_string`.

        Updating an existing CryptContext, which could previously be done via
        ``context.policy = CryptPolicy.from_source(source)``, should
        now be done using an explicit method: :meth:`CryptContext.update`,
        or :meth:`CryptContext.load`.
        """
        if _warn:
            warn(_preamble +
                 "Instead of ``CryptPolicy.from_source()``, "
                 "use ``CryptContext.from_string(path)`` "
                 " or ``CryptContext.from_path(source)``, as appropriate.",
                 DeprecationWarning, stacklevel=2)
        if isinstance(source, CryptPolicy):
            return source
        elif isinstance(source, dict):
            return cls(_internal_context=CryptContext(**source))
        elif not isinstance(source, (bytes,unicode)):
            raise TypeError("source must be CryptPolicy, dict, config string, "
                            "or file path: %r" % (type(source),))
        elif any(c in source for c in "\n\r\t") or not source.strip(" \t./\;:"):
            return cls(_internal_context=CryptContext.from_string(source))
        else:
            return cls(_internal_context=CryptContext.from_path(source))

    @classmethod
    def from_sources(cls, sources, _warn=True):
        """create a CryptPolicy instance by merging multiple sources.

        each source is interpreted as by :meth:`from_source`,
        and the results are merged together.

        .. deprecated:: 1.6

        Instead of using this method to merge multiple policies together,
        a :class:`CryptContext` instance should be created, and then
        the multiple sources merged together via :meth:`CryptContext.load`.
        """
        if _warn:
            warn(_preamble +
                 "Instead of ``CryptPolicy.from_sources()``, "
                 "use the various CryptContext constructors "
                 " followed by ``context.update()``.",
                 DeprecationWarning, stacklevel=2)
        if len(sources) == 0:
            raise ValueError("no sources specified")
        if len(sources) == 1:
            return cls.from_source(sources[0], _warn=False)
        kwds = {}
        for source in sources:
            kwds.update(cls.from_source(source, _warn=False)._context.to_dict(resolve=True))
        return cls(_internal_context=CryptContext(**kwds))

    def replace(self, *args, **kwds):
        """create a new CryptPolicy, optionally updating parts of the
        existing configuration.

        .. deprecated:: 1.6

        Callers of this method should :meth:`CryptContext.update` or
        :meth:`CryptContext.copy` instead.
        """
        if self._stub_policy:
            warn(_preamble +
                 "Instead of ``context.policy.replace()``, "
                 "use ``context.update()`` or ``context.copy()``.",
                 DeprecationWarning, stacklevel=2)
        else:
            warn(_preamble +
                 "Instead of ``CryptPolicy().replace()``, "
                 "create a CryptContext instance and "
                 "use ``context.update()`` or ``context.copy()``.",
                 DeprecationWarning, stacklevel=2)
        sources = [ self ]
        if args:
            sources.extend(args)
        if kwds:
            sources.append(kwds)
        return CryptPolicy.from_sources(sources, _warn=False)

    #=========================================================
    #instance attrs
    #=========================================================

    # internal CryptContext we're wrapping to handle everything
    # until this class is removed.
    _context = None

    # flag indicating this is wrapper generated by the CryptContext.policy
    # attribute, rather than one created independantly by the application.
    _stub_policy = False

    #=========================================================
    # init
    #=========================================================
    def __init__(self, *args, **kwds):
        context = kwds.pop("_internal_context", None)
        if context:
            assert isinstance(context, CryptContext)
            self._context = context
            self._stub_policy = kwds.pop("_stub_policy", False)
            assert not (args or kwds), "unexpected args: %r %r" % (args,kwds)
        else:
            if args:
                if len(args) != 1:
                    raise TypeError("only one positional argument accepted")
                if kwds:
                    raise TypeError("cannot specify positional arg and kwds")
                kwds = args[0]
            warn(_preamble +
                 "Instead of constructing a CryptPolicy instance, "
                 "create a CryptContext directly, or use ``context.update()`` "
                 "and ``context.load()`` to reconfigure existing CryptContext "
                 "instances.",
                 DeprecationWarning, stacklevel=2)
            self._context = CryptContext(**kwds)

    #=========================================================
    # public interface for examining options
    #=========================================================
    def has_schemes(self):
        """return True if policy defines *any* schemes for use.

        .. deprecated:: 1.6

        applications should use ``bool(context.schemes())`` instead.
        see :meth:`CryptContext.schemes`.
        """
        if self._stub_policy:
            warn(_preamble +
                 "Instead of ``context.policy.has_schemes()``, "
                 "use ``bool(context.schemes())``.",
                 DeprecationWarning, stacklevel=2)
        else:
            warn(_preamble +
                 "Instead of ``CryptPolicy().has_schemes()``, "
                 "create a CryptContext instance and "
                 "use ``bool(context.schemes())``.",
                 DeprecationWarning, stacklevel=2)
        return bool(self._context.schemes())

    def iter_handlers(self):
        """return iterator over handlers defined in policy.

        .. deprecated:: 1.6

        applications should use ``context.schemes(resolve=True))`` instead.
        see :meth:`CryptContext.schemes`.
        """
        if self._stub_policy:
            warn(_preamble +
                 "Instead of ``context.policy.iter_handlers()``, "
                 "use ``context.schemes(resolve=True)``.",
                 DeprecationWarning, stacklevel=2)
        else:
            warn(_preamble +
                 "Instead of ``CryptPolicy().iter_handlers()``, "
                 "create a CryptContext instance and "
                 "use ``context.schemes(resolve=True)``.",
                 DeprecationWarning, stacklevel=2)
        return self._context.schemes(resolve=True)

    def schemes(self, resolve=False):
        """return list of schemes defined in policy.

        .. deprecated:: 1.6

        applications should use :meth:`CryptContext.schemes` instead.
        """
        if self._stub_policy:
            warn(_preamble +
                 "Instead of ``context.policy.schemes()``, "
                 "use ``context.schemes()``.",
                 DeprecationWarning, stacklevel=2)
        else:
            warn(_preamble +
                 "Instead of ``CryptPolicy().schemes()``, "
                 "create a CryptContext instance and "
                 "use ``context.schemes()``.",
                 DeprecationWarning, stacklevel=2)
        return list(self._context.schemes(resolve=resolve))

    def get_handler(self, name=None, category=None, required=False):
        """return handler as specified by name, or default handler.

        .. deprecated:: 1.6

        applications should use :meth:`CryptContext.handler` instead,
        though note that the ``required`` keyword has been removed,
        and the new method will always act as if ``required=True``.
        """
        if self._stub_policy:
            warn(_preamble +
                 "Instead of ``context.policy.get_handler()``, "
                 "use ``context.handler()``.",
                 DeprecationWarning, stacklevel=2)
        else:
            warn(_preamble +
                 "Instead of ``CryptPolicy().get_handler()``, "
                 "create a CryptContext instance and "
                 "use ``context.handler()``.",
                 DeprecationWarning, stacklevel=2)
        if not name: # CryptContext.handler() uses different default value
            name = "default"
        # CryptContext.handler() doesn't support required=False,
        # so wrapping it in try/except
        try:
            return self._context.handler(name, category)
        except KeyError:
            if required:
                raise
            else:
                return None

    def get_min_verify_time(self, category=None):
        """get min_verify_time setting for policy.

        .. deprecated:: 1.6

        min_verify_time will be removed entirely in passlib 1.8
        """
        warn("get_min_verify_time() and min_verify_time option is deprecated, "
             "and will be removed in Passlib 1.8", DeprecationWarning,
             stacklevel=2)
        mvtmap = self._context._mvtmap
        if category:
            try:
                return mvtmap[category]
            except KeyError:
                pass
        return mvtmap.get(None) or 0

    def get_options(self, name, category=None):
        """return dictionary of options specific to a given handler.

        .. deprecated:: 1.6

        this method has no direct replacement in the 1.6 api, as there
        is not a clearly defined use-case. however, examining the output of
        :meth:`CryptContext.to_dict` should serve as the closest alternative.
        """
        # XXX: might make a public replacement, but need more study of the use cases.
        if self._stub_policy:
            warn(_preamble +
                 "``context.policy.get_options()`` will no longer be available.",
                 DeprecationWarning, stacklevel=2)
        else:
            warn(_preamble +
                 "``CryptPolicy().get_options()`` will no longer be available.",
                 DeprecationWarning, stacklevel=2)
        if hasattr(name, "name"):
            name = name.name
        return self._context._get_record_options(name, category)[0]

    def handler_is_deprecated(self, name, category=None):
        """check if handler has been deprecated by policy.

        .. deprecated:: 1.6

        this method has no direct replacement in the 1.6 api, as there
        is not a clearly defined use-case. however, examining the output of
        :meth:`CryptContext.to_dict` should serve as the closest alternative.
        """
        # XXX: might make a public replacement, but need more study of the use cases.
        if self._stub_policy:
            warn(_preamble +
                 "``context.policy.handler_is_deprecated()`` will no longer be available.",
                 DeprecationWarning, stacklevel=2)
        else:
            warn(_preamble +
                 "``CryptPolicy().handler_is_deprecated()`` will no longer be available.",
                 DeprecationWarning, stacklevel=2)
        if hasattr(name, "name"):
            name = name.name
        return self._context._is_deprecated_scheme(name, category)

    #=========================================================
    # serialization
    #=========================================================

    def iter_config(self, ini=False, resolve=False):
        """iterate over key/value pairs representing the policy object.

        .. deprecated:: 1.6

        applications should use :meth:`CryptContext.to_dict` instead.
        """
        if self._stub_policy:
            warn(_preamble +
                 "Instead of ``context.policy.iter_config()``, "
                 "use ``context.to_dict().items()``.",
                 DeprecationWarning, stacklevel=2)
        else:
            warn(_preamble +
                 "Instead of ``CryptPolicy().iter_config()``, "
                 "create a CryptContext instance and "
                 "use ``context.to_dict().items()``.",
                 DeprecationWarning, stacklevel=2)
        # hacked code that renders keys & values in manner that approximates
        # old behavior. context.to_dict() is much cleaner.
        context = self._context
        if ini:
            def render_key(key):
                return context._render_config_key(key).replace("__", ".")
            def render_value(value):
                if isinstance(value, (list,tuple)):
                    value = ", ".join(value)
                return value
            resolve = False
        else:
            render_key = context._render_config_key
            render_value = lambda value: value
        return (
            (render_key(key), render_value(value))
            for key, value in context._iter_config(resolve)
        )

    def to_dict(self, resolve=False):
        """export policy object as dictionary of options.

        .. deprecated:: 1.6

        applications should use :meth:`CryptContext.to_dict` instead.
        """
        if self._stub_policy:
            warn(_preamble +
                 "Instead of ``context.policy.to_dict()``, "
                 "use ``context.to_dict()``.",
                 DeprecationWarning, stacklevel=2)
        else:
            warn(_preamble +
                 "Instead of ``CryptPolicy().to_dict()``, "
                 "create a CryptContext instance and "
                 "use ``context.to_dict()``.",
                 DeprecationWarning, stacklevel=2)
        return self._context.to_dict(resolve)

    def to_file(self, stream, section="passlib"):
        """export policy to file.

        .. deprecated:: 1.6

        applications should use :meth:`CryptContext.to_string` instead,
        and then write the output to a file as desired.
        """
        if self._stub_policy:
            warn(_preamble +
                 "Instead of ``context.policy.to_file(stream)``, "
                 "use ``stream.write(context.to_string())``.",
                 DeprecationWarning, stacklevel=2)
        else:
            warn(_preamble +
                 "Instead of ``CryptPolicy().to_file(stream)``, "
                 "create a CryptContext instance and "
                 "use ``stream.write(context.to_string())``.",
                 DeprecationWarning, stacklevel=2)
        out = self._context.to_string(section=section)
        if PY2:
            out = out.encode("utf-8")
        stream.write(out)

    def to_string(self, section="passlib", encoding=None):
        """export policy to file.

        .. deprecated:: 1.6

        applications should use :meth:`CryptContext.to_string` instead.
        """
        if self._stub_policy:
            warn(_preamble +
                 "Instead of ``context.policy.to_string()``, "
                 "use ``context.to_string()``.",
                 DeprecationWarning, stacklevel=2)
        else:
            warn(_preamble +
                 "Instead of ``CryptPolicy().to_string()``, "
                 "create a CryptContext instance and "
                 "use ``context.to_string()``.",
                 DeprecationWarning, stacklevel=2)
        out = self._context.to_string(section=section)
        if encoding:
            out = out.encode(encoding)
        return out

    #=========================================================
    # eoc
    #=========================================================

#=========================================================
# _CryptRecord helper class
#=========================================================
class _CryptRecord(object):
    """wraps a handler and automatically applies various options.

    this is a helper used internally by CryptContext in order to reduce the
    amount of work that needs to be done by CryptContext.verify().
    this class takes in all the options for a particular (scheme, category)
    combination, and attempts to provide as short a code-path as possible for
    the particular configuration.
    """

    #================================================================
    # instance attrs
    #================================================================

    # informational attrs
    handler = None # handler instance this is wrapping
    category = None # user category this applies to
    deprecated = False # set if handler itself has been deprecated in config

    # rounds management - filled in by _init_rounds_options()
    _has_rounds_options = False # if _has_rounds_bounds OR _generate_rounds is set
    _has_rounds_bounds = False # if either min_rounds or max_rounds set
    _min_rounds = None #: minimum rounds allowed by policy, or None
    _max_rounds = None #: maximum rounds allowed by policy, or None
    _generate_rounds = None # rounds generation function, or None

    # encrypt()/genconfig() attrs
    settings = None # options to be passed directly to encrypt()

    # verify() attrs
    _min_verify_time = None

    # hash_needs_update() attrs
    _is_deprecated_by_handler = None # optional callable used by bcrypt/scram
    _has_rounds_introspection = False # if rounds can be extract from hash

    # cloned directly from handler, not affected by config options.
    identify = None
    genhash = None

    #================================================================
    # init
    #================================================================
    def __init__(self, handler, category=None, deprecated=False,
                 min_rounds=None, max_rounds=None, default_rounds=None,
                 vary_rounds=None, min_verify_time=None, passprep=None,
                 **settings):
        # store basic bits
        self.handler = handler
        self.category = category
        self.deprecated = deprecated
        self.settings = settings

        # validate & normalize rounds options
        self._init_rounds_options(min_rounds, max_rounds, default_rounds,
                             vary_rounds)

        # init wrappers for handler methods we modify args to
        self._init_encrypt_and_genconfig()
        self._init_verify(min_verify_time)
        self._init_hash_needs_update()

        # these aren't wrapped by _CryptRecord, copy them directly from handler.
        self.identify = handler.identify
        self.genhash = handler.genhash

        # let stringprep code wrap genhash/encrypt/verify if needed
        self._init_passprep(passprep)

    #================================================================
    # virtual attrs
    #================================================================
    @property
    def scheme(self):
        return self.handler.name

    @property
    def _errprefix(self):
        "string used to identify record in error messages"
        handler = self.handler
        category = self.category
        if category:
            return "%s %s config" % (handler.name, category)
        else:
            return "%s config" % (handler.name,)

    def __repr__(self):
        return "<_CryptRecord 0x%x for %s>" % (id(self), self._errprefix)

    #================================================================
    # rounds generation & limits - used by encrypt & deprecation code
    #================================================================
    def _init_rounds_options(self, mn, mx, df, vr):
        "parse options and compile efficient generate_rounds function"
        #----------------------------------------------------
        # extract hard limits from handler itself
        #----------------------------------------------------
        handler = self.handler
        if 'rounds' not in handler.setting_kwds:
            # doesn't even support rounds keyword.
            return
        hmn = getattr(handler, "min_rounds", None)
        hmx = getattr(handler, "max_rounds", None)

        def check_against_handler(value, name):
            "issue warning if value outside handler limits"
            if hmn is not None and value < hmn:
                warn("%s: %s value is below handler minimum %d: %d" %
                     (self._errprefix, name, hmn, value), PasslibConfigWarning)
            if hmx is not None and value > hmx:
                warn("%s: %s value is above handler maximum %d: %d" %
                     (self._errprefix, name, hmx, value), PasslibConfigWarning)

        #----------------------------------------------------
        # set policy limits
        #----------------------------------------------------
        if mn is not None:
            if mn < 0:
                raise ValueError("%s: min_rounds must be >= 0" % self._errprefix)
            check_against_handler(mn, "min_rounds")
            self._min_rounds = mn
            self._has_rounds_bounds = True

        if mx is not None:
            if mn is not None and mx < mn:
                raise ValueError("%s: max_rounds must be "
                                 ">= min_rounds" % self._errprefix)
            elif mx < 0:
                raise ValueError("%s: max_rounds must be >= 0" % self._errprefix)
            check_against_handler(mx, "max_rounds")
            self._max_rounds = mx
            self._has_rounds_bounds = True

        #----------------------------------------------------
        # validate default_rounds
        #----------------------------------------------------
        if df is not None:
            if mn is not None and df < mn:
                    raise ValueError("%s: default_rounds must be "
                                     ">= min_rounds" % self._errprefix)
            if mx is not None and df > mx:
                    raise ValueError("%s: default_rounds must be "
                                     "<= max_rounds" % self._errprefix)
            check_against_handler(df, "default_rounds")
        elif vr or mx or mn:
            # need an explicit default to work with
            df = getattr(handler, "default_rounds", None) or mx or mn
            assert df is not None, "couldn't find fallback default_rounds"
        else:
            # no need for rounds generation
            self._has_rounds_options = self._has_rounds_bounds
            return

        # clip default to handler & policy limits *before* vary rounds
        # is calculated, so that proportion vr values are scaled against
        # the effective default.
        def clip(value):
            "clip value to intersection of policy + handler limits"
            if mn is not None and value < mn:
                value = mn
            if hmn is not None and value < hmn:
                value = hmn
            if mx is not None and value > mx:
                value = mx
            if hmx is not None and value > hmx:
                value = hmx
            return value
        df = clip(df)

        #----------------------------------------------------
        # validate vary_rounds,
        # coerce df/vr to linear scale,
        # and setup scale_value() to undo coercion
        #----------------------------------------------------
        # NOTE: vr=0 same as if vr not set
        if vr:
            if vr < 0:
                raise ValueError("%s: vary_rounds must be >= 0" %
                                 self._errprefix)
            def scale_value(value, upper):
                return value
            if isinstance(vr, float):
                # vr is value from 0..1 expressing fraction of default rounds.
                if vr > 1:
                    # XXX: deprecate 1.0 ?
                    raise ValueError("%s: vary_rounds must be < 1.0" %
                                     self._errprefix)
                # calculate absolute vr value based on df & rounds_cost
                cost_scale = getattr(handler, "rounds_cost", "linear")
                assert cost_scale in ["log2", "linear"]
                if cost_scale == "log2":
                    # convert df & vr to linear scale for limit calc,
                    # but define scale_value() to convert back to log2.
                    df = 1<<df
                    def scale_value(value, upper):
                        if value <= 0:
                            return 0
                        elif upper:
                            return int(logb(value,2))
                        else:
                            return int(ceil(logb(value,2)))
                vr = int(df*vr)
            elif not isinstance(vr, int):
                raise TypeError("vary_rounds must be int or float")
            # else: vr is explicit number of rounds to vary df by.

        #----------------------------------------------------
        # set up rounds generation function.
        #----------------------------------------------------
        if not vr:
            # fixed rounds value
            self._generate_rounds = lambda : df
        else:
            # randomly generate rounds in range df +/- vr
            lower = clip(scale_value(df-vr,False))
            upper = clip(scale_value(df+vr,True))
            if lower == upper:
                self._generate_rounds = lambda: upper
            else:
                assert lower < upper
                self._generate_rounds = lambda: rng.randint(lower, upper)

        # hack for bsdi_crypt - want to avoid even-valued rounds
        # NOTE: this technically might generate a rounds value 1 larger
        # than the requested upper bound - but better to err on side of safety.
        if getattr(handler, "_avoid_even_rounds", False):
            gen = self._generate_rounds
            self._generate_rounds = lambda : gen()|1

        self._has_rounds_options = True

    #================================================================
    # encrypt() / genconfig()
    #================================================================
    def _init_encrypt_and_genconfig(self):
        "initialize genconfig/encrypt wrapper methods"
        settings = self.settings
        handler = self.handler

        # check no invalid settings are being set
        keys = handler.setting_kwds
        for key in settings:
            if key not in keys:
                raise KeyError("keyword not supported by %s handler: %r" %
                               (handler.name, key))

        # if _prepare_settings() has nothing to do, bypass our wrappers
        # with reference to original methods.
        if not (settings or self._has_rounds_options):
            self.genconfig = handler.genconfig
            self.encrypt = handler.encrypt

    def genconfig(self, **kwds):
        "wrapper for handler.genconfig() which adds custom settings/rounds"
        self._prepare_settings(kwds)
        return self.handler.genconfig(**kwds)

    def encrypt(self, secret, **kwds):
        "wrapper for handler.encrypt() which adds custom settings/rounds"
        self._prepare_settings(kwds)
        return self.handler.encrypt(secret, **kwds)

    def _prepare_settings(self, kwds):
        "add default values to settings for encrypt & genconfig"
        #load in default values for any settings
        if kwds:
            for k,v in iteritems(self.settings):
                if k not in kwds:
                    kwds[k] = v
        else:
            # faster, and the common case
            kwds.update(self.settings)

        # handle rounds
        if self._has_rounds_options:
            rounds = kwds.get("rounds")
            if rounds is None:
                # fill in default rounds value
                gen = self._generate_rounds
                if gen:
                    kwds['rounds'] = gen()
            elif self._has_rounds_bounds:
                # check bounds for application-provided rounds value.
                # XXX: should this raise an error instead of warning ?
                # NOTE: stackdepth=4 is so that error matches
                # where ctx.encrypt() was called by application code.
                mn = self._min_rounds
                if mn is not None and rounds < mn:
                    warn("%s requires rounds >= %d, increasing value from %d" %
                         (self._errprefix, mn, rounds), PasslibConfigWarning, 4)
                    rounds = mn
                mx = self._max_rounds
                if mx and rounds > mx:
                    warn("%s requires rounds <= %d, decreasing value from %d" %
                         (self._errprefix, mx, rounds), PasslibConfigWarning, 4)
                    rounds = mx
                kwds['rounds'] = rounds

    #================================================================
    # verify()
    #================================================================
    # TODO: once min_verify_time is removed, this will just be a clone
    # of handler.verify()

    def _init_verify(self, mvt):
        "initialize verify() wrapper - implements min_verify_time"
        if mvt:
            assert isinstance(mvt, (int,float)) and mvt > 0, "CryptPolicy should catch this"
            self._min_verify_time = mvt
        else:
            # no mvt wrapper needed, so just use handler.verify directly
            self.verify = self.handler.verify

    def verify(self, secret, hash, **context):
        "verify helper - adds min_verify_time delay"
        mvt = self._min_verify_time
        assert mvt > 0, "wrapper should have been replaced for mvt=0"
        start = tick()
        if self.handler.verify(secret, hash, **context):
            return True
        end = tick()
        delta = mvt + start - end
        if delta > 0:
            sleep(delta)
        elif delta < 0:
            # warn app they exceeded bounds (this might reveal
            # relative costs of different hashes if under migration)
            warn("CryptContext: verify exceeded min_verify_time: "
                 "scheme=%r min_verify_time=%r elapsed=%r" %
                 (self.scheme, mvt, end-start), PasslibConfigWarning)
        return False

    #================================================================
    # hash_needs_update()
    #================================================================
    def _init_hash_needs_update(self):
        """initialize state for hash_needs_update()"""
        # if handler has been deprecated, replace wrapper and skip other checks
        if self.deprecated:
            self.hash_needs_update = lambda hash: True
            return

        # let handler detect hashes with configurations that don't match
        # current settings. currently do this by calling
        # ``handler._deprecation_detector(**settings)``, which if defined
        # should return None or a callable ``is_deprecated(hash)->bool``.
        #
        # NOTE: this interface is still private, because it was hacked in
        # for the sake of bcrypt & scram, and is subject to change.
        handler = self.handler
        const = getattr(handler, "_deprecation_detector", None)
        if const:
            self._is_deprecated_by_handler = const(**self.settings)

        # XXX: what about a "min_salt_size" deprecator?

        # set flag if we can extract rounds from hash, allowing
        # hash_needs_update() to check for rounds that are outside of
        # the configured range.
        if self._has_rounds_bounds and hasattr(handler, "from_string"):
            self._has_rounds_introspection = True

    def hash_needs_update(self, hash):
        # init replaces this method entirely for this case.
        ### check if handler has been deprecated
        ##if self.deprecated:
        ##    return True

        # check handler's detector if it provided one.
        check = self._is_deprecated_by_handler
        if check and check(hash):
            return True

        # if we can parse rounds parameter, check if it's w/in bounds.
        if self._has_rounds_introspection:
            hash_obj = self.handler.from_string(hash)
            try:
                rounds = hash_obj.rounds
            except AttributeError:
                # XXX: hash_obj should generally have rounds attr,
                # so should a warning be raised here?
                pass
            else:
                mn = self._min_rounds
                if mn is not None and rounds < mn:
                    return True
                mx = self._max_rounds
                if mx and rounds > mx:
                    return True

        return False

    #================================================================
    # password stringprep
    #================================================================
    def _init_passprep(self, value):
        # NOTE: all of this code assumes secret uses utf-8 encoding if bytes.
        if not value:
            return
        self._stringprep = value
        names = _splitcomma(value)
        if names == ["raw"]:
            return
        funcs = [_passprep_funcs[name] for name in names]

        first = funcs[0]
        def wrap(orig):
            def wrapper(secret, *args, **kwds):
                if isinstance(secret, bytes):
                    secret = secret.decode("utf-8")
                return orig(first(secret), *args, **kwds)
            update_wrapper(wrapper, orig)
            wrapper._wrapped = orig
            return wrapper

        # wrap genhash & encrypt so secret is prep'd
        self.genhash = wrap(self.genhash)
        self.encrypt = wrap(self.encrypt)

        # wrap verify so secret is prep'd
        if len(funcs) == 1:
            self.verify = wrap(self.verify)
        else:
            # if multiple fallback prep functions,
            # try to verify with each of them.
            verify = self.verify
            def wrapper(secret, *args, **kwds):
                if isinstance(secret, bytes):
                    secret = secret.decode("utf-8")
                seen = set()
                for prep in funcs:
                    tmp = prep(secret)
                    if tmp not in seen:
                        if verify(tmp, *args, **kwds):
                            return True
                        seen.add(tmp)
                return False
            update_wrapper(wrapper, verify)
            wrapper._wrapped = verify
            self.verify = wrapper

    #================================================================
    # eoc
    #================================================================

#=========================================================
# main CryptContext class
#=========================================================
class CryptContext(object):
    """Helper for encrypting passwords using different algorithms.

    Instances of this class allow applications to choose a specific
    set of hash algorithms which they wish to support, set limits and defaults
    for the rounds and salt sizes those algorithms should use, flag
    which algorithms should be deprecated, and automatically handle
    migrating users to stronger hashes when they log in.

    This class can be created one of three ways: directly through it's
    constructor via keywords, loaded from a configuration string,
    or loaded from a file. Configuration strings / files can be created by hand;
    or automatically created by serializing an existing CryptContext, using
    :meth:``to_string``.

    :param \*\*kwds:

        CryptContext instances accept a wide number of keywords as possible
        options. Common keywords include ``schemes`` and ``default``.
        See :doc:`/lib/passlib.context-options` for a full list.

    Main Interface
    ==============
    Most applications will only need to make use two methods in a CryptContext
    instance:

    .. automethod:: encrypt
    .. automethod:: verify

    Applications which want to detect and re-encrypt deprecated
    hashes will want to use one of the following methods:

    .. automethod:: hash_needs_update
    .. automethod:: verify_and_update

    Additionally, the main interface offers a few helper methods,
    useful for certain border cases:

    .. automethod:: identify
    .. automethod:: genhash
    .. automethod:: genconfig

    Alternate Constructors
    ======================
    In addition to the main class constructor, which accepts a configuration
    as a set of keywords, there are the following alternate constructors:

    .. automethod:: from_string
    .. automethod:: from_path
    .. automethod:: copy

    Updating the Configuration
    ==========================
    CryptContext objects can have their configuration replaced or updated
    on the fly, and from a variety of sources (keywords, strings, files).
    This is done through two methods:

    .. automethod:: update(\*\*kwds)
    .. automethod:: load
    .. automethod:: load_path

    Examining the Configuration
    ===========================
    The CryptContext object also supports some basic inspection of it's
    current configuration:

    .. automethod:: schemes
    .. automethod:: default_scheme
    .. automethod:: handler

    More detailed inspection can be done through the serialization methods:

    .. automethod:: to_dict
    .. automethod:: to_string
    """
    # FIXME: altering the configuration of this object isn't threadsafe,
    # but is generally only done during application init, so not a major
    # issue (just yet).

    #===================================================================
    #instance attrs
    #===================================================================

    # tuple of handlers (from 'schemes' keyword)
    _handlers = None

    # tuple of scheme names (in same order as handlers)
    _schemes = None

    # tuple of extra category names (in alpha order, omits ``None``)
    _categories = None

    # triple-nested-dict which maps scheme -> category -> option -> value
    _scheme_options = None

    # dict mapping category -> default scheme
    _default_schemes = None

    # dict mapping category -> set of deprecated schemes
    _deprecated_schemes = None

    # dict mapping category -> min_verify_time
    _mvtmap = None

    # dict mapping (scheme,category) -> _CryptRecord instance.
    # initial values populated by load(), but extra keys
    # such as scheme=None for default record are populated on demand
    # by _get_record()
    _records = None

    # dict mapping category -> list of _CryptRecord instances for that category,
    # in order of schemes(). populated on demand by _get_record_list()
    _record_lists = None

    #===================================================================
    # secondary constructors
    #===================================================================
    @classmethod
    def from_string(cls, source, section="passlib", encoding="utf-8"):
        """create new CryptContext instance from an INI-formatted string.

        :arg source:
            bytes/unicode string containing INI-formatted content.

        :param section:
            option name of section to read from, defaults to ``"passlib"``.

        :arg encoding:
            optional encoding used when source is bytes, defaults to ``"utf-8"``.

        :returns:
            new CryptContext instance.

        usage example::

            >>> from passlib.context import CryptContext
            >>> context = CryptContext.from_string('''
            ... [passlib]
            ... schemes = sha256_crypt, des_crypt
            ... sha256_crypt__default_rounds = 30000
            ... ''')

        .. versionadded:: 1.6
        """
        if not isinstance(source, base_string_types):
            raise ExpectedTypeError(source, "unicode or bytes", "source")
        self = cls(_autoload=False)
        self.load(source, section=section, encoding=encoding)
        return self

    @classmethod
    def from_path(cls, path, section="passlib", encoding="utf-8"):
        """create new CryptContext instance from an INI-formatted file.

        this functions exactly the same as :meth:`from_string`,
        except that it loads from a local file.

        :arg source:
            path to local file containing INI-formatted config.

        :param section:
            option name of section to read from, defaults to ``"passlib"``.

        :arg encoding:
            encoding used to load file, defaults to ``"utf-8"``.

        :returns:
            new CryptContext instance.

        .. versionadded:: 1.6
        """
        self = cls(_autoload=False)
        self.load_path(path, section=section, encoding=encoding)
        return self

    def copy(self, **kwds):
        """return copy of existing CryptContext instance.

        this function returns a new CryptContext instance whose configuration
        is exactly the same as the original, with the exception that any keywords
        passed in will take precedence over the original settings.

        usage example::

            >>> # given an existing context, e.g...
            >>> from passlib.apps import custom_app_context

            >>> # copy can be used to make a clone
            >>> my_context = custom_app_context.copy(default="sha512_crypt")

            >>> # and the original will be unaffected by the change
            >>> my_context.default_scheme()
            "sha512_crypt"
            >>> custom_app_context.default_scheme()
            "sha256_crypt"

        .. seealso:: :meth:`update`

        .. versionchanged:: 1.6
            This method was previously named ``replace``, that name
            is still supported, but deprecated, and will be removed
            in Passlib 1.8.
        """
        other = CryptContext(**self.to_dict(resolve=True))
        if kwds:
            other.load(kwds, update=True)
        return other

    def replace(self, **kwds):
        "deprecated alias of :meth:`copy`"
        warn("CryptContext().replace() has been deprecated in Passlib 1.6, "
             "and will be removed in Passlib 1.8, "
             "it has been renamed to CryptContext().copy()",
             DeprecationWarning, stacklevel=2)
        return self.copy(**kwds)

    #===================================================================
    #init
    #===================================================================
    def __init__(self, schemes=None,
                 # keyword only...
                 policy=_UNSET, # <-- deprecated
                 _autoload=True, **kwds):
        # XXX: add ability to make flag certain contexts as immutable,
        #      e.g. the builtin passlib ones?
        # XXX: add a name or import path for the contexts, to help out repr?
        if schemes is not None:
            kwds['schemes'] = schemes
        if policy is not _UNSET:
            warn("The CryptContext ``policy`` keyword has been deprecated as of Passlib 1.6, "
                 "and will be removed in Passlib 1.8; please use "
                 "``CryptContext.from_string()` or "
                 "``CryptContext.from_path()`` instead.",
                 DeprecationWarning)
            if policy is None:
                self.load(kwds)
            elif isinstance(policy, CryptPolicy):
                self.load(policy._context)
                self.update(kwds)
            else:
                raise TypeError("policy must be a CryptPolicy instance")
        elif _autoload:
            self.load(kwds)
        else:
            assert not kwds, "_autoload=False and kwds are mutually exclusive"

    def __str__(self):
        if PY3:
            return self.to_string()
        else:
            return self.to_string().encode("utf-8")

    def __repr__(self):
        return "<CryptContext 0x%0x>" % id(self)

        # XXX: not sure if this would be helpful, or confusing...
        ### let repr output string required to recreate the CryptContext
        ##data = self.to_string(compact=True)
        ##if not PY3:
        ##    data = data.encode("utf-8")
        ##return "CryptContext.from_string(%r)" % (data,)

    #===================================================================
    # deprecated policy object
    #===================================================================
    def _get_policy(self):
        # The CryptPolicy class has been deprecated, so to support any
        # legacy accesses, we create a stub policy object so .policy attr
        # will continue to work.
        #
        # the code waits until app accesses a specific policy object attribute
        # before issuing deprecation warning, so developer gets method-specific
        # suggestion for how to upgrade.

        # NOTE: making a copy of the context so the policy acts like a snapshot,
        # to retain the pre-1.6 behavior.
        return CryptPolicy(_internal_context=self.copy(), _stub_policy=True)

    def _set_policy(self, policy):
        warn("The CryptPolicy class and the ``context.policy`` attribute have "
             "been deprecated as of Passlib 1.6, and will be removed in "
             "Passlib 1.8; please use the ``context.load()`` and "
             "``context.update()`` methods instead.",
             DeprecationWarning, stacklevel=2)
        if isinstance(policy, CryptPolicy):
            self.load(policy._context)
        else:
            raise TypeError("expected CryptPolicy instance")

    policy = property(_get_policy, _set_policy,
                    doc="[deprecated] returns CryptPolicy instance "
                        "tied to this CryptContext")

    #===================================================================
    # loading / updating configuration
    #===================================================================
    @staticmethod
    def _parse_ini_stream(stream, section, filename):
        "helper read INI from stream, extract passlib section as dict"
        # NOTE: this expects a unicode stream under py3,
        # and a utf-8 bytes stream under py2,
        # allowing the resulting dict to always use native strings.
        p = SafeConfigParser()
        if PY_MIN_32:
            # python 3.2 deprecated readfp in favor of read_file
            p.read_file(stream, filename)
        else:
            p.readfp(stream, filename)
        return dict(p.items(section))

    def load_path(self, path, update=False, section="passlib", encoding="utf-8"):
        """load new configuration into CryptContext from a local file.

        This function is a wrapper for :meth:`load`, which
        loads a configuration string from the local file *path*,
        instead of an in-memory source. It's behavior and options
        are otherwise identical to :meth:`!load` when provided with
        an INI-formatted string.

        .. versionadded:: 1.6
        """
        def helper(stream):
            kwds = self._parse_ini_stream(stream, section, path)
            return self.load(kwds, update=update)
        if PY3:
            # decode to unicode, which load() expected under py3
            with open(path, "rt", encoding=encoding) as stream:
                return helper(stream)
        elif encoding in ["utf-8", "ascii"]:
            # keep as utf-8 bytes, which load() expects under py2
            with open(path, "rb") as stream:
                return helper(stream)
        else:
            # transcode to utf-8 bytes
            with open(path, "rb") as fh:
                tmp = fh.read().decode(encoding).encode("utf-8")
                return helper(BytesIO(tmp))

    def load(self, source, update=False, section="passlib", encoding="utf-8"):
        """load new configuration into CryptContext, replacing existing config.

        :arg source:
            source of new configuration.

            *source* can be one of a few of different types:

            :class:`!dict` or another mapping

                the key/value pairs will be interpreted the same
                keywords for the :class:`CryptContext` class constructor.

            :class:`!unicode` or :class:`!bytes` string

                this will be interpreted as an INI-formatted file,
                and appropriate key/value pairs will be loaded from
                the specified *section*.

        :type update: bool
        :param update:
            By default, :meth:`load` will replace the existing configuration
            entirely. If ``update=True``, it will preserve any existing
            configuration options that are not overridden by the new source,
            much like the :meth:`update` method.

        :type section: str
        :param section:
            When parsing an INI-formatted string, :meth:`load` will look for
            a section named ``"passlib"``. This option allows an alternate
            section name to be used. Ignored when loading from a dictionary.

        :type encoding: str
        :param encoding:
            Encoding to use when decode bytes from string.
            Defaults to ``"utf-8"``. Ignoring when loading from a dictionary.

        :raises TypeError:
            * If the source cannot be identified.
            * If an unknown / malformed keyword is encountered.

        :raises ValueError:
            If an invalid keyword value is encountered.

        If an error occurs during a :meth:`!load` call, the :class`!CryptContext`
        instance will be restored to the configuration it was in before
        the :meth:`!load` call was made, it should never be left in an
        inconsistent state due to a load failure.

        .. versionadded:: 1.6
        """
        #-----------------------------------------------------------
        # autodetect source type, convert to dict
        #-----------------------------------------------------------
        parse_keys = True
        if isinstance(source, base_string_types):
            if PY3:
                source = to_unicode(source, encoding, errname="source")
            else:
                source = to_bytes(source, "utf-8", source_encoding=encoding,
                                  errname="source")
            source = self._parse_ini_stream(NativeStringIO(source), section,
                                            "<string>")
        elif isinstance(source, CryptContext):
            # do this a little more efficiently since we can extract
            # the keys as tuples directly from the other instance.
            source = dict(source._iter_config(resolve=True))
            parse_keys = False
        elif not hasattr(source, "items"):
            # assume it's not a mapping.
            raise ExpectedTypeError(source, "string or dict", "source")

        # XXX: add support for other iterable types, e.g. sequence of pairs?

        #-----------------------------------------------------------
        # parse dict keys into (category, scheme, option) format,
        # and merge with existing configuration if needed.
        #-----------------------------------------------------------
        if parse_keys:
            parse = self._parse_config_key
            source = dict((parse(key), value) for key, value in iteritems(source))
        if update and self._handlers is not None:
            if not source:
                return
            tmp = source
            source = dict(self._iter_config(resolve=True))
            source.update(tmp)

        #-----------------------------------------------------------
        # clear internal config, replace with content of source.
        #-----------------------------------------------------------
        # NOTE: if this fails, 'self' will be an unpredicatable state,
        # since config parsing can fail at a number of places.
        # the follow code fixes this by backing up the state, and restoring
        # it if any errors occur. this is somewhat... hacked...
        # but it works for now, and performance is not an issue in the
        # error case. but because of that, care should be taken
        # that _load() never modifies existing attrs, and instead replaces
        # them entirely.
        state = self.__dict__.copy()
        try:
            self._load(source)
        except:
            self.__dict__.clear()
            self.__dict__.update(state)
            raise

    def _load(self, source):
        """load source keys into internal configuration.

        note that if this throws error, object's config will be left
        in inconsistent state, load() takes care of backing up / restoring
        original config.
        """
        #-----------------------------------------------------------
        # build & validate list of handlers
        #-----------------------------------------------------------
        handlers  = []
        schemes = []
        data = source.get((None,None,"schemes"))
        if isinstance(data, str):
            data = _splitcomma(data)
        for elem in data or ():
            # resolve elem -> handler & scheme
            if hasattr(elem, "name"):
                handler = elem
                scheme = handler.name
                _validate_handler_name(scheme)
            elif isinstance(elem, str):
                handler = get_crypt_handler(elem)
                scheme = handler.name
            else:
                raise TypeError("scheme must be name or CryptHandler, "
                                "not %r" % type(elem))

            #check scheme name already in use
            if scheme in schemes:
                raise KeyError("multiple handlers with same name: %r" %
                               (scheme,))

            #add to handler list
            handlers.append(handler)
            schemes.append(scheme)

        self._handlers = handlers = tuple(handlers)
        self._schemes = schemes = tuple(schemes)

        #-----------------------------------------------------------
        # initialize internal storage, write all scheme-specific options
        # to _scheme_options, validate & store all global CryptContext
        # options in the appropriate private attrs.
        #-----------------------------------------------------------
        scheme_options = self._scheme_options = {}
        self._default_schemes = {}
        self._deprecated_schemes = {}
        self._mvtmap = {}
        categories = set()
        add_cat = categories.add
        for (cat, scheme, key), value in iteritems(source):
            add_cat(cat)
            # store scheme-specific options for later,
            # and let _CryptRecord() handle validation in next section.
            if scheme:
                # check for invalid options
                if key == "rounds":
                    # for now, translating this to 'default_rounds' to be helpful.
                    # need to pick one of the two as official,
                    # and deprecate the other one.
                    key = "default_rounds"
                elif key in _forbidden_scheme_options:
                    raise KeyError("%r option not allowed in CryptContext "
                                   "configuration" % (key,))
                # coerce strings for certain fields (e.g. min_rounds -> int)
                if isinstance(value, str):
                    func = _coerce_scheme_options.get(key)
                    if func:
                        value = func(value)
                # store value in scheme_options
                if scheme in scheme_options:
                    config = scheme_options[scheme]
                    if cat in config:
                        config[cat][key] = value
                    else:
                        config[cat] = {key: value}
                else:
                    scheme_options[scheme] = {cat: {key: value}}
            # otherwise it's a CryptContext option of some type.
            # perform validation here, and store internally.
            elif key == "default":
                if hasattr(value, "name"):
                    value = value.name
                elif not isinstance(value, str):
                    raise ExpectedTypeError(value, "str", "default")
                if schemes and value not in schemes:
                    raise KeyError("default scheme not found in policy")
                self._default_schemes[cat] = value
            elif key == "deprecated":
                if isinstance(value, str):
                    value = _splitcomma(value)
                elif not isinstance(value, (list,tuple)):
                    raise ExpectedTypeError(value, "str or seq", "deprecated")
                if schemes:
                    for scheme in value:
                        if not isinstance(scheme, str):
                            raise ExpectedTypeError(value, "str", "deprecated element")
                        if scheme not in schemes:
                            raise KeyError("deprecated scheme not found "
                                       "in policy: %r" % (scheme,))
                    # TODO: make sure there's at least one non-deprecated scheme.
                    # TODO: make sure default scheme hasn't been deprecated.
                self._deprecated_schemes[cat] = value
            elif key == "min_verify_time":
                warn("'min_verify_time' is deprecated as of Passlib 1.6, will be "
                     "ignored in 1.7, and removed in 1.8.", DeprecationWarning)
                value = float(value)
                if value < 0:
                    raise ValueError("'min_verify_time' must be >= 0")
                self._mvtmap[cat] = value
            elif key == "schemes":
                if cat:
                    raise KeyError("'schemes' context option is not allowed "
                                   "per category")
                #else: cat=None already handled above
            else:
                raise KeyError("unknown CryptContext keyword: %r" % (key,))
        categories.discard(None)
        self._categories = categories = tuple(sorted(categories))

        #-----------------------------------------------------------
        # compile table of _CryptRecord instances, one for every
        # (scheme,category) combination.
        #-----------------------------------------------------------
        # NOTE: could do all of this on-demand in _get_record(),
        # but _CryptRecord() handles final validation of settings,
        # and we want to alert the user to errors now instead of later.
        records = self._records = {}
        self._record_lists = {}
        get_options = self._get_record_options
        for handler in handlers:
            scheme = handler.name
            kwds, _ = get_options(scheme, None)
            records[scheme, None] = _CryptRecord(handler, **kwds)
            for cat in categories:
                kwds, has_cat_options = get_options(scheme, cat)
                if has_cat_options:
                    records[scheme, cat] = _CryptRecord(handler, **kwds)
                # NOTE: if handler has no category-specific opts, _get_record()
                # will automatically use the default category's record.
        # NOTE: default records for specific category stored under the
        # key (None,category); these are populated on-demand by _get_record().

    @staticmethod
    def _parse_config_key(ckey):
        """helper used to parse ``cat__scheme__option`` keys into a tuple"""
        # split string into 1-3 parts
        assert isinstance(ckey, str)
        parts = ckey.split("." if "." in ckey else "__")
        count = len(parts)
        if count == 1:
            cat, scheme, key = None, None, parts[0]
        elif count == 2:
            cat = None
            scheme, key = parts
        elif count == 3:
            cat, scheme, key = parts
        else:
            raise TypeError("keys must have less than 3 separators: %r" %
                            (ckey,))
        # validate & normalize the parts
        if cat == "default":
            cat = None
        elif not cat and cat is not None:
            raise TypeError("empty category: %r" % ckey)
        if scheme == "context":
            scheme = None
        elif not scheme and scheme is not None:
            raise TypeError("empty scheme: %r" % ckey)
        if not key:
            raise TypeError("empty option: %r" % ckey)
        return cat, scheme, key

    def update(self, *args, **kwds):
        """helper for quickly changing configuration.

        this acts much like the dictionary :meth:`!update` method;
        it accepts any keyword accepted by the :class:`CryptContext`
        constructor, and updates the context's configuration,
        replacing the original value(s).

        .. versionadded:: 1.6

        .. seealso:: :meth:`copy`
        """
        if args:
            if len(args) > 1:
                raise TypeError("expected at most one positional argument")
            if kwds:
                raise TypeError("positional arg and keywords mutually exclusive")
            self.load(args[0], update=True)
        elif kwds:
            self.load(kwds, update=True)

    # XXX: make this public?
    def _simplify(self):
        "helper to remove redundant/unused options"
        # don't do anything if no schemes are defined
        if not self._schemes:
            return

        def strip_items(target, filter):
            keys = [key for key,value in iteritems(target)
                    if filter(key,value)]
            for key in keys:
                del target[key]

        # remove redundant default.
        defaults = self._default_schemes
        if defaults.get(None) == self._schemes[0]:
            del defaults[None]

        # remove options for unused schemes.
        scheme_options = self._scheme_options
        schemes = self._schemes + ("all",)
        strip_items(scheme_options, lambda k,v: k not in schemes)

        # remove rendundant cat defaults.
        cur = self.default_scheme()
        strip_items(defaults, lambda k,v: k and v==cur)

        # remove redundant category deprecations.
        deprecated = self._deprecated_schemes
        cur = self._deprecated_schemes.get(None)
        strip_items(deprecated, lambda k,v: k and v==cur)

        # remove redundant category options.
        for scheme, config in iteritems(scheme_options):
            if None in config:
                cur = config[None]
                strip_items(config, lambda k,v: k and v==cur)

        # XXX: anything else?

    #===================================================================
    # reading configuration
    #===================================================================
    def _get_record_options(self, scheme, category):
        """return composite dict of options for given scheme + category.

        this is currently a private method, though some variant
        of it's output may eventually be made public.

        given a scheme & category, it returns two things:
        a set of all the keyword options to pass to the _CryptRecord constructor,
        and a bool flag indicating whether any of these options
        were specific to the named category. if this flag is false,
        the options are identical to the options for the default category.

        the options dict includes all the scheme-specific settings,
        as well as optional *deprecated* and *min_verify_time* keywords.
        """
        scheme_options = self._scheme_options
        has_cat_options = False

        # start with options common to all schemes
        common_kwds = scheme_options.get("all")
        if common_kwds is None:
            kwds = {}
        else:
            # start with global options
            tmp = common_kwds.get(None)
            kwds = tmp.copy() if tmp is not None else {}

            # add category options
            if category:
                tmp = common_kwds.get(category)
                if tmp is not None:
                    kwds.update(tmp)
                    has_cat_options = True

        # add scheme-specific options
        scheme_kwds = scheme_options.get(scheme)
        if scheme_kwds:
            # add global options
            tmp = scheme_kwds.get(None)
            if tmp is not None:
                kwds.update(tmp)

            # add category options
            if category:
                tmp = scheme_kwds.get(category)
                if tmp is not None:
                    kwds.update(tmp)
                    has_cat_options = True

        # add deprecated flag
        dep_map = self._deprecated_schemes
        if dep_map:
            deplist = dep_map.get(None)
            dep = (deplist is not None and scheme in deplist)
            if category:
                deplist = dep_map.get(category)
                if deplist is not None:
                    value = (scheme in deplist)
                    if value != dep:
                        dep = value
                        has_cat_options = True
            if dep:
                kwds['deprecated'] = True

        # add min_verify_time setting
        mvt_map = self._mvtmap
        if mvt_map:
            mvt = mvt_map.get(None)
            if category:
                value = mvt_map.get(category)
                if value is not None and value != mvt:
                    mvt = value
                    has_cat_options = True
            if mvt:
                kwds['min_verify_time'] = mvt

        return kwds, has_cat_options

    def schemes(self, resolve=False):
        """return schemes loaded into this CryptContext instance.

        :returns:
            returns list of schemes as a tuple.
            if ``resolve=True``, returns the actual handler objects instead
            of the names (but in the same order).

        .. versionadded:: 1.6
            This was previously available as ``CryptContext().policy.schemes()``
        """
        return self._handlers if resolve else self._schemes

    # XXX: need to decide if exposing this would be useful to applications
    # in any way that isn't already served by to_dict()
    ##def deprecated_schemes(self, category=None, resolve=False):
    ##    """return tuple of deprecated schemes"""
    ##    depmap = self._deprecated_schemes
    ##    if category and category in depmap:
    ##        deplist = depmap[category]
    ##    elif None in depmap:
    ##        deplist = depmap[None]
    ##    else:
    ##        return self.schemes(resolve)
    ##    if resolve:
    ##        return tuple(handler for handler in self._handlers
    ##                     if handler.name not in deplist)
    ##    else:
    ##        return tuple(scheme for scheme in self._schemes
    ##                     if scheme not in deplist)

    def _is_deprecated_scheme(self, scheme, category=None):
        "helper used by unittests to check if scheme is deprecated"
        return self._get_record(scheme, category).deprecated
#        kwds, _ = self._get_record_options(scheme, category)
#        return bool(kwds.get("deprecated"))

    def default_scheme(self, category=None, resolve=False):
        """return name of scheme that :meth:`encrypt` will use by default.

        .. versionadded:: 1.6
        """
        if resolve:
            scheme = self.default_scheme(category)
            for handler in self._handlers:
                if handler.name == scheme:
                    return handler
            raise AssertionError("failed to find matching handler")
        defaults = self._default_schemes
        if defaults:
            try:
                return defaults[category]
            except KeyError:
                pass
            if category:
                try:
                    return defaults[None]
                except KeyError:
                    pass
        try:
            return self._schemes[0]
        except IndexError:
            raise KeyError("no crypt algorithms loaded in this "
                           "CryptContext instance")

    # XXX: need to decide if exposing this would be useful in any way
    ##def categories(self):
    ##    """return user-categories with algorithm-specific options in this CryptContext.
    ##
    ##    this will always return a tuple.
    ##    if no categories besides the default category have been configured,
    ##    the tuple will be empty.
    ##    """
    ##    return self._categories

    # XXX: need to decide if exposing this would be useful to applications
    # in any meaningful way that isn't already served by to_dict()
    ##def options(self, scheme, category=None):
    ##    kwds, percat = self._config.get_options(scheme, category)
    ##    kwds.pop("min_verify_time", None)
    ##    return kwds

    def handler(self, scheme="default", category=None):
        """helper to resolve name of scheme -> handler object.

        the scheme may optionally be set to ``"default"``,
        in which case the handler attached to the default scheme will be
        returned. if ``category`` is specified, the default for that
        category will be returned.

        this will raise a :exc:`KeyError` if no scheme of that name has been
        loaded into this CryptContext.

        .. versionadded:: 1.6
            This was previously available as ``CryptContext().policy.get_handler()``
        """
        if scheme == "default":
            return self.default_scheme(category, True)
        for handler in self._handlers:
            if handler.name == scheme:
                return handler
        if self._handlers:
            raise KeyError("crypt algorithm not found in this "
                           "CryptContext instance: %r" % (scheme,))
        else:
            raise KeyError("no crypt algorithms loaded in this "
                           "CryptContext instance")

    def _has_unregistered(self):
        "check if any handlers in this context aren't in the global registry"
        return not all(_is_handler_registered(handler)
                       for handler in self._handlers)

    #===================================================================
    # exporting config
    #===================================================================
    def _iter_config(self, resolve=False):
        """regenerate original config.

        this is an iterator which yields ``(cat,scheme,option),value`` items,
        in the order they generally appear inside an INI file.
        if interpreted as a dictionary, it should match the original
        keywords passed to the CryptContext (aside from any canonization).

        it's mainly used as the internal backend for most of the public
        serialization methods.
        """
        # grab various bits of data
        defaults = self._default_schemes
        deprecated = self._deprecated_schemes
        mvt = self._mvtmap
        scheme_options = self._scheme_options
        schemes = sorted(scheme_options)

        # write loaded schemes (may differ from 'schemes' local var)
        value = self._schemes
        if value:
            if resolve:
                value = self._handlers
            yield (None, None, "schemes"), list(value)

        # then run through config for each user category
        for cat in (None,) + self._categories:

            # write default scheme (if set)
            value = defaults.get(cat)
            if value is not None:
                yield (cat, None, "default"), value

            # write deprecated-schemes list (if set)
            value = deprecated.get(cat)
            if value is not None:
                yield (cat, None, "deprecated"), list(value)

            # write mvt (if set)
            value = mvt.get(cat)
            if value is not None:
                yield (cat, None, "min_verify_time"), value

            # write per-scheme options for all schemes.
            for scheme in schemes:
                try:
                    kwds = scheme_options[scheme][cat]
                except KeyError:
                    pass
                else:
                    for key in sorted(kwds):
                        yield (cat, scheme, key), kwds[key]

    @staticmethod
    def _render_config_key(key, compact=False):
        "convert 3-part config key to single string"
        cat, scheme, option = key
        if cat:
            fmt = "%s.%s.%s" if compact else "%s__%s__%s"
            return fmt % (cat, scheme or "context", option)
        elif scheme:
            fmt = "%s.%s" if compact else "%s__%s"
            return fmt % (scheme, option)
        else:
            return option

    @staticmethod
    def _render_ini_value(key, value):
        "render value to string suitable for INI file"
        # convert lists to comma separated lists
        # (mainly 'schemes' & 'deprecated')
        if isinstance(value, (list,tuple)):
            value = ", ".join(value)

        # convert numbers to strings
        elif isinstance(value, num_types):
            if isinstance(value, float) and key[2] == "vary_rounds":
                value = ("%.2f" % value).rstrip("0") if value else "0"
            else:
                value = str(value)

        assert isinstance(value, str), \
               "expected string for key: %r %r" % (key, value)

        #escape any percent signs.
        return value.replace("%", "%%")

    def to_dict(self, resolve=False):
        """return as config dictionary;

        if ``resolve=True``, the ``schemes`` key will contain
        a list of handler objects rather than just their names.

        the output of this should be acceptable as input
        to the CryptContext constructor.

        usage example::

            >>> # you can dump the configuration of any crypt context...
            >>> from passlib.apps import ldap_nocrypt_context
            >>> ldap_nocrypt_context.to_dict()
            {'schemes': ['ldap_salted_sha1',
            'ldap_salted_md5',
            'ldap_sha1',
            'ldap_md5',
            'ldap_plaintext']}

        .. versionadded:: 1.6
            This was previously available as ``CryptContext().policy.to_dict()``
        """
        # XXX: should resolve default to conditional behavior
        # based on presence of unregistered handlers?
        render_key = self._render_config_key
        return dict((render_key(key), value)
                    for key, value in self._iter_config(resolve))

    def _write_to_parser(self, parser, section, compact=False):
        "helper to write to ConfigParser instance"
        render_key = self._render_config_key
        render_value = self._render_ini_value
        parser.add_section(section)
        for k,v in self._iter_config():
            v = render_value(k, v)
            k = render_key(k, compact)
            parser.set(section, k, v)

    def to_string(self, section="passlib", compact=False):
        """serialize to INI format and return as unicode string.

        :param section:
            name of INI section to output, defaults to ``"passlib"``.

        :param compact:
            if ``True``, this will attempt to return as short a string
            as possible, rather than a readable one.

        :returns:
            CryptContext configuration, serialized to a INI unicode string.

        usage example::

            >>> # you can dump the configuration of any crypt context...
            >>> from passlib.apps import ldap_nocrypt_context
            >>> print ldap_nocrypt_context.to_string()
            [passlib]
            schemes = ldap_salted_sha1, ldap_salted_md5, ldap_sha1, ldap_md5, ldap_plaintext

        passing the output of this method into :meth:`load`,
        :meth:`from_string` or :meth:`from_file` should recreate
        the exact state of the :class:`CryptContext` instance.

        .. versionadded:: 1.6
            This was previously available as ``CryptContext().policy.to_string()``
        """
        parser = SafeConfigParser()
        self._write_to_parser(parser, section, compact)
        buf = NativeStringIO()
        parser.write(buf)
        out = buf.getvalue()
        if compact:
            out = out.replace(", ", ",").rstrip() + "\n"
            out = re.sub(r"(?m)^([\w.]+)\s+=\s*", r"\1=", out)
        else:
            names = [ handler.name for handler in self._handlers
                     if not _is_handler_registered(handler) ]
            if names:
                names = ", ".join(repr(name) for name in names)
                out += "# NOTE: the %s handler(s) are not registered with Passlib,\n" % names
                out += "# so this string may not correctly reproduce the current configuration.\n\n"
        if not PY3:
            out = out.decode("utf-8")
        return out

    # XXX: is this useful enough to enable?
    ##def write_to_path(self, path, section="passlib", update=False):
    ##    "write to INI file"
    ##    parser = ConfigParser()
    ##    if update and os.path.exists(path):
    ##        if not parser.read([path]):
    ##            raise EnvironmentError("failed to read existing file")
    ##        parser.remove_section(section)
    ##    self._write_to_parser(parser, section)
    ##    fh = file(path, "w")
    ##    parser.write(fh)
    ##    fh.close()

    #===================================================================
    # _CryptRecord cache
    #===================================================================

    # NOTE: the CryptContext object takes the current configuration,
    # and creates a _CryptRecord containing the settings for each
    # (scheme,category) combination. This is used by encrypt() etc
    # to do a quick lookup of the appropriate record,
    # and hand off the real work to the record's methods,
    # which are optimized for the specific set of options.

    def _get_record(self, scheme, category=None):
        "return record for specific scheme & category (cached)"
        # quick lookup in cache
        try:
            return self._records[scheme, category]
        except KeyError:
            pass

        # if scheme=None, use category's default scheme,
        # and cache for next time.
        if not scheme:
            default = self.default_scheme(category)
            assert default
            record = self._records[None, category] = self._get_record(default,
                                                                      category)
            return record

        # if category has no record for scheme, use default category's record,
        # and cache for next time.
        if category:
            try:
                cache = self._records
                record = cache[scheme, category] = cache[scheme, None]
                return record
            except KeyError:
                pass

        # scheme not found in configuration.
        if scheme:
            raise KeyError("crypt algorithm not found in policy: %r" %
                           (scheme,))
        else:
            assert not self._schemes, "somehow lost default scheme!"
            raise KeyError("no crypt algorithms supported")

    def _get_record_list(self, category=None):
        "return list of records for category (cached)"
        try:
            return self._record_lists[category]
        except KeyError:
            value = self._record_lists[category] = [
                self._get_record(scheme, category)
                for scheme in self._schemes
                ]
            return value

    def _identify_record(self, hash, category, required=True):
        """internal helper to identify appropriate _CryptRecord for hash"""
        # FIXME: if multiple hashes could match (e.g. lmhash vs nthash)
        # this will only return first match. might want to do something
        # about this in future, but for now only hashes with unique identifiers
        # will work properly in a CryptContext.
        if not isinstance(hash, base_string_types):
            raise ExpectedStringError(hash, "hash")
        records = self._get_record_list(category)
        for record in records:
            if record.identify(hash):
                return record
        if not required:
            return None
        elif not records:
            raise KeyError("no crypt algorithms supported")
        else:
            raise ValueError("hash could not be identified")

    #===================================================================
    # password hash api
    #===================================================================

    # NOTE: all the following methods do is look up the appropriate
    #       _CryptRecord for a given (scheme,category) combination,
    #       and then let the record object take care of the rest.
    #       Each record object stores the options used
    #       by the specific (scheme,category) combination it manages.

    # XXX: would a better name be needs_update/is_deprecated?
    def hash_needs_update(self, hash, scheme=None, category=None):
        """check if hash is allowed by current policy, or if secret should be re-encrypted.

        the core of CryptContext's support for hash migration:

        this function takes in a hash string, and checks the scheme,
        number of rounds, and other properties against the current policy;
        and returns True if the hash is using a deprecated scheme,
        or is otherwise outside of the bounds specified by the policy.
        if so, the password should be re-encrypted using :meth:`encrypt`.

        :arg hash: existing hash string
        :param scheme: optionally identify specific scheme to check against.
        :param category: optional user category

        :returns: True/False
        """
        if scheme:
            if not isinstance(hash, base_string_types):
                raise ExpectedStringError(hash, "hash")
            record = self._get_record(scheme, category)
        else:
            record = self._identify_record(hash, category)
        return record.hash_needs_update(hash)

    def genconfig(self, scheme=None, category=None, **settings):
        """Call genconfig() for specified handler

        This wraps the genconfig() method of the appropriate handler
        (using the default if none other is specified).
        See the :ref:`password-hash-api` for details.

        The main different between this and calling a handlers' genhash method
        directly is that this method will add in any policy-specific
        options relevant for the particular hash.
        """
        return self._get_record(scheme, category).genconfig(**settings)

    def genhash(self, secret, config, scheme=None, category=None, **context):
        """Call genhash() for specified handler.

        This wraps the genconfig() method of the appropriate handler
        (using the default if none other is specified).
        See the :ref:`password-hash-api` for details.
        """
        # XXX: could insert normalization to preferred unicode encoding here
        return self._get_record(scheme, category).genhash(secret, config,
                                                          **context)

    def identify(self, hash, category=None, resolve=False, required=False):
        """Attempt to identify which algorithm hash belongs to w/in this context.

        :arg hash:
            The hash string to test.

        :param resolve:
            If ``True``, returns the handler itself,
            instead of the name of the handler.

        All registered algorithms will be checked in from last to first,
        and whichever one claims the hash first will be returned.

        :returns:
            The handler which first identifies the hash,
            or ``None`` if none of the algorithms identify the hash.
        """
        record = self._identify_record(hash, category, required)
        if record is None:
            return None
        elif resolve:
            return record.handler
        else:
            return record.scheme

    def encrypt(self, secret, scheme=None, category=None, **kwds):
        """encrypt secret, returning resulting hash.

        :arg secret:
            String containing the secret to encrypt

        :param scheme:
            Optionally specify the name of the algorithm to use.
            If no algorithm is specified, an attempt is made
            to guess from the hash string. If no hash string
            is specified, the last algorithm in the list is used.

        :param \*\*kwds:
            All other keyword options are passed to the algorithm's encrypt method.
            The two most common ones are "keep_salt" and "rounds".

        :returns:
            The secret as encoded by the specified algorithm and options.

        usage example::

            >>> # given an existing CryptContext...
            >>> from passlib.apps import custom_app_context

            >>> # calling encrypt will generate a new salt, and hash
            >>> # the password using the context's default scheme
            >>> custom_app_context.encrypt("fooey")
            '$5$rounds=39987$WWelpiPfgTdTrpSr$tosg/YcCKCzePQnB6eseVh8YdSKRkCJ6uQ/QpXoEUm.'

            >>> # optionally you can specify a particular scheme and options
            >>> # (though if these options are to be hardcoded, you should
            >>> # just create your own CryptContext instance).
            >>> custom_app_context.encrypt("fooey", "sha512_crypt", rounds=5000)
            '$6$D3OcBBac5qGdvIbT$mQvIwPS8bWx2DnSrZrFK3e1Rie1vv8hlixCoBfDSJ..Bg1E0PJVzKzAkdt/cBm9CdADrCxv6tOPjqqn8AxpF01'
        """
        # XXX: could insert normalization to preferred unicode encoding here
        return self._get_record(scheme, category).encrypt(secret, **kwds)

    def verify(self, secret, hash, scheme=None, category=None, **context):
        """verify secret against specified hash.

        This identifies the scheme used by the hash (within this context),
        and verifies that the specified password matches.

        If the policy specified a min_verify_time, this method
        will always take at least that amount of time
        (so as to not reveal legacy entries which use a weak hash scheme).

        :arg secret:
            the secret to verify
        :arg hash:
            hash string to compare to
        :param scheme:
            optional force context to use specfic scheme
            (must be listed in context)
        :param category:
            optional user category, if used by the application.
            defaults to ``None``.
        :param \*\*context:
            all additional keywords are passed to the appropriate handler,
            and should match it's
            :attr:`context keywords <passlib.hash.PasswordHash.context_kwds>`.

        :returns: True/False
        """
        if scheme:
            record = self._get_record(scheme, category)
        else:
            record = self._identify_record(hash, category)
        # XXX: have record strip context kwds if scheme doesn't use them?
        # XXX: could insert normalization to preferred unicode encoding here
        return record.verify(secret, hash, **context)

    def verify_and_update(self, secret, hash, scheme=None, category=None, **kwds):
        """verify secret and check if hash needs upgrading, in a single call.

        This is a convenience method for a common situation in most applications:
        When a user logs in, they must :meth:`verify` if the password matches;
        if successful, check if the hash algorithm
        has been deprecated (:meth:`hash_needs_update`); and if so,
        re-:meth:`encrypt` the secret.
        This method takes care of calling all of these 3 methods,
        returning a simple tuple for the application to use.

        :arg secret:
            the secret to verify
        :arg hash:
            hash string to compare to
        :param scheme:
            optional force context to use specfic scheme
            (must be listed in context)
        :param category:
            optional user category, if used by the application.
            defaults to ``None``.
        :param \*\*context:
            all additional keywords are passed to the appropriate handler,
            and should match it's
            :attr:`context keywords <passlib.hash.PasswordHash.context_kwds>`.

        :returns:
            The tuple ``(verified, new_hash)``, where one of the following
            cases is true:

            * ``(False, None)`` indicates the secret failed to verify.
            * ``(True, None)`` indicates the secret verified correctly,
              and the hash does not need upgrading.
            * ``(True, str)`` indicates the secret verified correctly,
              but the existing hash has been deprecated, and should be replaced
              by the :class:`str` returned as ``new_hash``.

        .. seealso:: :ref:`context-migrating-passwords` for a usage example.
        """
        if scheme:
            record = self._get_record(scheme, category)
        else:
            record = self._identify_record(hash, category)
        # XXX: have record strip context kwds if scheme doesn't use them?
        # XXX: could insert normalization to preferred unicode encoding here.
        if not record.verify(secret, hash, **kwds):
            return False, None
        elif record.hash_needs_update(hash):
            # NOTE: we re-encrypt with default scheme, not current one.
            return True, self.encrypt(secret, None, category, **kwds)
        else:
            return True, None

    #=========================================================
    #eoc
    #=========================================================

class LazyCryptContext(CryptContext):
    """CryptContext subclass which doesn't load handlers until needed.

    This is a subclass of CryptContext which takes in a set of arguments
    exactly like CryptContext, but won't load any handlers
    (or even parse it's arguments) until
    the first time one of it's methods is accessed.

    :arg schemes:
        the first positional argument can be a list of schemes, or omitted,
        just like CryptContext.

    :param onload:

        if a callable is passed in via this keyword,
        it will be invoked at lazy-load time
        with the following signature:
        ``onload(**kwds) -> kwds``;
        where ``kwds`` is all the additional kwds passed to LazyCryptContext.
        It should perform any additional deferred initialization,
        and return the final dict of options to be passed to CryptContext.

        .. versionadded:: 1.6

    :param create_policy:

        .. deprecated:: 1.6
            This option will be removed in Passlib 1.8.
            Applications should use *onload* instead.

    :param kwds:

        All additional keywords are passed to CryptContext;
        or to the *onload* function (if provided).

    This is mainly used internally by modules such as :mod:`passlib.apps`,
    which define a large number of contexts, but only a few of them will be needed
    at any one time. Use of this class saves the memory needed to import
    the specified handlers until the context instance is actually accessed.
    As well, it allows constructing a context at *module-init* time,
    but using :func:`!create_policy()` to provide dynamic configuration
    at *application-run* time.
    """
    _lazy_kwds = None

    # NOTE: the way this class works changed in 1.6.
    #       previously it just called _lazy_init() when ``.policy`` was
    #       first accessed. now that is done whenever any of the public
    #       attributes are accessed, and the class itself is changed
    #       to a regular CryptContext, to remove the overhead once it's unneeded.

    def __init__(self, schemes=None, **kwds):
        if schemes is not None:
            kwds['schemes'] = schemes
        self._lazy_kwds = kwds

    def _lazy_init(self):
        kwds = self._lazy_kwds
        if 'create_policy' in kwds:
            warn("The CryptPolicy class, and LazyCryptContext's "
                 "``create_policy`` keyword have been deprecated as of "
                 "Passlib 1.6, and will be removed in Passlib 1.8; "
                 "please use the ``onload`` keyword instead.",
                 DeprecationWarning)
            create_policy = kwds.pop("create_policy")
            result = create_policy(**kwds)
            policy = CryptPolicy.from_source(result, _warn=False)
            kwds = policy._context.to_dict()
        elif 'onload' in kwds:
            onload = kwds.pop("onload")
            kwds = onload(**kwds)
        del self._lazy_kwds
        super(LazyCryptContext, self).__init__(**kwds)
        self.__class__ = CryptContext

    def __getattribute__(self, attr):
        if (not attr.startswith("_") or attr.startswith("__")) and \
            self._lazy_kwds is not None:
                self._lazy_init()
        return object.__getattribute__(self, attr)

#=========================================================
# eof
#=========================================================
