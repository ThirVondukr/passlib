"""passlib.context - CryptContext implementation"""
#=========================================================
#imports
#=========================================================
from __future__ import with_statement
from passlib.utils import py32_lang
#core
from cStringIO import StringIO
if py32_lang:
    #Py3.2 removed old ConfigParser, put SafeConfigParser in it's place
    from ConfigParser import ConfigParser as SafeConfigParser
else:
    from ConfigParser import SafeConfigParser
import inspect
import re
import hashlib
from math import log as logb, ceil
import logging; log = logging.getLogger(__name__)
##import sys
##if sys.platform == "win32":
##    # On Windows, the best timer is time.clock()
##    from time import clock as timer
##else:
##    # On most other platforms the best timer is time.time()
##    from time import time as timer
import time
import os
import re
from warnings import warn
#site
try:
    from pkg_resources import resource_string
except ImportError:
    #not available eg: under GAE
    resource_string = None
#libs
from passlib.registry import get_crypt_handler, _validate_handler_name
from passlib.utils import to_bytes, to_unicode, bytes, Undef, \
                          is_crypt_handler, rng, \
                          PasslibPolicyWarning
#pkg
#local
__all__ = [
    'CryptPolicy',
    'CryptContext',
]

#=========================================================
#crypt policy
#=========================================================

# NOTE: doing this for security purposes, why would you ever want a fixed salt?
#: hash settings which aren't allowed to be set via policy
_forbidden_hash_options = frozenset([ "salt" ])

def _splitcomma(source):
    "split comma-separated string into list of strings"
    source = source.strip()
    if source.endswith(","):
        source = source[:-1]
    if not source:
        return []
    return [ elem.strip() for elem in source.split(",") ]

#--------------------------------------------------------
#policy class proper
#--------------------------------------------------------
class CryptPolicy(object):
    """stores configuration options for a CryptContext object.

    The CryptPolicy class constructor accepts a dictionary
    of keywords, which can include all the options
    listed in the :ref:`list of crypt context options <cryptcontext-options>`.

    Constructors
    ============
    In addition to passing in keywords directly,
    CryptPolicy objects can be constructed by the following methods:

    .. automethod:: from_path
    .. automethod:: from_string
    .. automethod:: from_source
    .. automethod:: from_sources
    .. automethod:: replace

    Introspection
    =============
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
        Instances of CryptPolicy should be treated as immutable.
        Use the :meth:`replace` method to mutate existing instances.
    """

    #=========================================================
    #class methods
    #=========================================================
    @classmethod
    def from_path(cls, path, section="passlib", encoding="utf-8"):
        """create new policy from specified section of an ini file.

        :arg path: path to ini file
        :param section: option name of section to read from.
        :arg encoding: optional encoding (defaults to utf-8)

        :raises EnvironmentError: if the file cannot be read

        :returns: new CryptPolicy instance.
        """
        #NOTE: we want config parser object to have native strings as keys.
        #      so we parse as bytes under py2, and unicode under py3.
        #
        #      encoding issues are handled under py2 via to_bytes(),
        #      which ensures everything is utf-8 internally.

        # Py2k #
        if encoding == "utf-8":
            #we want utf-8 anyways, so just load file in raw mode.
            with open(path, "rb") as stream:
                return cls._from_stream(stream, section, path)
        else:
            #kinda hacked - load whole file, transcode, and parse.
            with open(path, "rb") as stream:
                source = stream.read()
            source = source.decode(encoding).encode("utf-8")
            return cls._from_stream(StringIO(source), section, path)
        # Py3k #
        #with open(path, "r", encoding=encoding) as stream:
        #    return cls._from_stream(stream, section, path)
        # end Py3k #

    @classmethod
    def from_string(cls, source, section="passlib", encoding="utf-8"):
        """create new policy from specified section of an ini-formatted string.

        :arg source: bytes/unicode string containing ini-formatted content.
        :param section: option name of section to read from.
        :arg encoding: optional encoding if source is bytes (defaults to utf-8)

        :returns: new CryptPolicy instance.
        """
        #NOTE: we want config parser object to have native strings as keys.
        #      so we parse as bytes under py2, and unicode under py3.
        #      to handle encoding issues under py2, we use
        #      "to_bytes()" to transcode to utf-8 as needed.

        # Py2k #
        source = to_bytes(source, "utf-8", source_encoding=encoding, errname="source")
        # Py3k #
        #source = to_unicode(source, encoding, errname="source")
        # end Py3k #
        return cls._from_stream(StringIO(source), section, "<???>")

    @classmethod
    def _from_stream(cls, stream, section, filename=None):
        "helper for from_string / from_path"
        p = SafeConfigParser()
        if py32_lang:
            # Py3.2 deprecated readfp
            p.read_file(stream, filename or "<???>")
        else:
            p.readfp(stream, filename or "<???>")
        return cls(dict(p.items(section)))

    @classmethod
    def from_source(cls, source):
        """create new policy from input.

        :arg source:
            source may be a dict, CryptPolicy instance, filepath, or raw string.

            the exact type will be autodetected, and the appropriate constructor called.

        :raises TypeError: if source cannot be identified.

        :returns: new CryptPolicy instance.
        """
        if isinstance(source, CryptPolicy):
            # NOTE: can just return source unchanged,
            # since we're treating CryptPolicy objects as read-only
            return source

        elif isinstance(source, dict):
            return cls(source)

        elif isinstance(source, (bytes,unicode)):
            # FIXME: this autodetection makes me uncomfortable...
            # it assumes none of these chars should be in filepaths,
            # but should be in config string, in order to distinguish them.
            if any(c in source for c in "\n\r\t") or \
                    not source.strip(" \t./\;:"):
                return cls.from_string(source)

            # other strings should be filepath
            else:
                return cls.from_path(source)
        else:
            raise TypeError("source must be CryptPolicy, dict, config string, or file path: %r" % (type(source),))

    @classmethod
    def from_sources(cls, sources):
        """create new policy from list of existing policy objects.

        this method takes multiple sources and composites them on top
        of eachother, returning a single resulting CryptPolicy instance.
        this allows default policies to be specified, and then overridden
        on a per-context basis.

        :arg sources: list of sources to build policy from, elements may be any type accepted by :meth:`from_source`.

        :returns: new CryptPolicy instance
        """
        # check for no sources - should we return blank policy in that case?
        if len(sources) == 0:
            # XXX: er, would returning an empty policy be the right thing here?
            raise ValueError("no sources specified")

        # check if only one source
        if len(sources) == 1:
            return cls.from_source(sources[0])

        # else create policy from first source, update options, and rebuild.
        result = _UncompiledCryptPolicy()
        target = result._kwds
        for source in sources:
            policy = _UncompiledCryptPolicy.from_source(source)
            target.update(policy._kwds)

        #build new policy
        result._force_compile()
        return result

    def replace(self, *args, **kwds):
        """return copy of policy, with specified options replaced by new values.

        this is essentially a convience record around :meth:`from_sources`,
        except that it always inserts the current policy
        as the first element in the list;
        this allows easily making minor changes from an existing policy object.

        :param \*args: optional list of sources as accepted by :meth:`from_sources`.
        :param \*\*kwds: optional specific options to override in the new policy.

        :returns: new CryptPolicy instance
        """
        sources = [ self ]
        if args:
            sources.extend(args)
        if kwds:
            sources.append(kwds)
        return CryptPolicy.from_sources(sources)

    #=========================================================
    #instance attrs
    #=========================================================
    #: dict of (category,scheme,key) -> value, representing the original
    #  raw keywords passed into constructor. the rest of the policy's data
    #  structures are derived from this attribute via _compile()
    _kwds = None

    #: list of user categories in sorted order; first entry is always `None`
    _categories = None

    #: list of all schemes specified by `context.schemes`
    _schemes = None

    #: list of all handlers specified by `context.schemes`
    _handlers = None

    #: double-nested dict mapping key -> category -> normalized value.
    _context_options = None

    #: triply-nested dict mapping scheme -> category -> key -> normalized value.
    _scheme_options = None

    #=========================================================
    # init
    #=========================================================
    def __init__(self, *args, **kwds):
        if args:
            if len(args) != 1:
                raise TypeError("only one positional argument accepted")
            if kwds:
                raise TypeError("cannot specify positional arg and kwds")
            kwds = args[0]
            # XXX: type check, and accept strings for from_source ?
        parse = self._parse_option_key
        self._kwds = dict((parse(key), value) for key, value in
                          kwds.iteritems())
        self._compile()

    @staticmethod
    def _parse_option_key(ckey):
        "helper to expand policy keys into ``(category, name, option)`` tuple"
        ##if isinstance(ckey, tuple):
        ##    assert len(ckey) == 3, "keys must have 3 parts: %r" % (ckey,)
        ##    return ckey
        parts = ckey.split("." if "." in ckey else "__")
        count = len(parts)
        if count == 1:
            return None, None, parts[0]
        elif count == 2:
            scheme, key = parts
            if scheme == "context":
                scheme = None
            return None, scheme, key
        elif count == 3:
            cat, scheme, key = parts
            if cat == "default":
                cat = None
            if scheme == "context":
                scheme = None
            return cat, scheme, key
        else:
            raise TypeError("keys must have less than 3 separators: %r" %
                            (ckey,))

    #=========================================================
    # compile internal data structures
    #=========================================================
    def _compile(self):
        "compile internal caches from :attr:`_kwds`"
        source = self._kwds

        # build list of handlers & schemes
        handlers  = self._handlers = []
        schemes = self._schemes = []
        data = source.get((None,None,"schemes"))
        if isinstance(data, str):
            data = _splitcomma(data)
        if data:
            for elem in data:
                #resolve & validate handler
                if hasattr(elem, "name"):
                    handler = elem
                    scheme = handler.name
                    _validate_handler_name(scheme)
                else:
                    handler = get_crypt_handler(elem)
                    scheme = handler.name

                #check scheme hasn't been re-used
                if scheme in schemes:
                    raise KeyError("multiple handlers with same name: %r" %
                                   (scheme,))

                #add to handler list
                handlers.append(handler)
                schemes.append(scheme)

        # run through all other values in source, normalize them, and store in
        # scheme/context option dictionaries.
        scheme_options = self._scheme_options = {}
        context_options = self._context_options = {}
        norm_scheme_option = self._normalize_scheme_option
        norm_context_option = self._normalize_context_option
        cats = set([None])
        add_cat = cats.add
        for (cat, scheme, key), value in source.iteritems():
            add_cat(cat)
            if scheme:
                value = norm_scheme_option(key, value)
                if scheme in scheme_options:
                    config = scheme_options[scheme]
                    if cat in config:
                        config[cat][key] = value
                    else:
                        config[cat] = {key: value}
                else:
                    scheme_options[scheme] = {cat: {key: value}}
            elif key == "schemes":
                if cat:
                    raise KeyError("'schemes' context option is not allowed "
                                   "per category")
                continue
            else:
                value = norm_context_option(key, value)
                if key in context_options:
                    context_options[key][cat] = value
                else:
                    context_options[key] = {cat: value}

        # store list of categories
        self._categories = sorted(cats)

    @staticmethod
    def _normalize_scheme_option(key, value):
        # some hash options can't be specified in the policy, e.g. 'salt'
        if key in _forbidden_hash_options:
            raise KeyError("Passlib does not permit %r handler option "
                           "to be set via a policy object" % (key,))

        # for hash options, try to coerce everything to an int,
        # since most things are (e.g. the `*_rounds` options).
        elif isinstance(value, str):
            try:
                value = int(value)
            except ValueError:
                pass
        return value

    def _normalize_context_option(self, key, value):
        "validate & normalize option value"
        if key == "default":
            if hasattr(value, "name"):
                value = value.name
            schemes = self._schemes
            if schemes and value not in schemes:
                raise KeyError("default scheme not found in policy")

        elif key == "deprecated":
            if isinstance(value, str):
                value = _splitcomma(value)
            schemes = self._schemes
            if schemes:
                # if schemes are defined, do quick validation first.
                for scheme in value:
                    if scheme not in schemes:
                        raise KeyError("deprecated scheme not found "
                                   "in policy: %r" % (scheme,))

        elif key == "min_verify_time":
            value = float(value)
            if value < 0:
                raise ValueError("'min_verify_time' must be >= 0")

        else:
            raise KeyError("unknown context keyword: %r" % (key,))

        return value

    #=========================================================
    # private helpers for reading options
    #=========================================================
    def _get_option(self, scheme, category, key, default=None):
        "get specific option value, without inheritance"
        try:
            if scheme:
                return self._scheme_options[scheme][category][key]
            else:
                return self._context_options[key][category]
        except KeyError:
            return default

    def _get_handler_options(self, scheme, category):
        "return composite dict of handler options for given scheme + category"
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
        if scheme_kwds is not None:
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

        # add context options
        context_options = self._context_options
        if context_options is not None:
            # add deprecated flag
            dep_map = context_options.get("deprecated")
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

            # add min_verify_time flag
            mvt_map = context_options.get("min_verify_time")
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

    #=========================================================
    # public interface for examining options
    #=========================================================
    def has_schemes(self):
        "check if policy supports *any* schemes; returns True/False"
        return len(self._handlers) > 0

    def iter_handlers(self):
        "iterate through handlers for all schemes in policy"
        return iter(self._handlers)

    def schemes(self, resolve=False):
        "return list of supported schemes; if resolve=True, returns list of handlers instead"
        if resolve:
            return list(self._handlers)
        else:
            return list(self._schemes)

    def get_handler(self, name=None, category=None, required=False):
        """given the name of a scheme, return handler which manages it.

        :arg name: name of scheme, or ``None``
        :param category: optional user category
        :param required: if ``True``, raises KeyError if name not found, instead of returning ``None``.

        if name is not specified, attempts to return default handler.
        if returning default, and category is specified, returns category-specific default if set.

        :returns: handler attached to specified name or None
        """
        if name is None:
            name = self._get_option(None, category, "default")
            if not name and category:
                name = self._get_option(None, None, "default")
            if not name and self._handlers:
                return self._handlers[0]
            if not name:
                if required:
                    raise KeyError("no crypt algorithms found in policy")
                else:
                    return None
        for handler in self._handlers:
            if handler.name == name:
                return handler
        if required:
            raise KeyError("crypt algorithm not found in policy: %r" % (name,))
        else:
            return None

    def get_options(self, name, category=None):
        """return dict of options for specified scheme

        :arg name: name of scheme, or handler instance itself
        :param category: optional user category whose options should be returned

        :returns: dict of options for CryptContext internals which are relevant to this name/category combination.
        """
        # XXX: deprecate / enhance this function ?
        if hasattr(name, "name"):
            name = name.name
        return self._get_handler_options(name, category)[0]

    def handler_is_deprecated(self, name, category=None):
        "check if scheme is marked as deprecated according to this policy; returns True/False"
        # XXX: deprecate this function ?
        if hasattr(name, "name"):
            name = name.name
        kwds = self._get_handler_options(name, category)[0]
        return bool(kwds.get("deprecated"))

    def get_min_verify_time(self, category=None):
        # XXX: deprecate this function ?
        kwds = self._get_handler_options("all", category)[0]
        return kwds.get("min_verify_time") or 0

    #=========================================================
    # serialization
    #=========================================================

    ##def __iter__(self):
    ##    return self.iter_config(resolve=True)

    def iter_config(self, ini=False, resolve=False):
        """iterate through key/value pairs of policy configuration

        :param ini:
            If ``True``, returns data formatted for insertion
            into INI file. Keys use ``.`` separator instead of ``__``;
            lists of handlers are returned as comma-separated strings.

        :param resolve:
            If ``True``, returns handler objects instead of handler
            names where appropriate. Ignored if ``ini=True``.

        :returns:
            iterator which yields (key,value) pairs.
        """
        #
        #prepare formatting functions
        #
        sep = "." if ini else "__"

        def format_key(cat, name, key):
            if cat:
                return sep.join([cat, name or "context", key])
            if name:
                return sep.join([name, key])
            return key

        def encode_list(hl):
            if ini:
                return ", ".join(hl)
            else:
                return list(hl)

        #
        #run through contents of internal configuration
        #

        # write list of handlers at start
        if (None,None,"schemes") in self._kwds:
            if resolve and not ini:
                value = self._handlers
            else:
                value = self._schemes
            yield format_key(None, None, "schemes"), encode_list(value)

        # then per-category elements
        scheme_items = sorted(self._scheme_options.iteritems())
        get_option = self._get_option
        for cat in self._categories:

            # write deprecated list (if any)
            value = get_option(None, cat, "deprecated")
            if value is not None:
                yield format_key(cat, None, "deprecated"), encode_list(value)

            # write default declaration (if any)
            value = get_option(None, cat, "default")
            if value is not None:
                yield format_key(cat, None, "default"), value

            # write mvt (if any)
            value = get_option(None, cat, "min_verify_time")
            if value is not None:
                yield format_key(cat, None, "min_verify_time"), value

            # write configs for all schemes
            for scheme, config in scheme_items:
                if cat in config:
                    kwds = config[cat]
                    for key in sorted(kwds):
                        yield format_key(cat, scheme, key), kwds[key]

    def to_dict(self, resolve=False):
        "return policy as dictionary of keywords"
        return dict(self.iter_config(resolve=resolve))

    def _escape_ini_pair(self, k, v):
        if isinstance(v, str):
            v = v.replace("%", "%%") #escape any percent signs.
        elif isinstance(v, (int, long, float)):
            v = str(v)
        return k,v

    def _write_to_parser(self, parser, section):
        "helper for to_string / to_file"
        parser.add_section(section)
        for k,v in self.iter_config(ini=True):
            k,v = self._escape_ini_pair(k,v)
            parser.set(section, k,v)

    #XXX: rename as "to_stream" or "write_to_stream" ?
    def to_file(self, stream, section="passlib"):
        "serialize to INI format and write to specified stream"
        p = SafeConfigParser()
        self._write_to_parser(p, section)
        p.write(stream)

    def to_string(self, section="passlib", encoding=None):
        "render to INI string; inverse of from_string() constructor"
        buf = StringIO()
        self.to_file(buf, section)
        out = buf.getvalue()
        # Py2k #
        out = out.decode("utf-8")
        # end Py2k #
        if encoding:
            out = out.encode(encoding)
        return out

    ##def to_path(self, path, section="passlib", update=False):
    ##    "write to INI file"
    ##    p = ConfigParser()
    ##    if update and os.path.exists(path):
    ##        if not p.read([path]):
    ##            raise EnvironmentError("failed to read existing file")
    ##        p.remove_section(section)
    ##    self._write_to_parser(p, section)
    ##    fh = file(path, "w")
    ##    p.write(fh)
    ##    fh.close()

    #=========================================================
    #eoc
    #=========================================================

class _UncompiledCryptPolicy(CryptPolicy):
    """helper class which parses options but doesn't compile them,
    used by CryptPolicy.from_sources() to efficiently merge policy objects.
    """

    def _compile(self):
        "convert to actual policy"
        pass

    def _force_compile(self):
        "convert to real policy and compile"
        self.__class__ = CryptPolicy
        self._compile()

#---------------------------------------------------------
#load default policy from default.cfg
#---------------------------------------------------------
def _load_default_policy():
    "helper to try to load default policy from file"
    #if pkg_resources available, try to read out of egg (common case)
    if resource_string:
        try:
            return CryptPolicy.from_string(resource_string("passlib", "default.cfg"))
        except IOError:
            log.warn("error reading passlib/default.cfg, is passlib installed correctly?")
            pass

    #failing that, see if we can read it from package dir
    path = os.path.abspath(os.path.join(os.path.dirname(__file__), "default.cfg"))
    if os.path.exists(path):
        with open(path, "rb") as fh:
            return CryptPolicy.from_string(fh.read())

    #give up - this is not desirable at all, could use another fallback.
    log.error("can't find passlib/default.cfg, is passlib installed correctly?")
    return CryptPolicy()

default_policy = _load_default_policy()

#=========================================================
# helpers for CryptContext
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

    # rounds management
    _has_rounds = False # if handler has variable cost parameter
    _has_rounds_bounds = False # if min_rounds / max_rounds set
    _min_rounds = None #: minimum rounds allowed by policy, or None
    _max_rounds = None #: maximum rounds allowed by policy, or None

    # encrypt()/genconfig() attrs
    _settings = None # subset of options to be used as encrypt() defaults.

    # verify() attrs
    _min_verify_time = None

    # hash_needs_update() attrs
    _has_rounds_introspection = False

    # cloned from handler
    identify = None
    genhash = None

    #================================================================
    # init
    #================================================================
    def __init__(self, handler, category=None, deprecated=False,
                 min_rounds=None, max_rounds=None, default_rounds=None,
                 vary_rounds=None, min_verify_time=None,
                 **settings):
        self.handler = handler
        self.category = category
        self._compile_rounds(min_rounds, max_rounds, default_rounds,
                             vary_rounds)
        self._compile_encrypt(settings)
        self._compile_verify(min_verify_time)
        self._compile_deprecation(deprecated)

        # these aren't modified by the record, so just copy them directly
        self.identify = handler.identify
        self.genhash = handler.genhash

    @property
    def scheme(self):
        return self.handler.name

    @property
    def _ident(self):
        "string used to identify record in error messages"
        handler = self.handler
        category = self.category
        if category:
            return "%s %s policy" % (handler.name, category)
        else:
            return "%s policy" % (handler.name,)

    #================================================================
    # rounds generation & limits - used by encrypt & deprecation code
    #================================================================
    def _compile_rounds(self, mn, mx, df, vr):
        "parse options and compile efficient generate_rounds function"
        handler = self.handler
        if 'rounds' not in handler.setting_kwds:
            return
        hmn = getattr(handler, "min_rounds", None)
        hmx = getattr(handler, "max_rounds", None)

        def hcheck(value, name):
            "issue warnings if value outside of handler limits"
            if hmn is not None and value < hmn:
                warn("%s: %s value is below handler minimum %d: %d" %
                     (self._ident, name, hmn, value), PasslibPolicyWarning)
            if hmx is not None and value > hmx:
                warn("%s: %s value is above handler maximum %d: %d" %
                     (self._ident, name, hmx, value), PasslibPolicyWarning)

        def clip(value):
            "clip value to policy & handler limits"
            if mn is not None and value < mn:
                value = mn
            if hmn is not None and value < hmn:
                value = hmn
            if mx is not None and value > mx:
                value = mx
            if hmx is not None and value > hmx:
                value = hmx
            return value

        #----------------------------------------------------
        # validate inputs
        #----------------------------------------------------
        if mn is not None:
            if mn < 0:
                raise ValueError("%s: min_rounds must be >= 0" % self._ident)
            hcheck(mn, "min_rounds")

        if mx is not None:
            if mn is not None and mx < mn:
                raise ValueError("%s: max_rounds must be "
                                 ">= min_rounds" % self._ident)
            elif mx < 0:
                raise ValueError("%s: max_rounds must be >= 0" % self._ident)
            hcheck(mx, "max_rounds")

        if vr is not None:
            if isinstance(vr, str):
                assert vr.endswith("%")
                vr = float(vr.rstrip("%"))
                if vr < 0:
                    raise ValueError("%s: vary_rounds must be >= '0%%'" %
                                     self._ident)
                elif vr > 100:
                    raise ValueError("%s: vary_rounds must be <= '100%%'" %
                                     self._ident)
                vr_is_pct = True
            else:
                assert isinstance(vr, int)
                if vr < 0:
                    raise ValueError("%s: vary_rounds must be >= 0" %
                                     self._ident)
                vr_is_pct = False

        if df is None:
            # fallback to handler's default if available
            if vr or mx or mn:
                df = getattr(handler, "default_rounds", None) or mx or mn
        else:
            if mn is not None and df < mn:
                    raise ValueError("%s: default_rounds must be "
                                     ">= min_rounds" % self._ident)
            if mx is not None and df > mx:
                    raise ValueError("%s: default_rounds must be "
                                     "<= max_rounds" % self._ident)
            hcheck(df, "default_rounds")

        #----------------------------------------------------
        # set policy limits
        #----------------------------------------------------
        self._has_rounds_bounds = (mn is not None) or (mx is not None)
        self._min_rounds = mn
        self._max_rounds = mx

        #----------------------------------------------------
        # setup rounds generation function
        #----------------------------------------------------
        if df is None:
            self._generate_rounds = None
            self._has_rounds = self._has_rounds_bounds
        elif vr:
            scale_value = lambda v,uf: v
            if vr_is_pct:
                scale = getattr(handler, "rounds_cost", "linear")
                assert scale in ["log2", "linear"]
                if scale == "log2":
                    df = 1<<df
                    def scale_value(v, uf):
                        if v <= 0:
                            return 0
                        elif uf:
                            return int(logb(v,2))
                        else:
                            return int(ceil(logb(v,2)))
                vr = int(df*vr/100)
            lower = clip(scale_value(df-vr,False))
            upper = clip(scale_value(df+vr,True))
            if lower == upper:
                self._generate_rounds = lambda: upper
            else:
                assert lower < upper
                self._generate_rounds = lambda: rng.randint(lower, upper)
            self._has_rounds = True
        else:
            df = clip(df)
            self._generate_rounds = lambda: df
            self._has_rounds = True

    # filled in by _compile_rounds_settings()
    _generate_rounds = None

    #================================================================
    # encrypt() / genconfig()
    #================================================================
    def _compile_encrypt(self, settings):
        handler = self.handler
        skeys = handler.setting_kwds
        self._settings = dict((k,v) for k,v in settings.iteritems()
                             if k in skeys)

        if not (self._settings or self._has_rounds):
            # bypass prepare settings entirely.
            self.genconfig = handler.genconfig
            self.encrypt = handler.encrypt

    def genconfig(self, **kwds):
        self._prepare_settings(kwds)
        return self.handler.genconfig(**kwds)

    def encrypt(self, secret, **kwds):
        self._prepare_settings(kwds)
        return self.handler.encrypt(secret, **kwds)

    def _prepare_settings(self, kwds):
        "normalize settings for handler according to context configuration"
        #load in default values for any settings
        settings = self._settings
        for k in settings:
            if k not in kwds:
                kwds[k] = settings[k]

        #handle rounds
        if self._has_rounds:
            rounds = kwds.get("rounds")
            if rounds is None:
                gen = self._generate_rounds
                if gen:
                    kwds['rounds'] = gen()
            elif self._has_rounds_bounds:
                # XXX: should this raise an error instead of warning ?
                mn = self._min_rounds
                if mn is not None and rounds < mn:
                    warn("%s requires rounds >= %d, increasing value from %d" %
                         (self._ident, mn, rounds), PasslibPolicyWarning)
                    rounds = mn
                mx = self._max_rounds
                if mx and rounds > mx:
                    warn("%s requires rounds <= %d, decreasing value from %d" %
                         (self._ident, mx, rounds), PasslibPolicyWarning)
                    rounds = mx
                kwds['rounds'] = rounds

    #================================================================
    # verify()
    #================================================================
    def _compile_verify(self, mvt):
        if mvt:
            assert mvt > 0, "CryptPolicy should catch this"
            self._min_verify_time = mvt
        else:
            # no mvt wrapper needed, so just use handler.verify directly
            self.verify = self.handler.verify

    def verify(self, secret, hash, **context):
        "verify helper - adds min_verify_time delay"
        mvt = self._min_verify_time
        assert mvt
        start = time.time()
        ok = self.handler.verify(secret, hash, **context)
        end = time.time()
        delta = mvt + start - end
        if delta > 0:
            time.sleep(delta)
        elif delta < 0:
            #warn app they aren't being protected against timing attacks...
            warn("CryptContext: verify exceeded min_verify_time: "
                 "scheme=%r min_verify_time=%r elapsed=%r" %
                 (self.scheme, mvt, end-start))
        return ok

    #================================================================
    # hash_needs_update()
    #================================================================
    def _compile_deprecation(self, deprecated):
        if deprecated:
            self.hash_needs_update = lambda hash: True
            return

        handler = self.handler
        self._hash_needs_update = getattr(handler, "_hash_needs_update", None)

        # check if there are rounds, rounds limits, and if we can
        # parse the rounds from the handler. if that's the case...
        if self._has_rounds_bounds and hasattr(handler, "from_string"):
            self._has_rounds_introspection = True

    def hash_needs_update(self, hash):
        # NOTE: this is replaced by _compile_deprecation() if self.deprecated

        # XXX: could check if handler provides it's own helper, e.g.
        # getattr(handler, "hash_needs_update", None), possibly instead of
        # calling the default check below...
        #
        # NOTE: hacking this in for the sake of bcrypt & issue 25,
        # will formalize (and possibly change) interface later.
        hnu = self._hash_needs_update
        if hnu and hnu(hash):
            return True

        # if we can parse rounds parameter, check if it's w/in bounds.
        if self._has_rounds_introspection:
            hash_obj = self.handler.from_string(hash)
            try:
                rounds = hash_obj.rounds
            except AttributeError:
                # XXX: hash_obj should generally have rounds attr
                # should a warning be raised here?
                pass
            else:
                if rounds < self._min_rounds:
                    return True
                mx = self._max_rounds
                if mx and rounds > mx:
                    return True

        return False

    # filled in by init from handler._hash_needs_update
    _hash_needs_update = None

    #================================================================
    # eoc
    #================================================================

#=========================================================
# context classes
#=========================================================
class CryptContext(object):
    """Helper for encrypting passwords using different algorithms.

    :param policy:
        optionally override the default policy CryptContext starts with before options are added.

        If not specified, the new instance will inherit a set of default options (such as rounds, etc)
        from the passlib default policy (importable as :data:`passlib.context.default_policy`).

        If explicitly set to ``None``, the new instance will not inherit from the default policy,
        and will contain only the configuration specified by any additional keywords.

        Alternately, a custom CryptPolicy instance can be passed in,
        which allows loading the policy from a configuration file,
        combining multiple policies together, and other features.

    :param kwds:

        ``schemes`` and all other keywords are passed to the CryptPolicy constructor,
        or to :meth:`CryptPolicy.replace`, if a policy has also been specified.

    .. automethod:: replace

    Configuration
    =============
    .. attribute:: policy

        This exposes the :class:`CryptPolicy` instance
        which contains the configuration used by this context object.

        This attribute may be written to (replacing it with another CryptPolicy instance),
        in order to reconfigure a CryptContext while an application is running.
        However, this should only be done for context instances created by the application,
        and NOT for context instances provided by PassLib.

    Main Interface
    ==============
    .. automethod:: identify
    .. automethod:: encrypt
    .. automethod:: verify

    Migration Helpers
    =================
    .. automethod:: hash_needs_update
    .. automethod:: verify_and_update
    """
    #===================================================================
    #instance attrs
    #===================================================================
    _policy = None # policy object governing context - access via :attr:`policy`
    _records = None # map of (category,scheme) -> _CryptRecord instance
    _record_lists = None # map of category -> records for category, in order

    #===================================================================
    #init
    #===================================================================
    def __init__(self, schemes=None, policy=default_policy, **kwds):
        # XXX: add a name for the contexts, to help out repr?
        # XXX: add ability to make policy readonly for certain instances,
        #      eg the builtin passlib ones?
        if schemes:
            kwds['schemes'] = schemes
        if not policy:
            policy = CryptPolicy(**kwds)
        elif kwds:
            policy = policy.replace(**kwds)
        self.policy = policy

    def __repr__(self):
        # XXX: *could* have proper repr(), but would have to render policy
        # object options, and it'd be *really* long
        names = [ handler.name for handler in self.policy._handlers ]
        return "<CryptContext %0xd schemes=%r>" % (id(self), names)

    def replace(self, **kwds):
        """return mutated CryptContext instance

        this function operates much like :meth:`datetime.replace()` - it returns
        a new CryptContext instance whose configuration is exactly the
        same as the original, with the exception of any keywords
        specificed taking precedence over the original settings.

        this is identical to the operation ``CryptContext(policy=self.policy.replace(**kwds))``,
        see :meth:`CryptPolicy.replace` for more details.
        """
        return CryptContext(policy=self.policy.replace(**kwds))

    #XXX: make an update() method that just updates policy?
    ##def update(self, **kwds):
    ##    self.policy = self.policy.replace(**kwds)

    #===================================================================
    # policy management
    #===================================================================

    def _get_policy(self):
        return self._policy

    def _set_policy(self, value):
        if not isinstance(value, CryptPolicy):
            raise TypeError("value must be a CryptPolicy instance")
        if value is not self._policy:
            self._policy = value
            self._compile()

    policy = property(_get_policy, _set_policy)

    #------------------------------------------------------------------
    # compile policy information into _CryptRecord instances
    #------------------------------------------------------------------
    def _compile(self):
        "update context object internals based on new policy instance"
        policy = self._policy
        records = self._records = {}
        self._record_lists = {}
        handlers = policy._handlers
        if not handlers:
            return
        get_option = policy._get_option
        get_handler_options = policy._get_handler_options
        schemes = policy._schemes
        default_scheme = get_option(None, None, "default") or schemes[0]
        for cat in policy._categories:
            # build record for all schemes, re-using record from default
            # category if there aren't any category-specific options.
            for handler in handlers:
                scheme = handler.name
                kwds, has_cat_options = get_handler_options(scheme, cat)
                if cat and not has_cat_options:
                    records[scheme, cat] = records[scheme, None]
                else:
                    records[scheme, cat] = _CryptRecord(handler, cat, **kwds)
            # clone default scheme's record to None so we can resolve default
            if cat:
                scheme = get_option(None, cat, "default") or default_scheme
            else:
                scheme = default_scheme
            records[None, cat] = records[scheme, cat]

    def _get_record(self, scheme, category=None, required=True):
        "private helper used by CryptContext"
        try:
            return self._records[scheme, category]
        except KeyError:
            pass
        if category:
            # category not referenced in policy file.
            # so populate cache from default category.
            cache = self._records
            try:
                record = cache[scheme, None]
            except KeyError:
                pass
            else:
                cache[scheme, category] = record
                return record
        if not required:
            return None
        elif scheme:
            raise KeyError("crypt algorithm not found in policy: %r" %
                           (scheme,))
        else:
            assert not self._policy._handlers
            raise KeyError("no crypt algorithms supported")

    def _get_record_list(self, category=None):
        "return list of records for category"
        try:
            return self._record_lists[category]
        except KeyError:
            # XXX: could optimize for categories not in policy.
            get = self._get_record
            value = self._record_lists[category] = [
                get(scheme, category)
                for scheme in self._policy._schemes
            ]
            return value

    def _identify_record(self, hash, category=None, required=True):
        "internal helper to identify appropriate _HandlerRecord"
        records = self._get_record_list(category)
        for record in records:
            if record.identify(hash):
                return record
        if required:
            if not records:
                raise KeyError("no crypt algorithms supported")
            raise ValueError("hash could not be identified")
        else:
            return None

    #===================================================================
    #password hash api proxy methods
    #===================================================================

    # NOTE: all the following methods do is look up the appropriate
    #       _CryptRecord for a given (scheme,category) combination,
    #       and then let the record object take care of the rest,
    #       since it will have optimized itself for the particular
    #       settings used within the policy by that (scheme,category).

    def hash_needs_update(self, hash, category=None):
        """check if hash is allowed by current policy, or if secret should be re-encrypted.

        the core of CryptContext's support for hash migration:

        this function takes in a hash string, and checks the scheme,
        number of rounds, and other properties against the current policy;
        and returns True if the hash is using a deprecated scheme,
        or is otherwise outside of the bounds specified by the policy.
        if so, the password should be re-encrypted using ``ctx.encrypt(passwd)``.

        :arg hash: existing hash string
        :param category: optional user category

        :returns: True/False
        """
        # XXX: add scheme kwd for compatibility w/ other methods?
        return self._identify_record(hash, category).hash_needs_update(hash)

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
        #XXX: could insert normalization to preferred unicode encoding here
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
        if hash is None:
            if required:
                raise ValueError("no hash provided")
            return None
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
        """
        #XXX: could insert normalization to preferred unicode encoding here
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
        if hash is None:
            return False
        if scheme:
            record = self._get_record(scheme, category)
        else:
            record = self._identify_record(hash, category)
        # XXX: strip context kwds if scheme doesn't use them?
        # XXX: could insert normalization to preferred unicode encoding here
        return record.verify(secret, hash, **context)

    def verify_and_update(self, secret, hash, scheme=None, category=None, **kwds):
        """verify secret and check if hash needs upgrading, in a single call.

        This is a convience method for a common situation in most applications:
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
        if hash is None:
            return False, None
        if scheme:
            record = self._get_record(scheme, category)
        else:
            record = self._identify_record(hash, category)
        # XXX: strip context kwds if scheme doesn't use them?
        # XXX: could insert normalization to preferred unicode encoding here
        if not record.verify(secret, hash, **kwds):
            return False, None
        elif record.hash_needs_update(hash):
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

    :param create_policy:

        if a callable is passed in via this keyword,
        it will be invoked at lazy-load time
        with the following signature:
        ``create_policy(**kwds) -> CryptPolicy``;
        where ``kwds`` is all the additional kwds passed to LazyCryptContext.
        It should return a CryptPolicy instance, which will then be used
        by the CryptContext.

    :param kwds:

        All additional keywords are passed to CryptPolicy;
        or to the create_policy function if provided.

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
    #       to a regular CryptContext, to remove the overhead one it's unneeded.

    def __init__(self, schemes=None, **kwds):
        if schemes is not None:
            kwds['schemes'] = schemes
        self._lazy_kwds = kwds

    def _lazy_init(self):
        kwds = self._lazy_kwds
        if 'create_policy' in kwds:
            create_policy = kwds.pop("create_policy")
            kwds = dict(policy=create_policy(**kwds))
        super(LazyCryptContext, self).__init__(**kwds)
        del self._lazy_kwds
        self.__class__ = CryptContext

    def __getattribute__(self, attr):
        if not attr.startswith("_"):
            self._lazy_init()
        return object.__getattribute__(self, attr)

#=========================================================
# eof
#=========================================================
