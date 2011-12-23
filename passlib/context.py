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

#--------------------------------------------------------
#constants controlling parsing of special kwds
#--------------------------------------------------------

#: CryptContext kwds which aren't allowed to have category specifiers
_forbidden_category_context_options = frozenset([ "schemes", ])
    #NOTE: forbidding 'schemes' because it would really complicate the behavior
    # of CryptContext.identify & CryptContext.lookup.
    # most useful behaviors here can be had by overriding deprecated
    # and default, anyways.

#: hash settings which aren't allowed to be set via policy
_forbidden_hash_options = frozenset([ "salt" ])
    #NOTE: doing this for security purposes, why would you ever want a fixed salt?

#: CryptContext kwds which should be parsed into comma separated list of strings
_context_comma_options = frozenset([ "schemes", "deprecated" ])

#--------------------------------------------------------
#parsing helpers
#--------------------------------------------------------
def _parse_policy_key(key):
    "helper to normalize & parse policy keys; returns ``(category, name, option)``"
    orig = key
    if '.' not in key and '__' in key:
        # this lets user specify kwds in python using '__' as separator,
        # since python doesn't allow '.' in identifiers.
        key = key.replace("__", ".")
    parts = key.split(".")
    if len(parts) == 1:
        cat = None
        name = "context"
        opt, = parts
    elif len(parts) == 2:
        cat = None
        name, opt = parts
    elif len(parts) == 3:
        cat, name, opt = parts
    else:
        raise KeyError("keys must have less than 3 separators: %r" % (orig,))
    if cat == "default":
        cat = None
    assert name
    assert opt
    return cat, name, opt

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
        items = p.items(section)
        return cls(**dict(items))

    @classmethod
    def from_source(cls, source):
        """create new policy from input.

        :arg source:
            source may be a dict, CryptPolicy instance, filepath, or raw string.

            the exact type will be autodetected, and the appropriate constructor called.

        :raises TypeError: if source cannot be identified.

        :returns: new CryptPolicy instance.
        """
        if isinstance(source, cls):
            #NOTE: can just return source unchanged,
            #since we're treating CryptPolicy objects as read-only
            return source

        elif isinstance(source, dict):
            return cls(**source)

        elif isinstance(source, (bytes,unicode)):
            #FIXME: this autodetection makes me uncomfortable...
            if any(c in source for c in "\n\r\t") or not source.strip(" \t./\;:"): #none of these chars should be in filepaths, but should be in config string
                return cls.from_string(source)

            else: #other strings should be filepath
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
        #check for no sources - should we return blank policy in that case?
        if len(sources) == 0:
            #XXX: er, would returning an empty policy be the right thing here?
            raise ValueError("no sources specified")

        #check if only one source
        if len(sources) == 1:
            return cls.from_source(sources[0])

        #else, build up list of kwds by parsing each source
        # TODO: could probably replace this with some code that just merges _options
        # and then calls _rebuild() on the final policy.
        kwds = {}
        for source in sources:
            policy = cls.from_source(source)
            kwds.update(policy.iter_config(resolve=True))

        #build new policy
        return cls(**kwds)

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
    #: triply-nested dict mapping category -> scheme -> key -> value.
    #: this is the internal representation of the original constructor options,
    #: and is used when serializing.
    _options = None

    #: list of user categories in sorted order;
    #: first entry will always be `None`
    _categories = None

    #: list of all handlers specified by `context.schemes`
    _handlers = None

    #: dict mapping category -> names of deprecated handlers
    _deprecated = None

    #: dict mapping category -> min verify time
    _min_verify_time = None

    #: dict mapping (scheme, category) -> _PolicyRecord instance.
    #: each _PolicyRecord encodes the final composite set of options
    #: to be used for that (scheme, category) combination.
    #: (None, category) will point to the default record for a given category.
    _records = None

    #=========================================================
    #init
    #=========================================================
    def __init__(self, **kwds):
        self._from_dict(kwds)
        self._rebuild()

    #---------------------------------------------------------
    # load config from dict
    #---------------------------------------------------------
    def _from_dict(self, kwds):
        "update :attr:`_options` from constructor keywords"
        options = self._options = {None: {None: {}}}
        validate = self._validate_option_key
        normalize = self._normalize_option_value

        for full_key, value in kwds.iteritems():
            cat, scheme, key = _parse_policy_key(full_key)
            validate(cat, scheme, key)
            value = normalize(cat, scheme, key, value)
            try:
                config = options[cat]
            except KeyError:
                config = options[cat] = {}
            try:
                kwds = config[scheme]
            except KeyError:
                config[scheme] = {key: value}
            else:
                kwds[key] = value

        self._categories = sorted(options)
        assert self._categories[0] is None

    def _validate_option_key(self, cat, scheme, key):
        "forbid certain (cat,scheme,key) combinations"
        if scheme == "context":
            if cat and key in _forbidden_category_context_options:
                # e.g 'schemes'
                raise KeyError("%r context option not allowed "
                               "per-category" % (key,))
        elif key in _forbidden_hash_options:
            # e.g. 'salt'
            raise KeyError("Passlib does not permit %r handler option "
                           "to be set via a policy object" % (key,))

    def _normalize_option_value(self, cat, scheme, key, value):
        "normalize option value types"
        if scheme == "context":
            # 'schemes', 'deprecated' may be passed in as comma-separated
            # lists, need to be split apart into list of strings.
            if key in _context_comma_options:
                if isinstance(value, str):
                    value = _splitcomma(value)

            # this should be a float value (number of seconds)
            elif key == "min_verify_time":
                value = float(value)

            # if default specified as handler, convert to name.
            # handler will be found via context.schemes
            elif key == "default":
                if hasattr(value, "name"):
                    value = value.name

        else:
            # for hash options, try to coerce everything to an int,
            # since most things are (e.g. the `*_rounds` options).
            if value is not None:
                try:
                    value = int(value)
                except ValueError:
                    pass

        return value

    #---------------------------------------------------------
    # rebuild policy
    #---------------------------------------------------------
    def _rebuild(self):
        "(re)build internal caches from :attr:`_options`"

        #
        # build list of handlers
        #
        get_option_value = self._get_option_value
        handlers = self._handlers = []
        handler_names = set()
        for input in (get_option_value(None, "context", "schemes") or []):
            #resolve & validate handler
            if hasattr(input, "name"):
                handler = input
                name = handler.name
                _validate_handler_name(name)
            else:
                handler = get_crypt_handler(input)
                name = handler.name

            #check name hasn't been re-used
            if name in handler_names:
                raise KeyError("multiple handlers with same name: %r" % (name,))

            #add to handler list
            handlers.append(handler)
            handler_names.add(name)

        #
        # build deprecated map, ensure names are valid
        #
        dep_map = self._deprecated = {}
        for cat in self._categories:
            deplist = get_option_value(cat, "context", "deprecated")
            if deplist is None:
                continue
            if handlers:
                for scheme in deplist:
                    if scheme not in handler_names:
                        raise KeyError("deprecated scheme not found "
                                       "in policy: %r" % (scheme,))
            dep_map[cat] = deplist

        #
        # build records for all (scheme, category) combinations
        #
        records = self._records = {}
        if handlers:
            default_scheme = get_option_value(None, "context", "default") or \
                             handlers[0].name
            for cat in self._categories:
                for handler in handlers:
                    scheme = handler.name
                    kwds, has_cat_options = self._get_handler_options(scheme,
                                                                      cat)
                    if cat and not has_cat_options:
                        # just re-use record from default category
                        records[scheme, cat] = records[scheme, None]
                    else:
                        records[scheme, cat] = _PolicyRecord(handler, cat,
                                                                **kwds)
                if cat:
                    scheme = get_option_value(cat, "context", "default") or \
                             default_scheme
                else:
                    scheme = default_scheme
                if scheme not in handler_names:
                    raise KeyError("default scheme not found in policy: %r" %
                                   (scheme,))
                records[None, cat] = records[scheme, cat]

        #
        # build min verify time map
        #
        mvt_map = self._min_verify_time = {}
        for cat in self._categories:
            value = get_option_value(cat, "context", "min_verify_time")
            if value is None:
                continue
            if value < 0:
                raise ValueError("min_verify_time must be >= 0")
            mvt_map[cat] = value

    #=========================================================
    # private helpers for reading :attr:`_options`
    #=========================================================
    def _get_option_value(self, category, scheme, key, default=None):
        "get value from nested options dict"
        try:
            return self._options[category][scheme][key]
        except KeyError:
            return default

    def _get_option_kwds(self, category, scheme, default=None):
        "get all kwds for specified category & scheme "
        try:
            return self._options[category][scheme]
        except KeyError:
            return default

    def _get_handler_options(self, scheme, category):
        "return composite dict of handler options for given scheme + category"
        options = self._options
        has_cat_options = False

        # start with global.all kwds
        global_config = options[None]
        kwds = global_config.get("all")
        if kwds:
            kwds = kwds.copy()
        else:
            kwds = {}

        # add category.all kwds
        if category and category in options:
            config = options[category]
            tmp = config.get("all")
            if tmp:
                kwds.update(tmp)
                has_cat_options = True
        else:
            config = None

        # add global.scheme kwds
        tmp = global_config.get(scheme)
        if tmp:
            kwds.update(tmp)

        # add category.scheme kwds
        if config:
            tmp = config.get(scheme)
            if tmp:
                kwds.update(tmp)
                has_cat_options = True

        # add deprecated flag
        deplist = self._deprecated.get(None)
        dep = (deplist is not None and scheme in deplist)
        if category:
            deplist = self._deprecated.get(category)
            if deplist is not None:
                default_dep = dep
                dep = (scheme in deplist)
                if default_dep ^ dep:
                    has_cat_options = True
        if dep:
            kwds['deprecated'] = True

        return kwds, has_cat_options

    #=========================================================
    # public interface (used by CryptContext)
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
            return [h.name for h in self._handlers]

    def _get_record(self, name, category=None, required=True):
        "private helper used by CryptContext"
        # NOTE: this is speed-critical since it's called a lot by CryptContext
        try:
            return self._records[name, category]
        except KeyError:
            pass
        if category:
            # category not referenced in policy file.
            # so populate cache from default category.
            cache = self._records
            try:
                record = cache[name, None]
            except KeyError:
                pass
            else:
                cache[name, category] = record
                return record
        if not required:
            return None
        elif name:
            raise KeyError("crypt algorithm not found in policy: %r" % (name,))
        else:
            assert not self._handlers
            raise KeyError("no crypt algorithms found in policy")

    def get_handler(self, name=None, category=None, required=False):
        """given the name of a scheme, return handler which manages it.

        :arg name: name of scheme, or ``None``
        :param category: optional user category
        :param required: if ``True``, raises KeyError if name not found, instead of returning ``None``.

        if name is not specified, attempts to return default handler.
        if returning default, and category is specified, returns category-specific default if set.

        :returns: handler attached to specified name or None
        """
        record = self._get_record(name, category, required)
        if record:
            return record.handler
        else:
            assert not required
            return None

    def get_options(self, name, category=None):
        """return dict of options for specified scheme

        :arg name: name of scheme, or handler instance itself
        :param category: optional user category whose options should be returned

        :returns: dict of options for CryptContext internals which are relevant to this name/category combination.
        """
        if hasattr(name, "name"):
            name = name.name
        return self._get_handler_options(name, category)[0]

    def handler_is_deprecated(self, name, category=None):
        "check if scheme is marked as deprecated according to this policy; returns True/False"
        if hasattr(name, "name"):
            name = name.name
        deplist = self._deprecated.get(category)
        if deplist is None and category:
            deplist = self._deprecated.get(None)
        return deplist is not None and name in deplist

    def get_min_verify_time(self, category=None):
        "return minimal time that verify() should take, according to this policy"
        # NOTE: this is speed-critical since it's called a lot by CryptContext
        try:
            return self._min_verify_time[category]
        except KeyError:
            value = self._min_verify_time[category] = \
                    self.get_min_verify_time(None) if category else 0
            return value

    #=========================================================
    #serialization
    #=========================================================
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
            iterator which yeilds (key,value) pairs.
        """
        #
        #prepare formatting functions
        #
        if ini:
            fmt1 = "%s.%s.%s"
            fmt2 = "%s.%s"
            def encode_handler(h):
                return h.name
            def encode_hlist(hl):
                return ", ".join(h.name for h in hl)
            def encode_nlist(hl):
                return ", ".join(hl)
        else:
            fmt1 = "%s__%s__%s"
            fmt2 = "%s__%s"
            encode_nlist = list
            if resolve:
                def encode_handler(h):
                    return h
                encode_hlist = list
            else:
                def encode_handler(h):
                    return h.name
                def encode_hlist(hl):
                    return [ h.name for h in hl ]

        def format_key(cat, name, opt):
            if cat:
                return fmt1 % (cat, name or "context", opt)
            if name:
                return fmt2 % (name, opt)
            return opt

        #
        #run through contents of internal configuration
        #

        # write list of handlers at start
        value = self._handlers
        if value:
            yield format_key(None, None, "schemes"), encode_hlist(value)

        # then per-category elements
        for cat in self._categories:
            config = self._options[cat]
            kwds = config.get("context")
            if kwds:
                # write deprecated list (if any)
                value = kwds.get("deprecated")
                if value is not None:
                    yield format_key(cat, None, "deprecated"), \
                          encode_nlist(value)

                # write default declaration (if any)
                value = kwds.get("default")
                if value is not None:
                    yield format_key(cat, None, "default"), value

                # write mvt (if any)
                value = kwds.get("min_verify_time")
                if value is not None:
                    yield format_key(cat, None, "min_verify_time"), value

            # write configs for all schemes
            for scheme in sorted(config):
                if scheme == "context":
                    continue
                kwds = config[scheme]
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

class _PolicyRecord(object):
    """wraps a handler and automatically applies various options

    this is a helper used internally by CryptPolicy and CryptContext
    in order to reduce the amount of work that needs to be done when
    CryptContext.verify() et al are called.
    """

    #================================================================
    # instance attrs
    #================================================================

    # informational attrs
    handler = None # handler instance this is wrapping
    category = None # user category this applies to
    options = None # dict of all applicable options from policy (treat as RO)
    deprecated = False # indicates if policy deprecated whole scheme
    _ident = None # string used to identify record in error messages

    # attrs used by settings / hash generation
    _settings = None # subset of options to be used as encrypt() defaults.
    _has_rounds = False # if handler has variable cost parameter
    _has_rounds_bounds = False # if min_rounds / max_rounds set
    _min_rounds = None #: minimum rounds allowed by policy, or None
    _max_rounds = None #: maximum rounds allowed by policy, or None

    # attrs used by deprecation handling
    _has_rounds_introspection = False

    # cloned from handler
    identify = None
    genhash = None
    verify = None

    #================================================================
    # init
    #================================================================
    def __init__(self, handler, category=None, deprecated=False, **options):
        self.handler = handler
        self.category = category
        self.options = options
        self.deprecated = deprecated
        if category:
            self._ident = "%s %s policy" % (handler.name, category)
        else:
            self._ident = "%s policy" % (handler.name,)
        self._compile_settings(options)
        self._compile_deprecation(options)

        # these aren't modified by the record, so just copy them directly
        self.identify = handler.identify
        self.genhash = handler.genhash
        self.verify = handler.verify

    #================================================================
    # config generation & helpers
    #================================================================
    def _compile_settings(self, options):
        handler = self.handler
        self._settings = dict((k,v) for k,v in options.iteritems()
                             if k in handler.setting_kwds)

        if 'rounds' in handler.setting_kwds:
            self._compile_rounds_settings(options)

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
                    warn("%s requires rounds >= %d, clipping value: %d" %
                         (self._ident, mn, rounds), PasslibPolicyWarning)
                    rounds = mn
                mx = self._max_rounds
                if mx and rounds > mx:
                    warn("%s requires rounds <= %d, clipping value: %d" %
                         (self._ident, mx, rounds), PasslibPolicyWarning)
                    rounds = mx
                kwds['rounds'] = rounds

    def _compile_rounds_settings(self, options):
        "parse options and compile efficient generate_rounds function"

        handler = self.handler
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
        mn = options.get("min_rounds")
        mx = options.get("max_rounds")
        df = options.get("default_rounds")
        vr = options.get("vary_rounds")

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

        if df is None:
            df = mx or mn
        else:
            if mn is not None and df < mn:
                    raise ValueError("%s: default_rounds must be "
                                     ">= min_rounds" % self._ident)
            if mx is not None and df > mx:
                    raise ValueError("%s: default_rounds must be "
                                     "<= max_rounds" % self._ident)
            hcheck(df, "default_rounds")

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
            if vr and df is None:
                # fallback to handler's default if available
                df = getattr(handler, "default_rounds", None)

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
    # deprecation helpers
    #================================================================
    def _compile_deprecation(self, options):
        if self.deprecated:
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
        if hnu and hnu(hash, **self.options):
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
#load default policy from default.cfg
#=========================================================
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
#
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
    policy = None #policy object governing context

    #===================================================================
    #init
    #===================================================================
    def __init__(self, schemes=None, policy=default_policy, **kwds):
        #XXX: add a name for the contexts, to help out repr?
        if schemes:
            kwds['schemes'] = schemes
        if not policy:
            policy = CryptPolicy(**kwds)
        elif kwds:
            policy = policy.replace(**kwds)
        self.policy = policy

    def __repr__(self):
        #XXX: *could* have proper repr(), but would have to render policy object options, and it'd be *really* long
        names = [ handler.name for handler in self.policy.iter_handlers() ]
        return "<CryptContext %0xd schemes=%r>" % (id(self), names)

    #XXX: make an update() method that just updates policy?

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

    #===================================================================
    #policy adaptation
    #===================================================================
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
        scheme = self.identify(hash, required=True)
        record = self.policy._get_record(scheme, category)
        return record.hash_needs_update(hash)

    #===================================================================
    #password hash api proxy methods
    #===================================================================
    def genconfig(self, scheme=None, category=None, **settings):
        """Call genconfig() for specified handler

        This wraps the genconfig() method of the appropriate handler
        (using the default if none other is specified).
        See the :ref:`password-hash-api` for details.

        The main different between this and calling a handlers' genhash method
        directly is that this method will add in any policy-specific
        options relevant for the particular hash.
        """
        record = self.policy._get_record(scheme, category, True)
        return record.genconfig(**settings)

    def genhash(self, secret, config, scheme=None, category=None, **context):
        """Call genhash() for specified handler.

        This wraps the genconfig() method of the appropriate handler
        (using the default if none other is specified).
        See the :ref:`password-hash-api` for details.
        """
        #NOTE: this doesn't use category in any way, but accepts it for consistency
        if scheme:
            handler = self.policy.get_handler(scheme, required=True)
        else:
            handler = self.identify(config, resolve=True, required=True)
        #XXX: could insert normalization to preferred unicode encoding here
        return handler.genhash(secret, config, **context)

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
        #NOTE: this doesn't use category in any way, but accepts it for consistency
        if hash is None:
            if required:
                raise ValueError("no hash specified")
            return None
        handler = None
        for handler in self.policy.iter_handlers():
            if handler.identify(hash):
                if resolve:
                    return handler
                else:
                    return handler.name
        if required:
            if handler is None:
                raise KeyError("no crypt algorithms supported")
            raise ValueError("hash could not be identified")
        return None

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
        record = self.policy._get_record(scheme, category, True)
        return record.encrypt(secret, **kwds)

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
        #quick checks
        if hash is None:
            return False

        mvt = self.policy.get_min_verify_time(category)
        if mvt:
            start = time.time()

        #locate handler
        if scheme:
            handler = self.policy.get_handler(scheme, required=True)
        else:
            handler = self.identify(hash, resolve=True, required=True)

        #strip context kwds if scheme doesn't use them
        ##for k in context.keys():
        ##    if k not in handler.context_kwds:
        ##        del context[k]

        #XXX: could insert normalization to preferred unicode encoding here

        #use handler to verify secret
        result = handler.verify(secret, hash, **context)

        if mvt:
            #delta some amount of time if verify took less than mvt seconds
            end = time.time()
            delta = mvt + start - end
            if delta > 0:
                time.sleep(delta)
            elif delta < 0:
                #warn app they aren't being protected against timing attacks...
                warn("CryptContext: verify exceeded min_verify_time: scheme=%r min_verify_time=%r elapsed=%r" %
                     (handler.name, mvt, end-start))

        return result

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
        if not scheme:
            scheme = self.identify(hash, required=True)
        ok = self.verify(secret, hash, scheme, category, **kwds)
        if not ok:
            return False, None
        record = self.policy._get_record(scheme, category)
        if record.hash_needs_update(hash):
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

    def __init__(self, schemes=None, **kwds):
        if schemes is not None:
            kwds['schemes'] = schemes
        self._lazy_kwds = kwds

    def _lazy_init(self):
        kwds = self._lazy_kwds
        del self._lazy_kwds
        if 'create_policy' in kwds:
            create_policy = kwds.pop("create_policy")
            kwds = dict(policy=create_policy(**kwds))
        super(LazyCryptContext, self).__init__(**kwds)

    #NOTE: 'policy' property calls _lazy_init the first time it's accessed,
    #      and relies on CryptContext.__init__ to replace it with an actual instance.
    #      it should then have no more effect from then on.
    class _PolicyProperty(object):

        def __get__(self, obj, cls):
            if obj is None:
                return self
            obj._lazy_init()
            assert isinstance(obj.policy, CryptPolicy)
            return obj.policy

    policy = _PolicyProperty()

#=========================================================
# eof
#=========================================================
