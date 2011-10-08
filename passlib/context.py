"""passlib.context - CryptContext implementation"""
#=========================================================
#imports
#=========================================================
from __future__ import with_statement
from passlib.utils import py32_lang
#core
from cStringIO import StringIO
# Py2k #
    #note: importing ConfigParser to handle passlib 1.4 / earlier files
from ConfigParser import SafeConfigParser,ConfigParser,InterpolationSyntaxError
# Py3k #
#if py32_lang:
#    #Py3.2 removed old ConfigParser, put SafeConfigParser in it's place
#    from ConfigParser import ConfigParser as SafeConfigParser
#else:
#    from ConfigParser import SafeConfigParser
# end Py3k #
import inspect
import re
import hashlib
from math import log as logb
import logging; log = logging.getLogger(__name__)
import time
import os
from warnings import warn
#site
try:
    from pkg_resources import resource_string
except ImportError:
    #not available eg: under GAE
    resource_string = None
#libs
from passlib.registry import get_crypt_handler, _unload_handler_name
from passlib.utils import to_bytes, to_unicode, bytes, Undef, \
                          is_crypt_handler, splitcomma, rng
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
    if '.' not in key and '__' in key: #lets user specifiy programmatically (since python doesn't allow '.')
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
        raise KeyError("keys must have 0..2 separators: %r" % (orig,))
    if cat == "default":
        cat = None
    assert name
    assert opt
    return cat, name, opt

def _parse_policy_value(cat, name, opt, value):
    "helper to parse policy values"
    #FIXME: kinda primitive to parse things this way :|
    if name == "context":
        if opt in _context_comma_options:
            if isinstance(value, str):
                return splitcomma(value)
        elif opt == "min_verify_time":
            return float(value)
        return value
    else:
        #try to coerce everything to int
        try:
            return int(value)
        except ValueError:
            return value

def parse_policy_items(source):
    "helper to parse CryptPolicy options"
    # py2k #
    if hasattr(source, "iteritems"):
        source = source.iteritems()
    # py3k #
    #if hasattr(source, "items"):
    #    source = source.items()
    # end py3k #
    for key, value in source:
        cat, name, opt = _parse_policy_key(key)
        if name == "context":
            if cat and opt in _forbidden_category_context_options:
                raise KeyError("%r context option is not allowed per-category" % (opt,))
        else:
            if opt in _forbidden_hash_options:
                raise KeyError("%r handler option is not allowed to be set via a policy object" % (opt,))
        value = _parse_policy_value(cat, name, opt, value)
        yield cat, name, opt, value

# Py2k #
def _is_legacy_parse_error(err):
    "helper for parsing config files"
    #NOTE: passlib 1.4 and earlier used ConfigParser,
    # when they should have been using SafeConfigParser
    # (which passlib 1.5+ switched to)
    # this has no real security effects re: passlib,
    # but some 1.4 config files that have "vary_rounds = 10%"
    # may throw an error under SafeConfigParser,
    # and should read "vary_rounds = 10%%"
    #
    # passlib 1.6 and on will only use SafeConfigParser,
    # but passlib 1.5 tries to detect the above 10% error,
    # issue a warning, and retry w/ ConfigParser,
    # for backward compat.
    #
    # this function's purpose is to encapsulate that
    # backward-compat behavior.
    value = err.args[0]
    #'%' must be followed by '%' or '(', found: '%'
    if value == "'%' must be followed by '%' or '(', found: '%'":
        return True
    return False
# end Py2k #

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
        # Py2k #
        pos = stream.tell()
        # end Py2k #

        p = SafeConfigParser()
        if py32_lang:
            # Py3.2 deprecated readfp
            p.read_file(stream, filename or "<???>")
        else:
            p.readfp(stream, filename or "<???>")

        # Py2k #
        try:
            items = p.items(section)
        except InterpolationSyntaxError, err:
            if not _is_legacy_parse_error(err):
                raise
            #support for deprecated 1.4 behavior, will be removed in 1.6
            if filename:
                warn("from_path(): the file %r contains an unescaped '%%', this will be fatal in passlib 1.6" % (filename,), stacklevel=3)
            else:
                warn("from_string(): the provided string contains an unescaped '%', this will be fatal in passlib 1.6", stacklevel=3)
            p = ConfigParser()
            stream.seek(pos)
            p.readfp(stream)
            items = p.items(section)

        # py3k #
        #items = p.items(section)
        # end py3k #

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
        kwds = {}
        for source in sources:
            policy = cls.from_source(source)
            kwds.update(policy.iter_config(resolve=True))

        #build new policy
        return cls(**kwds)

    def replace(self, *args, **kwds):
        """return copy of policy, with specified options replaced by new values.

        this is essentially a convience wrapper around :meth:`from_sources`,
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
    #NOTE: all category dictionaries below will have a minimum of 'None' as a key

    #:list of all handlers, in order they will be checked when identifying (reverse of order specified)
    _handlers = None #list of password hash handlers instances.

    #:dict mapping category -> default handler for that category
    _default = None

    #:dict mapping category -> set of handler names which are deprecated for that category
    _deprecated = None

    #:dict mapping category -> min verify time
    _min_verify_time = None

    #:dict mapping category -> dict mapping hash name -> dict of options for that hash
    # if a category is specified, particular hash names will be mapped ONLY if that category
    # has options which differ from the default options.
    _options = None

    #:dict mapping (handler name, category) -> dict derived from options.
    # this is used to cache results of the get_option() method
    _cache = None

    #=========================================================
    #init
    #=========================================================
    def __init__(self, **kwds):
        self._from_dict(kwds)

    #=========================================================
    #internal init helpers
    #=========================================================
    def _from_dict(self, kwds):
        "configure policy from constructor keywords"
        #
        #init cache & options
        #
        context_options = {}
        options = self._options = {None:{"context":context_options}}
        self._cache = {}

        #
        #normalize & sort keywords
        #
        for cat, name, opt, value in parse_policy_items(kwds):
            copts = options.get(cat)
            if copts is None:
                copts = options[cat] = {}
            config = copts.get(name)
            if config is None:
                copts[name] = {opt:value}
            else:
                config[opt] = value

        #
        #parse list of schemes, and resolve to handlers.
        #
        schemes = context_options.get("schemes") or []
        handlers = self._handlers = []
        handler_names = set()
        for scheme in schemes:
            #resolve & validate handler
            if is_crypt_handler(scheme):
                handler = scheme
            else:
                handler = get_crypt_handler(scheme)
            name = handler.name
            if not name:
                raise TypeError("handler lacks name: %r" % (handler,))

            #check name hasn't been re-used
            if name in handler_names:
                #XXX: should this just be a warning ?
                raise KeyError("multiple handlers with same name: %r" % (name,))

            #add to handler list
            handlers.append(handler)
            handler_names.add(name)

        #
        #build _deprecated & _default maps
        #
        dmap = self._deprecated = {}
        fmap = self._default = {}
        mvmap = self._min_verify_time = {}
        for cat, config in options.iteritems():
            kwds = config.pop("context", None)
            if not kwds:
                continue

            #list of deprecated schemes
            deps = kwds.get("deprecated") or []
            if deps:
                if handlers:
                    for scheme in deps:
                        if scheme not in handler_names:
                            raise KeyError("known scheme in deprecated list: %r" % (scheme,))
                dmap[cat] = frozenset(deps)

            #default scheme
            fb = kwds.get("default")
            if fb:
                if handlers:
                    if hasattr(fb, "name"):
                        fb = fb.name
                    if fb not in handler_names:
                        raise KeyError("unknown scheme set as default: %r" % (fb,))
                    fmap[cat] = self.get_handler(fb, required=True)
                else:
                    fmap[cat] = fb

            #min verify time
            value = kwds.get("min_verify_time")
            if value:
                mvmap[cat] = value
            #XXX: error or warning if unknown key found in kwds?
        #NOTE: for dmap/fmap/mvmap -
        # if no cat=None value is specified, each has it's own defaults,
        # (handlers[0] for fmap, set() for dmap, 0 for mvmap)
        # but we don't store those in dict since it would complicate policy merge operation

    #=========================================================
    #public interface (used by CryptContext)
    #=========================================================
    def has_schemes(self):
        "check if policy supported *any* schemes; returns True/False"
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

    def get_handler(self, name=None, category=None, required=False):
        """given the name of a scheme, return handler which manages it.

        :arg name: name of scheme, or ``None``
        :param category: optional user category
        :param required: if ``True``, raises KeyError if name not found, instead of returning ``None``.

        if name is not specified, attempts to return default handler.
        if returning default, and category is specified, returns category-specific default if set.

        :returns: handler attached to specified name or None
        """
        if name:
            for handler in self._handlers:
                if handler.name == name:
                    return handler
        else:
            fmap = self._default
            if category in fmap:
                return fmap[category]
            elif category and None in fmap:
                return fmap[None]
            else:
                handlers = self._handlers
                if handlers:
                    return handlers[0]
                raise KeyError("no crypt algorithms supported")
        if required:
            raise KeyError("no crypt algorithm by that name: %r" % (name,))
        return None

    def get_options(self, name, category=None):
        """return dict of options for specified scheme

        :arg name: name of scheme, or handler instance itself
        :param category: optional user category whose options should be returned

        :returns: dict of options for CryptContext internals which are relevant to this name/category combination.
        """
        if hasattr(name, "name"):
            name = name.name

        cache = self._cache
        key = (name, category)
        try:
            return cache[key]
        except KeyError:
            pass

        #TODO: pre-calculate or at least cache some of this.
        options = self._options

        #start with default values
        kwds = options[None].get("all")
        if kwds is None:
            kwds = {}
        else:
            kwds = kwds.copy()

        #mix in category default values
        if category and category in options:
            tmp = options[category].get("all")
            if tmp:
                kwds.update(tmp)

        #mix in hash-specific options
        tmp = options[None].get(name)
        if tmp:
            kwds.update(tmp)

        #mix in category hash-specific options
        if category and category in options:
            tmp = options[category].get(name)
            if tmp:
                kwds.update(tmp)

        cache[key] = kwds
        return kwds

    def handler_is_deprecated(self, name, category=None):
        "check if scheme is marked as deprecated according to this policy; returns True/False"
        if hasattr(name, "name"):
            name = name.name
        dmap = self._deprecated
        if category in dmap:
            return name in dmap[category]
        elif category and None in dmap:
            return name in dmap[None]
        else:
            return False

    def get_min_verify_time(self, category=None):
        "return minimal time that verify() should take, according to this policy"
        mvmap = self._min_verify_time
        if category in mvmap:
            return mvmap[category]
        elif category and None in mvmap:
            return mvmap[None]
        else:
            return 0

    #=========================================================
    #serialization
    #=========================================================
    def iter_config(self, ini=False, resolve=False):
        """iterate through key/value pairs of policy configuration

        :param ini:
            If ``True``, returns data formatted for insertion
            into INI file. Keys use ``.`` separator instead of ``__``;
            list of handlers returned as comma-separated strings.

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
                return ", ".join(name for name in hl)
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
        value = self._handlers
        if value:
            yield format_key(None, None, "schemes"), encode_hlist(value)

        for cat, value in self._deprecated.iteritems():
            yield format_key(cat, None, "deprecated"), encode_nlist(value)

        for cat, value in self._default.iteritems():
            yield format_key(cat, None, "default"), encode_handler(value)

        for cat, value in self._min_verify_time.iteritems():
            yield format_key(cat, None, "min_verify_time"), value

        for cat, copts in self._options.iteritems():
            for name in sorted(copts):
                config = copts[name]
                for opt in sorted(config):
                    value = config[opt]
                    yield format_key(cat, name, opt), value

    def to_dict(self, resolve=False):
        "return policy as dictionary of keywords"
        return dict(self.iter_config(resolve=resolve))

    def _escape_ini_pair(self, k, v):
        if isinstance(v, str):
            v = v.replace("%", "%%") #escape any percent signs.
        elif isinstance(v, (int, long)):
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
    def _prepare_rounds(self, handler, opts, settings):
        "helper for prepare_default_settings"
        mn = opts.get("min_rounds")
        mx = opts.get("max_rounds")
        rounds = settings.get("rounds")
        if rounds is None:
            df = opts.get("default_rounds") or mx or mn
            if df is not None:
                vr = opts.get("vary_rounds")
                if vr:
                    if isinstance(vr, str):
                        rc = getattr(handler, "rounds_cost", "linear")
                        vr = int(vr.rstrip("%"))
                            #NOTE: deliberately strip >1 %,
                            #in case an interpolation-escaped %%
                            #makes it through to here.
                        assert 0 <= vr < 100
                        if rc == "log2":
                            #let % variance scale the number of actual rounds, not the logarithmic value
                            df = 2**df
                            vr = int(df*vr/100)
                            lower = int(logb(df-vr,2)+.5) #err on the side of strength - round up
                            upper = int(logb(df+vr,2))
                        else:
                            assert rc == "linear"
                            vr = int(df*vr/100)
                            lower = df-vr
                            upper = df+vr
                    else:
                        lower = df-vr
                        upper = df+vr
                    if lower < 1:
                        lower = 1
                    if mn and lower < mn:
                        lower = mn
                    if mx and upper > mx:
                        upper = mx
                    if lower > upper:
                        #NOTE: this mainly happens when default_rounds>max_rounds, which shouldn't usually happen
                        rounds = upper
                        warn("vary default rounds: lower bound > upper bound, using upper bound (%d > %d)" % (lower, upper))
                    else:
                        rounds = rng.randint(lower, upper)
                else:
                    rounds = df
        if rounds is not None:
            if mx and rounds > mx:
                rounds = mx
            if mn and rounds < mn: #give mn predence if mn > mx
                rounds = mn
            settings['rounds'] = rounds

    def _prepare_settings(self, handler, category=None, **settings):
        "normalize settings for handler according to context configuration"
        opts = self.policy.get_options(handler, category)
        if not opts:
            return settings

        #load in default values for any settings
        for k in handler.setting_kwds:
            if k not in settings and k in opts:
                settings[k] = opts[k]

        #handle rounds
        if 'rounds' in handler.setting_kwds:
            self._prepare_rounds(handler, opts, settings)

        #done
        return settings

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
        handler = self.identify(hash, resolve=True, required=True)
        policy = self.policy

        #check if handler has been deprecated
        if policy.handler_is_deprecated(handler, category):
            return True

        #get options, and call compliance helper (check things such as rounds, etc)
        opts = policy.get_options(handler, category)

        #XXX: could check if handler provides it's own helper, eg getattr(handler, "hash_needs_update", None),
        #and call that instead of the following default behavior
        if hasattr(handler, "_hash_needs_update"):
            #NOTE: hacking this in for the sake of bcrypt & issue 25,
            #      will formalize (and possibly change) interface later.
            if handler._hash_needs_update(hash, **opts):
                return True

        if opts:
            #check if we can parse hash to check it's rounds parameter
            if ('min_rounds' in opts or 'max_rounds' in opts) and \
               'rounds' in handler.setting_kwds and hasattr(handler, "from_string"):
                    info = handler.from_string(hash)
                    rounds = getattr(info, "rounds", None) #should generally work, but just in case
                    if rounds is not None:
                        min_rounds = opts.get("min_rounds")
                        if min_rounds is not None and rounds < min_rounds:
                            return True
                        max_rounds = opts.get("max_rounds")
                        if max_rounds is not None and rounds > max_rounds:
                            return True

        return False

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
        handler = self.policy.get_handler(scheme, category, required=True)
        settings = self._prepare_settings(handler, category, **settings)
        return handler.genconfig(**settings)

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
        handler = self.policy.get_handler(scheme, category, required=True)
        kwds = self._prepare_settings(handler, category, **kwds)
        #XXX: could insert normalization to preferred unicode encoding here
        return handler.encrypt(secret, **kwds)

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
        ok = self.verify(secret, hash, scheme=scheme, category=category, **kwds)
        if not ok:
            return False, None
        if self.hash_needs_update(hash, category=category):
            return True, self.encrypt(secret, category=category, **kwds)
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
