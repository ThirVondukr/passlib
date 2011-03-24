"""passlib.context - CryptContext implementation"""
#=========================================================
#imports
#=========================================================
from __future__ import with_statement
#core
from cStringIO import StringIO
from ConfigParser import ConfigParser
import inspect
import re
import hashlib
from math import log as logb
import logging; log = logging.getLogger(__name__)
import time
import os
from warnings import warn
#site
from pkg_resources import resource_string
#libs
from passlib.registry import get_crypt_handler
from passlib.utils import Undef, is_crypt_handler, splitcomma, rng
#pkg
#local
__all__ = [
    'CryptPolicy',
    'CryptContext',
]

#=========================================================
#crypt policy
#=========================================================
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
        raise KeyError, "keys must have 0..2 separators: %r" % (orig,)
    if cat == "default":
        cat = None
    assert name
    assert opt
    return cat, name, opt

def _parse_policy_value(cat, name, opt, value):
    "helper to parse policy values"
    #FIXME: kinda primitive :|
    if name == "context":
        if opt == "schemes" or opt == "deprecated":
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
    if hasattr(source, "iteritems"):
        source = source.iteritems()
    for key, value in source:
        cat, name, opt = _parse_policy_key(key)
        if name == "context":
            if cat and opt == "schemes":
                raise KeyError, "current code does not support per-category schemes"
                #NOTE: forbidding this because it would really complicate the behavior
                # of CryptContext.identify & CryptContext.lookup.
                # most useful behaviors here can be had by overridding deprecated and default, anyways.
        else:
            if opt == "salt":
                raise KeyError, "'salt' option is not allowed to be set via a policy object"
                #NOTE: doing this for security purposes, why would you ever want a fixed salt?
        value = _parse_policy_value(cat, name, opt, value)
        yield cat, name, opt, value

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
    """

    #=========================================================
    #class methods
    #=========================================================
    @classmethod
    def from_path(cls, path, section="passlib"):
        """create new policy from specified section of an ini file.

        :arg path: path to ini file
        :param section: option name of section to read from.

        :raises EnvironmentError: if the file cannot be read

        :returns: new CryptPolicy instance.
        """
        p = ConfigParser()
        if not p.read([path]):
            raise EnvironmentError, "failed to read config file"
        return cls(**dict(p.items(section)))

    @classmethod
    def from_string(cls, source, section="passlib"):
        """create new policy from specified section of an ini-formatted string.

        :arg source: string containing ini-formatted content.
        :param section: option name of section to read from.

        :returns: new CryptPolicy instance.
        """
        p = ConfigParser()
        b = StringIO(source)
        p.readfp(b)
        return cls(**dict(p.items(section)))

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

        elif isinstance(source, (str,unicode)):
            #FIXME: this autodetection makes me uncomfortable...
            if any(c in source for c in "\n\r\t") or not source.strip(" \t./\;:"): #none of these chars should be in filepaths, but should be in config string
                return cls.from_string(source)

            else: #other strings should be filepath
                return cls.from_path(source)
        else:
            raise TypeError, "source must be CryptPolicy, dict, config string, or file path: %r" % (type(source),)

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
            raise ValueError, "no sources specified"

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
        except that it always inserts the current policy as the first element
        in the list.

        this allows easily making minor changes from an existing policy object.

        :param args: optional list of sources as accepted by :meth:`from_sources`.
        :param kwds: optional specific options to override in the new policy.

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
        options = self._options = {None:{"context":{}}}
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
        handlers = self._handlers = []
        seen = set()
        schemes = options[None]['context'].get("schemes") or []
        for scheme in schemes:
            #resolve & validate handler
            if is_crypt_handler(scheme):
                handler = scheme
            else:
                handler = get_crypt_handler(scheme)
            name = handler.name
            if not name:
                raise TypeError, "handler lacks name: %r" % (handler,)

            #check name hasn't been re-used
            if name in seen:
                raise KeyError, "multiple handlers with same name: %r" % (name,)
            seen.add(name)

            #add to handler list
            handlers.append(handler)

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
            deps = kwds.get("deprecated")
            if deps:
                if handlers:
                    for scheme in deps:
                        if scheme not in seen:
                            raise KeyError, "known scheme in deprecated list: %r" % (scheme,)
                dmap[cat] = frozenset(deps)

            #default scheme
            fb = kwds.get("default")
            if fb:
                if handlers:
                    if hasattr(fb, "name"):
                        fb = fb.name
                    if fb not in seen:
                        raise KeyError, "unknown scheme set as default: %r" % (fb,)
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
                raise KeyError, "no crypt algorithms supported"
        if required:
            raise KeyError, "no crypt algorithm by that name: %r" % (name,)
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
        elif category and None in mvap:
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
        else:
            fmt1 = "%s__%s__%s"
            fmt2 = "%s__%s"
            if resolve:
                def encode_handler(h):
                    return h
                def encode_hlist(hl):
                    return list(hl)
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
            yield format_key(cat, None, "deprecated"), encode_hlist(value)

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

    def _write_to_parser(self, parser, section):
        "helper for to_string / to_file"
        parser.add_section(section)
        for k,v in self.iter_config(ini=True):
            parser.set(section, k,v)

    def to_file(self, stream, section="passlib"):
        "serialize to INI format and write to specified stream"
        p = ConfigParser()
        self._write_to_parser(p, section)
        p.write(stream)

    def to_string(self, section="passlib"):
        "render to INI string; inverse of from_string() constructor"
        b = StringIO()
        self.to_file(b, section)
        return b.getvalue()

    ##def to_path(self, path, section="passlib", update=False):
    ##    "write to INI file"
    ##    p = ConfigParser()
    ##    if update and os.path.exists(path):
    ##        if not p.read([path]):
    ##            raise EnvironmentError, "failed to read existing file"
    ##        p.remove_section(section)
    ##    self._write_to_parser(p, section)
    ##    fh = file(path, "w")
    ##    p.write(fh)
    ##    fh.close()

    #=========================================================
    #eoc
    #=========================================================

#load the default policy instance setup by passlib, which all CryptContexts inherit by default
default_policy = CryptPolicy.from_string(resource_string("passlib", "default.cfg"))

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
    """
    #===================================================================
    #instance attrs
    #===================================================================
    policy = None #policy object governing context

    #===================================================================
    #init
    #===================================================================
    def __init__(self, schemes=None, policy=default_policy, **kwds):
        #XXX: add a name for the contexts?
        if schemes:
            kwds['schemes'] = schemes
        if not policy:
            policy = CryptPolicy(**kwds)
        elif kwds:
            policy = policy.replace(**kwds)
        if not policy.has_schemes():
            raise ValueError, "at least one scheme must be specified"
        self.policy = policy

    def __repr__(self):
        #XXX: *could* have proper repr(), but would have to render policy object options, and it'd be *really* long
        names = [ handler.name for handler in self.policy.iter_handlers() ]
        return "<CryptContext %0xd schemes=%r>" % (id(self), names)

    def replace(self, **kwds):
        "returns new CryptContext with specified options modified from original; similar to CryptPolicy.replace"
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
                    if mn and lower < mn:
                        lower = mn
                    if mx and upper > mx:
                        upper = mx
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
                raise ValueError, "no hash specified"
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
                raise KeyError, "no crypt algorithms supported"
            raise ValueError, "hash could not be identified"
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
            optional force context to use specfic scheme (must be allowed by context)

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
                warn("CryptContext: verify exceeded min_verify_time: scheme=%r min_verify_time=%r elapsed=%r", handler.name, mvt, end-start)

        return result

    #TODO: check this works properly, and expose it to ease requirements for apps to use migration features
    ##def verify_and_update(self, secret, hash, scheme=None, category=None, **kwds):
    ##    ok = self.verify(secret, hash, scheme=scheme, category=category, **kwds)
    ##    if not ok:
    ##        return False, None
    ##    if self.hash_needs_update(secret, hash, category=category):
    ##        return True, self.encrypt(secret, **kwds)
    ##    else:
    ##        return True, None

    #=========================================================
    #eoc
    #=========================================================

#=========================================================
# eof
#=========================================================
