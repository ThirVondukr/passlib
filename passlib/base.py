"""passlib - implementation of various password hashing functions

Context options

    schemes - list of names or handler instances which should be recognized by context
    deprecated - list names of handlers which should context should only use to validate *old* hashes
    default - optional name of handler to use for encrypting new hashes.

Many schemes support their own options, such as min/max/default rounds.

"""
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
##import passlib.drivers.as _hmod
from passlib.utils import Undef, is_crypt_handler, splitcomma, rng
#pkg
#local
__all__ = [
    #global registry
    'register_crypt_handler',
    'register_crypt_location',
    'get_crypt_handler',
    'list_crypt_handlers'

    #contexts
    'CryptPolicy',
    'CryptContext',
]

#=========================================================
#proxy object
#=========================================================
class PasslibHashProxy(object):
    """proxy module passlib.hash

    this module is in fact an object which lazy-loads
    the requested password hash algorithm from wherever it has been stored.
    it acts as a thin wrapper around :func:`passlib.base.get_crypt_handler`.
    """
    __name__ = "passlib.hash"
    __package__ = None

    def __getattr__(self, attr):
        if attr.startswith("_"):
            raise AttributeError, "unknown attribute: %r" % (attr,)
        handler = get_crypt_handler(attr, None)
        if handler is None:
            raise AttributeError, "unknown password hash: %r" % (attr,)
        setattr(self, attr, handler)
        return handler

    def __repr__(self):
        return "<proxy module 'passlib.hash'>"

    def __dir__(self):
        "report list of all actual attrs, PLUS all known algorithms that haven't been loaded"
        attrs = set(dir(self.__class__))
        attrs.update(self.__dict__)
        attrs.update(_driver_locations)
        return sorted(attrs)

#NOTE: this is inserted into sys.modules by passlib/__init__.py
_hashmod = PasslibHashProxy()

#=========================================================
#global registry
#=========================================================

#: dict mapping hash names -> loaded driver objects (uses passlib.hash.__dict__ so the two will always be in sync)
_drivers = _hashmod.__dict__

#: dict mapping hash names -> (module name, None | class name) that should be location of driver
_driver_locations = {
    "apr_md5_crypt":    ("passlib.drivers.md5_crypt",   "apr_md5_crypt"),
    "bcrypt":           ("passlib.drivers.bcrypt",      "bcrypt"),
    "bigcrypt":         ("passlib.drivers.des_crypt",   "bigcrypt"),
    "bsdi_crypt":       ("passlib.drivers.des_crypt",   "bsdi_crypt"),
    "crypt16":          ("passlib.drivers.des_crypt",   "crypt16"),
    "des_crypt":        ("passlib.drivers.des_crypt",   "des_crypt"),
    "hex_md4":          ("passlib.drivers.digests",     "hex_md4"),
    "hex_md5":          ("passlib.drivers.digests",     "hex_md5"),
    "hex_sha1":         ("passlib.drivers.digests",     "hex_sha1"),
    "hex_sha256":       ("passlib.drivers.digests",     "hex_sha256"),
    "hex_sha512":       ("passlib.drivers.digests",     "hex_sha512"),
    "ldap_md5":         ("passlib.drivers.ldap",        "ldap_md5"),
    "ldap_sha1":        ("passlib.drivers.ldap",        "ldap_sha1"),
    "ldap_salted_md5":  ("passlib.drivers.ldap",        "ldap_salted_md5"),
    "ldap_salted_sha1": ("passlib.drivers.ldap",        "ldap_salted_sha1"),
    "md5_crypt":        ("passlib.drivers.md5_crypt",   "md5_crypt"),
    "mysql323":         ("passlib.drivers.mysql",       "mysql323"),
    "mysql41":          ("passlib.drivers.mysql",       "mysql41"),
    "nthash":           ("passlib.drivers.nthash",      "nthash"),
    "phpass":           ("passlib.drivers.phpass",      "phpass"),
    "plaintext":        ("passlib.drivers.misc",        "plaintext"),
    "postgres_md5":     ("passlib.drivers.postgres",    "postgres_md5"),
    "postgres_plaintext":("passlib.drivers.postgres",   "postgres_plaintext"),
    "sha1_crypt":       ("passlib.drivers.sha1_crypt",  "sha1_crypt"),
    "sha256_crypt":     ("passlib.drivers.sha2_crypt",  "sha256_crypt"),
    "sha512_crypt":     ("passlib.drivers.sha2_crypt",  "sha512_crypt"),
    "sun_md5_crypt":    ("passlib.drivers.sun_md5_crypt","sun_md5_crypt"),
    "unix_fallback":    ("passlib.drivers.misc",        "unix_fallback"),
}

def register_crypt_location(name, path):
    "register location to lazy-load driver when requested"
    global _driver_locations
    if ':' in path:
        modname, modattr = path.split(":")
    else:
        modname = path
        modattr = None
    _driver_locations[name] = (modname, modattr)

def register_crypt_handler(obj, force=False):
    "register CryptHandler handler"
    global _drivers

    #validate obj
    if not is_crypt_handler(obj):
        raise TypeError, "object does not appear to be a CryptHandler: %r" % (obj,)
    assert obj, "CryptHandlers must be boolean True: %r" % (obj,)

    #validate name
    name = obj.name
    if not name:
        raise ValueError, "name is null: %r" % (name,)
    if name.lower() != name:
        raise ValueError, "name must be lower-case: %r" % (name,)
    if re.search("[^_a-z0-9]",name):
        raise ValueError, "invalid characters in name (only underscore, a-z, 0-9 allowed): %r" % (name,)

    #check for existing handler
    other = _drivers.get(name)
    if other:
        if other is obj:
            return #already registered
        if force:
            log.warning("overriding previous handler registered to name %r: %r", name, other)
        else:
            raise ValueError, "handler already registered for name %r: %r" % (name, other)

    #put handler into hash module
    _drivers[name] = obj
    log.info("registered crypt handler %r: %r", name, obj)

def get_crypt_handler(name, default=Undef):
    "resolve crypt algorithm name"
    global _drivers, _driver_locations

    #check if handler loaded
    handler = _drivers.get(name)
    if handler:
        return handler

    #normalize name (and if changed, check dict again)
    alt = name.replace("-","_").lower()
    if alt != name:
        warn("handler names be lower-case, and use underscores instead of hyphens: %r => %r" % (name, alt))
        name = alt

        #check if handler loaded
        handler = _drivers.get(name)
        if handler:
            return handler

    #check if lazy load mapping has been specified for this driver
    route = _driver_locations.get(name)
    if route:
        modname, modattr = route

        #try to load the module - any import errors indicate runtime config,
        # either missing packages, or bad path provided to register_crypt_location()
        mod = __import__(modname, None, None, ['dummy'], 0)

        #first check if importing module triggered register_crypt_handler(),
        #though this is discouraged due to it's magical implicitness
        handler = _drivers.get(name)
        if handler:
            #XXX: issue deprecation warning here?
            assert is_crypt_handler(handler), "unexpected object: name=%r object=%r" % (name, handler)
            return handler

        #if attribute specified, assume *that's* the handler, otherwise assume the module itself.
        if modattr:
            handler = getattr(mod, modattr)
        else:
            handler = mod

        #XXX: can this ever happen under legitimate circumstances?
        if handler.name != name:
            raise RuntimeError, "handler name does not match expected name: %r vs %r" % (handler.name, name)

        #run through register_crypt_handler, to validate it
        register_crypt_handler(handler)

        return handler

    #TODO: check egg entry points under name "passlib.hash"

    #fail!
    if default is Undef:
        raise KeyError, "no crypt handler found for algorithm: %r" % (name,)
    else:
        return default

def list_crypt_handlers():
    "return sorted list of all known crypt algorithm names"
    return filter(lambda x: not x.startswith("_"), dir(_hashmod))

#=========================================================
#policy
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

    .. note::
        Instances of CryptPolicy should be treated as immutable.
    """

    #=========================================================
    #class methods
    #=========================================================
    @classmethod
    def from_path(cls, path, section="passlib"):
        "create new policy from specified section of an ini file"
        p = ConfigParser()
        if not p.read([path]):
            raise EnvironmentError, "failed to read config file"
        return cls(**dict(p.items(section)))

    @classmethod
    def from_string(cls, source, section="passlib"):
        p = ConfigParser()
        b = StringIO(source)
        p.readfp(b)
        return cls(**dict(p.items(section)))

    @classmethod
    def from_source(cls, source):
        "helper which accepts CryptPolicy, filepath, raw string, and returns policy"
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
        "create new policy from list of existing policy objects"
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
        "return copy of policy, with specified options replaced by new values"
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
                raise KeyError, "handler lacks name: %r" % (handler,)

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
                            raise ValueError, "unspecified scheme in deprecated list: %r" % (scheme,)
                dmap[cat] = frozenset(deps)

            #default scheme
            fb = kwds.get("default")
            if fb:
                if handlers:
                    if hasattr(fb, "name"):
                        fb = fb.name
                    if fb not in seen:
                        raise ValueError, "unspecified scheme set as default: %r" % (fb,)
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
    def has_handlers(self):
        return len(self._handlers) > 0

    def iter_handlers(self):
        "iterate through all loaded handlers in policy"
        return iter(self._handlers)

    def get_handler(self, name=None, category=None, required=False):
        """given an algorithm name, return algorithm handler which manages it.

        :arg name: name of algorithm, or ``None``
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
        "return dict of options attached to specified hash"
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
        "check if algorithm is deprecated according to policy"
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
        "return minimal time verify() should run according to policy"
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
        "return as dictionary of keywords"
        return dict(self.iter_config(resolve=resolve))

    def _write_to_parser(self, parser, section):
        "helper for to_string / to_file"
        parser.add_section(section)
        for k,v in self.iter_config(ini=True):
            parser.set(section, k,v)

    def to_string(self, section="passlib"):
        "render to INI string"
        p = ConfigParser()
        self._write_to_parser(p, section)
        b = StringIO()
        p.write(b)
        return b.getvalue()

    def to_path(self, path, section="passlib", update=False):
        "write to INI file"
        p = ConfigParser()
        if update and os.path.exists(path):
            if not p.read([path]):
                raise EnvironmentError, "failed to read existing file"
            p.remove_section(section)
        self._write_to_parser(p, section)
        fh = file(path, "w")
        p.write(fh)
        fh.close()

    #=========================================================
    #eoc
    #=========================================================

default_policy = CryptPolicy.from_string(resource_string("passlib", "default.cfg"))

#=========================================================
#
#=========================================================
class CryptContext(object):
    """Helper for encrypting passwords using different algorithms.

    Different storage contexts (eg: linux shadow files vs openbsd shadow files)
    may use different sets and subsets of the available algorithms.
    This class encapsulates such distinctions: it represents an ordered
    list of algorithms, each with a unique name. It contains methods
    to verify against existing algorithms in the context,
    and still encrypt using new algorithms as they are added.

    Because of all of this, it's basically just a list object.
    However, it contains some dictionary-like features
    such as looking up algorithms by name, and it's restriction
    that no two algorithms in a list share the same name
    causes it to act more like an "ordered set" than a list.

    In general use, none of this matters.
    The typical use case is as follows::

        >>> from passlib import hash
        >>> #create a new context that only understands Md5Crypt & BCrypt
        >>> myctx = hash.CryptContext([ hash.BCrypt, hash.Md5Crypt,  ])

        >>> #the last one in the list will be used as the default for encrypting...
        >>> hash1 = myctx.encrypt("too many secrets")
        >>> hash1
        '$2a$11$RvViwGZL./LkWfdGKTrgeO4khL/PDXKe0TayeVObQdoew7TFwhNFy'

        >>> #choose algorithm explicitly
        >>> hash2 = myctx.encrypt("too many secrets", alg="md5-crypt")
        >>> hash2
        '$1$E1g0/BY.$gS9XZ4W2Ea.U7jMueBRVA.'

        >>> #verification will autodetect the right hash
        >>> myctx.verify("too many secrets", hash1)
        True
        >>> myctx.verify("too many secrets", hash2)
        True
        >>> myctx.verify("too many socks", hash2)
        False

        >>> #you can also have it identify the algorithm in use
        >>> myctx.identify(hash1)
        'bcrypt'
        >>> #or just return the CryptHandler instance directly
        >>> myctx.identify(hash1, resolve=True)
        <passlib.BCrypt object, name="bcrypt">

        >>> #you can get a list of algs...
        >>> myctx.keys()
        [ 'md5-crypt', 'bcrypt' ]

        >>> #and get the CryptHandler object by name
        >>> bc = myctx['bcrypt']
        >>> bc
        <passlib.BCrypt object, name="bcrypt">
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
        elif kwds or not isinstance(policy, CryptPolicy):
            if isinstance(policy, (list,tuple)):
                policy = list(policy)
            else:
                policy = [policy]
            if kwds:
                policy.append(kwds)
            policy = CryptPolicy.from_sources(policy)
        if not policy.has_handlers():
            raise ValueError, "at least one scheme must be specified"
        self.policy = policy

    def __repr__(self):
        #XXX: *could* have proper repr(), but would have to render policy object options, and it'd be *really* long
        names = [ handler.name for handler in self.policy.iter_handlers() ]
        return "<CryptContext %0xd schemes=%r>" % (id(self), names)

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
                    if isinstance(vr, str) and vr.endswith("%"):
                        rc = getattr(handler, "rounds_cost", "linear")
                        vr = int(vr[:-1])
                        assert 0 <= vr < 100
                        if rc == "log2": #let % variance scale the linear number of rounds, not the log rounds cost
                            vr = int(logb(vr*.01*(2**df),2)+.5)
                        else:
                            vr = int(df*vr/100)
                    rounds = rng.randint(df-vr,df+vr)
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
        """check if hash is allowed by current policy, or if secret should be re-encrypted"""
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
        """Call genconfig() for specified handler"""
        handler = self.policy.get_handler(scheme, category, required=True)
        settings = self._prepare_settings(handler, category, **settings)
        return handler.genconfig(**settings)

    def genhash(self, secret, config, scheme=None, category=None, **context):
        """Call genhash() for specified handler"""
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
        for handler in self.policy.iter_handlers():
            if handler.identify(hash):
                if resolve:
                    return handler
                else:
                    return handler.name
        if required:
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

        :param **kwds:
            All other keyword options are passed to the algorithm's encrypt method.
            The two most common ones are "keep_salt" and "rounds".

        :returns:
            The secret as encoded by the specified algorithm and options.
        """
        if not self:
            raise ValueError, "no algorithms registered"
        handler = self.policy.get_handler(scheme, category, required=True)
        kwds = self._prepare_settings(handler, category, **kwds)
        #XXX: could insert normalization to preferred unicode encoding here
        return handler.encrypt(secret, **kwds)

    def verify(self, secret, hash, scheme=None, category=None, **context):
        """verify secret against specified hash

        :arg secret:
            the secret to encrypt
        :arg hash:
            hash string to compare to
        :param scheme:
            optional force context to use specfic scheme (must be allowed by context)
        """
        #quick checks
        if not self:
            raise ValueError, "no crypt schemes registered"
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
            delta = time.time() - start - mvt
            if delta > 0:
                time.sleep(delta)

        return result

    #=========================================================
    #eoc
    #=========================================================

#=========================================================
# eof
#=========================================================
