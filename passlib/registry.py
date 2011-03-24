"""passlib.registry - registry for password hash handlers"""
#=========================================================
#imports
#=========================================================
#core
import inspect
import re
import logging; log = logging.getLogger(__name__)
from warnings import warn
#site
#libs
from passlib.utils import Undef, is_crypt_handler
#pkg
#local
__all__ = [
    "register_crypt_handler_path",
    "register_crypt_handler",
    "get_crypt_handler",
    "list_crypt_handlers",
]

#=========================================================
#registry proxy object
#=========================================================
class PasslibRegistryProxy(object):
    """proxy module passlib.hash

    this module is in fact an object which lazy-loads
    the requested password hash algorithm from wherever it has been stored.
    it acts as a thin wrapper around :func:`passlib.registry.get_crypt_handler`.
    """
    __name__ = "passlib.hash"
    __package__ = None

    def __getattr__(self, attr):
        if attr.startswith("_"):
            raise AttributeError, "missing attribute: %r" % (attr,)
        handler = get_crypt_handler(attr, None)
        if handler:
            return handler
        else:
            raise AttributeError, "unknown password hash: %r" % (attr,)

    def __setattr__(self, attr, value):
        register_crypt_handler(value, name=attr)

    def __repr__(self):
        return "<proxy module 'passlib.hash'>"

    def __dir__(self):
        #add in handlers that will be lazy-loaded,
        #otherwise this is std dir implementation
        attrs = set(dir(self.__class__))
        attrs.update(self.__dict__)
        attrs.update(_handler_locations)
        return sorted(attrs)

    #=========================================================
    #eoc
    #=========================================================

#singleton instance
_proxy = PasslibRegistryProxy()

#==========================================================
#internal registry state
#==========================================================

#: dict mapping name -> handler for all loaded handlers. uses proxy's dict so they stay in sync.
_handlers = _proxy.__dict__

#: dict mapping name -> (module path, attribute) for lazy-loading of handlers
_handler_locations = {
    #NOTE: this is a hardcoded list of the handlers built into passlib,
    #applications should call register_crypt_handler_location() to add their own
    "apr_md5_crypt":    ("passlib.handlers.md5_crypt",   "apr_md5_crypt"),
    "bcrypt":           ("passlib.handlers.bcrypt",      "bcrypt"),
    "bigcrypt":         ("passlib.handlers.des_crypt",   "bigcrypt"),
    "bsdi_crypt":       ("passlib.handlers.des_crypt",   "bsdi_crypt"),
    "crypt16":          ("passlib.handlers.des_crypt",   "crypt16"),
    "des_crypt":        ("passlib.handlers.des_crypt",   "des_crypt"),
    "hex_md4":          ("passlib.handlers.digests",     "hex_md4"),
    "hex_md5":          ("passlib.handlers.digests",     "hex_md5"),
    "hex_sha1":         ("passlib.handlers.digests",     "hex_sha1"),
    "hex_sha256":       ("passlib.handlers.digests",     "hex_sha256"),
    "hex_sha512":       ("passlib.handlers.digests",     "hex_sha512"),
    "ldap_plaintext":   ("passlib.handlers.ldap_digests","ldap_plaintext"),
    "ldap_md5":         ("passlib.handlers.ldap_digests","ldap_md5"),
    "ldap_sha1":        ("passlib.handlers.ldap_digests","ldap_sha1"),
    "ldap_salted_md5":  ("passlib.handlers.ldap_digests","ldap_salted_md5"),
    "ldap_salted_sha1": ("passlib.handlers.ldap_digests","ldap_salted_sha1"),
    "md5_crypt":        ("passlib.handlers.md5_crypt",   "md5_crypt"),
    "mysql323":         ("passlib.handlers.mysql",       "mysql323"),
    "mysql41":          ("passlib.handlers.mysql",       "mysql41"),
    "nthash":           ("passlib.handlers.nthash",      "nthash"),
    "oracle10":         ("passlib.handlers.oracle",      "oracle10"),
    "oracle11":         ("passlib.handlers.oracle",      "oracle11"),
    "phpass":           ("passlib.handlers.phpass",      "phpass"),
    "plaintext":        ("passlib.handlers.misc",        "plaintext"),
    "postgres_md5":     ("passlib.handlers.postgres",    "postgres_md5"),
    "sha1_crypt":       ("passlib.handlers.sha1_crypt",  "sha1_crypt"),
    "sha256_crypt":     ("passlib.handlers.sha2_crypt",  "sha256_crypt"),
    "sha512_crypt":     ("passlib.handlers.sha2_crypt",  "sha512_crypt"),
    "sun_md5_crypt":    ("passlib.handlers.sun_md5_crypt","sun_md5_crypt"),
    "unix_fallback":    ("passlib.handlers.misc",        "unix_fallback"),
}

#: master regexp for detecting valid handler names
_name_re = re.compile("^[a-z][_a-z0-9]{2,}$")

#: names which aren't allowed for various reasons (mainly keyword conflicts in CryptContext)
_forbidden_names = frozenset(["policy", "context", "all", "default", "none"])

#==========================================================
#registry frontend functions
#==========================================================
def register_crypt_handler_path(name, path):
    """register location to lazy-load handler when requested.

    custom hashes may be registered via :func:`register_crypt_handler`,
    or they may be registered by this function,
    which will delay actually importing and loading the handler
    until a call to :func:`get_crypt_handler` is made for the specified name.

    :arg name: name of handler
    :arg path: module import path

    the specified module path should contain a password hash handler
    called :samp:`{name}`, or the path may contain a semicolon,
    specifying the module and module attribute to use.
    """
    global _handler_locations
    if ':' in path:
        modname, modattr = path.split(":")
    else:
        modname, modattr = path, name
    _handler_locations[name] = (modname, modattr)

def register_crypt_handler(handler, force=False, name=None):
    """register password hash handler.

    this method immediately registers a handler with the internal passlib registry,
    so that it will be returned by :func:`get_crypt_handler` when requested.

    :arg handler: the password hash handler to register
    :param force: force override of existing handler (defaults to False)

    :raises TypeError:
        if the specified object does not appear to be a valid handler.

    :raises ValueError:
        if the specified object's name (or other required attributes)
        contain invalid values.

    :raises KeyError:
        if a (different) handler was already registered with
        the same name, and ``force=True`` was not specified.
    """
    global _handlers, _name_re

    #validate handler
    if not is_crypt_handler(handler):
        raise TypeError, "object does not appear to be a crypt handler: %r" % (handler,)
    assert handler, "crypt handlers must be boolean True: %r" % (handler,)

    #if name specified, make sure it matched
    #(this is mainly used as a check to help __setattr__)
    if name:
        if name != handler.name:
            raise ValueError, "handlers must be stored only under their own name"
    else:
        name = handler.name

    #validate name
    if not name:
        raise ValueError, "name is null: %r" % (name,)
    if name.lower() != name:
        raise ValueError, "name must be lower-case: %r" % (name,)
    if not _name_re.match(name):
        raise ValueError, "invalid characters in name (must be 3+ characters, begin with a-z, and contain only underscore, a-z, 0-9): %r" % (name,)
    if '__' in name:
        raise ValueError, "name may not contain double-underscores: %r" % (name,)
    if name in _forbidden_names:
        raise ValueError, "that name is not allowed: %r" % (name,)

    #check for existing handler
    other = _handlers.get(name)
    if other:
        if other is handler:
            return #already registered
        if force:
            log.warning("overriding previous handler registered to name %r: %r", name, other)
        else:
            raise KeyError, "a handler has already registered for the name %r: %r (use force=True to override)" % (name, other)

    #register handler in dict
    _handlers[name] = handler
    log.info("registered crypt handler %r: %r", name, handler)

def get_crypt_handler(name, default=Undef):
    """return handler for specified password hash scheme.

    this method looks up a handler for the specified scheme.
    if the handler is not already loaded,
    it checks if the location is known, and loads it first.

    :arg name: name of handler to return
    :param default: if specified, returns default value if no handler found.

    :raises KeyError: if no handler matching that name is found, and no default specified

    :returns: handler attached to name, or default if specified
    """
    global _handlers, _handler_locations

    #check if handler loaded
    handler = _handlers.get(name, None)
    if handler:
        return handler

    #normalize name (and if changed, check dict again)
    alt = name.replace("-","_").lower()
    if alt != name:
        warn("handler names be lower-case, and use underscores instead of hyphens: %r => %r" % (name, alt))
        name = alt

        #check if handler loaded
        handler = _handlers.get(name)
        if handler:
            return handler

    #check if lazy load mapping has been specified for this driver
    route = _handler_locations.get(name)
    if route:
        modname, modattr = route

        #try to load the module - any import errors indicate runtime config,
        # either missing packages, or bad path provided to register_crypt_handler_path()
        mod = __import__(modname, None, None, ['dummy'], 0)

        #first check if importing module triggered register_crypt_handler(),
        #(though this is discouraged due to it's magical implicitness)
        handler = _handlers.get(name)
        if handler:
            #XXX: issue deprecation warning here?
            assert is_crypt_handler(handler), "unexpected object: name=%r object=%r" % (name, handler)
            return handler

        #then get real handler & register it
        handler = getattr(mod, modattr)
        register_crypt_handler(handler, name=name)
        return handler

    #fail!
    if default is Undef:
        raise KeyError, "no crypt handler found for algorithm: %r" % (name,)
    else:
        return default

def list_crypt_handlers(loaded_only=False):
    """return sorted list of all known crypt handler names.

    :param loaded_only: if ``True``, only returns names of handlers which have actually been loaded.

    :returns: list of names of all known handlers
    """
    global _handlers, _handler_locations
    names = set(_handlers)
    if not loaded_only:
        names.update(_handler_locations)
    return sorted(names)

#=========================================================
# eof
#=========================================================
