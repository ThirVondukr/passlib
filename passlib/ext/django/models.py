"""passlib.ext.django.models -- monkeypatch django hashing framework"""
#=============================================================================
# imports
#=============================================================================
# core
import logging; log = logging.getLogger(__name__)
from warnings import warn
# site
from django import VERSION
from django.conf import settings
# pkg
from passlib.context import CryptContext
from passlib.exc import ExpectedTypeError
from passlib.ext.django.utils import _PatchManager, hasher_to_passlib_name, \
                                     get_passlib_hasher, get_preset_config, MIN_DJANGO_VERSION
from passlib.utils.compat import unicode
# local
__all__ = ["password_context"]

#=============================================================================
# global attrs
#=============================================================================

# the context object which this patches contrib.auth to use for password hashing.
# configuration controlled by ``settings.PASSLIB_CONFIG``.
password_context = CryptContext()

# function mapping User objects -> passlib user category.
# may be overridden via ``settings.PASSLIB_GET_CATEGORY``.
def _get_category(user):
    """default get_category() implementation"""
    if user.is_superuser:
        return "superuser"
    elif user.is_staff:
        return "staff"
    else:
        return None

# object used to track state of patches applied to django.
_manager = _PatchManager(log=logging.getLogger(__name__ + "._manager"))

# patch status
_patched = False

#=============================================================================
# applying & removing the patches
#=============================================================================
def _apply_patch():
    """monkeypatch django's password handling to use ``passlib_context``,
    assumes the caller will configure the object.
    """
    #
    # setup environment & patch-paths
    #
    if VERSION < MIN_DJANGO_VERSION:
        raise RuntimeError("passlib.ext.django requires django >= %s" % (MIN_DJANGO_VERSION,))

    log.debug("preparing to monkeypatch 'django.contrib.auth' ...")
    global _patched
    assert not _patched, "monkeypatching already applied"

    HASHERS_PATH = "django.contrib.auth.hashers"
    MODELS_PATH = "django.contrib.auth.models"
    USER_PATH = MODELS_PATH + ":User"
    FORMS_PATH = "django.contrib.auth.forms"

    #
    # import some helpers from hashers module
    #
    from django.contrib.auth.hashers import is_password_usable

    #
    # patch ``User.set_password() & ``User.check_password()`` to use
    # context & get_category (would just leave these as wrappers for hashers
    # module under django 1.4, but then we couldn't pass User object into
    # get_category very easily)
    #
    @_manager.monkeypatch(USER_PATH)
    def set_password(user, password):
        """passlib replacement for User.set_password()"""
        if password is None:
            user.set_unusable_password()
        else:
            # NOTE: pulls _get_category from module globals
            cat = _get_category(user)
            user.password = password_context.encrypt(password, category=cat)

    @_manager.monkeypatch(USER_PATH)
    def check_password(user, password):
        """passlib replacement for User.check_password()"""
        hash = user.password
        if password is None or not is_password_usable(hash):
            return False
        # NOTE: pulls _get_category from module globals
        cat = _get_category(user)
        ok, new_hash = password_context.verify_and_update(password, hash,
                                                          category=cat)
        if ok and new_hash is not None:
            # migrate to new hash if needed.
            user.password = new_hash
            user.save()
        return ok

    #
    # override check_password() with our own implementation
    #
    @_manager.monkeypatch(HASHERS_PATH)
    @_manager.monkeypatch(MODELS_PATH)
    def check_password(password, encoded, setter=None, preferred="default"):
        """passlib replacement for check_password()"""
        # XXX: this currently ignores "preferred" keyword, since its purpose
        #      was for hash migration, and that's handled by the context.
        if password is None or not is_password_usable(encoded):
            return False
        ok = password_context.verify(password, encoded)
        if ok and setter and password_context.needs_update(encoded):
            setter(password)
        return ok

    #
    # patch the other functions defined in the ``hashers`` module, as well
    # as any other known locations where they're imported within ``contrib.auth``
    #
    @_manager.monkeypatch(HASHERS_PATH, wrap=True)
    @_manager.monkeypatch(MODELS_PATH, wrap=True)
    def make_password(__wrapped__, password, salt=None, hasher="default"):
        """passlib replacement for make_password()"""
        if password is None:
            return __wrapped__(None)
        if hasher == "default":
            scheme = None
        else:
            scheme = hasher_to_passlib_name(hasher)
        kwds = dict(scheme=scheme)
        handler = password_context.handler(scheme)
        if "salt" in handler.setting_kwds:
            if hasher.startswith("unsalted_"):
                # Django 1.4.6+ uses a separate 'unsalted_sha1' hasher for "sha1$$digest",
                # but passlib just reuses it's "sha1" handler ("sha1$salt$digest"). To make
                # this work, have to explicitly tell the sha1 handler to use an empty salt.
                kwds['salt'] = ''
            elif salt:
                # Django make_password() autogenerates a salt if salt is bool False (None / ''),
                # so we only pass the keyword on if there's actually a fixed salt.
                kwds['salt'] = salt
        return password_context.encrypt(password, **kwds)

    @_manager.monkeypatch(HASHERS_PATH)
    @_manager.monkeypatch(FORMS_PATH)
    def get_hasher(algorithm="default"):
        """passlib replacement for get_hasher()"""
        if algorithm == "default":
            scheme = None
        else:
            scheme = hasher_to_passlib_name(algorithm)
        # NOTE: resolving scheme -> handler instead of
        #       passing scheme into get_passlib_hasher(),
        #       in case context contains custom handler
        #       shadowing name of a builtin handler.
        handler = password_context.handler(scheme)
        return get_passlib_hasher(handler, algorithm=algorithm)

    # identify_hasher() was added in django 1.5,
    # patching it anyways for 1.4, so passlib's version is always available.
    @_manager.monkeypatch(HASHERS_PATH)
    @_manager.monkeypatch(FORMS_PATH)
    def identify_hasher(encoded):
        """passlib helper to identify hasher from encoded password"""
        handler = password_context.identify(encoded, resolve=True,
                                            required=True)
        algorithm = None
        if handler.name == "django_salted_sha1" and encoded.startswith("sha1$$"):
            # django 1.4.6+ uses a separate hasher for "sha1$$digest" hashes,
            # but passlib just reuses the "sha1$salt$digest" handler.
            # we want to resolve to correct django hasher.
            algorithm = "unsalted_sha1"
        return get_passlib_hasher(handler, algorithm=algorithm)

    _patched = True
    log.debug("... finished monkeypatching django")

def _remove_patch():
    """undo the django monkeypatching done by this module.
    offered as a last resort if it's ever needed.

    .. warning::
        This may cause problems if any other Django modules have imported
        their own copies of the patched functions, though the patched
        code has been designed to throw an error as soon as possible in
        this case.
    """
    global _patched
    if _patched:
        log.debug("removing django monkeypatching...")
        _manager.unpatch_all(unpatch_conflicts=True)
        password_context.load({})
        _patched = False
        log.debug("...finished removing django monkeypatching")
        return True
    if _manager: # pragma: no cover -- sanity check
        log.warning("reverting partial monkeypatching of django...")
        _manager.unpatch_all()
        password_context.load({})
        log.debug("...finished removing django monkeypatching")
        return True
    log.debug("django not monkeypatched")
    return False

#=============================================================================
# main code
#=============================================================================
def _load():
    global _get_category

    # TODO: would like to add support for inheriting config from a preset
    #       (or from existing hasher state) and letting PASSLIB_CONFIG
    #       be an update, not a replacement.

    # TODO: wrap and import any custom hashers as passlib handlers,
    #       so they could be used in the passlib config.

    # load config from settings
    _UNSET = object()
    config = getattr(settings, "PASSLIB_CONFIG", _UNSET)
    if config is _UNSET:
        # XXX: should probably deprecate this alias
        config = getattr(settings, "PASSLIB_CONTEXT", _UNSET)
    if config is _UNSET:
        config = "passlib-default"
    if config is None:
        warn("setting PASSLIB_CONFIG=None is deprecated, "
             "and support will be removed in Passlib 1.8, "
             "use PASSLIB_CONFIG='disabled' instead.",
             DeprecationWarning)
        config = "disabled"
    elif not isinstance(config, (unicode, bytes, dict)):
        raise ExpectedTypeError(config, "str or dict", "PASSLIB_CONFIG")

    # load custom category func (if any)
    get_category = getattr(settings, "PASSLIB_GET_CATEGORY", None)
    if get_category and not callable(get_category):
        raise ExpectedTypeError(get_category, "callable", "PASSLIB_GET_CATEGORY")

    # check if we've been disabled
    if config == "disabled":
        if _patched: # pragma: no cover -- sanity check
            log.error("didn't expect monkeypatching would be applied!")
        _remove_patch()
        return

    # resolve any preset aliases
    if isinstance(config, str) and '\n' not in config:
        config = get_preset_config(config)

    # setup context
    _apply_patch()
    password_context.load(config)
    if get_category:
        # NOTE: _get_category is module global which is read by
        #       monkeypatched functions constructed by _apply_patch()
        _get_category = get_category
    log.debug("passlib.ext.django loaded")

# wrap load function so we can undo any patching if something goes wrong
try:
    _load()
except:
    _remove_patch()
    raise

#=============================================================================
# eof
#=============================================================================
