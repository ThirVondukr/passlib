"""passlib.ext.django.utils - helper functions for patching Django hashing

.. warning::

    This code is experimental and subject to change,
    and not officially documented in Passlib just yet
    (though it should work).
"""
#===================================================================
#imports
#===================================================================
#site
from warnings import warn
#pkg
from passlib.utils import is_crypt_context, bytes
#local
__all__ = [
    "get_category",
    "set_django_password_context",
]

#===================================================================
#lazy imports
#===================================================================

_has_django0 = None # old 0.9 django - lacks unusable_password support
_dam = None #django.contrib.auth.models reference

def _import_django():
    global _dam, _has_django0
    if _dam is None:
        import django.contrib.auth.models as _dam
        from django import VERSION
        _has_django0 = VERSION < (1,0)
    return _dam

#===================================================================
#constants
#===================================================================

#: base context mirroring django's setup
STOCK_CTX = """
[passlib]
schemes =
    django_salted_sha1, django_salted_md5,
    django_des_crypt, hex_md5,
    django_disabled

default = django_salted_sha1

deprecated = hex_md5
"""

#: default context used by app
DEFAULT_CTX = """
[passlib]
schemes =
    sha512_crypt,
    pbkdf2_sha256,
    django_salted_sha1, django_salted_md5,
    django_des_crypt, hex_md5,
    django_disabled

default = sha512_crypt

deprecated =
    pbkdf2_sha256,
    django_salted_sha1, django_salted_md5,
    django_des_crypt, hex_md5

all__vary_rounds = 5%%

sha512_crypt__default_rounds = 15000
staff__sha512_crypt__default_rounds = 25000
superuser__sha512_crypt__default_rounds = 35000
"""

#===================================================================
# helpers
#===================================================================

def get_category(user):
    """default get_category() implementation used by set_django_password_context

    this is the function used if ``settings.PASSLIB_GET_CONTEXT`` is not
    specified.

    it maps superusers to the ``"superuser"`` category,
    staff to the ``"staff"`` category,
    and all others to the default category.
    """
    if user.is_superuser:
        return "superuser"
    if user.is_staff:
        return "staff"
    return None

def um(func):
    "unwrap method (eg User.set_password -> orig func)"
    return func.im_func

#===================================================================
# monkeypatch framework
#===================================================================

# NOTE: this moneypatcher was written to be useful
#       outside of this module, and re-invokable,
#       which is why it tries so hard to maintain
#       sanity about it's patch state.

_django_patch_state = None #dict holding refs to undo patch

def set_django_password_context(context=None, get_category=get_category):
    """monkeypatches :mod:`!django.contrib.auth` to use specified password context.

    :arg context:
        Passlib context to use for Django password hashing.
        If ``None``, restores original Django functions.

        In order to support existing hashes,
        any context specified should include
        all the hashes in :data:`django_context`
        in addition to custom hashes.

    :param get_category:
        Optional function to use when mapping Django user ->
        CryptContext category.

        If a function, should have syntax ``catfunc(user) -> category|None``.
        If ``None``, no function is used.

        By default, uses a function which returns ``"superuser"``
        for superusers, and ``"staff"`` for staff.

    This function monkeypatches the following parts of Django:

    * :func:`!django.contrib.auth.models.check_password`
    * :meth:`!django.contrib.auth.models.User.check_password`
    * :meth:`!django.contrib.auth.models.User.set_password`

    It also stores the provided context in
    :data:`!django.contrib.auth.models.User.password_context`,
    for easy access.
    """
    global _django_patch_state, _dam, _has_django0
    _import_django()
    state = _django_patch_state
    User = _dam.User

    # issue warning if something else monkeypatched User
    # while our patch was applied.
    if state is not None:
        if um(User.set_password) is not state['user_set_password']:
            warn("another library has patched "
                    "django.contrib.auth.models:User.set_password")
        if um(User.check_password) is not state['user_check_password']:
            warn("another library has patched"
                    "django.contrib.auth.models:User.check_password")
        if _dam.check_password is not state['models_check_password']:
            warn("another library has patched"
                    "django.contrib.auth.models:check_password")

    #check if we should just restore original state
    if context is None:
        if state is not None:
            del User.password_context
            _dam.check_password = state['orig_models_check_password']
            User.set_password   = state['orig_user_set_password']
            User.check_password = state['orig_user_check_password']
            _django_patch_state = None
        return

    #validate inputs
    if not is_crypt_context(context):
        raise TypeError("context must be CryptContext instance or None: %r" %
                        (type(context),))

    #backup original state if this is first call
    if state is None:
        _django_patch_state = state = dict(
            orig_user_check_password = um(User.check_password),
            orig_user_set_password   = um(User.set_password),
            orig_models_check_password = _dam.check_password,
        )

    #prepare replacements
    if _has_django0:
        UNUSABLE_PASSWORD = "!"
    else:
        UNUSABLE_PASSWORD = _dam.UNUSABLE_PASSWORD

    def set_password(user, raw_password):
        "passlib replacement for User.set_password()"
        if raw_password is None:
            if _has_django0:
                # django 0.9
                user.password = UNUSABLE_PASSWORD
            else:
                user.set_unusable_password()
        else:
            cat = get_category(user) if get_category else None
            user.password = context.encrypt(raw_password, category=cat)

    def check_password(user, raw_password):
        "passlib replacement for User.check_password()"
        if raw_password is None:
            return False
        hash = user.password
        if not hash or hash == UNUSABLE_PASSWORD:
            return False
        cat = get_category(user) if get_category else None
        ok, new_hash = context.verify_and_update(raw_password, hash,
                                                 category=cat)
        if ok and new_hash is not None:
            user.password = new_hash
            user.save()
        return ok

    def raw_check_password(raw_password, enc_password):
        "passlib replacement for check_password()"
        if not enc_password or enc_password == UNUSABLE_PASSWORD:
            raise ValueError("no password hash specified")
        return context.verify(raw_password, enc_password)

    #set new state
    User.password_context = context
    User.set_password   = state['user_set_password']   = set_password
    User.check_password = state['user_check_password'] = check_password
    _dam.check_password = state['models_check_password'] = raw_check_password
    state['context' ] = context
    state['get_category'] = get_category

##def get_django_password_context():
##    """return current django password context
##
##    This returns the current :class:`~passlib.context.CryptContext` instance
##    set by :func:`set_django_password_context`.
##    If not context has been set, returns ``None``.
##    """
##    global _django_patch_state
##    if _django_patch_state:
##        return _django_patch_state['context']
##    else:
##        return None

#===================================================================
#eof
#===================================================================
