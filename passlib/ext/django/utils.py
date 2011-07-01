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
from django.contrib.auth.models import User
#pkg
from passlib.utils import is_crypt_context, bytes
#local
__all__ = [
    "get_category",
    "set_django_password_context",
]

#===================================================================
#monkeypatch framework
#===================================================================

# NOTE: this moneypatcher was written to be useful
#       outside of this module, and re-invokable,
#       which is why it tries so hard to maintain
#       sanity about it's patch state.

_django_patch_state = None

def get_category(user):
    "default get_category() implementation used by set_django_password_context"
    if user.is_superuser:
        return "superuser"
    if user.is_staff:
        return "staff"
    return None

def um(func):
    "unwrap method (eg User.set_password -> orig func)"
    return func.im_func

def set_django_password_context(context=None, get_category=get_category):
    """monkeypatches django.contrib.auth to use specified password context

    :arg context:
        Passlib context to use for Django password hashing.
        If ``None``, restores original django functions.

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
    """
    global _django_patch_state
    state = _django_patch_state

    # issue warning if something else monkeypatched User
    # while our patch was applied.
    if state is not None:
        if um(User.set_password) is not state['set_password']:
            warning("another library has patched django's User.set_password")
        if um(User.check_password) is not state['check_password']:
            warning("another library has patched django's User.check_password")

    #check if we should just restore original state
    if context is None:
        if state is not None:
            User.pwd_context = None
            User.set_password   = state['orig_set_password']
            User.check_password = state['orig_check_password']
            _django_patch_state = None
        return

    if not is_crypt_context(context):
        raise TypeError("context must be CryptContext instance or None: %r" %
                        (type(context),))

    #backup original state if this is first call
    if state is None:
        _django_patch_state = state = dict(
            orig_check_password = um(User.check_password),
            orig_set_password   = um(User.set_password),
        )

    #prepare replacements
    def set_password(user, raw_password):
        "passlib replacement for User.set_password()"
        if raw_password is None:
            user.set_unusable_password()
        else:
            cat = get_category(user) if get_category else None
            user.password = context.encrypt(raw_password, category=cat)

    def check_password(user, raw_password):
        "passlib replacement for User.check_password()"
        hash = user.password
        cat = get_category(user) if get_category else None
        ok, new_hash = context.verify_and_update(raw_password, hash,
                                                 category=cat)
        if ok and new_hash:
            user.password = new_hash
            user.save()
        return ok

    #set new state
    User.pwd_context = context #just to make it easy to get to.
    User.set_password   = state['set_password']   = set_password
    User.check_password = state['check_password'] = check_password

#===================================================================
#eof
#===================================================================
