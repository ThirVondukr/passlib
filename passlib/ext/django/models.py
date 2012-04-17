"""passlib.ext.django.models

.. warning::

    This code is experimental and subject to change
    (though it should work).

see the Passlib documentation for details on how to use this app
"""
#===================================================================
#imports
#===================================================================
#site
from django.conf import settings
#pkg
from passlib.context import CryptContext
from passlib.utils import is_crypt_context
from passlib.utils.compat import bytes, unicode, base_string_types
from passlib.ext.django.utils import DEFAULT_CTX, get_category, \
    set_django_password_context

#===================================================================
#main
#===================================================================
def patch():
    #get config
    ctx = getattr(settings, "PASSLIB_CONTEXT", "passlib-default")
    catfunc = getattr(settings, "PASSLIB_GET_CATEGORY", get_category)

    #parse & validate input value
    if ctx == "disabled" or ctx is None:
        # remove any patching that was already set, just in case.
        set_django_password_context(None)
        return
    if ctx == "passlib-default":
        ctx = DEFAULT_CTX
    if isinstance(ctx, base_string_types):
        ctx = CryptContext.from_string(ctx)
    if not is_crypt_context(ctx):
        raise TypeError("django settings.PASSLIB_CONTEXT must be CryptContext "
                        "instance or configuration string: %r" % (ctx,))

    #monkeypatch django.contrib.auth.models:User
    set_django_password_context(ctx, get_category=catfunc)

patch()

#===================================================================
#eof
#===================================================================
