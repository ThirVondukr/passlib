"""passlib.ext.django.models

.. warning::

    This code is experimental and subject to change,
    and not officially documented in Passlib just yet
    (though it should work).

see the Passlib documentation for details on how to use this app
"""
#===================================================================
#imports
#===================================================================
#site
from django.conf import settings
#pkg
from passlib.context import CryptContext, CryptPolicy
from passlib.utils import is_crypt_context, bytes
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
    if not ctx:
        # remove any patching that was already set, just in case.
        set_django_password_context(None)
        return
    if ctx == "passlib-default":
        ctx = DEFAULT_CTX
    if isinstance(ctx, (unicode, bytes)):
        ctx = CryptPolicy.from_string(ctx)
    if isinstance(ctx, CryptPolicy):
        ctx = CryptContext(policy=ctx)
    if not is_crypt_context(ctx):
        raise TypeError("django settings.PASSLIB_CONTEXT must be CryptContext instance or config string: %r" % (ctx,))

    #monkeypatch django.contrib.auth.models:User
    set_django_password_context(ctx, get_category=catfunc)

patch()

#===================================================================
#eof
#===================================================================
