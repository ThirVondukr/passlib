"""passlib.ext.django.models

.. warning::

    This code is experimental and subject to change,
    and not officially documented in Passlib just yet
    (though it should work).

When this is imported on Django load,
it automatically monkeypatches
:class:`django.contrib.auth.models.User`
to use a Passlib CryptContext instance in place of normal Django
password authentication. This provides hash migration,
ability to set stronger policies for superuser & staff passwords,
and stronger password hashing schemes.

You can set the following options in django ``settings.py``:

``PASSLIB_CONTEXT``
   This may be one of a number of values:

   * The string ``"passlib-default"``, which will cause Passlib
     to replace Django's hash routines with a builtin policy
     that supports all existing django hashes; but as users
     log in, upgrades them all to :class:`~passlib.hash.pbkdf2_sha256`.
     It also supports stronger hashing for the superuser account.

     This is the default behavior if ``PASSLIB_CONTEXT`` is not set.

     The exact policy can be found at
     :data:`passlib.ext.django.models.passlib_default_ctx`.

   * ``None``, in which case this app will do nothing when django is loaded.

   * A :class:`~passlib.context.CryptContext`
     instance which will be used in place of the normal Django password
     hash routines.

     It is *strongly* recommended to use a context which will support
     the existing Django hashes.

   * A multiline config string suitable for passing to
     :meth:`passlib.context.CryptPolicy.from_string`.
     This will be parsed and used much like a :class:`!CryptContext` instance.

``PASSLIB_GET_CATEGORY``

   By default, Passlib will invoke the specified context with a category
   string that's dependant on the User instance.
   superusers will be assigned to the ``superuser`` category,
   staff to the ``staff`` category, and all other accounts
   assigned to ``None``.

   This allows overriding that logic by specifying an alternate
   function of the format ``get_category(user) -> category|None``.

   .. seealso::

        See :ref:`user-categories` for more details about
        the category system in Passlib.
"""
#===================================================================
#imports
#===================================================================
#site
from django.conf import settings
#pkg
from passlib.context import CryptContext, CryptPolicy
from passlib.utils import is_crypt_context, bytes
from passlib.ext.django.utils import get_category, set_django_password_context

#===================================================================
#constants
#===================================================================

#: default context used by app
passlib_default_ctx = """
[passlib]
schemes =
    pbkdf2_sha256,
    django_salted_sha1, django_salted_md5,
    django_des_crypt, hex_md5,
    django_disabled

default = pbkdf2_sha256

deprecated =
    django_salted_sha1, django_salted_md5,
    django_des_crypt, hex_md5

all__vary_rounds = 5%%

pbkdf2_sha256__default_rounds = 4000
staff__pbkdf2_sha256__default_rounds = 8000
superuser__pbkdf2_sha256__default_rounds = 10000
"""

#===================================================================
#main
#===================================================================
def patch():
    #get config
    ctx = getattr(settings, "PASSLIB_CONTEXT", "passlib-default")
    catfunc = getattr(settings, "PASSLIB_GET_CATEGORY", get_category)

    #parse & validate input value
    if not ctx:
        return
    if ctx == "passlib-default":
        ctx = passlib_default_ctx
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
