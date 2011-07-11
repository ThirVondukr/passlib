.. index:: django; password hashing app

==================================================
:mod:`passlib.ext.django` - Django Password Helper
==================================================

.. module:: passlib.ext.django

.. warning::

    This module is currently under development.
    It will probably work, but has not seen very much
    testing or real-world use, and may change in future releases;
    *caveat emptor*.

.. todo::

    This documentation needs to be cleaned up significantly
    for new users.

Overview
========
This module is intended for use with
`Django <http://www.djangoproject.com>`_-based web applications.
It contains a Django app which allows you to override
Django's :doc:`default <passlib.hash.django_std>` password hash formats
with any passlib :doc:`CryptContext <passlib.context>`.
By default, it comes configured to add support for
:class:`~passlib.hash.pbkdf2_sha256`, and will automatically
upgrade all existing Django passwords as your users log in.

Installation
=============
Installation is simple, just add ``passlib.ext.django`` to
``settings.INSTALLED_APPS``. This module will handle
everything else.

Once done, when this app is imported by Django,
it will automatically monkeypatch
:class:`!django.contrib.auth.models.User`
to use a Passlib CryptContext instance in place of normal Django
password authentication. This provides hash migration,
ability to set stronger policies for superuser & staff passwords,
and stronger password hashing schemes.

Configuration
=============
You can set the following options in django ``settings.py``:

``PASSLIB_CONTEXT``
   This may be one of a number of values:

   * The string ``"passlib-default"``, which will cause Passlib
     to replace Django's hash routines with a builtin policy
     that supports all existing django hashes; but as users
     log in, upgrades them all to :class:`~passlib.hash.pbkdf2_sha256`.
     It also supports stronger hashing for the superuser account.

     This is the default behavior if ``PASSLIB_CONTEXT`` is not set.

     The exact default policy can be found at
     :data:`passlib.ext.django.utils.DEFAULT_CTX`.

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

Utility Functions
=================
.. module:: passlib.ext.django.utils

Whether or not you install this application into Django,
the following utility functions are available for overriding
Django's password hashes:

.. data:: DEFAULT_CTX

    This is a string containing the default hashing policy
    that will be used by this application if none is specified
    via ``settings.PASSLIB_CONTEXT``.    
    It defaults to the following::
    
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
    
.. autofunction:: get_category

.. autofunction:: set_django_password_context