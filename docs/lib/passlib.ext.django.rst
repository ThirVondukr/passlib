.. index:: django; password hashing app

==================================================
:mod:`passlib.ext.django` - Django Password Helper
==================================================

.. module:: passlib.ext.django

.. warning::

    This submodule should be considered "release candidate" quality.
    It works, and has good unittest coverage,
    but has not seen very much real-world use.
    *caveat emptor*, and please report any issues.

    This module is currently not compatible with Django 1.4's new
    password hashing system, or formats.

.. todo::

    This documentation needs to be cleaned up significantly
    for new users.

Overview
========
This module is intended for use with
`Django <http://www.djangoproject.com>`_-based web applications.
It contains a Django app which allows you to override
Django's builtin password hashing routines
to use any Passlib :doc:`CryptContext <passlib.context>` configuration.
It provides the following features:

* Custom configurations allow the use of any password hash supported by Passlib.
* Increased-strength hashing for staff and admin accounts.
* Automatically upgrading of deprecated and weaker hashes.
* Default configuration supports all standard Django hash formats,
  and automatically upgrades all hashes to use :class:`~passlib.hash.sha512_crypt`
  (upgrades only occur when the user logs in or changes their password).
* Tested against Django 0.9 - 1.3

Installation
=============
Installation is simple: once Passlib is installed, just add
``"passlib.ext.django"`` to Django's ``settings.INSTALLED_APPS``.
This app will handle everything else.

Once installed, when this app is imported by Django, it will automatically monkeypatch
:class:`!django.contrib.auth.models.User` to use a Passlib
:class:`~passlib.context.CryptContext` instance in place of the normal Django
password authentication routines.
This provides hash migration, the ability to set stronger policies
for superuser & staff passwords, and stronger password hashing schemes.

Configuration
=============
While the default configuration should be secure, once installed,
you may set the following options in django ``settings.py``:

``PASSLIB_CONTEXT``
   This may be one of a number of values:

   * The string ``"passlib-default"``, which will cause Passlib
     to replace Django's hash routines with a builtin policy
     that supports all existing django hashes; but as users
     log in, upgrades them all to :class:`~passlib.hash.pbkdf2_sha256`.
     It also supports stronger hashing for the superuser account.

     This is the default behavior if ``PASSLIB_CONTEXT`` is not set.

     The exact default policy used can be found in
     :data:`~passlib.ext.django.utils.DEFAULT_CTX`.

   * ``"disabled"``, in which case this app will do nothing when Django is loaded.

   * A multiline configuration string suitable for passing to
     :meth:`passlib.context.CryptContext.from_string`.
     It is *strongly* recommended to use a configuration which will support
     the existing Django hashes
     (see :data:`~passlib.ext.django.utils.STOCK_CTX`).

``PASSLIB_GET_CATEGORY``

   By default, Passlib will invoke the specified context with a category
   string that's dependant on the User instance.  superusers will be assigned
   to the ``superuser`` category, staff to the ``staff`` category, and all
   other accounts assigned to ``None``.

   This configuration option allows overriding that logic
   by specifying an alternate function with the call signature
   ``get_category(user) -> category|None``.

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
            sha512_crypt,
            django_salted_sha1, django_salted_md5,
            django_des_crypt, hex_md5,
            django_disabled

        default = sha512_crypt

        deprecated =
            django_salted_sha1, django_salted_md5,
            django_des_crypt, hex_md5

        all__vary_rounds = 5%%

        sha512_crypt__default_rounds = 15000
        staff__sha512_crypt__default_rounds = 25000
        superuser__sha512_crypt__default_rounds = 35000

.. data:: STOCK_CTX

    This is a string containing the a hashing policy
    which should be exactly the same as Django's default behavior.
    It is mainly useful as a template for building off of
    when defining your own custom hashing policy
    via ``settings.PASSLIB_CONTEXT``.
    It defaults to the following::

        [passlib]
        schemes =
            django_salted_sha1, django_salted_md5,
            django_des_crypt, hex_md5,
            django_disabled

        default = django_salted_sha1

        deprecated = hex_md5

.. autofunction:: get_category

.. autofunction:: set_django_password_context
