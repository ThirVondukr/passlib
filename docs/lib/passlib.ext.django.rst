.. index:: django; password hashing app

==================================================
:mod:`passlib.ext.django` - Django Password Helper
==================================================

.. module:: passlib.ext.django

.. warning::

    This module is currently under development.
    It works and has good unittest coverage,
    but has not seen very much real-world use;
    *caveat emptor*.

.. todo::

    This documentation needs to be cleaned up significantly
    for new users.

Overview
========
This module is intended for use with
`Django <http://www.djangoproject.com>`_-based web applications.
It contains a Django app which allows you to override
Django's builtin password hashing routine
with any Passlib :doc:`CryptContext <passlib.context>` instance.
By default, it comes configured to add support for
:class:`~passlib.hash.sha512_crypt`, and will automatically
upgrade all existing Django password hashes as your users log in.

:doc:`SHA512-Crypt <passlib.hash.sha512_crypt>`
was chosen as the best choice for the average Django deployment:
accelerated implementations are available on most stock Linux systems,
as well as Google App Engine, and Passlib provides a pure-python
fallback for all other platforms. 

Installation
=============
Installation is simple: just add ``"passlib.ext.django"`` to
Django's ``settings.INSTALLED_APPS``. This app will handle
everything else.

Once done, when this app is imported by Django,
it will automatically monkeypatch
:class:`!django.contrib.auth.models.User`
to use a Passlib :class:`~passlib.context.CryptContext` instance
in place of the normal Django password authentication routines.

This provides hash migration, the ability to set stronger policies
for superuser & staff passwords, and stronger password hashing schemes.

Configuration
=============
Once installed, you can set the following options in django ``settings.py``:

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

   * ``None``, in which case this app will do nothing when Django is loaded.

   * A multiline configuration string suitable for passing to
     :meth:`passlib.context.CryptPolicy.from_string`.
     It is *strongly* recommended to use a configuration which will support
     the existing Django hashes
     (see :data:`~passlib.ext.django.utils.STOCK_CTX`).

``PASSLIB_GET_CATEGORY``

   By default, Passlib will invoke the specified context with a category
   string that's dependant on the User instance.
   superusers will be assigned to the ``superuser`` category,
   staff to the ``staff`` category, and all other accounts
   assigned to ``None``.

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
