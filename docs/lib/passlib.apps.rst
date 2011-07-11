==================================================================
:mod:`passlib.apps` - Helpers for various applications
==================================================================

.. module:: passlib.apps
    :synopsis: encrypting & verifying passwords used in sql servers and other applications

This lists a number of :class:`!CryptContext` instances that are predefined
by PassLib for easily handling the multiple formats used by various applications.
(For details about how to use a :class:`!CryptContext` instance,
see :doc:`passlib.context-usage`).

.. _quickstart-custom-applications:

Custom Applications
===================
.. data:: custom_app_context

    This :class:`!CryptContext` object is provided for new python applications
    to quickly and easily add password hashing support.
    It offers:

    * Support for :class:`~passlib.hash.sha256_crypt` and :class:`~passlib.hash.sha512_crypt`
    * Defaults to SHA256-Crypt under 32 bit systems; SHA512-Crypt under 64 bit systems.
    * Comes pre-configured with strong rounds settings.

    For applications which want to quickly add a password hash,
    all they need to do is the following::

        >>> #import the context under an app-specific name (so it can easily be replaced later)
        >>> from passlib.apps import custom_app_context as pwd_context

        >>> #encrypting a password...
        >>> hash = pwd_context.encrypt("somepass")

        >>> #verifying a password...
        >>> ok = pwd_context.verify("somepass", hash)

        >>> #[optional] encrypting a password for an admin account - uses stronger settings
        >>> hash = pwd_context.encrypt("somepass", category="admin")

.. seealso::

    The :doc:`/new_app_quickstart`.

.. index:: django; crypt context

Django
======
.. data:: django_context

    This object provides a pre-configured :class:`!CryptContext` instance
    for handling `Django <http://www.djangoproject.com>`_
    password hashes, as used by Django's ``django.contrib.auth`` module.
    It recognizes all the :doc:`builtin Django hashes <passlib.hash.django_std>`.
    It defaults to using the :class:`~passlib.hash.django_salted_sha1` hash.
    
.. _ldap-contexts:

LDAP
====
Passlib provides two contexts related to ldap hashes:

.. data:: ldap_context

    This object provides a pre-configured :class:`!CryptContext` instance
    for handling LDAPv2 password hashes. It recognizes all
    the :ref:`standard ldap hashes <standard-ldap-hashes>`.

    It defaults to using the ``{SSHA}`` password hash.
    For times when there should be another default, using code such as the following::

        >>> from passlib.apps import ldap_context
        >>> ldap_context = ldap_context.replace(default="ldap_salted_md5")

        >>> #the new context object will now default to {SMD5}:
        >>> ldap_context.encrypt("password")
        '{SMD5}T9f89F591P3fFh1jz/YtW4aWD5s='

.. data:: ldap_nocrypt_context

    This object recognizes all the standard ldap schemes that :data:`!ldap_context`
    does, *except* for the ``{CRYPT}``-based schemes.

.. index:: mysql; crypt context

.. _mysql-contexts:

MySQL
=====
This module provides two pre-configured :class:`!CryptContext` instances
for handling MySQL user passwords:

.. data:: mysql_context

    This object should recognize the new :class:`~passlib.hash.mysql41` hashes,
    as well as any legacy :class:`~passlib.hash.mysql323` hashes.

    It defaults to mysql41 when generating new hashes.

    This should be used with MySQL version 4.1 and newer.

.. data:: mysql3_context

    This object is for use with older MySQL deploys which only recognize
    the :class:`~passlib.hash.mysql323` hash.

    This should be used only with MySQL version 3.2.3 - 4.0.

.. index:: drupal; crypt context, wordpress; crypt context, phpbb3; crypt context, phpass; crypt context

PHPass
======
`PHPass <http://www.openwall.com/phpass/>`_ is a PHP password hashing library,
and hashes derived from it are found in a number of PHP applications.
It is found in a wide range of PHP applications, including Drupal and Wordpress.

.. data:: phpass_context

    This object following the standard PHPass logic:
    it supports :class:`~passlib.hash.bcrypt`, :class:`~passlib.hash.bsdi_crypt`,
    and implements an custom scheme called the "phpass portable hash" :class:`~passlib.hash.phpass` as a fallback.

    BCrypt is used as the default if support is available,
    otherwise the Portable Hash will be used as the default.

    .. versionchanged:: 1.5
        Now uses Portable Hash as fallback if BCrypt isn't available.
        Previously used BSDI-Crypt as fallback
        (per original PHPass implementation),
        but it was decided PHPass is in fact more secure.

.. data:: phpbb3_context

    This object supports phpbb3 password hashes, which use a variant of :class:`~passlib.hash.phpass`.

.. index:: postgres; crypt context

PostgreSQL
==========
.. data:: postgres_context

    This object should recognize password hashes stores in PostgreSQL's ``pg_shadow`` table;
    which are all assumed to follow the :class:`~passlib.hash.postgres_md5` format.

    Note that the username must be provided whenever encrypting or verifying a postgres hash::

        >>> from passlib.apps import postgres_context

        >>> #encrypting a password...
        >>> postgres_context.encrypt("somepass", user="dbadmin")
        'md578ed0f0ab2be0386645c1b74282917e7'

        >>> #verifying a password...
        >>> postgres_context.verify("somepass", 'md578ed0f0ab2be0386645c1b74282917e7', user="dbadmin")
        True
        >>> postgres_context.verify("wrongpass", 'md578ed0f0ab2be0386645c1b74282917e7', user="dbadmin")
        False

.. index:: roundup; crypt context

Roundup
=======
The `Roundup Issue Tracker <http://www.roundup-tracker.org>`_ has long
supported a series of different methods for encoding passwords.
The following contexts are available for reading Roundup password hash fields:

.. data:: roundup10_context

    This object should recognize all password hashes used by Roundup 1.4.16 and earlier:
    :class:`~passlib.hash.ldap_hex_sha1` (the default),
    :class:`~passlib.hash.ldap_hex_md5`, :class:`~passlib.hash.ldap_des_crypt`,
    and :class:`~passlib.hash.roundup_plaintext`.

.. data:: roundup15_context

    Roundup 1.4.17 adds support for :class:`~passlib.hash.ldap_pbkdf2_sha1`
    as it's preferred hash format.
    This context supports all the :data:`roundup10_context` hashes,
    but adds that hash as well (and uses it as the default).

.. data:: roundup_context

    this is an alias for the latest version-specific roundup context supported
    by passlib, currently the :data:`!roundup15_context`.
