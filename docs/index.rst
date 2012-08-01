==========================================
Passlib |release| documentation
==========================================

Welcome
=======
Passlib is a password hashing library for Python 2 & 3, which provides
cross-platform implementations of over 30 password hashing algorithms, as well
as a framework for managing existing password hashes. It's designed to be useful
for a wide range of tasks, from verifying a hash found in /etc/shadow, to
providing full-strength password hashing for multi-user application.

As a quick sample, the following code hashes and then verifies a password
using the :doc:`SHA256-Crypt </lib/passlib.hash.sha256_crypt>` algorithm::

    >>> # import the hash algorithm
    >>> from passlib.hash import sha256_crypt

    >>> # generate new salt, and hash a password
    >>> hash = sha256_crypt.encrypt("toomanysecrets")
    >>> hash
    '$5$rounds=80000$zvpXD3gCkrt7tw.1$QqeTSolNHEfgryc5oMgiq1o8qCEAcmye3FoMSuvgToC'

    >>> # verifying the password
    >>> sha256_crypt.verify("toomanysecrets", hash)
    True
    >>> sha256_crypt.verify("joshua", hash)
    False

Content Summary
===============

.. rst-class:: floater

.. seealso:: :ref:`What's new in Passlib 1.6 <whats-new>`

Introductory Materials
----------------------

    :doc:`install`
        requirements & installation instructions

    :doc:`overview`
        describes how Passlib is laid out

    :doc:`New Application Quickstart <new_app_quickstart>`
        choosing a password hash for new applications

----

Password Hashing Algorithms
---------------------------
    :mod:`passlib.hash`
        all the password hashes supported by Passlib --
            - :doc:`Overview <lib/passlib.hash>`
            - :ref:`mcf-hashes`
            - :ref:`ldap-hashes`
            - :ref:`database-hashes`
            - :ref:`windows-hashes`
            - :ref:`other-hashes`

    :doc:`PasswordHash interface <password_hash_api>`
        examples & documentation of the common hash interface
        used by all the hash algorithms in Passlib.

CryptContext Objects
--------------------
    :mod:`passlib.context`
        provides the :class:`!CryptContext` class, a flexible container
        for managing and migrating between multiple hash algorithms.

    :mod:`passlib.apps`
        predefined CryptContext objects for managing the hashes used by
        MySQL, PostgreSQL, OpenLDAP, and others applications.

    :mod:`passlib.hosts`
        predefined CryptContext objects for managing the hashes
        found in Linux & BSD "shadow" files.

Application Helpers
-------------------
    :mod:`passlib.apache`
        classes for manipulating Apache's ``htpasswd`` and ``htdigest`` files.

    :mod:`passlib.ext.django`
        Django plugin which monkeypatches support for (almost) any hash in Passlib.

..
    Support Modules
    ---------------
        :mod:`passlib.exc`

            custom warnings and exceptions used by Passlib
    :mod:`passlib.registry`
    :mod:`passlib.utils`

----

Other Documents
---------------
    :doc:`modular_crypt_format`
        reference listing "modular crypt format" support across Unix systems.

    :doc:`Changelog <history>`
        Passlib's release history

Online Resources
================

    ================ ===================================================
    Homepage:        `<http://passlib.googlecode.com>`_
    Online Docs:     `<http://packages.python.org/passlib>`_
    Discussion:      `<http://groups.google.com/group/passlib-users>`_
    ---------------- ---------------------------------------------------
    ---------------- ---------------------------------------------------
    PyPI:            `<http://pypi.python.org/pypi/passlib>`_
    Downloads:       `<http://code.google.com/p/passlib/downloads>`_
    Source:          `<http://code.google.com/p/passlib/source>`_
    ================ ===================================================
