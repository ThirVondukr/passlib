========================================================================
:class:`passlib.hash.mysql323` - MySQL 3.2.3 password hash
========================================================================

.. currentmodule:: passlib.hash


This class implements the first of MySQL's password hash functions,
used to store it's user account passwords. Introduced in MySQL 3.2.3
under the function ``PASSWORD()``, this function was renamed
to ``OLD_PASSWORD()`` under MySQL 4.1, when a newer password
hash algorithm was introduced (see :class:`~passlib.hash.mysql41`).

.. warning::

    This algorithm is extremely weak, and should not be used
    for any purposes besides manipulating existing Mysql 3.2.3-4.0
    password hashes.

Usage
=====
Users will most likely find the frontends provided by :mod:`passlib.apps`
to be more useful than accessing this class directly.
That aside, this class can be used as follows::

    >>> from passlib.hash import mysql323 as mold

    >>> mold.encrypt("password") #encrypt password
    '5d2e19393cc5ef67'

    >>> mold.identify('5d2e19393cc5ef67') #check if hash is recognized
    True
    >>> mold.identify('$1$3azHgidD$SrJPt7B.9rekpmwJwtON31') #check if another type of hash is recognized
    False

    >>> mold.verify("password", '5d2e19393cc5ef67') #verify correct password
    True
    >>> mold.verify("secret", '5d2e19393cc5ef67') #verify incorrect password
    False

Interface
=========
.. autoclass:: mysql323()

Format & Algorithm
==================
A mysql-323 password hash consists of 16 hexidecimal digits,
directly encoding the 64 bit checksum. MySQL always uses
lower-case letters, and so does PassLib
(though PassLib will recognize upper case letters as well).

The algorithm used is extremely simplistic, for details,
see the source implementation linked to below [#f1]_.

Security Issues
===============
Lacking any sort of salt, ignoring all whitespace,
and having a simplistic algorithm amounts to little more than a checksum,
this is not secure, and should not be used for *any* purpose but verifying existing MySQL 3.2.3 - 4.0 password hashes.

References
==========
.. [#f1] Source of implementation used by passlib -
         `<http://djangosnippets.org/snippets/1508/>`_

.. [#f2] Mysql document describing transition -
         `<http://dev.mysql.com/doc/refman/4.1/en/password-hashing.html>`_
