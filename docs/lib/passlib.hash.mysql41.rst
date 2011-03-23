=====================================================================
:class:`passlib.hash.mysql41` - MySQL 4.1 password hash
=====================================================================

.. currentmodule:: passlib.hash

This class implements the second of MySQL's password hash functions,
used to store it's user account passwords. Introduced in MySQL 4.1.1
under the function ``PASSWORD()``, it replaced the previous
algorithm (:class:`~passlib.hash.mysql323`) as the default
used by MySQL, and is still in active use under MySQL 5.

.. warning::

    This algorithm is extremely weak, and should not be used
    for any purposes besides manipulating existing Mysql 4.1+
    password hashes.

Usage
=====
Users will most likely find the frontends provided by :mod:`passlib.apps`
to be more useful than accessing this class directly.
That aside, this class can be used in the same manner
as :class:`~passlib.hash.mysql323`.

Interface
=========
.. autoclass:: mysql41()

Format & Algorithm
==================
A mysql-41 password hash consists of an asterisk ``*`` followed
by 40 hexidecimal digits, directly encoding the 160 bit checksum.
An example hash (of ``password``) is ``*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19``.
MySQL always uses upper-case letters,
and so does PassLib (though PassLib will recognize lower-case letters as well).

The checksum is calculated simply, as the SHA1 hash of the SHA1 hash of the password,
which is then encoded into hexidecimal.

Security Issues
===============
Lacking any sort of salt, and using only 2 rounds
of the common SHA1 message digest, it's not very secure,
and should not be used for *any*
purpose but verifying existing MySQL 4.1+ password hashes.
