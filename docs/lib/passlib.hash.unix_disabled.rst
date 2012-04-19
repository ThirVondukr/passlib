==================================================================
:class:`passlib.hash.unix_disabled` - Unix Disabled Account Helper
==================================================================

.. currentmodule:: passlib.hash

This class does not provide an encryption scheme,
but instead provides a helper for handling disabled
password fields as found in unix ``/etc/shadow`` files.

Usage
=====
This class is mainly useful only for plugging into a
:class:`~passlib.context.CryptContext` instance.
It can be used directly as follows::

    >>> from passlib.hash import unix_disabled as ud

    >>> # 'encrypting' a password always results in "!" or "*"
    >>> ud.encrypt("password")
    '!'

    >>> # verifying will fail for all passwords and hashes
    >>> ud.verify("password", "!")
    False
    >>> ud.verify("letmein", "*NOPASSWORD*")
    False

    >>> # all strings are recognized - if used in conjunction with other hashes,
    >>> # this should be the last one checked.
    >>> ud.identify('!')
    True
    >>> ud.identify('*')
    True
    >>> ud.identify('')
    True


Interface
=========
.. autoclass:: unix_disabled

Deviations
==========
According to the Linux ``shadow`` man page, an empty string is treated
as a wildcard by Linux, allowing all passwords. For security purposes,
this behavior is NOT supported; empty strings are treated the same as ``!``.
