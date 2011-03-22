==================================================================
:class:`passlib.hash.unix_fallback` - Unix Fallback Helper
==================================================================

.. currentmodule:: passlib.hash

This class does not provide an encryption scheme,
but instead provides a helper for handling disabled / wildcard
password fields as found in unix ``/etc/shadow`` files.

Usage
=====
This class is mainly useful only for plugging into a :class:`~passlib.context.CryptContext`.
When used, it should always be the last scheme in the list,
as it is designed to provide a fallback behavior.
It can be used directly as follows::

    >>> from passlib.hash import unix_fallback as uf

    >>> #'encrypting' a password always results in "!", the default reject hash.
    >>> uf.encrypt("password")
    '!'

    >>> uf.identify('!') #check if hash is recognized (all hashes are recognized)
    True
    >>> uf.identify('')
    True

    >>> uf.verify("password", "") #verify against empty string - all password allowed
    True
    >>> uf.verify("password", "!") #verify against non-empty string - no passwords allowed
    False

Interface
=========
.. autoclass:: unix_fallback
