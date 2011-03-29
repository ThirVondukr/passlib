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

    >>> #check if hash is recognized (all strings are recognized)
    >>> uf.identify('!')
    True
    >>> uf.identify('*')
    True
    >>> uf.identify('')
    True

    >>> #verify against non-empty string - no passwords allowed
    >>> uf.verify("password", "!")
    False

    >>> #verify against empty string:
    >>> #   * by default, no passwords allowed
    >>> #   * all passwords allowed IF enable_wildcard=True
    >>> uf.verify("password", "")
    False
    >>> uf.verify("password", "", enable_wildcard=True)
    True

Interface
=========
.. autoclass:: unix_fallback

Deviations
==========
According to the Linux ``shadow`` man page, an empty string is treated
as a wildcard by Linux, allowing all passwords. For security purposes,
this behavior is not enabled unless specifically requested by the application.
