=============================================================
:mod:`passlib.crypto.digest` - Hash & Related Helpers
=============================================================

.. module:: passlib.crypto.digest
    :synopsis: Internal cryptographic helpers

.. versionadded:: 1.7

This module provides various cryptographic support functions used by Passlib
to implement the various password hashes it provides, as well as paper over
some VM & version incompatibilities.

Hash Functions
==============
.. autofunction:: norm_hash_name
.. autofunction:: lookup_hash

.. autoclass:: HashInfo()

.. note::

    :func:`!lookup_hash` supports all hashes available directly in :mod:`hashlib`,
    as well as offered through :func:`hashlib.new`.
    It will also fallback to passlib's builtin MD4 implementation if one is not natively available.

HMAC Functions
==============

.. autofunction:: compile_hmac

PKCS#5 Key Derivation Functions
===============================
.. autofunction:: pbkdf1
.. autofunction:: pbkdf2_hmac

.. note::

    The details of PBKDF1 and PBKDF2 are specified in :rfc:`2898`.
