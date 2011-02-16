==================================================================
:mod:`passlib.drivers.nthash` - Windows NT-HASH for Unix
==================================================================

.. module:: passlib.drivers.nthash
    :synopsis: Windows NT-HASH for Unix

.. warning::

    This scheme is notoriously weak (since it's based on :mod:`~passlib.utils.md4`).
    Online tables exist for quickly performing pre-image attacks on this scheme.
    **Do not use** in new code. Stop using in old code if possible.

This module implements the Windows NT-HASH algorithm,
encoded in a manner compatible with the :ref:`modular-crypt-format`.
It is found on some unix systems where the administrator has decided
to store user passwords in a manner compatible with the SMB/CIFS protocol.
It has no salt, or variable rounds.

Usage
=====

.. todo::

    document usage

Functions
=========
.. autofunction:: genconfig
.. autofunction:: genhash
.. autofunction:: encrypt
.. autofunction:: identify
.. autofunction:: verify

In addition to the normal password hash api, this module also exposes
the following method:

.. function:: raw_nthash(secret, hex=False)

    perform raw nthash calculation, returning either
    raw digest, or as lower-case hexidecimal characters.

Format & Algorithm
==================
A nthash encoded for crypt consists of ``$3$${checksum}`` or
``$NT${checksum}``; where ``{checksum}`` is 32 hexidecimal digits
encoding the checksum. An example hash (of ``password``) is ``$3$$8846f7eaee8fb117ad06bdd830b7586c``.

The checksum is simply the :mod:`~passlib.utils.md4` digest
of the secret using the ``UTF16-LE`` encoding, encoded in hexidecimal
