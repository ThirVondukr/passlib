==================================================================
:class:`passlib.hash.sha256_crypt` - SHA-256 Crypt
==================================================================

.. currentmodule:: passlib.hash

Defined by the same specification as :class:`~passlib.hash.sha512_crypt`,
SHA256-Crypt is identical to SHA512-Crypt in almost every way, including
design and security issues. It's main advantage over SHA512-Crypt is
that it may be faster on 32 bit operating systems.

.. seealso:: :doc:`SHA512-Crypt <passlib.hash.sha512_crypt>`

Usage
=====
This class can be used in exactly the same manner as :class:`~passlib.hash.sha512_crypt`.

Interface
=========
.. autoclass:: sha256_crypt(checksum=None, salt=None, rounds=None, strict=False)

Format & Algorithm
==================
SHA256-Crypt is defined by the same specification as SHA512-Crypt.
The format and algorithm are exactly the same, except for
the following notable differences:

* it uses the :ref:`modular crypt prefix <modular-crypt-format>` ``$5$``, whereas SHA-512-Crypt uses ``$6$``.
* it uses the SHA-256 message digest in place of the SHA-512 message digest.
* it's output hash is correspondingly smaller in size, encoding a 256 bit checksum instead of 512.

See SHA512-Crypt for more details.
