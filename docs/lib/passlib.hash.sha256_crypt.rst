==================================================================
:mod:`passlib.drivers.sha256_crypt` - SHA-256 Crypt
==================================================================

.. module:: passlib.drivers.sha526_crypt
    :synopsis: SHA-256 Crypt

This scheme is identical to :mod:`~passlib.drivers.sha512_crypt` in almost every way,
they are defined by the same specification and have the same design and structure,
except the following differences:

* it uses the prefix ``$5$`` where the SHA-512-Crypt uses ``$6$``.
* it uses SHA-256 as it's internal hash function instead of SHA-512.
* it's output hash is correspondingly smaller.

For details about this module, see :mod:`~passlib.drivers.sha512_crypt`.
