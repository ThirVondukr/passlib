========================================================
:mod:`passlib.utils.md4` - MD4 message digest algorithm
========================================================

.. module:: passlib.utils.md4
    :synopsis: MD4 message digest algorithm

.. warning::

    This digest is considered **VERY INSECURE**,
    and not suitable for any new cryptographic activities.
    Trivial-cost real-world attacks exist for all
    password algorithms, stream ciphers, etc, that have
    been based on MD4.
    Do not use this hash or derived schemes unless you *really* have to.

This module implements the MD4 hash algorithm in pure python,
based on the `rfc 1320 <http://www.faqs.org/rfcs/rfc1320.html>`_ specification of MD4.

.. autoclass:: md4

.. note::

    If MD4 support is detected in :mod:`!hashlib`, the :class:`!md4` class in this module
    will be replaced by a function wrapping :mod:`!hashlib`'s implementation,
    which should be faster, but otherwise behave exactly the same.
