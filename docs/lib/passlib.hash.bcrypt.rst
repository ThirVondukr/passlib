==================================================================
:class:`passlib.hash.bcrypt` - BCrypt
==================================================================

.. currentmodule:: passlib.hash

BCrypt was developed to replace :class:`~passlib.hash.md5_crypt` for BSD systems.
It uses a modified version of the Blowfish stream cipher. Featuring
a large salt and variable number of rounds, it's currently the default
password hash for many systems (notably BSD), and has no known weaknesses.

.. note::

    It is strongly recommended to install PyBcrypt if this algorithm
    is going to be used.

Usage
=====

.. todo::

    write usage instructions

Functions
=========
.. autoclass:: bcrypt

Format & Algorithm
==================
Bcrypt is compatible with the :ref:`modular-crypt-format`, and uses ``$2$`` and ``$2a$`` as the identifying prefix
for all it's strings (``$2$`` is seen only for legacy hashes which used an older version of Bcrypt).
An example hash (of ``password``) is ``$2a$12$GhvMmNVjRW29ulnudl.LbuAnUtN/LRfe1JsBm1Xu6LE3059z5Tr8m``.
Bcrypt hashes have the format ``$2a${cost}${salt}{checksum}``, where:

* ``{cost}`` is the cost parameter, encoded as 2 zero-padded decimal digits,
  which determines the number of rounds used via ``rounds=2**cost`` (cost is 12 in the example).
* ``{salt}`` is the 22 character salt string, using the characters ``[./A-Za-z0-9]`` (``GhvMmNVjRW29ulnudl.Lbu`` in the example).
* ``{checksum}`` is the 31 character checksum, using the same characters as the salt (``AnUtN/LRfe1JsBm1Xu6LE3059z5Tr8m`` in the example).

BCrypt's algorithm is described in detail in it's specification document,
listed below.

Deviations
==========
This implementation of bcrypt differs from others in a few ways:

* The bcrypt specification (and implementations) have no predefined
  or predictable behavior when passed a salt containing characters
  outside of the base64 range. To avoid this situtation,
  PassLib will simply throw an error if invalid characters
  are provided for the salt.

* Before generating a hash, PassLib encodes unicode passwords using UTF-8.
  While the algorithm accepts passwords containing any 8-bit value
  except for ``\x00``, it specifies no preference for encodings,
  or for handling unicode strings.

References
==========
* `<http://www.usenix.org/event/usenix99/provos/provos_html/>`_ - the bcrypt format specification
* `<http://www.mindrot.org/projects/jBCrypt/>`_ - java implementation used as reference for PassLib
