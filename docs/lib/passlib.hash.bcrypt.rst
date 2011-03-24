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

Interface
=========
.. autoclass:: bcrypt

Format & Algorithm
==================
Bcrypt is compatible with the :ref:`modular-crypt-format`, and uses ``$2$`` and ``$2a$`` as the identifying prefix
for all it's strings (``$2$`` is seen only for legacy hashes which used an older version of Bcrypt).
An example hash (of ``password``) is ``$2a$12$GhvMmNVjRW29ulnudl.LbuAnUtN/LRfe1JsBm1Xu6LE3059z5Tr8m``.
Bcrypt hashes have the format :samp:`$2a${rounds}${salt}{checksum}`, where:

* :samp:`{rounds}` is the cost parameter, encoded as 2 zero-padded decimal digits,
  which determines the number of iterations used via :samp:`{iterations}=2**{rounds}` (rounds is 12 in the example).
* :samp:`{salt}` is the 22 character salt string, using the characters in the regexp range ``[./A-Za-z0-9]`` (``GhvMmNVjRW29ulnudl.Lbu`` in the example).
* :samp:`{checksum}` is the 31 character checksum, using the same characters as the salt (``AnUtN/LRfe1JsBm1Xu6LE3059z5Tr8m`` in the example).

BCrypt's algorithm is described in detail in it's specification document [#f1]_.

Deviations
==========
This implementation of bcrypt differs from others in a few ways:

* Restricted salt string character set:

  BCrypt does not specify what the behavior should be when
  passed a salt string outside of the regexp range ``[./A-Za-z0-9]``.
  In order to avoid this situtation, PassLib strictly limits salts to the
  allowed character set, and will throw a ValueError if an invalid
  salt character is encountered.

* Unicode Policy:

  The underlying algorithm takes in a password specified
  as a series of non-null bytes, and does not specify what encoding
  should be used; though a ``us-ascii`` compatible encoding
  is implied by nearly all implementations of bcrypt
  as well as all known reference hashes.

  In order to provide support for unicode strings,
  PassLib will encode unicode passwords using ``utf-8``
  before running them through bcrypt. If a different
  encoding is desired by an application, the password should be encoded
  before handing it to PassLib.

References
==========
.. [#f1] `<http://www.usenix.org/event/usenix99/provos/provos_html/>`_ - the bcrypt format specification
