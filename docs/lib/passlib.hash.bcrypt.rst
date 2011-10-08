==================================================================
:class:`passlib.hash.bcrypt` - BCrypt
==================================================================

.. currentmodule:: passlib.hash

BCrypt was developed to replace :class:`~passlib.hash.md5_crypt` for BSD systems.
It uses a modified version of the Blowfish stream cipher. Featuring
a large salt and variable number of rounds, it's currently the default
password hash for many systems (notably BSD), and has no known weaknesses.
It is one of the three hashes Passlib :ref:`recommends <recommended-hashes>`
for new applications.

.. note::

    It is strongly recommended to install
    :ref:`PyBcrypt or BCryptor <optional-libraries>`
    if this algorithm is going to be used.

Usage
=====
This class can be used directly as follows::

    >>> from passlib.hash import bcrypt

    >>> #generate new salt, encrypt password
    >>> h = bcrypt.encrypt("password")
    >>> h
    '$2a$12$NT0I31Sa7ihGEWpka9ASYrEFkhuTNeBQ2xfZskIiiJeyFXhRgS.Sy'

    >>> #same, but with explict number of rounds
    >>> bcrypt.encrypt("password", rounds=8)
    '$2a$08$8wmNsdCH.M21f.LSBSnYjQrZ9l1EmtBc9uNPGL.9l75YE8D8FlnZC'

    >>> #check if hash is a bcrypt hash
    >>> bcrypt.identify(h)
    True
    >>> #check if some other hash is recognized
    >>> bcrypt.identify('$1$3azHgidD$SrJPt7B.9rekpmwJwtON31')
    False

    >>> #verify correct password
    >>> bcrypt.verify("password", h)
    True
    >>> #verify incorrect password
    >>> bcrypt.verify("wrong", h)
    False

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

* Padding Bits

  BCrypt's base64 encoding results in the last character of the salt
  encoding only 2 bits of data, the remaining 4 are "padding" bits.
  Similarly, the last character of the digest contains 4 bits of data,
  and 2 padding bits. Because of the way they are coded, many BCrypt implementations
  will reject all passwords if these padding bits are not set to 0.
  Due to a legacy issue with Passlib <= 1.5.2,
  Passlib instead prints a warning if it encounters hashes with any padding bits set,
  and will then validate them correctly. 
  (This behavior will eventually be deprecated and such hashes
  will throw a :exc:`ValueError` instead).

.. rubric:: Footnotes

.. [#f1] `<http://www.usenix.org/event/usenix99/provos/provos_html/>`_ - the bcrypt format specification
