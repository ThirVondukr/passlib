===================================================================
:class:`passlib.hash.sha512_crypt` - SHA-512 Crypt
===================================================================

.. currentmodule:: passlib.hash

SHA-512 Crypt and SHA-256 Crypt were developed in 2008 by Ulrich Drepper [#f1]_
as a successor to :class:`~passlib.hash.md5_crypt`. They include fixes
and advancements such as variable rounds, and use of NIST-approved cryptographic primitives.
SHA-256 / SHA-512 Crypt are currently the default password hash for many systems
(notably Linux), and have no known weaknesses.
SHA-512 Crypt is one of the three hashes Passlib :ref:`recommends <recommended-hashes>`
for new applications.

Usage
=====
This class can be used directly as follows::

    >>> from passlib.hash import sha512_crypt as sc

    >>> #generate new salt, encrypt password
    >>> h = sc.encrypt("password")
    >>> h
    '$6$rounds=40000$xCsOXRqPPk5AGDFu$o5eyqxEoOSq0dLRFbPxEHp5Jc1vFVj47BNT.h9gmjSHXDS15mjIM.GSUaT5r6Z.Xa1Akrv4FAgKJE3EfbkJxs1'

    >>> #same, but with explict number of rounds
    >>> sc.encrypt("password", rounds=10000)
    '$6$rounds=10000$QWT8AlDMYRms7vSx$.1267Pg6Opn9CblFndtBJ2Q0AI0fcI2IX93zX3gi1Qse./j.VlKYX59NIUlbs0A66wCbfu/vra9wMv2uwTZAI.'

    >>> #check if hash is recognized
    >>> sc.identify(h)
    True
    >>> #check if some other hash is recognized
    >>> sc.identify('$1$3azHgidD$SrJPt7B.9rekpmwJwtON31')
    False

    >>> #verify correct password
    >>> sc.verify("password", h)
    True
    >>> sc.verify("secret", h) #verify incorrect password
    False

Interface
=========
.. autoclass:: sha512_crypt(checksum=None, salt=None, rounds=None, strict=False)

Format & Algorithm
==================
An example sha512-crypt hash (of the string ``password``) is:

    ``$6$rounds=40000$JvTuqzqw9bQ8iBl6$SxklIkW4gz00LvuOsKRCfNEllLciOqY/FSAwODHon45YTJEozmy.QAWiyVpuiq7XMTUMWbIWWEuQytdHkigcN/``.

An sha512-crypt hash string has the format :samp:`$6$rounds={rounds}${salt}${checksum}`, where:

* ``$6$`` is the prefix used to identify sha512-crypt hashes,
  following the :ref:`modular-crypt-format`

* :samp:`{rounds}` is the decimal number of rounds to use (40000 in the example).

* :samp:`{salt}` is 0-16 characters drawn from ``[./0-9A-Za-z]``, providing a
  96-bit salt (``JvTuqzqw9bQ8iBl6`` in the example).

* :samp:`{checksum}` is 86 characters drawn from the same set, encoding a 512-bit
  checksum.

  (``SxklIkW4gz00LvuOsKRCfNEllLciOqY/FSAwODHon45YTJEozmy.QAWiyVpuiq7XMTUMWbIWWEuQytdHkigcN/`` in the example).

There is also an alternate format :samp:`$6${salt}${checksum}`,
which can be used when the rounds parameter is equal to 5000
(see the ``implicit_rounds`` parameter above).

The algorithm used by SHA512-Crypt is laid out in detail
in the specification document linked to below [#f1]_.

Deviations
==========
This implementation of sha512-crypt differs from the specification,
and other implementations, in a few ways:

* Zero-Padded Rounds:

  The specification does not specify how to deal with zero-padding
  within the rounds portion of the hash. No existing examples
  or test vectors have zero padding, and allowing it would
  result in multiple encodings for the same configuration / hash.
  To prevent this situation, PassLib will throw an error if the rounds
  parameter in a hash has leading zeros.

* Restricted salt string character set:

  The underlying algorithm can unambigously handle salt strings
  which contain any possible byte value besides ``\x00`` and ``$``.
  However, PassLib strictly limits salts to the
  :mod:`hash 64 <passlib.utils.h64>` character set,
  as nearly all implementations of sha512-crypt generate
  and expect salts containing those characters,
  but may have unexpected behaviors for other character values.

* Unicode Policy:

  The underlying algorithm takes in a password specified
  as a series of non-null bytes, and does not specify what encoding
  should be used; though a ``us-ascii`` compatible encoding
  is implied by nearly all implementations of sha512-crypt
  as well as all known reference hashes.

  In order to provide support for unicode strings,
  PassLib will encode unicode passwords using ``utf-8``
  before running them through sha512-crypt. If a different
  encoding is desired by an application, the password should be encoded
  before handing it to PassLib.

.. rubric:: Footnotes

.. [#f1] Ulrich Drepper's SHA-256/512-Crypt specification, reference implementation, and test vectors - `sha-crypt specification <http://www.akkadia.org/drepper/sha-crypt.html>`_
