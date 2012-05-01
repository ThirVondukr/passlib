==================================================================
:class:`passlib.hash.sha256_crypt` - SHA-256 Crypt
==================================================================

.. currentmodule:: passlib.hash

SHA-256 Crypt and SHA-512 Crypt were developed in 2008 by Ulrich Drepper [#f1]_,
designed as the successor to :class:`~passlib.hash.md5_crypt`.
They include fixes and advancements such as variable rounds, and use of NIST-approved cryptographic primitives.
The design involves repeated composition of the underlying digest algorithm,
using various arbitrary permutations of inputs.
SHA-512 / SHA-256 Crypt are currently the default password hash for many systems
(notably Linux), and have no known weaknesses.
SHA-256 Crypt is one of the three hashes Passlib :ref:`recommends <recommended-hashes>`
for new applications.
This class can be used directly as follows::

    >>> from passlib.hash import sha256_crypt

    >>> # generate new salt, encrypt password
    >>> hash = sha256_crypt.encrypt("password")
    >>> hash
    '$5$rounds=80000$wnsT7Yr92oJoP28r$cKhJImk5mfuSKV9b3mumNzlbstFUplKtQXXMo4G6Ep5'

    >>> # same, but with explict number of rounds
    >>> sha256_crypt.encrypt("password", rounds=12345)
    '$5$rounds=12345$q3hvJE5mn5jKRsW.$BbbYTFiaImz9rTy03GGi.Jf9YY5bmxN0LU3p3uI1iUB'

    >>> # verify password
    >>> sha256_crypt.verify("password", hash)
    True
    >>> sha256_crypt.verify("letmein", hash)
    False

.. seealso::

    * :ref:`password hash usage <password-hash-examples>` -- for more usage examples

    * :doc:`sha512_crypt <passlib.hash.sha512_crypt>` -- the companion 512-bit version of this hash.

Interface
=========
.. autoclass:: sha256_crypt()

.. note::

    This class will use the first available of two possible backends:

    * stdlib :func:`crypt()`, if the host OS supports SHA256-Crypt (most Linux systems).
    * a pure python implementation of SHA256-Crypt built into Passlib.

    You can see which backend is in use by calling the :meth:`get_backend()` method.

Format & Algorithm
==================
An example sha256-crypt hash (of the string ``password``) is:

    ``$5$rounds=80000$wnsT7Yr92oJoP28r$cKhJImk5mfuSKV9b3mumNzlbstFUplKtQXXMo4G6Ep5``

An sha256-crypt hash string has the format :samp:`$5$rounds={rounds}${salt}${checksum}`, where:

* ``$5$`` is the prefix used to identify sha256-crypt hashes,
  following the :ref:`modular-crypt-format`

* :samp:`{rounds}` is the decimal number of rounds to use (80000 in the example).

* :samp:`{salt}` is 0-16 characters drawn from ``[./0-9A-Za-z]``, providing a
  96-bit salt (``wnsT7Yr92oJoP28r`` in the example).

* :samp:`{checksum}` is 43 characters drawn from the same set, encoding a 256-bit
  checksum (``cKhJImk5mfuSKV9b3mumNzlbstFUplKtQXXMo4G6Ep5`` in the example).

There is also an alternate format :samp:`$5${salt}${checksum}`,
which can be used when the rounds parameter is equal to 5000
(see the ``implicit_rounds`` parameter above).

The algorithm used by SHA256-Crypt is laid out in detail
in the specification document linked to below [#f1]_.

Deviations
==========
This implementation of sha256-crypt differs from the specification,
and other implementations, in a few ways:

* Zero-Padded Rounds:

  The specification does not specify how to deal with zero-padding
  within the rounds portion of the hash. No existing examples
  or test vectors have zero padding, and allowing it would
  result in multiple encodings for the same configuration / hash.
  To prevent this situation, Passlib will throw an error if the rounds
  parameter in a hash has leading zeros.

* Restricted salt string character set:

  The underlying algorithm can unambigously handle salt strings
  which contain any possible byte value besides ``\x00`` and ``$``.
  However, Passlib strictly limits salts to the
  :data:`hash64 <passlib.utils.HASH64_CHARS>` character set,
  as nearly all implementations of sha256-crypt generate
  and expect salts containing those characters,
  but may have unexpected behaviors for other character values.

* Unicode Policy:

  The underlying algorithm takes in a password specified
  as a series of non-null bytes, and does not specify what encoding
  should be used; though a ``us-ascii`` compatible encoding
  is implied by nearly all implementations of sha256-crypt
  as well as all known reference hashes.

  In order to provide support for unicode strings,
  Passlib will encode unicode passwords using ``utf-8``
  before running them through sha256-crypt. If a different
  encoding is desired by an application, the password should be encoded
  before handing it to Passlib.

.. rubric:: Footnotes

.. [#f1] Ulrich Drepper's SHA-256/512-Crypt specification, reference
   implementation, and test vectors -
   `sha-crypt specification <http://www.akkadia.org/drepper/sha-crypt.html>`_
