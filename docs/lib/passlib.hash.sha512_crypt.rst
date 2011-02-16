===================================================================
:mod:`passlib.drivers.sha512_crypt` - SHA-512 Crypt 
===================================================================

.. module:: passlib.drivers.sha512_crypt
    :synopsis: SHA-512 Crypt

SHA-512 Crypt and SHA-256 Crypt were developed as a response
to :mod:`~passlib.drivers.bcrypt`. They are descendants of :mod:`~passlib.drivers.md5_crypt`,
and incorporate many changes: replaced MD5 with newer message digest algorithms,
some internal cleanups in MD5-Crypt's rounds algorithm,
and the introduction of a variable rounds parameter.
SHA-512 Crypt is currently the default password hash for many systems
(notably Linux), and has no known weaknesses.

Usage
=====

.. todo::

    write usage instructions

Functions
=========
.. autofunction:: genconfig
.. autofunction:: genhash
.. autofunction:: encrypt
.. autofunction:: identify
.. autofunction:: verify

Format & Algorithm
==================
An example hash (of ``password``) is:

    ``$6$rounds=40000$JvTuqzqw9bQ8iBl6$SxklIkW4gz00LvuOsKRCfNEllLciOqY/FSAwODHon45YTJEozmy.QAWiyVpuiq7XMTUMWbIWWEuQytdHkigcN/``.

An sha512-crypt hash string has the format ``$6$rounds={rounds}${salt}${checksum}``, where:

* ``$6$`` is the prefix used to identify sha512-crypt hashes,
  following the :ref:`modular-crypt-format`

* ``{rounds}`` is the decimal number of rounds to use (40000 in the example).

* ``{salt}`` is 0-16 characters drawn from ``[./0-9A-Za-z]``, providing a
  96-bit salt (``JvTuqzqw9bQ8iBl6`` in the example).

* ``{checksum}`` is 86 characters drawn from the same set, encoding a 512-bit
  checksum.

  (``SxklIkW4gz00LvuOsKRCfNEllLciOqY/FSAwODHon45YTJEozmy.QAWiyVpuiq7XMTUMWbIWWEuQytdHkigcN/`` in the example).

There is also an alternate format ``$6${salt}${checksum}``,
which can be used when the rounds parameter is equal to 5000.

The algorithm used by SHA512-Crypt is laid out in detail
in the specification document linked to below.

Deviations
==========
This implementation of sha512-crypt differs from the specification,
and other implementations, in a few ways:

* The specification does not specify how to deal with zero-padding
  within the rounds portion of the hash. No existing examples
  or test vectors have zero padding, and allowing it would
  result in multiple encodings for the same configuration / hash.
  To prevent this situation, PassLib will throw an error if the rounds in a hash
  have leading zeros.

* While the underlying algorithm technically allows salt strings
  to contain any possible byte value besides ``\x00`` and ``$``,
  this would conflict with many uses of sha512-crypt, such as within
  unix ``/etc/shadow`` files. Futhermore, most unix systems
  will only generate salts using the standard 64 characters listed above.
  This implementation follows along with that, by strictly limiting
  salt strings to the least common denominator, ``[./0-9A-Za-z]``.

* Before generating a hash, PassLib encodes unicode passwords using UTF-8.
  While the algorithm accepts passwords containing any 8-bit value
  except for ``\x00``, it specifies no preference for encodings,
  or for handling unicode strings.

References
==========
* `sha-crypt specification <http://www.akkadia.org/drepper/sha-crypt.html>`_ - Ulrich Drepper's SHA-256/512-Crypt specification, reference implementation, and test vectors
