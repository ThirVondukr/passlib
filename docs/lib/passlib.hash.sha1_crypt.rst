===================================================================
:mod:`passlib.drivers.sha1_crypt` - SHA-1 Crypt
===================================================================

.. module:: passlib.drivers.sha1_crypt
    :synopsis: SHA-1 Crypt

SHA1-Crypt is a hash algorithm introduced by NetBSD in 2004.
It's based on a variation of the PBKDF1 algorithm,
and supports a large salt and variable number of rounds.

Usage
=====
Supporting a variable sized salt and variable number of rounds,
this scheme is used in exactly the same way as :mod:`~passlib.drivers.sha512_crypt`.

Functions
=========
.. autofunction:: genconfig
.. autofunction:: genhash
.. autofunction:: encrypt
.. autofunction:: identify
.. autofunction:: verify

Format
======
An example hash (of ``password``) is ``$sha1$40000$jtNX3nZ2$hBNaIXkt4wBI2o5rsi8KejSjNqIq``.
An sha1-crypt hash string has the format ``$sha1${rounds}${salt}${checksum}``, where:

* ``$sha1$`` is the prefix used to identify sha1-crypt hashes,
  following the :ref:`modular-crypt-format`

* ``{rounds}`` is the decimal number of rounds to use (40000 in the example).

* ``{salt}`` is 0-64 characters drawn from ``[./0-9A-Za-z]``
  (``jtNX3nZ2`` in the example).

* ``{checksum}`` is 28 characters drawn from the same set, encoding a 168-bit
  checksum. (``hBNaIXkt4wBI2o5rsi8KejSjNqIq/`` in the example).

Algorithm
=========
The checksum is calculated using a modified version of PBKDF1,
replacing it's use of the SHA1 message digest with HMAC-SHA1,
(which does not suffer from the current vulnerabilities that SHA1 itself does,
as well as providing some of the advancements made in PDKDF2).

* first, the HMAC-SHA1 digest of ``{salt}$sha1${rounds}`` is generated,
  using the password as the HMAC-SHA1 key.

* then, for ``rounds-1`` iterations, the previous HMAC-SHA1 digest
  is fed back through HMAC-SHA1, again using the password
  as the HMAC-SHA1 key.

* the checksum is then rendered into hash-64 format
  using an ordering that roughly corresponds to big-endian
  encoding of 24-bit chunks (see :data:`passlib.drivers.sha1_crypt._chk_offsets` for exact byte order).

Deviations
==========
This implementation of sha1-crypt differs from the NetBSD implementation
in a few ways:

* The NetBSD implementation randomly varies the actual number of rounds
  when generating a new configuration string, in order to decrease
  predictability. This feature is provided by PassLib to *all* hashes,
  via the :class:`CryptContext` class, and so it omitted
  from this hash implementation.

* The specification does not specify how to deal with zero-padding
  within the rounds portion of the hash. No existing examples
  or test vectors have zero padding, and allowing it would
  result in multiple encodings for the same configuration / hash.
  To prevent this situation, PassLib will throw an error if the rounds in a hash
  have leading zeros.

* While the underlying algorithm technically allows salt strings
  to contain any possible byte value besides ``\x00`` and ``$``,
  this would conflict with many uses of sha1-crypt, such as within
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
* `<http://mail-index.netbsd.org/tech-userlevel/2004/05/29/0001.html>`_ - description of algorithm
* `<http://fxr.googlebit.com/source/lib/libcrypt/crypt-sha1.c?v=NETBSD-CURRENT>`_ - NetBSD implementation of SHA1-Crypt
* `<http://tools.ietf.org/html/rfc2898>`_ - rfc defining PBKDF1 & PBKDF2
