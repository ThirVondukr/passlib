===============================================================
:mod:`passlib.hash.sun_md5_crypt` - Sun MD5 Crypt password hash
===============================================================

.. module:: passlib.hash.sun_md5_crypt
    :synopsis: Sun MD5 Crypt

.. warning::

    This implementation has not been compared
    very carefully against any existing implementations,
    and it's behavior may not match under various border cases.
    It should not be relied on for anything but novelty purposes
    for the time being.

This algorithm is used by Solaris, as a replacement for the aging des-crypt.
It is mainly used on later versions of Solaris, and is not found many other
places. While based on the MD5 message digest, it has very little at all
in common with the :mod:`~passlib.hash.md5_crypt` algorithm. It supports
32 bit variable rounds and an 8 character salt. Due to a theoretic pre-image
attacks on the MD5 message digest, this algorithm should probably not
be used in new deploys.

Usage
=====
This module supports both rounds and salts,
and so can be used in the exact same manner
as :mod:`~passlib.hash.sha512_crypt`.

Functions
=========
.. autofunction:: genconfig
.. autofunction:: genhash
.. autofunction:: encrypt
.. autofunction:: identify
.. autofunction:: verify

Format
======
An example hash (of ``passwd``) is ``$md5,rounds=5000$GUBv0xjJ$mSwgIswdjlTY0YxV7HBVm0``.
A sun-md5-crypt hash string has the format ``$md5,rounds={rounds}${salt}${checksum}``, where:

* ``$md5,`` is the prefix used to identify the hash.
* ``{rounds}`` is the decimal number of rounds to use (5000 in the example).
* ``{salt}`` is 0-8 salt characters drawn from ``[./0-9A-Za-z]`` (``GUBv0xjJ`` in the example).
* ``{checksum}`` is 22 characters drawn from the same set,
  encoding a 128-bit checksum (``mSwgIswdjlTY0YxV7HBVm0`` in the example).

An alternate format, ``$md5${salt}${checksum}`` is used when the rounds value is 0.

.. note::
    Solaris seems to deviate from the :ref:`modular-crypt-format` in that
    it considers ``$`` *or* ``,`` to indicate the end of the identifier.

.. warning::

    One of the remaining issues with this implementation is that some
    existing sun-md5-crypt hashes found on the web use a ``$`` in place of the ``,``.
    It is unclear whether this is an accepted alternate format or just a typo,
    nor whether this is supposed to affect the checksum in the resulting hash string.

Algorithm
=========
The algorithm used is based around the MD5 message digest and the "Muffett Coin Toss" algorithm (so named
by one of the creators). Given a password, the number of rounds, and a salt...

* an initial MD5 digest is created from the concatentation of the password,
  and the configuration string (using the format ``$md5,rounds={rounds}${salt}``).

* for rounds+4096 iterations, a new digest is created:
    - ``MuffetCoinToss(rounds, previous digest)`` is called, resulting in a 0 or 1.
    - if a 1, the next digest is the MD5 of: the last digest concatenated with a constant
      data string, along with the current iteration number as an ascii string.
    - if a 0, the same as 1, except that magic constant data is not included.

* The final checksum is then encoded into :mod:`hash64 <~passlib.hash.h64>` using the same
  transposed byte order that :mod:`~passlib.hash.md5_crypt` uses.

The constant data string is referenced above is a 1517 byte ascii string... an excerpt from Hamlet,
starting with ``To be, or not to be...`` and ending with ``...all my sins remember'd.\n``,
with a null character appended (exact Project Gutenberg source linked to below).

.. warning::

    Note that this has a weakness in that the per-round operation appends data
    which is known to the attacker, the coin flip algorithm only serves to
    frustrate brute-force attacks. Reversing this hash is dependant
    on MD5's general pre-image attack resistance (which is currently theoretically vulnerable).

Muffer Coin Toss
----------------
The Muffet Coin Toss algorithm is as follows:
Given the current round number, and a 16 byte MD5 digest, it returns a 0 or 1,
using the following formula:

.. note::

    All references below to a specific bit of the digest should be interpreted mod 128.
    All references below to a specific byte of the digest should be interpreted mod 16.

the coinflip generates two 8 bit integers ``X`` & ``Y`` as follows:

* ``X`` is generated from the following formula:

  for each ``i`` in 0..7 inclusive:

    - let ``A`` be the ``i``'th byte of the digest, as an 8-bit int.
    - let ``B`` be the ``i+3``'th byte of the digest, as an 8-bit int.

    - let ``R`` be ``A`` shifted right by ``B % 5`` bits.

    - let ``V`` be the ``R``'th byte of the digest.
    - if the ``A % 8``'th bit of ``B`` is 1, divide ``V`` by 2.

    - use the ``V``'th bit of the digest as the ``i``'th bit of ``X``.

* ``Y`` is generated exactly the same as ``X``, except that
  ``A`` is the ``i+8``'th byte of the digest,
  and ``B`` is the ``i+11``'th byte of the digest.

* if bit ``round`` of the digest is 1, ``X`` is divided by 2.
* if bit ``round+64`` of the digest is 1, ``Y`` is divided by 2.

* the final result is ``X``'th bit of the digest XORed against ``Y``'th bit of the digest.

References
==========
* `<http://dropsafe.crypticide.com/article/1389>`_ - gives overview of & motivations for the algorithm
* `<http://www.ibiblio.org/pub/docs/books/gutenberg/etext98/2ws2610.txt>`_ - the source of Hamlet's speech, used byte-for-byte as the constant data.
