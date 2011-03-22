=================================================================
:class:`passlib.hash.sun_md5_crypt` - Sun MD5 Crypt
=================================================================

.. currentmodule:: passlib.hash

This algorithm is used by Solaris, as a replacement for the aging :class:`~passlib.hash.des_crypt`.
It is mainly used on later versions of Solaris, and is not found many other
places. While based on the MD5 message digest, it has very little at all
in common with the :class:`~passlib.hash.md5_crypt` algorithm. It supports
32 bit variable rounds and an 8 character salt.

.. warning::

    This implementation has not been compared
    very carefully against the official implementation or reference documentation,
    and it's behavior may not match under various border cases.
    It should not be relied on for anything but novelty purposes
    for the time being.

Usage
=====
This class supports both rounds and salts,
and so can be used in the exact same manner
as :doc:`SHA-512 Crypt <passlib.hash.sha512_crypt>`.

Interface
=========
.. autoclass:: sun_md5_crypt(checksum=None, salt=None, rounds=None, strict=False)

Format
======
An example hash (of ``passwd``) is ``$md5,rounds=5000$GUBv0xjJ$mSwgIswdjlTY0YxV7HBVm0``.
A sun-md5-crypt hash string has the format :samp:`$md5,rounds={rounds}${salt}${checksum}`, where:

* ``$md5,`` is the prefix used to identify the hash.
* :samp:`{rounds}` is the decimal number of rounds to use (5000 in the example).
* :samp:`{salt}` is 0-8 salt characters drawn from ``[./0-9A-Za-z]`` (``GUBv0xjJ`` in the example).
* :samp:`{checksum}` is 22 characters drawn from the same set,
  encoding a 128-bit checksum (``mSwgIswdjlTY0YxV7HBVm0`` in the example).

An alternate format, :samp:`$md5${salt}${checksum}` is used when the rounds value is 0.

.. note::
    Solaris seems to deviate from the :ref:`modular-crypt-format` in that
    it considers ``$`` *or* ``,`` to indicate the end of the identifier.

.. rst-class:: html-toggle

Algorithm
=========
The algorithm used is based around the MD5 message digest and the "Muffett Coin Toss" algorithm (so named
by one of the creators [#mct]_ ).

1. Given a password, the number of rounds, and a salt string.

2. an initial MD5 digest is created from the concatentation of the password,
   and the configuration string (using the format :samp:`$md5,rounds={rounds}${salt}`).

3. for rounds+4096 iterations, a new digest is created:
    i. a buffer is initialized, containing the previous round's MD5 digest (for the first round,
       the digest from step 2 is used).
    ii. ``MuffetCoinToss(rounds, previous digest)`` is called, resulting in a 0 or 1.
    iii. If step 3.ii results in a 1, a constant data string is added to the buffer;
         if the result is a 0, the string is not added for this round.
         The constant data string is a 1517 byte excerpt from Hamlet [#f2]_
         (``To be, or not to be...all my sins remember'd.\n``),
         including an appended null character.

    iv. the current round as an integer (zero-indexed) is converted to a string (not zero-padded) and added to the buffer.
    v. the output for this round is the MD5 digest of the buffer's contents.

4. The final checksum is then encoded into :mod:`hash64 <passlib.hash.h64>` format using the same
   transposed byte order that :class:`~passlib.hash.md5_crypt` uses.

Muffet Coin Toss
----------------
The Muffet Coin Toss algorithm is as follows:
Given the current round number, and a 16 byte MD5 digest, it returns a 0 or 1,
using the following formula:

.. note::

    All references below to a specific bit of the digest should be interpreted mod 128.
    All references below to a specific byte of the digest should be interpreted mod 16.

1. A 8-bit integer :samp:`{X}` is generated from the following formula:
   for each :samp:`{i}` in 0..7 inclusive:

    * let :samp:`{A}` be the :samp:`{i}`'th byte of the digest, as an 8-bit int.
    * let :samp:`{B}` be the :samp:`{i}+3`'rd byte of the digest, as an 8-bit int.

    * let :samp:`{R}` be :samp:`{A}` shifted right by :samp:`{B} % 5` bits.

    * let :samp:`{V}` be the :samp:`{R}`'th byte of the digest.
    * if the :samp:`{A} % 8`'th bit of :samp:`{B}` is 1, divide :samp:`{V}` by 2.

    * use the :samp:`{V}`'th bit of the digest as the :samp:`{i}`'th bit of :samp:`{X}`.

2. Another 8-bit integer, :samp:`{Y}`, is generated exactly the same manner as :samp:`{X}`, except that:

    * :samp:`{A}` is the :samp:`{i}+8`'th byte of the digest,
    * :samp:`{B}` is the :samp:`{i}+11`'th byte of the digest.

3. if bit :samp:`{round}` of the digest is 1, :samp:`{X}` is divided by 2.

4. if bit :samp:`{round}+64` of the digest is 1, :samp:`{Y}` is divided by 2.

5. the final result is :samp:`{X}`'th bit of the digest XORed against :samp:`{Y}`'th bit of the digest.

..
    todo: should review / verify this --

    Security Issues
    ===============
    Note that this has a weakness in that the per-round operation appends data
    which is known to the attacker, the coin flip algorithm only serves to
    frustrate brute-force attacks. Reversing this hash is dependant
    on MD5's general pre-image attack resistance (which is currently theoretically vulnerable).

Deviations
==========
PassLib's implementation of Sun-MD5-Crypt deviates from the official implementation
in at least one way:

* Unicode Policy:

  The underlying algorithm takes in a password specified
  as a series of non-null bytes, and does not specify what encoding
  should be used; though a ``us-ascii`` compatible encoding
  is implied by all known reference hashes.

  In order to provide support for unicode strings,
  PassLib will encode unicode passwords using ``utf-8``
  before running them through sun-md5-crypt. If a different
  encoding is desired by an application, the password should be encoded
  before handing it to PassLib.

Since PassLib's pure python implmentation was written based on the algorithm
description above, and has not been properly tested against a reference implementation,
it may have other bugs and deviations from the correct behavior.

* One of the remaining issues with this implementation is that some
  existing sun-md5-crypt hashes found on the web use a ``$`` in place of the ``,``.
  It is unclear whether this is an accepted alternate format or just a typo,
  nor whether this is supposed to affect the checksum in the resulting hash string.

References
==========
.. [#mct] Overview of & motivations for the algorithm - `<http://dropsafe.crypticide.com/article/1389>`_

.. [#f2] The source of Hamlet's speech, used byte-for-byte as the constant data - `<http://www.ibiblio.org/pub/docs/books/gutenberg/etext98/2ws2610.txt>`_
