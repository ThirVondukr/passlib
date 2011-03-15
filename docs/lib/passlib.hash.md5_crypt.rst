==================================================================
:class:`passlib.hash.md5_crypt` - MD5 Crypt
==================================================================

.. currentmodule:: passlib.hash

This algorithm was developed for FreeBSD in 1994 by Poul-Henning Kamp,
to replace the aging :class:`passlib.hash.des_crypt`.
It has since been adopted by a wide variety of other Unix flavors, and is found
in many other contexts as well. Due to it's origins, it's sometimes referred to as "FreeBSD MD5 Crypt".
Security-wise it is considered to be steadily weakening (due to fixed cost),
and most unix flavors have since replaced with with stronger schemes,
such as :class:`~passlib.hash.sha512_crypt` and :class:`~passlib.hash.bcrypt`.

Usage
=====
PassLib provides an md5_crypt class, which can be can be used directly as follows::

    >>> from passlib.hash import md5_crypt as mc

    >>> mc.encrypt("password") #generate new salt, encrypt password
    '$1$3azHgidD$SrJPt7B.9rekpmwJwtON31'

    >>> mc.identify('$1$3azHgidD$SrJPt7B.9rekpmwJwtON31') #check if hash is recognized
    True
    >>> mc.identify('JQMuyS6H.AGMo') #check if some other hash is recognized
    False

    >>> mc.verify("password", '$1$3azHgidD$SrJPt7B.9rekpmwJwtON31') #verify correct password
    True
    >>> mc.verify("secret", '$1$3azHgidD$SrJPt7B.9rekpmwJwtON31') #verify incorrect password
    False

Interface
=========
.. autoclass:: md5_crypt(checksum=None, salt=None, strict=False)

Format
======
An example md5-crypt hash (of the string ``password``) is ``$1$5pZSV9va$azfrPr6af3Fc7dLblQXVa0``.

An md5-crypt hash string has the format :samp:`$1${salt}${checksum}`, where:

* ``$1$`` is the prefix used to identify md5-crypt hashes,
  following the :ref:`modular-crypt-format`
* :samp:`{salt}` is 0-8 characters drawn from the regexp range ``[./0-9A-Za-z]``;
  providing a 48-bit salt (``5pZSV9va`` in the example).
* :samp:`{checksum}` is 22 characters drawn from the same character set as the salt;
  encoding a 128-bit checksum (``azfrPr6af3Fc7dLblQXVa0`` in the example).

.. _md5-crypt-algorithm:

.. rst-class:: html-toggle

Algorithm
=========
The MD5-Crypt algorithm [#f1]_ calculates a checksum as follows:

1. A password string and salt string are provided.

   (The salt should not include the magic prefix,
   it should match string referred to as :samp:`{salt}` in the format section).

2. If needed, the salt should be truncated to a maximum of 8 characters.

..

3. Start MD5 digest B.

4. Add the password to digest B.

5. Add the salt to digest B.

6. Add the password to digest B.

7. Finish MD5 digest B.

..

8. Start MD5 digest A.

9. Add the password to digest A.

10. Add the constant string ``$1$`` to digest A.

11. Add the salt to digest A.

12. For each block of 16 bytes in the password string,
    add digest B to digest A.

13. For the remaining N bytes of the password string,
    add the first N bytes of digest B to digest A.

14. For each bit of the binary representation of the length
    of the password string; starting with the lowest value bit,
    up to and including the largest bit set to 1:

    a. If the current bit is set 1, add the first character of the password to digest A.
    b. Otherwise, add a NULL character to digest A.

15. Finish MD5 digest A.

..

16. For 1000 rounds (round values 0..999 inclusive),
    perform the following steps:

    a. Start MD5 Digest C for the round.
    b. If the round is odd, add the password to digest C.
    c. If the round is even, add the previous round's result to digest C (for round 0, add digest A instead).
    d. If the round is not a multiple of 3, add the salt to digest C.
    e. If the round is not a multiple of 7, add the password to digest C.
    f. If the round is even, repeat step b.
    g. If the round is odd, repeat step c.
    h. Finish MD5 digest C for the round; this is the result for this round.

17. Transpose the 16 bytes of the final round's result in the
    following order: ``12,6,0,13,7,1,14,8,2,15,9,3,5,10,4,11``.

18. Encode the resulting 16 byte string into a 22 character
    :mod:`hash 64 <passlib.utils.h64.encode_bytes>`-encoded string
    (the 2 msb bits encoded by the last hash64 character are used as 0 padding).
    This results in the portion of the md5 crypt hash string referred to as :samp:`{checksum}` in the format section.

Security Issues
===============
MD5-Crypt has a couple of issues which have weakened it,
though it is not yet considered broken:

* It relies on the MD5 message digest, for which theoretical pre-image attacks exist [#f2]_.
  However, not only is this attack still only theoretical, but none of MD5's weaknesses
  have been show to affect MD5-Crypt's security.

* The fixed number of rounds, combined with the availability
  of high-throughput MD5 implementations, means this algorithm
  is increasingly vulnerable to brute force attacks.
  It is this issue which has motivated it's replacement
  by new algorithms such as :class:`~passlib.hash.bcrypt`
  and :class:`~passlib.hash.sha512_crypt`.

Deviations
==========
PassLib's implementation of md5-crypt differs from the reference implementation (and others) in two ways:

* Restricted salt string character set:

  The underlying algorithm can unambigously handle salt strings
  which contain any possible byte value besides ``\x00`` and ``$``.
  However, PassLib strictly limits salts to the
  :mod:`hash 64 <passlib.utils.h64>` character set,
  as nearly all implementations of md5-crypt generate
  and expect salts containing those characters,
  but may have unexpected behaviors for other character values.

* Unicode Policy:

  The underlying algorithm takes in a password specified
  as a series of non-null bytes, and does not specify what encoding
  should be used; though a ``us-ascii`` compatible encoding
  is implied by nearly all implementations of md5-crypt
  as well as all known reference hashes.

  In order to provide support for unicode strings,
  PassLib will encode unicode passwords using ``utf-8``
  before running them through md5-crypt. If a different
  encoding is desired by an application, the password should be encoded
  before handing it to PassLib.

References
==========
.. [#f1] The authoritative reference for MD5-Crypt is Poul-Henning Kamp's original
         FreeBSD implementation -
         `<http://www.freebsd.org/cgi/cvsweb.cgi/~checkout~/src/lib/libcrypt/crypt.c?rev=1.2>`_

.. [#f2] Security issues with MD5 -
         `<http://en.wikipedia.org/wiki/MD5#Security>`_.
