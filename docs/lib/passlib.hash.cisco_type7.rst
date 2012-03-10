.. index:: cisco; type 7 hash

==================================================================
:class:`passlib.hash.cisco_type7` - Cisco "Type 7" hash
==================================================================

.. currentmodule:: passlib.hash

This class implements the "Type 7" password encoding used Cisco IOS.
This is not actually a true hash, but a reversible encoding of the plaintext
password. Type 7 strings are (and were designed to be) **plaintext equivalent**;
the goal was to protect from "over the shoulder" eavesdropping, and
little else. They can be trivially decoded. **Do not use for any purpose
where actual security is needed**.

.. note::

    This implementation should work correctly for most cases, but may not
    fully implement some edge cases (see `Deviations`_ below).
    Please report any issues encountered.

.. seealso::

    * :doc:`passlib.hash.md5_crypt` (referred to as a "type 5" hash by Cisco)
    * :doc:`passlib.hash.cisco_pix`

Usage
=====
This class can be used directly as follows::

    >>> from passlib.hash import cisco_type7 as ct

    >>> # encode password
    >>> h = ct.encrypt("password")
    >>> h
    '044B0A151C36435C0D'

    >>> #verify correct password
    >>> ct.verify("password", h)
    True
    >>> #verify incorrect password
    >>> pm.verify("letmein", h)
    False

    >>> #check if hash is recognized
    >>> ct.identify(h)
        True
    >>> #check if some other hash is recognized
    >>> ct.identify('$1$3azHgidD$SrJPt7B.9rekpmwJwtON31')
    False

    >>> # to demonstrate this is an encoding, not a real hash,
    >>> # this class supports decoding the resulting string:
    >>> ct.decode(h)
    "password"

Interface
=========
.. autoclass:: cisco_type7()

.. rst-class:: html-toggle

Format & Algorithm
==================
The Cisco Type 7 encoding consists of two decimal digits
(encoding the salt), followed a series of hexdecimal characters,
two for every byte in the encoded password.
An example encoding (of ``"password"``) is ``044B0A151C36435C0D``.
This has a salt/offset of 4 (``04`` in the example),
and encodes password via ``4B0A151C36435C0D``.

The algorithm is a straightforward XOR Cipher (though note the description below
may not be entirely correct, see `Deviations`_ for details):

1. The algorithm relies on the following ``ascii``-encoded 53-byte
   secret key::

    dsfd;kfoA,.iyewrkldJKDHSUBsgvca69834ncxv9873254k;fg87

2. A integer salt should be generated from the range
   0 .. 15. The first two characters of the encoded string are the
   zero-padded decimal encoding of the salt.

3. The remaining characters of the encoded string are generated as follows:
   For each byte in the password (starting with the 0th byte),
   the :samp:`{i}`'th byte of the password is encoded as follows:

    * let ``j=(i + salt) % keylen``
    * XOR the :samp:`{i}`'th byte of the password with the :samp:`{j}`'th byte
      of the secret key.
    * encode the resulting byte as uppercase hexidecimal,
      and append to the encoded string.

Deviations
==========
This implementation differs from the official one in a few ways.
It may be updated as more information becomes available.

* Unicode Policy:

  Type 7 encoding is primarily used with ``ASCII`` passwords,
  how it handles other characters is not known.

  In order to provide support for unicode strings, PassLib will encode unicode
  passwords using ``UTF-8`` before running them through this algorithm. If a
  different encoding is desired by an application, the password should be
  encoded before handing it to PassLib.

* Magic Key:

  Some implementations contain a truncated 26-byte key instead of the
  53-byte key listed above. However, it is likely those implementations have an
  incomplete copy of the key, as they exhibit other issues as well after
  the 26th byte is reached (throwing an error, truncating the password,
  outputing garbage), instead of wrapping around to the beginning of the key.

* Salt Range:

  All known test vectors contain salt values in ``range(0,16)``.
  However, the algorithm itself should be able to handle any salt value
  in ``range(0,53)`` (the size of the key). For maximum compatibility with
  other implementations, Passlib will accept ``range(0,53)``, but only
  generate salts in ``range(0,16)``.

* While this implementation handles all known test vectors,
  and tries to make sense of the disparate implementations,
  the actual algorithm has not been published by Cisco,
  so there may be other unknown deviations.

.. rubric:: Footnotes

.. [#] Description of Type 7 algorithm -
       `<http://pen-testing.sans.org/resources/papers/gcih/cisco-ios-type-7-password-vulnerability-100566>`_,
       `<http://wiki.nil.com/Deobfuscating_Cisco_IOS_Passwords>`_
