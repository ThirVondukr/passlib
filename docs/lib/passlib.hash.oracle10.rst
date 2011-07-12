==================================================================
:class:`passlib.hash.oracle10` - Oracle 10g password hash
==================================================================

.. currentmodule:: passlib.hash

This class implements the hash algorithm used by the Oracle Database up to
version 10g Rel.2. It was superceded by a newer algorithm in :class:`Oracle 11 <passlib.hash.oracle11>`.

.. warning::

    This hash is not secure, and should not be used for any purposes
    besides manipulating existing Oracle 10 password hashes.

.. warning::

    This implementation has not been compared
    very carefully against the official implementation or reference documentation,
    and it's behavior may not match under various border cases.
    It should not be relied on for anything but novelty purposes
    for the time being.

Usage
=====
This class can be used directly as follows (note that this class requires
a username for all encrypt/verify operations)::

    >>> from passlib.hash import oracle10 as or10

    >>> #encrypt password using specified username
    >>> h = or10.encrypt("password", "username")
    >>> h
    '872805F3F4C83365'

    >>> or10.identify(h) #check if hash is recognized
    True
    >>> or10.identify('$1$3azHgidD$SrJPt7B.9rekpmwJwtON31') #check if some other hash is recognized
    False

    >>> or10.verify("password", h, "username") #verify correct password
    True
    >>> or10.verify("password", h, "somebody") #verify correct password w/ wrong username
    False
    >>> or10.verify("password", h, "username") #verify incorrect password
    False

Interface
=========
.. autoclass:: oracle10()

.. rst-class:: html-toggle

Format & Algorithm
==================
Oracle10 hashes all consist of a series of 16 hexidecimal digits,
representing the resulting checksum.
Oracle10 hashes can be formed by the following procedure:

1. Concatenate the username and password together.
2. Convert the result to upper case
3. Encoding the result in a multi-byte format [#enc]_ such that ascii characters (eg: ``USER``) are represented
   with additional null bytes inserted (eg: ``\x00U\x00S\x00E\x00R``).
4. Right-pad the result with null bytes, to bring the total size to an integer multiple of 8.
   this is the final input string.
5. The input string is then encoded using DES in CBC mode.
   The string ``\x01\x23\x45\x67\x89\xAB\xCD\xEF`` is used as the DES key,
   and a block of null bytes is used as the CBC initialization vector.
   All but the last block of ciphertext is discarded.
6. The input string is then run through DES-CBC a second time;
   this time the last block of ciphertext from step 5 is used as the DES key,
   a block of null bytes is still used as the CBC initialization vector.
   All but the last block of ciphertext is discarded.
7. The last block of ciphertext of step 6 is converted
   to a hexdecimal string, and returned as the checksum.

Security Issues
===============
This algorithm it not suitable for *any* use besides manipulating existing
Oracle10 account passwords, due to the following flaws [#flaws]_:

* It's use of the username as a salt value means that common usernames
  (eg ``system``) will occur more frequently as salts,
  weakening the effectiveness of the salt in foiling pre-computed tables.

* The fact that is it case insensitive, and simply concatenates the username
  and password, greatly reduces the keyspace for brute-force
  or pre-computed attacks.

* It's simplicity makes high-speed brute force attacks much more feasible.

Deviations
==========
PassLib's implementation of the Oracle10g hash may deviate from the official
implementation in unknown ways, as there is no official documentation.
There is only one known issue:

* Unicode Policy

  Lack of testing (and test vectors) leaves it unclear
  as to how Oracle 10g handles passwords containing non-7bit ascii.
  In order to provide support for unicode strings,
  PassLib will encode unicode passwords using ``utf-16-be`` [#enc]_
  before running them through the Oracle10g algorithm.
  This behavior may be altered in the future, if further testing
  reveals another behavior is more in line with the official representation.
  This note applies as well to any provided username,
  as they are run through the same policy.

.. rubric:: Footnotes

.. [#enc] The exact encoding used in step 3 of the algorithm is not clear from known references.
          PassLib uses ``utf-16-be``, as this is both compatible with existing test vectors
          and supports unicode input.

.. [#flaws] Whitepaper analyzing flaws in this algorithm -
            `<http://www.isg.rhul.ac.uk/~ccid/publications/oracle_passwd.pdf>`_.

.. [#] Description of Oracle10g and Oracle11g algorithms -
       `<http://www.notesbit.com/index.php/scripts-oracle/oracle-11g-new-password-algorithm-is-revealed-by-seclistsorg/>`_.

