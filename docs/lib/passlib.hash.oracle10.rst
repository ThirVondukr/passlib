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

Format
======
Oracle10 hashes all consist of a series of 16 hexidecimal digits,
representing the resulting checksum.

.. rst-class:: html-toggle

Algorithm
=========
Oracle10 hashes are formed by:

1. Concatenate the username and password together.
2. Convert the result to upper case
3. Encoding the result in a multi-byte format [#enc]_ such that ascii characters (eg: ``user``) are represented
   with additional null bytes inserted (eg: ``\x00u\x00s\x00e\x00r``).
4. Right-pad the result with null bytes to bring the size to an integer multiple of 8.
   this is the final input string.
5. The input string is then encoded using DES-CBC,
   using the key ``\x01\x23\x45\x67\x89\xAB\xCD\xEF``,
   and a null initialization vector.
6. The input string is then run through DES-CBC a second time,
   using the last block of ciphertext from step 5
   as the key for the second round.
7. The last block of ciphertext of step 6 is converted
   to a hexdecimal string, and returned as the checksum.

Security Issues
===============
This algorithm it not suitable for *any* use besides manipulating existing
Oracle10 account passwords, due to the following flaws:

* It's use of the username as a salt value means that common usernames
  (eg ``system``) will occur more frequently as salts,
  weakening the effectiveness of the salt in foiling pre-computed tables.

* The fact that is it case insensitive, and simply concatenates the username
  and password, greatly reduces the requirements for brute-force
  or pre-computed attacks.

* It's simplicity makes high-speed brute force attacks much more feasible.

Deviations
==========
PassLib's implementation of the Oracle10g hash may deviate from the official
implementation in unknown ways, as there is no official documentation.
There is only one known issue:

* Unicode Policy
  Lack of testing (and test vectors) leaves it unclear
  as to how Oracle 11g handles passwords containing non-7bit ascii.

  In order to provide support for unicode strings,
  PassLib will encode unicode passwords using ``utf-16-be``
  before running them through Oracle11.
  This behavior may be altered in the future, if further testing
  reveals another behavior is more in line with the official representation.

  This note applies as well to any provided username,
  as they are run through the same policy.

References
==========
.. [#enc] The exact encoded used in the algorithm is not clear from known references (see below).

.. [#] Description of Oracle10g and Oracle11g algorithms -
       `<http://www.notesbit.com/index.php/scripts-oracle/oracle-11g-new-password-algorithm-is-revealed-by-seclistsorg/>`_.
