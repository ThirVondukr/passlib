.. index:: Cisco; PIX hash

==================================================================
:class:`passlib.hash.cisco_pix` - Cisco PIX hash
==================================================================

.. versionadded:: 1.6

.. warning::

    This hash is not secure, and should not be used for any purposes
    besides manipulating existing Cisco PIX password hashes.

.. currentmodule:: passlib.hash

This class implements the password hash algorithm commonly found on Cisco
PIX firewalls. This class can be used directly as follows::

    >>> from passlib.hash import cisco_pix as pix

    >>> # encrypt password using specified username
    >>> hash = pix.encrypt("password", user="user")
    >>> hash
    'A5XOy94YKDPXCo7U'

    >>> # verify correct password
    >>> pix.verify("password", hash, user="user")
    True
    >>> # verify correct password w/ wrong username
    >>> pm.verify("password", hash, user="other")
    False
    >>> # verify incorrect password
    >>> pm.verify("letmein", hash, user="user")
    False

    >>> # encrypt password without associate user account
    >>> hash2 = pix.encrypt("password")
    >>> hash2
    'NuLKvvWGg.x9HEKO'

    >>> # verify password without associated user account
    >>> pix.verify("password", hash2)
    True

.. seealso:: the generic :ref:`PasswordHash usage examples <password-hash-examples>`

Interface
=========
.. autoclass:: cisco_pix()

.. note::

    This hash algorithm has a context-sensitive percularity.
    It takes in an optional username, used to salt the hash,
    but with specific restrictions...

    * The username *must* be provided in order to correctly hash passwords
      associated with a user account on the Cisco device.

    * Conversely, the username *must not* be provided (or must be set to ``""``)
      in order to correctly hash passwords which don't have an associated user
      account (such as the "enable" password).

.. rst-class:: html-toggle

Format & Algorithm
==================
Cisco PIX hashes consist of a 12 byte digest, encoded as a 16 character
:data:`HASH64 <passlib.utils.h64>`-encoded string. An example
hash (of ``"password"``) is ``"NuLKvvWGg.x9HEKO"``.

The digest is calculated as follows:

1. The password is encoded using an ``ASCII``-compatible encoding
   (all known references are strict 7-bit ascii, and Passlib uses ``UTF-8``
   to provide unicode support).
2. If the hash is associated with a user account,
   append the first four bytes of the user account name
   to the end of the password. If the hash is NOT associated
   with a user account (e.g. it's the "enable" password),
   this step should be omitted.
3. The resulting password should be truncated to 16 bytes,
   or the right side NULL padded to 16 bytes, as appropriate.
4. Run the result of step 3 through MD5.
5. Discard every 4th byte of the 16-byte MD5 hash, starting
   with the 4th byte.
6. Encode the 12-byte result using :data:`HASH64 <passlib.utils.h64>`.

Security Issues
===============
This algorithm is not suitable for *any* use besides manipulating existing
Cisco PIX hashes, due to the following flaws:

* It's use of the username as a salt value (and only the first four characters
  at that), means that common usernames (e.g. ``admin``, ``cisco``) will occur
  more frequently as salts, weakening the effectiveness of the salt in
  foiling pre-computed tables.

* It's truncation of the ``password+user`` combination to 16 characters
  additionally limits the keyspace, and the effectiveness of the username
  as a salt; making pre-computed and brute force attacks much more feasible.

* Since the keyspace of ``user+password`` is still a subset of ascii characters,
  existing MD5 lookup tables have an increased chance of being able to
  reverse common hashes.

* It's simplicity, and the weakness of MD5, makes high-speed brute force attacks
  much more feasible.

* Furthermore, it discards of 1/4 of MD5's already small 16 byte digest,
  making collisions much more likely.

Deviations
==========
This implementation differs from the standard in one main way:

* Unicode Policy:

  The official Cisco PIX algorithm is primarily used with ``ascii`` passwords,
  how it handles other characters is not known.

  In order to provide support for unicode strings,
  Passlib will encode unicode passwords using ``utf-8``
  before running them through this algorithm. If a different
  encoding is desired by an application, the password should be encoded
  before handing it to Passlib.

* While this implementation agrees with all known references,
  the actual algorithm has not been published by Cisco, so there may be other
  unknown deviations.

.. rubric:: Footnotes

.. [#] Description of PIX algorithm -
       `<http://www.perlmonks.org/index.pl?node_id=797623>`_

.. [#] Message threads hinting at how username is handled -
       `<http://www.openwall.com/lists/john-users/2010/02/02/7>`_,
       `<www.freerainbowtables.com/phpBB3/viewtopic.php?f=2&t=1441>`_
