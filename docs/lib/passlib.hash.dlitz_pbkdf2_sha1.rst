===========================================================================
:class:`passlib.hash.dlitz_pbkdf2_sha1` - Dwayne Litzenberger's PBKDF2 hash
===========================================================================

.. index:: pbkdf2 hash; dlitz

.. currentmodule:: passlib.hash

This class provides an implementation of Dwayne Litzenberger's
PBKDF2-HMAC-SHA1 hash format [#dlitz]_. PBKDF2 is a key derivation function [#pbkdf2]_
that is ideally suited as the basis for a password hash, as it provides
variable length salts, variable number of rounds.

.. seealso::

    * :ref:`password hash usage <password-hash-examples>` --
      for examples of how to use this class via the common hash interface.

    * :doc:`cta_pbkdf2_sha1 <passlib.hash.cta_pbkdf2_sha1>`
      for another hash which looks almost exactly like this one.

Interface
=========
.. autoclass:: dlitz_pbkdf2_sha1()

Format & Algorithm
==================

A example hash (of ``password``) is:

    ``$p5k2$2710$.pPqsEwHD7MiECU0$b8TQ5AMQemtlaSgegw5Je.JBE3QQhLbO``.

All of this scheme's hashes have the format :samp:`$p5k2${rounds}${salt}${checksum}`,
where:

* ``$p5k2$`` is used as the :ref:`modular-crypt-format` identifier.

* :samp:`{rounds}` is the number of PBKDF2 iterations to perform,
  stored as lowercase hexidecimal number with no zero-padding (in the example: ``2710`` or 10000 iterations).

* :samp:`{salt}` is the salt string, which can be any number of characters,
  drawn from the :data:`hash64 charset <passlib.utils.HASH64_CHARS>`
  (``.pPqsEwHD7MiECU0`` in the example).

* :samp:`{checksum}` is 32 characters, which encode
  the resulting 24-byte PBKDF2 derived key using :func:`~passlib.utils.ab64_encode`
  (``b8TQ5AMQemtlaSgegw5Je.JBE3QQhLbO`` in the example).

In order to generate the checksum, the password is first encoded into UTF-8 if it's unicode.
Then, the entire configuration string (all of the hash except the checksum, ie :samp:`$p5k2${rounds}${salt}`)
is used as the PBKDF2 salt. PBKDF2 is called using the encoded password, the full salt,
the specified number of rounds, and using HMAC-SHA1 as it's psuedorandom function.
24 bytes of derived key are requested, and the resulting key is encoded and used
as the checksum portion of the hash.

.. rubric:: Footnotes

.. [#dlitz] The reference for this hash format - `<http://www.dlitz.net/software/python-pbkdf2/>`_.

.. [#pbkdf2] The specification for the PBKDF2 algorithm - `<http://tools.ietf.org/html/rfc2898#section-5.2>`_.
