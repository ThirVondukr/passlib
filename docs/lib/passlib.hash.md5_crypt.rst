==================================================================
:class:`passlib.hash.md5_crypt` - MD5 Crypt
==================================================================

.. currentmodule:: passlib.hash

This algorithm was developed to replace the aging des-crypt.
It is supported by a wide variety of unix flavors, and is found
in other contexts as well. Security-wise, MD5-Crypt lacks newer features,
such as a variable number of rounds. Futhermore, the MD5 message digest
algorithm which it's based around is considered broken,
though pre-image attacks are currently only theoretical.
Despite this, MD5-Crypt itself is not considered broken,
and is still considered ok to use, though new applications
should use a stronger scheme (eg :class:`~passlib.hash.sha512_crypt`) if possible.

Usage
=====
This module can be used directly as follows::

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

Functions
=========
.. autoclass:: md5_crypt

Format
======
An example hash (of ``password``) is ``$1$5pZSV9va$azfrPr6af3Fc7dLblQXVa0``.
An md5-crypt hash string has the format ``$1${salt}${checksum}``, where:

* ``$1$`` is the prefix used to identify md5_crypt hashes,
  following the :ref:`modular-crypt-format`
* ``{salt}`` is 0-8 characters drawn from ``[./0-9A-Za-z]``,
  providing a 48-bit salt (``5pZSV9va`` in the example).
* ``{checksum}`` is 22 characters drawn from the same set,
  encoding a 128-bit checksum (``azfrPr6af3Fc7dLblQXVa0`` in the example).

Algorithm
=========
The algorithm used by MD5-Crypt is convoluted,
and is best described by examining the BSD implementation
linked to below, or the source code to this module.

It uses the MD5 message digest algorithm to generate
various intermediate digests based on combinations
of the secret, the salt, and some fixed constant strings.

It then performs a fixed 1000 rounds of recursive digests,
combining the secret, salt, and last digest in varying orders.

The resulting checksum is a convoluted form of
the last resulting digest, encoded in hash64.

Deviations
==========
This implementation of md5-crypt differs from others in a few ways:

* While the underlying algorithm technically allows salt strings
  to contain any possible byte value besides ``\x00`` and ``$``,
  this would conflict with many uses of md5-crypt, such as within
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
* `<http://www.freebsd.org/cgi/cvsweb.cgi/~checkout~/src/lib/libcrypt/crypt.c?rev=1.2>`_ - primary reference used for information & implementation
