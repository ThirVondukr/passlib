===============================================================
:samp:`passlib.hash.pbkdf2_{digest}` - Generic PBKDF2 Hashes
===============================================================

.. index:: pbkdf2 hash; generic mcf

.. currentmodule:: passlib.hash

PassLib provides three custom hash schemes based on the PBKDF2 [#pbkdf2]_ algorithm
which are compatible with the :ref:`modular crypt format <modular-crypt-format>`:
:class:`!pbkdf2_sha1`, :class:`!pbkdf2_sha256`, :class:`!pbkdf2_sha512`.
They feature variable length salts, variable rounds.

Security-wise, PBKDF2 is currently one of the leading key derivation functions,
and has no known security issues.
Though the original PBKDF2 specification uses the SHA-1 message digest,
it is not vulnerable to any of the known weaknesses of SHA-1 [#hmac-sha1]_,
and can be safely used. However, for those still concerned, SHA-256 and SHA-512
versions are offered as well.
PBKDF2-SHA512 is one of the three hashes Passlib
:ref:`recommends <recommended-hashes>` for new applications.

.. seealso::

    Alternate version of these hashes - :doc:`LDAP-Compatible Simple PBKDF2 Hashes <passlib.hash.ldap_pbkdf2_digest>`

Usage
=====
All of the following classes can be used directly as follows::

    >>> from passlib.hash import pbkdf2_sha256 as engine

    >>> #generate new salt, encrypt password
    >>> hash = engine.encrypt("password")
    >>> hash
    '$pbkdf2-sha256$6400$0ZrzXitFSGltTQnBWOsdAw$Y11AchqV4b0sUisdZd0Xr97KWoymNE0LNNrnEgY4H9M'

    >>> #same, but with explicit number of rounds and salt length
    >>> engine.encrypt("password", rounds=8000, salt_size=10) 
    '$pbkdf2-sha256$8000$XAuBMIYQQogxRg$tRRlz8hYn63B9LYiCd6PRo6FMiunY9ozmMMI3srxeRE'

    >>> #check if hash is a pbkdf2-sha256 hash
    >>> engine.identify(hash)
    True
    >>> #check if some other hash is recognized
    >>> engine.identify('$1$3azHgidD$SrJPt7B.9rekpmwJwtON31')
    False

    >>> #verify correct password
    >>> engine.verify("password", hash)
    True
    >>> #verify incorrect password
    >>> engine.verify("wrong", hash)
    False

Interface
=========
.. class:: pbkdf2_sha1()

    except for the choice of message digest,
    this class is the same as :class:`pbkdf2_sha512`.

.. class:: pbkdf2_sha256()

    except for the choice of message digest,
    this class is the same as :class:`pbkdf2_sha512`.

.. autoclass:: pbkdf2_sha512()

.. _mcf-pbkdf2-format:

Format & Algorithm
==================
An example :class:`!pbkdf2_sha256` hash (of ``password``)::

    $pbkdf2-sha256$6400$.6UI/S.nXIk8jcbdHx3Fhg$98jZicV16ODfEsEZeYPGHU3kbrUrvUEXOPimVSQDD44

All of the pbkdf2 hashes defined by passlib
follow the same format, :samp:`$pbkdf2-{digest}${rounds}${salt}${checksum}`.

* :samp:`$pbkdf2-{digest}$`` is used as the :ref:`modular-crypt-format` identifier
  (``$pbkdf2-sha256$`` in the example).

* :samp:`{digest}` - this specifies the particular cryptographic hash
  used in conjunction with HMAC to form PBKDF2's pseudorandom function
  for that particular hash (``sha256`` in the example).

* :samp:`{rounds}` - the number of iterations that should be performed.
  this is encoded as a positive decimal number with no zero-padding
  (``6400`` in the example).

* :samp:`{salt}` - this is the :func:`adapted base64 encoding <passlib.utils.adapted_b64_encode>`
  of the raw salt bytes passed into the PBKDF2 function.

* :samp:`{checksum}` - this is the :func:`adapted base64 encoding <passlib.utils.adapted_b64_encode>`
  of the raw derived key bytes returned from the PBKDF2 function.
  Each scheme uses output size of it's specific :samp:`{digest}`
  as the size of the raw derived key. This is enlarged
  by appromixately 4/3 by the base64 encoding,
  resulting in a checksum size of 27, 43, and 86 for each of the respective algorithms.

The algorithm used by all of these schemes is deliberately identical and simple:
The password is encoded into UTF-8 if not already encoded,
and passed through :func:`~passlib.utils.pbkdf2.pbkdf2`
along with the decoded salt, the number of rounds,
and a prf built from HMAC + the respective message digest.
The result is then encoded using :func:`~passlib.utils.adapted_b64_encode`.

.. rubric:: Footnotes

.. [#pbkdf2] The specification for the PBKDF2 algorithm - `<http://tools.ietf.org/html/rfc2898#section-5.2>`_,
             part of :rfc:`2898`.

.. [#hmac-sha1] While SHA1 has fallen to collision attacks, HMAC-SHA1 as used by PBKDF2
                is still considered secure - `<http://www.schneier.com/blog/archives/2005/02/sha1_broken.html>`_.
