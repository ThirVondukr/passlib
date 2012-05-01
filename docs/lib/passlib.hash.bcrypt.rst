==================================================================
:class:`passlib.hash.bcrypt` - BCrypt
==================================================================

.. currentmodule:: passlib.hash

BCrypt was developed to replace :class:`~passlib.hash.md5_crypt` for BSD systems.
It uses a modified version of the Blowfish stream cipher. Featuring
a large salt and variable number of rounds, it's currently the default
password hash for many systems (notably BSD), and has no known weaknesses.
It is one of the three hashes Passlib :ref:`recommends <recommended-hashes>`
for new applications. This class can be used directly as follows::

    >>> from passlib.hash import bcrypt

    >>> # generate new salt, encrypt password
    >>> h = bcrypt.encrypt("password")
    >>> h
    '$2a$12$NT0I31Sa7ihGEWpka9ASYrEFkhuTNeBQ2xfZskIiiJeyFXhRgS.Sy'

    >>> # the same, but with an explicit number of rounds
    >>> bcrypt.encrypt("password", rounds=8)
    '$2a$08$8wmNsdCH.M21f.LSBSnYjQrZ9l1EmtBc9uNPGL.9l75YE8D8FlnZC'

    >>> #verify password
    >>> bcrypt.verify("password", h)
    True
    >>> bcrypt.verify("wrong", h)
    False

.. note::

    It is strongly recommended to install
    :ref:`py-bcrypt or bcryptor <optional-libraries>`
    if this algorithm is going to be used.

.. seealso:: the generic :ref:`PasswordHash usage examples <password-hash-examples>`

Interface
=========
.. autoclass:: bcrypt()

.. _bcrypt-backends:

.. index:: environmental variable; PASSLIB_BUILTIN_BCRYPT

.. note::

    This class will use the first available of four possible backends:

    1. `py-bcrypt <http://www.mindrot.org/projects/py-bcrypt/>`_, if installed.
    2. `bcryptor <https://bitbucket.org/ares/bcryptor/overview>`_, if installed.
    3. stdlib's :func:`crypt.crypt()`, if the host OS supports BCrypt
       (primarily BSD-derived systems).
    4. A pure-python implementation of BCrypt, built into Passlib (disabled by default).

    It should be noted that the pure-python implementation (#4) is too slow
    to be useable, given the number of rounds currently required for security.
    Because of this, it is disabled by default, unless the environment variable
    ``PASSLIB_BUILTIN_BCRYPT="enabled"`` is set.

    If the first three backends are not available, and the builtin
    backend has not been enabled, :meth:`encrypt` and :meth:`verify`
    will throw a :exc:`~passlib.exc.MissingBackendError` when they are called.

    You can see which backend is in use by calling the :meth:`get_backend()` method.

.. versionchanged:: 1.6
    The pure-python backend was added, though it's disabled by default
    for security. (speedups are welcome!)

Format & Algorithm
==================
Bcrypt is compatible with the :ref:`modular-crypt-format`, and uses ``$2$`` and ``$2a$`` as the identifying prefix
for all it's strings (``$2$`` is seen only for legacy hashes which used an older version of Bcrypt).
An example hash (of ``password``) is ``$2a$12$GhvMmNVjRW29ulnudl.LbuAnUtN/LRfe1JsBm1Xu6LE3059z5Tr8m``.
Bcrypt hashes have the format :samp:`$2a${rounds}${salt}{checksum}`, where:

* :samp:`{rounds}` is the cost parameter, encoded as 2 zero-padded decimal digits,
  which determines the number of iterations used via :samp:`{iterations}=2**{rounds}` (rounds is 12 in the example).
* :samp:`{salt}` is the 22 character salt string, using the characters in the regexp range ``[./A-Za-z0-9]`` (``GhvMmNVjRW29ulnudl.Lbu`` in the example).
* :samp:`{checksum}` is the 31 character checksum, using the same characters as the salt (``AnUtN/LRfe1JsBm1Xu6LE3059z5Tr8m`` in the example).

While BCrypt's basic algorithm is described in it's design document [#f1]_,
the OpenBSD implementation [#f2]_ is considered the canonical reference, even
though it differs from the design document in a few small ways.

Deviations
==========
This implementation of bcrypt differs from others in a few ways:

* Restricted salt string character set:

  BCrypt does not specify what the behavior should be when
  passed a salt string outside of the regexp range ``[./A-Za-z0-9]``.
  In order to avoid this situtation, Passlib strictly limits salts to the
  allowed character set, and will throw a ValueError if an invalid
  salt character is encountered.

* Unicode Policy:

  The underlying algorithm takes in a password specified
  as a series of non-null bytes, and does not specify what encoding
  should be used; though a ``us-ascii`` compatible encoding
  is implied by nearly all implementations of bcrypt
  as well as all known reference hashes.

  In order to provide support for unicode strings,
  Passlib will encode unicode passwords using ``utf-8``
  before running them through bcrypt. If a different
  encoding is desired by an application, the password should be encoded
  before handing it to Passlib.

* Padding Bits

  BCrypt's base64 encoding results in the last character of the salt
  encoding only 2 bits of data, the remaining 4 are "padding" bits.
  Similarly, the last character of the digest contains 4 bits of data,
  and 2 padding bits. Because of the way they are coded, many BCrypt implementations
  will reject all passwords if these padding bits are not set to 0.
  Due to a legacy issue with Passlib <= 1.5.2,
  Passlib instead prints a warning if it encounters hashes with any padding bits set,
  and will then validate them correctly.
  (This behavior will eventually be deprecated and such hashes
  will throw a :exc:`ValueError` instead).

* the crypt_blowfish bug, and the 2x/2y hashes

  .. _crypt-blowfish-bug:

  Pre-1.1 versions of the `crypt_blowfish <http://www.openwall.com/crypt/>`_
  bcrypt implementation suffered from a serious flaw [#eight]_
  in how they handled 8-bit passwords. The manner in which the flaw was fixed resulted
  in two new bcrypt hash identifiers:

  ``$2x$``, allowing sysadmins to mark ``$2a$`` hashes which potentially were
  generated with the buggy algorithm. Passlib 1.6 recognizes, but does not
  currently support generating or verifying these hashes.

  ``$2y$``, the default for crypt_blowfish 1.1 and newer, indicates
  the hash was generated with the canonical OpenBSD-compatible algorithm,
  and should match *correctly* generated ``$2a$`` hashes.
  Passlib 1.6 can generate and verify these hashes.

  As well, crypt_blowfish 1.2 modified the way it generates ``$2a$`` hashes,
  so that passwords containing the byte value 0xFF are hashed in a manner
  incompatible with either the buggy or canonical algorithms. Passlib
  does not support this variant either, though it should rarely be needed.

.. rubric:: Footnotes

.. [#f1] the bcrypt format specification -
         `<http://www.usenix.org/event/usenix99/provos/provos_html/>`_

.. [#f2] the OpenBSD BCrypt source -
         `<http://www.openbsd.org/cgi-bin/cvsweb/src/lib/libc/crypt/bcrypt.c>`_

.. [#eight] The flaw in pre-1.1 crypt_blowfish is described here -
            `CVE-2011-2483 <http://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2011-2483>`_
