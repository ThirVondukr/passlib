==================================================================
:class:`passlib.hash.scrypt` - SCrypt
==================================================================

.. versionadded:: 1.7

.. currentmodule:: passlib.hash

This is a custom hash scheme provided by Passlib which allows storing password hashes
generated using the SCrypt [#scrypt-home]_ key derivation function, and is designed
as the of a new generation of "memory hard" functions.

.. warning::

    Be careful when using this algorithm, as the memory and CPU requirements
    needed to achieve adequate security are generally higher than acceptable for heavily used
    production systems [#scrypt-cost]_: unlike many password hashes, increasing
    the rounds value of scrypt will increase the *memory* required, as well as the time.

This class can be used directly as follows::

    >>> from passlib.hash import scrypt

    >>> # generate new salt, encrypt password
    >>> h = scrypt.hash("password")
    >>> h
    '$2a$12$NT0I31Sa7ihGEWpka9ASYrEFkhuTNeBQ2xfZskIiiJeyFXhRgS.Sy'

    >>> # the same, but with an explicit number of rounds
    >>> scrypt.using(rounds=8).hash("password")
    '$scrypt$16,8,1$aM15713r3Xsvxbi31lqr1Q$nFNh2CVHVjNldFVKDHDlm4CbdRSCdEBsjjJxD.iCs5E'

    >>> # verify password
    >>> scrypt.verify("password", h)
    True
    >>> scrypt.verify("wrong", h)
    False

.. note::

    It is strongly recommended that you install
    `scrypt <https://pypi.python.org/pypi/scrypt>`_
    when using this hash.

.. seealso:: the generic :ref:`PasswordHash usage examples <password-hash-examples>`

Interface
=========
.. autoclass:: scrypt()

Scrypt Backends
---------------

This class will use the first available of two possible backends:

1. The C-accelarated `scrypt <https://pypi.python.org/pypi/scrypt>`_ package, if installed.
2. A pure-python implementation of SCrypt, built into Passlib.

.. warning::

    *It is strongly recommended to install the external scrypt package*.

    The pure-python backend is intended as a reference and last-resort implementation only;
    it is 10-100x too slow to be usable in production at a secure ``rounds`` cost.

Format & Algorithm
==================
This Scrypt hash format is compatible with the :ref:`modular-crypt-format`, and uses ``$scrypt$`` as the identifying prefix
for all its strings. An example hash (of ``password``) is:

  ``$scrypt$16,8,1$aM15713r3Xsvxbi31lqr1Q$nFNh2CVHVjNldFVKDHDlm4CbdRSCdEBsjjJxD.iCs5E``

This string has the format :samp:`$scrypt${nExp},{r},{p}${salt}${checksum}`, where:

* :samp:`{nExp}` is the exponent for calculating SCRYPT's cost parameter (N), encoded as a decimal digit,
  (nExp is 16 in the example, corresponding to n=65536).

* :samp:`{r}` is the value of SCRYPT's block size parameter (r), encoded as a decimal digit,
  (r is 8 in the example).

* :samp:`{p}` is the value of SCRYPT's parallel count parameter (p), encoded as a decimal digit,
  (p is 1 in the example).

* :samp:`{salt}` - this is the :func:`adapted base64 encoding <passlib.utils.ab64_encode>`
  of the raw salt bytes passed into the SCRYPT function (``aM15713r3Xsvxbi31lqr1Q`` in the example).

* :samp:`{checksum}` - this is the :func:`adapted base64 encoding <passlib.utils.ab64_encode>`
  of the raw derived key bytes returned from the SCRYPT function.
  This hash currently always uses 32 bytes, resulting in a 43-character checksum.
  (``nFNh2CVHVjNldFVKDHDlm4CbdRSCdEBsjjJxD.iCs5E`` in the example).

The algorithm used by all of these schemes is deliberately identical and simple:
The password is encoded into UTF-8 if not already encoded,
and run throught the SCRYPT function; along with the salt, and the values of n, r, and p.
The first 32 bytes of the returned result are encoded as the checksum.

See `<http://www.tarsnap.com/scrypt.html>`_ for the canonical description of the scrypt kdf.

Security Issues
===============
See the warning at the top of this page about the tradeoff between memory usage
and security that comes as part of altering scrypt's rounds parameter.

Deviations
==========
There is not a standardized format for encoding scrypt-hashed passwords in a manner compatible
with the modular crypt format; the format documented here is specific to passlib.

That said, the raw contents of these hashes should be identical to the output of any other
scrypt kdf implementation.

.. rubric:: Footnotes

.. [#scrypt-home] the SCrypt KDF homepage -
   `<http://www.tarsnap.com/scrypt.html>`_

.. [#scrypt-cost] posts discussing security implications of scrypt's tying memory cost to calculation time -
   `<http://blog.ircmaxell.com/2014/03/why-i-dont-recommend-scrypt.html>`_,
   `<http://security.stackexchange.com/questions/26245/is-bcrypt-better-than-scrypt>`_,
   `<http://security.stackexchange.com/questions/4781/do-any-security-experts-recommend-bcrypt-for-password-storage>`_
