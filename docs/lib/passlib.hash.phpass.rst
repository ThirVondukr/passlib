.. index:: phpass; portable hash, phpbb3; phpass hash

==================================================================
:class:`passlib.hash.phpass` - PHPass' Portable Hash
==================================================================

.. currentmodule:: passlib.hash

This algorithm is used primarily by PHP software
which uses PHPass [#home],
a PHP library similar to PassLib. The PHPass Portable Hash
is a custom password hash used by PHPass as a fallback
when none of it's other hashes are available.
Due to it's reliance on MD5, and the simplistic implementation,
other hash algorithms should be used if possible.

Usage
=====
Supporting a variable sized salt and variable number of rounds,
this scheme is used in exactly the same way as :doc:`bcrypt <passlib.hash.bcrypt>`.

Interface
=========
.. autoclass:: phpass(checksum=None, salt=None, rounds=None, strict=False)

Format
==================
An example hash (of ``password``) is ``$P$8ohUJ.1sdFw09/bMaAQPTGDNi2BIUt1``.
A phpass portable hash string has the format :samp:`$P${rounds}{salt}{checksum}`, where:

* ``$P$`` is the prefix used to identify phpass hashes,
  following the :ref:`modular-crypt-format`.

* :samp:`{rounds}`  is a single character encoding a 6-bit integer
  representing the number of rounds used. This is logarithmic,
  the real number of rounds is ``2**rounds``. (in the example, rounds is encoded as ``8``, or 2**13 iterations).

* :samp:`{salt}` is eight characters drawn from ``[./0-9A-Za-z]``,
  providing a 48-bit salt (``ohUJ.1sd`` in the example).

* :samp:`{checksum}` is 22 characters drawn from the same set,
  encoding the 128-bit checksum (``Fw09/bMaAQPTGDNi2BIUt1`` in the example).

.. note::

  Note that phpBB3 databases uses the alternate prefix ``$H$``, both prefixes
  are recognized by this implementation, and the checksums are the same.

Algorithm
=========
PHPass uses a straightforward algorithm to calculate the checksum:

1. an initial result is generated from the MD5 digest of the salt string + the secret.
2. for :samp:`2**{rounds}` iterations, a new result is created from the MD5 digest of the last result + the password.
3. the last result is then encoded according to the format described above.

Deviations
==========
This implementation of phpass differs from the specification in one way:

* Unicode Policy:

  The underlying algorithm takes in a password specified
  as a series of non-null bytes, and does not specify what encoding
  should be used; though a ``us-ascii`` compatible encoding
  is implied by nearly all known reference hashes.

  In order to provide support for unicode strings,
  PassLib will encode unicode passwords using ``utf-8``
  before running them through phpass. If a different
  encoding is desired by an application, the password should be encoded
  before handing it to PassLib.

.. rubric:: Footnotes

.. [#pp] PHPass homepage, which describes the Portable Hash algorithm -
         `<http://www.openwall.com/phpass/>`_
