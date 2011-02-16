==================================================================
:mod:`passlib.hash.phpass` - PHPass Portable Hash
==================================================================

.. module:: passlib.hash.phpass
    :synopsis: PHPass Portable Hash

This algorithm is used primarily by PHP software
which uses the `PHPass <http://www.openwall.com/phpass/>`_ library,
a PHP library similar to PassLib. The PHPass Portable Hash
is a custom password hash used by PHPass as a fallback
when none of it's other hashes are available.
Due to it's reliance on MD5, and the simplistic implementation,
other hash algorithms should be used if possible.

Usage
=====
.. todo::

    write usage instructions

Functions
=========
.. autofunction:: genconfig
.. autofunction:: genhash
.. autofunction:: encrypt
.. autofunction:: identify
.. autofunction:: verify

Format
==================
An example hash (of ``password``) is ``$P$8ohUJ.1sdFw09/bMaAQPTGDNi2BIUt1``.
A phpass portable hash string has the format ``$P${rounds}{salt}{checksum}``, where:

* ``$P$`` is the prefix used to identify phpass hashes,
  following the :ref:`modular-crypt-format`.
  Note that phpBB3 databases uses the alternate prefix ``$H$``, both prefixes
  are recognized by this module, and the checksums are the same.

* ``{rounds}``  is a single character encoding a 6-bit integer
  encoding the number of rounds used. This is logarithmic,
  the real number of rounds is ``2**rounds``. (rounds is encoded as ``8``, or 2**13 rounds, in the example).

* ``{salt}`` is eight characters drawn from ``[./0-9A-Za-z]``,
  providing a 48-bit salt (``ohUJ.1sd`` in the example).

* ``{checksum}`` is 22 characters drawn from the same set,
  encoding the 128-bit checksum (``Fw09/bMaAQPTGDNi2BIUt1`` in the example).

Algorithm
=========
PHPass uses a straightforward algorithm to calculate the checksum:

* an initial result is generated from the MD5 digest of the salt string + the secret.
* for ``2**rounds`` iterations, a new result is created from the MD5 digest of the last result + the secret.
* the last result is then encoded according to the format described above.

Deviations
==========
This implementation of phpass differs from the specification in one way:

* Unicode strings are encoded using UTF-8 before being passed into the algorithm.
  While the original code accepts passwords containing any 8-bit value,
  it has no specific policy for dealing with unicode.

References
==========
* `<http://www.openwall.com/phpass/>`_ - PHPass homepage, which describes the algorithm
