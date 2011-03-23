==================================================================
:class:`passlib.hash.oracle11` - Oracle 11g password hash
==================================================================

.. currentmodule:: passlib.hash

This class implements the hash algorithm introduced in version 11g of the Oracle Database.
It supercedes the :class:`Oracle 10 <passlib.hash.oracle10>` password hash.

.. warning::

    This implementation has not been compared
    very carefully against the official implementation or reference documentation,
    and it's behavior may not match under various border cases.
    It should not be relied on for anything but novelty purposes
    for the time being.

Usage
=====
PassLib provides an oracle11 class, which can be can be used directly as follows::

    >>> from passlib.hash import oracle11 as or11

    >>> #generate new salt, encrypt password
    >>> h = or11.encrypt("password")
    >>> h
    'S:4143053633E59B4992A8EA17D2FF542C9EDEB335C886EED9C80450C1B4E6'

    >>> or11.identify(h) #check if hash is recognized
    True
    >>> or11.identify('JQMuyS6H.AGMo') #check if some other hash is recognized
    False

    >>> or11.verify("password", h) #verify correct password
    True
    >>> or11.verify("secret", h) #verify incorrect password
    False

Interface
=========
.. autoclass:: oracle11(checksum=None, salt=None, strict=False)

Format & Algorithm
==================
An example oracle11 hash (of the string ``password``) is:

    ``'S:4143053633E59B4992A8EA17D2FF542C9EDEB335C886EED9C80450C1B4E6'``

An oracle11 hash string has the format :samp:`S:{checksum}{salt}`, where:

* ``S:`` is the prefix used to identify oracle11 hashes
  (as distinct from oracle10 hashes, which have no constant prefix).
* :samp:`{checksum}` is 40 hexidecimal characters;
  encoding a 160-bit checksum.

  (``4143053633E59B4992A8EA17D2FF542C9EDEB335`` in the example)

* :samp:`{salt}` is 20 hexidecimal characters;
  providing a 80-bit salt (``C886EED9C80450C1B4E6`` in the example).

The Oracle 11 hash has a very simple algorithm: The salt is decoded
from it's hexidecimal representation into binary, and the SHA-1 digest
of :samp:`{password}{raw_salt}` is then encoded into hexidecimal, and returned as the checksum.

Deviations
==========
PassLib's implementation of the Oracle11g hash may deviate from the official
implementation in unknown ways, as there is no official documentation.
There is only one known issue:

* Unicode Policy

  Lack of testing (and test vectors) leaves it unclear
  as to how Oracle 11g handles passwords containing non-7bit ascii.
  In order to provide support for unicode strings,
  PassLib will encode unicode passwords using ``utf-8``
  before running them through Oracle11.
  This behavior may be altered in the future, if further testing
  reveals another behavior is more in line with the official representation.

References
==========
.. [#] Description of Oracle10g and Oracle11g algorithms -
       `<http://www.notesbit.com/index.php/scripts-oracle/oracle-11g-new-password-algorithm-is-revealed-by-seclistsorg/>`_.
