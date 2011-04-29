==================================================================
:class:`passlib.hash.plaintext` - Plaintext
==================================================================

.. currentmodule:: passlib.hash

This class stores passwords in plaintext.
This is, of course, ridiculously insecure;
it is provided for backwards compatibility when migrating
existing applications. *It should not be used* for any other purpose.

.. seealso::

    * :class:`passlib.hash.ldap_plaintext` is probably more appropriate
      to use in conjunction with other LDAP style hashes.

Usage
=====
This class is mainly useful only for plugging into a :class:`~passlib.context.CryptContext`.
When used, it should always be the last scheme in the list,
as it will recognize all hashes.
It can be used directly as follows::

    >>> from passlib.hash import plaintext as pt

    >>> #"encrypt" password
    >>> pt.encrypt("password")
    'password'

    >>> nt.identify('password') #check if hash is recognized (all hashes are recognized)
    True

    >>> nt.verify("password", "password") #verify correct password
    True
    >>> nt.verify("secret", "password") #verify incorrect password
    False

Interface
=========
.. autoclass:: plaintext
