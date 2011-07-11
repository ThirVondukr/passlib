===========================================================
:samp:`passlib.hash.ldap_{crypt}` - LDAP crypt() Wrappers
===========================================================

.. currentmodule:: passlib.hash

Passlib provides support for all the standard
LDAP hash formats specified by :rfc:`2307`.
One of these, identified by RFC 2307 as the ``{CRYPT}`` scheme,
is somewhat different from the others.
Instead of specifying a password hashing scheme,
it's supposed to wrap the host OS's :func:`!crypt()`.

Being host-dependant, the actual hashes supported
by this scheme may differ greatly between host systems.
In order to provide uniform support across platforms,
Passlib defines a corresponding :samp:`ldap_{xxx}_crypt` scheme
for each of the :ref:`standard unix hashes <standard-unix-hashes>`.

.. seealso::

    * :doc:`passlib.hash.ldap_std` - the other standard LDAP hashes.

    * :mod:`!passlib.apps` for a :ref:`list of premade ldap contexts <ldap-contexts>`.

Usage
=====
These classes all wrap the underlying implementations,
and are mainly useful only for plugging them into a :class:`~passlib.context.CryptContext`.
However, they can be used directly as follows::

    >>> from passlib.hash import ldap_md5_crypt as lmc

    >>> #encrypt password
    >>> h = lmc.encrypt("password")
    >>> h
    '{CRYPT}$1$gwvn5BO0$3dyk8j.UTcsNUPrLMsU6/0'

    >>> lmc.identify(h) #check if hash is recognized
    True
    >>> lmc.identify('JQMuyS6H.AGMo') #check if some other hash is recognized
    False

    >>> lmc.verify("password", h) #verify correct password
    True
    >>> lmc.verify("secret", h) #verify incorrect password
    False

Interface
=========
.. class:: ldap_des_crypt()
.. class:: ldap_bsdi_crypt()
.. class:: ldap_md5_crypt()
.. class:: ldap_bcrypt()
.. class:: ldap_sha1_crypt()
.. class:: ldap_sha256_crypt()
.. class:: ldap_sha512_crypt()

    All of these classes have the same interface as their corresponding
    underlying hash (eg :class:`des_crypt`, :class:`md5_crypt`, etc).

.. note::

    In order to determine if a particular hash is actually supported
    natively by your host OS, use an test such as
    ``ldap_des_crypt.has_backend("os_crypt")`` or similar.

.. rubric:: Footnotes

.. [#pwd] The manpage for :command:`slappasswd` - `<http://gd.tuwien.ac.at/linuxcommand.org/man_pages/slappasswd8.html>`_.

.. [#rfc] The basic format for these hashes is laid out in RFC 2307 - `<http://www.ietf.org/rfc/rfc2307.txt>`_
