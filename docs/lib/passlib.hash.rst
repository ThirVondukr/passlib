==============================================
:mod:`passlib.hash` - Password Hashing Schemes
==============================================

.. module:: passlib.hash
    :synopsis: all password hashes provided by PassLib

Overview
========
The :mod:`!passlib.hash` module contains all the password hashes built into Passlib.
Each object within this package implements a different password hashing scheme,
but all have the same uniform interface. The hashes in this module can used in two ways:

They can be imported and used directly, as in the following example::

    >>> from passlib.hash import md5_crypt
    >>> md5_crypt.encrypt("password")
    '$1$IU54yC7Y$nI1wF8ltcRvaRHwMIjiJq1'

More commonly, they can be referenced by name
when constructing a custom :doc:`CryptContext <passlib.context>` object,
as in the following example::

    >>> from passlib.context import CryptContext
    >>> #note below that md5_crypt and des_crypt are both names of classes in passlib.hash
    >>> pwd_context = CryptContext(["md5_crypt", "des_crypt"])
    >>> pwd_context.encrypt("password")
    '$1$2y72Yi12$o6Yu2OyjN.9FiK.9HJ7i5.'

.. seealso::

    * :ref:`password-hash-api` -- details the
      interface used by all password hashes in this module.

    * :doc:`Quickstart Guide </new_app_quickstart>` --
      for advice on choosing an appropriately secure hash for your new application.

.. _mcf-hashes:

Unix & "Modular Crypt" Hashes
=============================
Aside from the "archaic" schemes below, most modern Unix flavors
use password hashes which follow the :ref:`modular crypt format <modular-crypt-format>`,
allowing them to be easily distinguished when used within the same file.
The basic format :samp:`${scheme}${hash}` has also been adopted for use
by other applications and password hash schemes.

.. _archaic-unix-schemes:

Archaic Unix Schemes
--------------------
All of the following hashes are/were used by various Unix flavors
to store user passwords; most are based on the DES block cipher,
and predate the arrival of the modular crypt format.
They should all be considered insecure at best, but may be useful when reading
legacy password entries:

.. toctree::
    :maxdepth: 1

    passlib.hash.des_crypt
    passlib.hash.bsdi_crypt
    passlib.hash.bigcrypt
    passlib.hash.crypt16

.. _standard-unix-hashes:

Standard Unix Schemes
---------------------
All these schemes are currently used by various Unix flavors to store user passwords.
They all follow the modular crypt format.

.. toctree::
    :maxdepth: 1

    passlib.hash.md5_crypt
    passlib.hash.bcrypt
    passlib.hash.sha1_crypt
    passlib.hash.sun_md5_crypt
    passlib.hash.sha256_crypt
    passlib.hash.sha512_crypt

Other Modular Crypt Schemes
---------------------------
While most of these schemes are not (commonly) used by any Unix flavor to store user passwords,
they can be used compatibly along side other modular crypt format hashes.

.. toctree::
    :maxdepth: 1

    passlib.hash.apr_md5_crypt
    passlib.hash.phpass
    passlib.hash.nthash
    passlib.hash.pbkdf2_digest
    passlib.hash.cta_pbkdf2_sha1
    passlib.hash.dlitz_pbkdf2_sha1

Special note should be made of the fallback helper,
which is not an actual hash scheme, but provides "disabled account"
behavior found in many Linux & BSD password files:

.. toctree::
    :maxdepth: 1

    passlib.hash.unix_fallback

.. _ldap-hashes:

LDAP / RFC2307 Hashes
=====================

All of the following hashes use a variant of the password hash format
used by LDAPv2. Originally specified in :rfc:`2307` and used by OpenLDAP [#openldap]_,
the basic format ``{SCHEME}HASH`` has seen widespread adoption in a number of programs.

.. _standard-ldap-hashes:

Standard LDAP Schemes
---------------------
.. toctree::
    :hidden:

    passlib.hash.ldap_std

The following schemes are explicitly defined by RFC 2307,
and are supported by OpenLDAP.

* :class:`passlib.hash.ldap_md5` - MD5 digest
* :class:`passlib.hash.ldap_sha1` - SHA1 digest
* :class:`passlib.hash.ldap_salted_md5` - salted MD5 digest
* :class:`passlib.hash.ldap_salted_sha1` - salted SHA1 digest

.. toctree::
    :maxdepth: 1

    passlib.hash.ldap_crypt

* :class:`passlib.hash.ldap_plaintext` - LDAP-Aware Plaintext Handler

Non-Standard LDAP Schemes
-------------------------
None of the following schemes are actually used by LDAP,
but follow the LDAP format:

.. toctree::
    :hidden:

    passlib.hash.ldap_other

* :class:`passlib.hash.ldap_hex_md5` - Hex-encoded MD5 Digest
* :class:`passlib.hash.ldap_hex_sha1` - Hex-encoded SHA1 Digest

.. toctree::
    :maxdepth: 1

    passlib.hash.ldap_pbkdf2_digest
    passlib.hash.atlassian_pbkdf2_sha1
    passlib.hash.fshp

* :class:`passlib.hash.roundup_plaintext` - Roundup-specific LDAP Plaintext Handler

.. _database-hashes:

Database Hashes
===============
The following schemes are used by various SQL databases
to encode their own user accounts.
These schemes have encoding and contextual requirements
not seen outside those specific contexts:

.. toctree::
    :maxdepth: 1

    passlib.hash.mysql323
    passlib.hash.mysql41
    passlib.hash.postgres_md5
    passlib.hash.oracle10
    passlib.hash.oracle11

.. _other-hashes:

Other Hashes
============
The following schemes are used in various contexts,
but have formats or uses which cannot be easily placed
in one of the above categories:

.. toctree::
    :maxdepth: 1

    passlib.hash.django_std
    passlib.hash.grub_pbkdf2_sha512
    passlib.hash.hex_digests
    passlib.hash.plaintext

.. rubric:: Footnotes

.. [#openldap] OpenLDAP homepage - `<http://www.openldap.org/>`_.
