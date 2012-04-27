==============================================
:mod:`passlib.hash` - Password Hashing Schemes
==============================================

.. module:: passlib.hash
    :synopsis: all password hashes provided by Passlib

Overview
========
The :mod:`!passlib.hash` module contains all the password hash algorithms built into Passlib.
While each hash has it's own options and output format, they all share a common interface,
documented in detail in the :ref:`password-hash-api`. The following pages
first describe the common interface, and then each hash in detail (
it's including format, algorithm, and known security issues).

.. seealso:: :doc:`Quickstart Guide </new_app_quickstart>` -- advice on
    choosing an appropriately secure hash for your new application.

Usage
=====
All of the hashes in this module can used in two ways:

1. They can be imported and used directly, as in the following example
   with the :class:`md5_crypt` hash::

        >>> # import the desired hash
        >>> from passlib.hash import md5_crypt

        >>> # hash the password - encrypt() takes care of salt generation, unicode encoding, etc.
        >>> hash = md5_crypt.encrypt("password")
        >>> hash
        '$1$IU54yC7Y$nI1wF8ltcRvaRHwMIjiJq1'

        >>> # verify a password against an existing hash:
        >>> md5_crypt.verify("password", hash)
        True

2. Alternately, when working with multiple algorithms at once, it is frequently useful
   to construct a :ref:`CryptContext <context-overview>` object instead;
   and reference the hashes by name only. For example, the following
   code creates a :class:`!CryptContext` object which recognizes both
   the :class:`md5_crypt` and :class:`des_crypt` hash algorithms::

        >>> # import and create the context object
        >>> from passlib.context import CryptContext
        >>> pwd_context = CryptContext(schemes=["md5_crypt", "des_crypt"])

        >>> # hash two different passwords (context objects used the first scheme as the default)
        >>> hash1 = pwd_context.encrypt("password")
        >>> hash1
        '$1$2y72Yi12$o6Yu2OyjN.9FiK.9HJ7i5.'
        >>> hash2 = pwd_context.encrypt("letmein", scheme="des_crypt")
        >>> hash2
        '0WMdk/ven8bok'

        >>> # the context object takes care of figuring out which hash belongs to which algorithm.
        >>> pwd_context.verify("password", hash1)
        True
        >>> pwd_context.verify("letmein", hash1)
        False
        >>> pwd_context.verify("letmein", hash2)
        True

For additional details, usage examples, and full documentation of all
methods and attributes provided by the common hash interface:

.. toctree::
    :maxdepth: 2

    /password_hash_api

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
    passlib.hash.pbkdf2_digest
    passlib.hash.cta_pbkdf2_sha1
    passlib.hash.dlitz_pbkdf2_sha1
    passlib.hash.scram

* :class:`passlib.hash.bsd_nthash` - FreeBSD's MCF-compatible :doc:`nthash <passlib.hash.nthash>` encoding

Special note should be made of the fallback helper,
which is not an actual hash scheme, but provides "disabled account"
behavior found in many Linux & BSD password files:

.. toctree::
    :maxdepth: 1

    passlib.hash.unix_disabled

.. _ldap-hashes:

LDAP / RFC2307 Hashes
=====================

All of the following hashes use a variant of the password hash format
used by LDAPv2. Originally specified in :rfc:`2307` and used by OpenLDAP [#openldap]_,
the basic format ``{SCHEME}HASH`` has seen widespread adoption in a number of programs.

.. [#openldap] OpenLDAP homepage - `<http://www.openldap.org/>`_.


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

SQL Database Hashes
===================
The following schemes are used by various SQL databases
to encode their own user accounts.
These schemes have encoding and contextual requirements
not seen outside those specific contexts:

.. toctree::
    :maxdepth: 1

    passlib.hash.mssql2000
    passlib.hash.mssql2005
    passlib.hash.mysql323
    passlib.hash.mysql41
    passlib.hash.postgres_md5
    passlib.hash.oracle10
    passlib.hash.oracle11

.. _windows-hashes:

MS Windows Hashes
=================
The following hashes are used in various places by Microsoft Windows.
As they were designed for "internal" use, they generally contain
no identifying markers, identifying them is pretty much context-dependant.

.. toctree::
    :maxdepth: 1

    passlib.hash.lmhash
    passlib.hash.nthash
    passlib.hash.msdcc
    passlib.hash.msdcc2

.. _other-hashes:

Other Hashes
============
The following schemes are used in various contexts,
but have formats or uses which cannot be easily placed
in one of the above categories:

.. toctree::
    :maxdepth: 1

    passlib.hash.cisco_pix

* *Cisco "Type 5" hashes* - see :doc:`md5_crypt <passlib.hash.md5_crypt>`

.. toctree::
    :maxdepth: 1

    passlib.hash.cisco_type7
    passlib.hash.django_std
    passlib.hash.grub_pbkdf2_sha512
    passlib.hash.hex_digests
    passlib.hash.plaintext
