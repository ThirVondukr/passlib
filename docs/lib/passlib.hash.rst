============================================
:mod:`passlib.hash` - Password Hash Schemes
============================================

.. module:: passlib.hash
    :synopsis: all password hashes provided by PassLib

This module contains classes implementing each of the password hashes built into
passlib. As well, any external hashes registered using :func:`register_crypt_handler`
will be inserted into this module.

Each class within this package implements a single password hashing scheme,
and follows passlib's :ref:`password-hash-api`.
While many applications may find it easier to use a :class:`CryptContext`
instance, or retreive handlers via :func:`get_crypt_handler`, they can
also be imported and used directly from this package, as in the following example:

    >>> from passlib.hash import md5_crypt
    >>> hash = md5_crypt.encrypt("password")

PassLib contains the following builtin password algorithms:

Archaic Unix Schemes
--------------------
All these schemes are/were used by various unix flavors to store user passwords;
most are based on the DES block cipher,
and predate the arrival of the :ref:`modular crypt format <modular-crypt-format>`.
There are all considered insecure (at best), but may be useful when reading
legacy password entries:

.. toctree::
    :maxdepth: 1

    passlib.hash.des_crypt
    passlib.hash.bsdi_crypt
    passlib.hash.bigcrypt
    passlib.hash.crypt16

Standard Unix Schemes
---------------------
All these schemes are currently used by various unix flavors to store user passwords.
They all follow the :ref:`modular crypt format <modular-crypt-format>` for encoding idenfiable hashes.

.. toctree::
    :maxdepth: 1

    passlib.hash.md5_crypt
    passlib.hash.bcrypt
    passlib.hash.sha1_crypt
    passlib.hash.sun_md5_crypt
    passlib.hash.sha256_crypt
    passlib.hash.sha512_crypt

Non-Standard Unix-Compatible Schemes
------------------------------------
While most of these schemes are not commonly used by any unix flavor to store user passwords,
these are compatible with the :ref:`modular crypt format <modular-crypt-format>`, and can be
used in contexts which support them, in parallel with the others following
the modular crypt format.

.. toctree::
    :maxdepth: 1

    passlib.hash.apr_md5_crypt
    passlib.hash.phpass
    passlib.hash.nthash

Database Schemes
----------------
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

Other Schemes
-------------
The following schemes are used in various contexts,
mainly for legacy compatibility purposes.

.. toctree::
    :maxdepth: 1

    passlib.hash.hex_digests
    passlib.hash.ldap_digests
    passlib.hash.plaintext
    passlib.hash.unix_fallback
