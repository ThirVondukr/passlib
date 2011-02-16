============================================
:mod:`passlib.drivers. - Password Hash Schemes
============================================

.. module:: passlib.hash
    :synopsis: package containing all builtin password hashes

This subpackage contains handlers for all the password hashes built into
passlib. As well, any third-party handlers registered using :func:`register_crypt_handler`
will be inserted into this package.

Each module within this package implements a single password hashing scheme,
and follows passlib's :ref:`password-hash-api`.
While many applications may find it easier to use a :class:`CryptContext`
instance, or retreive handlers via :func:`get_crypt_handler`, they can
also be imported and used directly from this package:

    >>> from passlib.drivers.import md5_crypt
    >>> hash = md5_crypt.encrypt("password")

Passlib contains the following builtin password algorithms:

Standard Unix Schemes
---------------------
All these schemes are/were used by various unix flavors to store user passwords.
Because of this, all these schemes (except des-crypt and ext-des-crypt) follow
the :ref:`modular crypt format <modular-crypt-format>`.

.. toctree::
    :maxdepth: 1

    passlib.drivers.des_crypt
    passlib.drivers.ext_des_crypt
    passlib.drivers.md5_crypt
    passlib.drivers.bcrypt
    passlib.drivers.sha1_crypt
    passlib.drivers.sha256_crypt
    passlib.drivers.sha512_crypt

.. toctree::
    :hidden:

    passlib.drivers.sun_md5_crypt

.. todo::

    These aren't fully implemented / tested yet:

    * :mod:`~passlib.drivers.sun_md5_crypt` - MD5-based scheme used by Solaris 10 (NOT related to md5-crypt above).

Non-Standard Unix-Compatible Schemes
------------------------------------
While most of these schemes are not commonly used by any unix flavor to store user passwords,
these are compatible with the :ref:`modular crypt format <modular-crypt-format>`, and can be
used in contexts which support them, in parallel with the others following
the modular crypt format.

.. toctree::
    :maxdepth: 1

    passlib.drivers.apr_md5_crypt
    passlib.drivers.phpass
    passlib.drivers.nthash

Other Schemes
-------------
The following schemes are used in very specified contexts,
and have encoding schemes and other requirements
not seen outside those specific contexts:

.. toctree::
    :maxdepth: 1

    passlib.drivers.mysql_323
    passlib.drivers.mysql_41
    passlib.drivers.postgres_md5
