==================================================================
:mod:`passlib.servers` - Contexts for SQL Database & Other Servers
==================================================================

.. module:: passlib.servers
    :synopsis: frontend for encrypting & verifying passwords used in various sql databases

PostgreSQL
==========
This module provides a single pre-configured :class:`CryptContext` instance
which should be capable of recognizing passwords in modern postgres systems:

.. object:: postgres_context

    This object should recognize password hashes stores in postgres' pg_shadow table.
    it can recognize :class:`~passlib.hash.postgres_md5` hashes,
    as well as plaintext hashes.
    It defaults to postgres_md5 when generating new hashes.

    note that the username must be provided whenever encrypting or verifying a postgres hash.

MySQL
=====
This module provides two pre-configured :class:`CryptContext` instances
for handling MySQL user passwords:

.. object:: mysql_context

    This object should recognize the new :class:`~passlib.hash.mysql41` hashes,
    as well as any legacy :class:`~passlib.hash.mysql323` hashes.
    It defaults to mysql41 when generating new hashes.

    This should be used for all mysql versions from 4.1 onward.

.. object:: mysql3_context

    This object is for use with older MySQL deploys which only recognize
    the :class:`~passlib.hash.mysql323` hash.

    This should be used only for mysql version 3 systems.

LDAP
====
This module provides a pre-configured :class:`!CryptContext` instance
for handling LDAPv2 password hashes:

.. object:: ldap_context

    This object is for use when reading LDAP password hashes.

.. warning::

    PassLib does not currently support the ``{CRYPT}`` password hash method.
