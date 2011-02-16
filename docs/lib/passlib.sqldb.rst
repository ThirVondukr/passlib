============================================
:mod:`passlib.sqldb` - SQL Database Helpers
============================================

.. module:: passlib.sqldb
    :synopsis: frontend for encrypting & verifying passwords used in various sql databases

PostgreSQL
==========
This module provides a single pre-configured :class:`CryptContext` instance
which should be capable of recognizing passwords in modern postgres systems:

.. object:: postgres_context

    This object should recognize password hashes stores in postgres' pg_shadow table.
    it can recognize :mod:`~passlib.drivers.postgres_md5` hashes,
    as well as plaintext hashes.
    It defaults to postgres_md5 when generating new hashes.

    note that the username must be provided whenever encrypting or verifying a postgres hash.

MySQL
=====
This module provides two pre-configured :class:`CryptContext` instances
for handling MySQL user passwords:

.. object:: mysql_context

    This object should recognize the new :mod:`~passlib.drivers.mysql_41` hashes,
    as well as any legacy :mod:`~passlib.drivers.mysql_323` hashes.
    It defaults to mysql_41 when generating new hashes.

.. object:: mysql3_context

    This object is for use with older MySQL deploys which only recognize
    the :mod:`~passlib.drivers.mysql_323` hash.
