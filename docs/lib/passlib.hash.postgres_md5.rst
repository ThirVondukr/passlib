==================================================================
:mod:`passlib.hash.postgres_md5` - PostgreSQL MD5 password hash
==================================================================

.. module:: passlib.hash.postgres_md5
    :synopsis: PostgreSQL MD5 password hash

.. warning::

    This hash is not secure, and should not be used for any purposes
    besides manipulating existing PostgreSQL password hashes.

This module implemented the md5-based hash algorithm used by PostgreSQL to store
it's user account passwords. This scheme was introduced in PostgreSQL 7.2;
prior to this PostgreSQL stored it's password in plain text. This scheme
uses the username as a salt value, and so it only technically salted,
as common user account names can be predicted and precalculated. Because
of this, it's not suitable for *any* use besides manipulating existing
PostgreSQL account passwords.

Usage
=====
Users will most likely find the frontend provided by :mod:`passlib.sqldb`
to be more useful than accessing this module directly.
That aside, this module can be used directly as follows::

    >>> from passlib.hash.import postgres_md5 as pm

    >>> pm.encrypt("password", "username") #encrypt password using specified username
    'md55a231fcdb710d73268c4f44283487ba2'

    >>> pm.identify('md55a231fcdb710d73268c4f44283487ba2') #check if hash is recognized
    True
    >>> pm.identify('$1$3azHgidD$SrJPt7B.9rekpmwJwtON31') #check if some other hash is recognized
    False

    >>> pm.verify("password", 'md55a231fcdb710d73268c4f44283487ba2', "username") #verify correct password
    True
    >>> pm.verify("password", 'md55a231fcdb710d73268c4f44283487ba2', "somebody") #verify correct password w/ wrong username
    False
    >>> pm.verify("password", 'md55a231fcdb710d73268c4f44283487ba2', "username") #verify incorrect password
    False

Functions
=========
.. autofunction:: genconfig
.. autofunction:: genhash
.. autofunction:: encrypt
.. autofunction:: identify
.. autofunction:: verify

Format & Algorithm
==================
Postgres-MD5 hashes all have the format ``md5{checksum}``,
where ``{checksum}`` is 32 hexidecimal digits, encoding a 128-bit checksum.
This checksum is the MD5 message digest of the password concatenated with the username.

References
==========
* `<http://archives.postgresql.org/pgsql-hackers/2001-06/msg00952.php>`_ - discussion leading up to design of algorithm
* `<http://archives.postgresql.org/pgsql-php/2003-01/msg00021.php>`_ - message explaining postgres md5 hash algorithm
