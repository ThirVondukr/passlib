.. index:: postgres; md5 hash

==================================================================
:class:`passlib.hash.postgres_md5` - PostgreSQL MD5 password hash
==================================================================

.. currentmodule:: passlib.hash

This class implements the md5-based hash algorithm used by PostgreSQL to store
it's user account passwords. This scheme was introduced in PostgreSQL 7.2;
prior to this PostgreSQL stored it's password in plain text.

.. warning::

    This hash is not secure, and should not be used for any purposes
    besides manipulating existing PostgreSQL password hashes.

Usage
=====
Users will most likely find the frontend provided by :mod:`passlib.apps`
to be more useful than accessing this class directly.
That aside, this class can be used directly as follows::

    >>> from passlib.hash import postgres_md5 as pm

    >>> #encrypt password using specified username
    >>> h = pm.encrypt("password", "username")
    >>> h
    'md55a231fcdb710d73268c4f44283487ba2'

    >>> pm.identify(h) #check if hash is recognized
    True
    >>> pm.identify('$1$3azHgidD$SrJPt7B.9rekpmwJwtON31') #check if some other hash is recognized
    False

    >>> pm.verify("password", h, "username") #verify correct password
    True
    >>> pm.verify("password", h, "somebody") #verify correct password w/ wrong username
    False
    >>> pm.verify("password", h, "username") #verify incorrect password
    False

Interface
=========
.. autoclass:: postgres_md5()

Format & Algorithm
==================
Postgres-MD5 hashes all have the format :samp:`md5{checksum}`,
where :samp:`{checksum}` is 32 hexidecimal digits, encoding a 128-bit checksum.
This checksum is the MD5 message digest of the password concatenated with the username.

Security Issues
===============
This algorithm it not suitable for *any* use besides manipulating existing
PostgreSQL account passwords, due to the following flaws:

* It's use of the username as a salt value means that common usernames
  (eg ``admin``, ``root``, ``postgres``) will occur more frequently as salts,
  weakening the effectiveness of the salt in foiling pre-computed tables.

* Since the keyspace of ``user+password`` is still a subset of ascii characters,
  existing MD5 lookup tables have an increased chance of being able to reverse common hashes.

* It's simplicity makes high-speed brute force attacks much more feasible [#brute]_ .

.. rubric:: Footnotes

.. [#] Discussion leading up to design of algorithm -
       `<http://archives.postgresql.org/pgsql-hackers/2001-06/msg00952.php>`_

.. [#] Message explaining postgres md5 hash algorithm -
       `<http://archives.postgresql.org/pgsql-php/2003-01/msg00021.php>`_

.. [#brute] Blog post demonstrating brute-force attack `<http://pentestmonkey.net/blog/cracking-postgres-hashes/>`_.
