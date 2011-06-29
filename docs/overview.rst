================
Library Overview
================

Passlib is a collection of routines for managing password hashes
such as found in unix "shadow" files, as returned by stdlib's :func:`!crypt`,
as stored in mysql and postgres, and various other places.
Passlib's contents can be roughly grouped into three categories:
password hashes, password contexts, and utility functions.

.. note::

    New applications which just need drop-in password hashing support
    should see the :doc:`new_app_quickstart`.

Password Hashes
===============
All of the hash schemes supported by Passlib are implemented
as classes importable from the :mod:`passlib.hash` module.
All of these classes support a single uniform interface of standard class methods.
These methods are documented in detail by the :ref:`password hash api <password-hash-api>`.

As a quick example of how a password hash can be used directly::

    >>> #import the SHA512-Crypt class:
    >>> from passlib.hash import sha512_crypt as sc

    >>> #generate new salt, encrypt password:
    >>> h = sc.encrypt("password")
    >>> h
    '$6$rounds=40000$xCsOXRqPPk5AGDFu$o5eyqxEoOSq0dLRFbPxEHp5Jc1vFVj47BNT.h9gmjSHXDS15mjIM.GSUaT5r6Z.Xa1Akrv4FAgKJE3EfbkJxs1'

    >>> #same, but with explict number of rounds:
    >>> sc.encrypt("password", rounds=10000)
    '$6$rounds=10000$QWT8AlDMYRms7vSx$.1267Pg6Opn9CblFndtBJ2Q0AI0fcI2IX93zX3gi1Qse./j.VlKYX59NIUlbs0A66wCbfu/vra9wMv2uwTZAI.'

    >>> #check if string is recognized as belonging to this hash scheme:
    >>> sc.identify(h)
    True
    >>> #check if some other hash is recognized:
    >>> sc.identify('$1$3azHgidD$SrJPt7B.9rekpmwJwtON31')
    False

    >>> #verify correct password:
    >>> sc.verify("password", h)
    True
    >>> #verify incorrect password:
    >>> sc.verify("secret", h)
    False

Password Contexts
=================
Mature applications frequently have to deal with tables of existing password
hashes. Over time, they have to migrate to newer and stronger schemes; as well as raise
the requirements for existing algorithms as more processing power becomes available.
In this case, directly importing and handling the various schemes
generally becomes complicated and tedious.

The :mod:`passlib.context` module provides the :class:`!CryptContext` class and other
utilties to help with these use-cases. This class handles
managing multiple password hash schemes, deprecation & migration of old hashes, and
many other policy requirements.

A quick example of how a password context can be used::

    >>> #importing the 'linux_context', which understands
    >>> #all hashes found on standard linux systems:
    >>> from passlib.hosts import linux_context as lc

    >>> #try encrypting a password
    >>> lc.encrypt("password")
    '$6$rounds=30000$suoPoYtkbccdZa3v$DW2KUcV98H4IrvlBB0YZf4DM8zqz5vduygB3OROhPzwHE5PDNVkpSUjJfjswn/dXqidha5t5CSCCIhtm6mIDR1'

    >>> #try encrypting a password using a specified scheme
    >>> lc.encrypt("password", scheme="des_crypt")
    'q1Oyx5r9mdGZ2'

    >>> #try verifying a password (scheme is autodetected)
    >>> lc.verify('password', 'q1Oyx5r9mdGZ2')
    True

Predefined Password Contexts
============================
In addition to the :mod:`!passlib.context` module,
PassLib provides a number of pre-configured :class:`!CryptContext` instances
in order to get users started quickly:

* The :mod:`passlib.apache` module contains classes
  for managing htpasswd and htdigest files.

* The :mod:`passlib.apps` module contains pre-configured
  instances for managing hashes used by Postgres, Mysql, and LDAP, and others.

* The :mod:`passlib.hosts` module contains pre-configured
  instances for managing hashes as found in the /etc/shadow files
  on Linux and BSD systems.

Utility Functions
=================
The :mod:`passlib.registry` and :mod:`passlib.utils` modules contain a large number
of support functions, most of which are only needed when
are implementing custom password hash schemes. Most users of passlib
will not need to use these.
