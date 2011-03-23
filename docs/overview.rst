================
Library Overview
================

PassLib is a collection of routines for managing password hashes
as found in unix /etc/shadow files, as returned by stdlib `crypt()`,
as stored in mysql and postgres, and various other places.
PassLib's contents can be roughly grouped into three categories:
password hashes, password contexts, and utility functions.

Password Hash Schemes
=====================
All of the hash schemes supported by passlib are implemented
as classes importable from the :mod:`passlib.hash` module.
All of these classes support a single uniform interface of standard class methods.
These methods are documented in detail by next section, the :doc:`password hash api <password_hash_api>`.

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
generally becomes complicated and tedious. For these and similar use-cases,
the :mod:`passlib.context` module provides the :class:`!CryptContext` class, which handles
multiple password hash schemes, deprecation of old hashes, and
many other policy requirements.

In addition to using the class itself, PassLib provides a number of
pre-configured :class:`!CryptContext` instances
in order to get users started quickly:

* The :mod:`passlib.apache` module contains classes
  for managing htpasswd and htdigest files.

* The :mod:`passlib.apps` module contains pre-configured
  instances for managing hashes used by postgres, mysql, and ldap.

* The :mod:`passlib.hosts` module contains pre-configured
  instances for managing hashes as found in the /etc/shadow files
  on Linux and BSD systems.

* And finally the :mod:`passlib.context` module, which provides
  the :class:`!CryptContext` class itself, allowing
  an application to setup the particular configuration it required.

.. note::

    For new applications which just need drop-in support for some manner
    of password encryption, so they can secure store passwords
    and then forget about it, they should see :data:`passlib.apps.custom_app_context`.

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

Utility Functions
=================
The :mod:`passlib.utils` module contains a large number
of support functions, most of which are only needed when
are implementing custom password hash schemes. Most users of passlib
will not need to use this subpackage.

.. todo::

    Add documentation showing how to create custom password hash handlers.
