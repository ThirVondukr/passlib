==============================================
:mod:`passlib.context` - CryptContext Overview
==============================================

.. module:: passlib.context
    :synopsis: CryptContext class for managing multiple password hash schemes

Overview
========
Different storage contexts (eg: linux shadow files vs openbsd shadow files)
may use different sets and subsets of the available algorithms.
Similarly, over time, applications may need to deprecate password schemes
in favor of newer ones, or raise the number of rounds required
by existing hashes.

This module provides the :class:`CryptContext` class, which is designed
to handle (as much as possible) of these tasks for an application.
Essentially, a :class:`!CryptContext` instance contains a list
of hash handlers that it should recognize, along with information
about which ones are deprecated, which is the default,
and what configuration constraints an application has placed
on a particular hash.

Usage
=====
To start off with a simple example of how to create and use a CryptContext::

    >>> from passlib.context import CryptContext

    >>> #create a new context that only understands Md5Crypt & DesCrypt:
    >>> myctx = CryptContext([ "md5_crypt", "des_crypt" ])

    >>> #unless overidden, the first hash listed
    >>> #will be used as the default for encrypting
    >>> #(in this case, md5_crypt):
    >>> hash1 = myctx.encrypt("too many secrets")
    >>> hash1
    '$1$nH3CrcVr$pyYzik1UYyiZ4Bvl1uCtb.'

    >>> #the scheme may be forced explicitly,
    >>> #though it must be one of the ones recognized by the context:
    >>> hash2 = myctx.encrypt("too many secrets", scheme="des-crypt")
    >>> hash2
    'm9pvLj4.hWxJU'

    >>> #verification will autodetect the correct type of hash:
    >>> myctx.verify("too many secrets", hash1)
    True
    >>> myctx.verify("too many secrets", hash2)
    True
    >>> myctx.verify("too many socks", hash2)
    False

    >>> #you can also have it identify the algorithm in use:
    >>> myctx.identify(hash1)
    'md5_crypt'

    >>> #or just return the handler instance directly:
    >>> myctx.identify(hash1, resolve=True)
    <class 'passlib.handlers.md5_crypt.md5_crypt'>

If introspection of a :class:`!CryptContext` instance
is needed, all configuration options are stored in a :class:`CryptPolicy` instance accessible through
their ``policy`` attribute::

    >>> from passlib.context import CryptContext
    >>> myctx = CryptContext([ "md5_crypt", "des_crypt" ], deprecated="des_crypt")

    >>> #get a list of schemes recognized in this context:
    >>> myctx.policy.schemes()
    [ 'md5-crypt', 'bcrypt' ]

    >>> #get the default handler class :
    >>> myctx.policy.get_handler()
    <class 'passlib.handlers.md5_crypt.md5_crypt'>

Interface
=========
This details the constructors and methods provided by :class:`!CryptContext`
and :class:`!CryptPolicy`. A list of all the keyword options accepted by these classes is listed separately
in :doc:`passlib.context-options`.

.. autoclass:: CryptContext(schemes=None, policy=<default policy>, \*\*kwds)

.. autoclass:: CryptPolicy(\*\*kwds)
