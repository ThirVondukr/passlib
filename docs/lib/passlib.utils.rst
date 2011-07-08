=============================================
:mod:`passlib.utils` - Helper Functions
=============================================

.. module:: passlib.utils
    :synopsis: helper functions for implementing password hashes

This module contains a number of utility functions used by passlib
to implement the builtin handlers, and other code within passlib.
They may also be useful when implementing custom handlers for existing legacy formats.

Constants
=========

.. data:: sys_bits

    Native bit size of host architecture (either 32 or 64 bit).
    used for various purposes internally.

.. data:: unix_crypt_schemes

    List of the names of all the handlers in :mod:`passlib.hash`
    which are supported by the native :func:`crypt()` function
    of at least one OS.

    For all hashes in this list, the expression
    ``get_crypt_handler(name).has_backend("os_crypt")``
    will return ``True`` iff there is native OS support for that hash.

    This list is used by :data:`~passlib.hosts.host_context`
    and :data:`~passlib.apps.ldap_context` to determine
    which hashes are supported by the host.

    See :ref:`mcf-identifiers` for a table of which OSes
    are known to support which hashes.

.. autoexception:: MissingBackendError

Decorators
==========
.. autofunction:: classproperty

String Manipulation
===================
.. autofunction:: splitcomma

Bytes Manipulation
==================

.. autofunction:: bytes_to_int
.. autofunction:: int_to_bytes
.. autofunction:: xor_bytes

Randomness
==========
.. data:: rng

    The random number generator used by passlib to generate
    salt strings and other things which don't require a
    cryptographically strong source of randomness.

    If :func:`os.urandom` support is available,
    this will be an instance of :class:`!random.SystemRandom`,
    otherwise it will use the default python PRNG class,
    seeded from various sources at startup.

.. autofunction:: getrandbytes
.. autofunction:: getrandstr

.. autofunction:: generate_password(size=10, charset=<default>)

Object Tests
============
.. autofunction:: is_crypt_handler
.. autofunction:: is_crypt_context
.. autofunction:: has_rounds_info
.. autofunction:: has_salt_info

Submodules
==========
There are also a few sub modules which provide additional utility functions:

.. toctree::
    :maxdepth: 1

    passlib.utils.des
    passlib.utils.h64
    passlib.utils.md4
    passlib.utils.pbkdf2
    passlib.utils.handlers
