=============================================
:mod:`passlib.utils` - Helper Functions
=============================================

.. module:: passlib.utils
    :synopsis: helper functions for implementing password hashes

This module contains a number of utility functions used by passlib
to implement the builtin handlers, and other code within passlib.
They may also be useful when implementing custom handlers for existing legacy formats.

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
.. autofunction:: list_to_bytes
.. autofunction:: bytes_to_list

.. autofunction:: xor_bytes

Randomness
==========
.. data:: rng

    The random number generator used by passlib to generate
    salt strings and other things which don't require a
    cryptographically strong source of randomness.

.. autofunction:: getrandbytes
.. autofunction:: getrandstr

Object Tests
============
.. autofunction:: is_crypt_handler

.. autofunction:: is_crypt_context

Submodules
==========
There are also a few sub modules which provide additional utility functions:

.. toctree::
    :maxdepth: 1

    passlib.utils.des
    passlib.utils.h64
    passlib.utils.md4
    passlib.utils.pbkdf2

.. todo::

    document this module...

    passlib.utils.handlers
