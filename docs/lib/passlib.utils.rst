=============================================
:mod:`passlib.utils` - Helper Functions
=============================================

.. module:: passlib.utils
    :synopsis: internal helpers for implementing password hashes

This module contains a number of utility functions used by Passlib
to implement the builtin hashes and other internals.
They may also be useful when implementing custom handlers for existing legacy formats.

.. warning::

    This module is primarily used as an internal support module.
    It's interface has not been finalized yet, and may be changed somewhat
    between major releases of Passlib, as the internal code is cleaned up
    and simplified.

Constants
=========

..
    .. data:: sys_bits

        Native bit size of host architecture (either 32 or 64 bit).
        used for various purposes internally.

.. data:: unix_crypt_schemes

    List of the names of all the hashes in :mod:`passlib.hash`
    which are natively supported by :func:`crypt` on at least one operating
    system.

    For all hashes in this list, the expression
    :samp:`passlib.hash.{alg}.has_backend("os_crypt")`
    will return ``True`` if the host OS natively supports the hash.
    This list is used by :data:`~passlib.hosts.host_context`
    and :data:`~passlib.apps.ldap_context` to determine
    which hashes are supported by the host.

    .. seealso:: :ref:`mcf-identifiers` for a table of which OSes are known to support which hashes.

..
    PYPY
    JYTHON
    rounds_cost_values

..
    Decorators
    ==========
    .. autofunction:: classproperty

Unicode Helpers
===============
.. autofunction:: consteq
.. autofunction:: saslprep

Bytes Helpers
=============
.. autofunction:: xor_bytes
.. autofunction:: render_bytes
.. autofunction:: int_to_bytes
.. autofunction:: bytes_to_int

Encoding Helpers
================
.. autofunction:: is_same_codec
.. autofunction:: is_ascii_codec
.. autofunction:: is_ascii_safe
.. autofunction:: to_bytes
.. autofunction:: to_unicode
.. autofunction:: to_native_str

Base64 Encoding
===============

Base64Engine Class
------------------
Passlib has to deal with a number of different Base64 encodings,
with varying endianness, as well as wildly different character <-> value
mappings. This is all encapsulated in the :class:`Base64Engine` class,
which provides common encoding actions for an arbitrary base64-style encoding
scheme. There are also a couple of predefined instances which are commonly
used by the hashes in Passlib.

.. autoclass:: Base64Engine

Common Character Maps
---------------------
.. data:: BASE64_CHARS

    Character map used by standard MIME-compatible Base64 encoding scheme.

.. data:: HASH64_CHARS

    Base64 character map used by a number of hash formats;
    the ordering is wildly different from the standard base64 character map.

    This encoding system appears to have originated with
    :class:`~passlib.hash.des_crypt`, but is used by
    :class:`~passlib.hash.md5_crypt`, :class:`~passlib.hash.sha256_crypt`,
    and others. Within Passlib, this encoding is referred as the "hash64" encoding,
    to distinguish it from normal base64 and others.

.. data:: BCRYPT_CHARS

    Base64 character map used by :class:`~passlib.hash.bcrypt`.
    The ordering is wildly different from both the standard base64 character map,
    and the common hash64 character map.

Predefined Instances
--------------------
.. data:: h64

    Predefined instance of :class:`Base64Engine` which uses
    the :data:`!HASH64_CHARS` character map and little-endian encoding.
    (see :data:`HASH64_CHARS` for more details).

.. data:: h64big

    Predefined variant of :data:`h64` which uses big-endian encoding.
    This is mainly used by :class:`~passlib.hash.des_crypt`.

.. versionchanged:: 1.6
   Previous versions of Passlib contained
   a module named :mod:`!passlib.utils.h64`; As of Passlib 1.6 this
   was replaced by the the ``h64`` and ``h64big`` instances of
   the :class:`Base64Engine` class;
   the interface remains mostly unchanged.


Other
-----
.. autofunction:: ab64_encode
.. autofunction:: ab64_decode

..
    .. data:: AB64_CHARS

        Variant of standard Base64 character map used by some
        custom Passlib hashes (see :func:`ab64_encode`).

..
    Host OS
    =======
    .. autofunction:: safe_crypt
    .. autofunction:: tick

Randomness
==========
.. data:: rng

    The random number generator used by Passlib to generate
    salt strings and other things which don't require a
    cryptographically strong source of randomness.

    If :func:`os.urandom` support is available,
    this will be an instance of :class:`!random.SystemRandom`,
    otherwise it will use the default python PRNG class,
    seeded from various sources at startup.

.. autofunction:: getrandbytes
.. autofunction:: getrandstr
.. autofunction:: generate_password(size=10, charset=<default charset>)

Interface Tests
===============
.. autofunction:: is_crypt_handler
.. autofunction:: is_crypt_context
.. autofunction:: has_rounds_info
.. autofunction:: has_salt_info

Submodules
==========
There are also a few sub modules which provide additional utility functions:

.. toctree::
    :maxdepth: 1

    passlib.utils.handlers
    passlib.utils.des
    passlib.utils.pbkdf2

..
    passlib.utils.compat
