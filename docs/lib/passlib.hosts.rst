============================================
:mod:`passlib.hosts` - OS Password Handling
============================================

.. module:: passlib.hosts
    :synopsis: encrypting & verifying operating system passwords

This module provides :class:`!CryptContext` instances for encrypting &
verifying password hashes tied to user accounts of various operating systems.
While (most) of the objects are available cross-platform,
their use is oriented primarily towards Linux and BSD variants.

.. seealso::

    :mod:`passlib.context` module for details about how to use a :class:`!CryptContext` instance.

Unix Password Hashes
====================
PassLib provides a number of pre-configured :class:`!CryptContext` instances
which can identify and manipulate all the formats used by Linux and BSD.
See the :ref:`modular crypt identifier list <mcf-identifiers>` for a complete
list of which hashes are supported by which operating system.

Predefined Contexts
-------------------
PassLib provides :class:`!CryptContext` instances
for the following Unix variants:

.. data:: linux_context

    context instance which recognizes hashes used
    by the majority of Linux distributions.
    encryption defaults to :class:`!sha512_crypt`.

.. data:: freebsd_context

    context instance which recognizes all hashes used by FreeBSD 8.
    encryption defaults to :class:`!bcrypt`.

.. data:: netbsd_context

    context instance which recognizes all hashes used by NetBSD.
    encryption defaults to :class:`!bcrypt`.

.. data:: openbsd_context

    context instance which recognizes all hashes used by OpenBSD.
    encryption defaults to :class:`!bcrypt`.

.. note::

    All of the above contexts include the :class:`~passlib.hash.unix_fallback` handler
    as a final fallback. This special handler treats all strings as invalid passwords,
    particularly the common strings ``!`` and ``*`` which are used to indicate
    that an account has been disabled [#shadow]_. It can also be configured
    to treat empty strings as a wildcard allowing in all passwords,
    though this behavior is disabled by default for security reasons.

A quick usage example, using the :data:`!linux_context` instance::

    >>> from passlib.hosts import linux_context
    >>> hash = linux_context.encrypt("password")
    >>> hash
    '$6$rounds=31779$X2o.7iqamZ.bAigR$ojbo/zh6sCmUuibhM7lnqR4Vy0aB3xGZXOYVLgtTFgNYiXaTNn/QLUz12lDSTdxJCLXHzsHiWCsaryAlcbAal0'
    >>> linux_context.verify("password", hash)
    True
    >>> linux_context.identify(hash)
    'sha512_crypt'
    >>> linux_context.encrypt("password", scheme="des_crypt")
    '2fmLLcoHXuQdI'
    >>> linux_context.identify('2fmLLcoHXuQdI')
    'des_crypt'

Current Host OS
---------------

.. data:: host_context

    :platform: Unix

    It should support all the algorithms the native OS :func:`!crypt` will support.
    The main difference is that it provides introspection about *which* schemes
    are available on a given system, as well as defaulting to the strongest
    algorithm and decent number of rounds when encrypting new passwords
    (whereas :func:`!crypt` invariably defaults to using :mod:`~passlib.hash.des_crypt`).

    This can be used in conjunction with stdlib's :mod:`!spwd` module
    to verify user passwords on the local system::

        >>> #NOTE/WARNING: this example requires running as root on most systems.
        >>> import spwd, os
        >>> from passlib.hosts import host_context
        >>> hash = spwd.getspnam(os.environ['USER']).sp_pwd
        >>> host_context.verify("toomanysecrets", hash)
        True

    .. versionchanged:: 1.4
        This object is only available on systems where the stdlib :mod:`!crypt` module is present.
        In version 1.3 and earlier, it was available on non-Unix systems, though it did nothing useful.


References
==========

.. [#shadow] Man page for Linux /etc/shadow - `<http://linux.die.net/man/5/shadow>`_
