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

Supported Schemes
-----------------
PassLib provides a number of pre-configured :class:`!CryptContext` instances
which can identify and manipulate all the formats used by Linux and BSD.
The following chart lists the various operating systems, which
hash algorithms are known to be supported, as well as the hash's
identifying prefix (see the :ref:`modular crypt format <modular-crypt-format>`).

==================================== ========== =========== =========== =========== ===========
Scheme                               Prefix     Linux       FreeBSD     NetBSD      OpenBSD
==================================== ========== =========== =========== =========== ===========
:class:`~passlib.hash.nthash`        ``$3$``                y
:class:`~passlib.hash.des_crypt`     n/a        y           y           y           y
:class:`~passlib.hash.bsdi_crypt`    ``_``                  y           y
:class:`~passlib.hash.md5_crypt`     ``$1$``    y           y           y           y
:class:`~passlib.hash.bcrypt`        ``$2a$``               y           y           y
:class:`~passlib.hash.sha1_crypt`    ``$sha1$``                         y
:class:`~passlib.hash.sha256_crypt`  ``$5$``    y
:class:`~passlib.hash.sha512_crypt`  ``$6$``    y
==================================== ========== =========== =========== =========== ===========

Predefined Contexts
-------------------
PassLib provides :class:`!CryptContext` instances
for the following Unix variants listed in `supported schemes`_:

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


.. _modular-crypt-format:
.. rst-class:: html-toggle

Modular Crypt Format
--------------------

Historically, most unix systems supported only :class:`~passlib.hash.des_crypt`.
Around the same time, many incompatible variations were also developed,
but their hashes were not easily distingiushable from each other
(see :ref:`archaic-unix-schemes`); making it impossible to use
multiple hashes on one system, or progressively migrate to a newer scheme.

This was solved with the advent of the *Modular Crypt Format*,
introduced around the time that :class:`~passlib.hash.md5_crypt` was developed.
This format allows hashs from multiple schemes to exist within the same
database, by requiring that all hash strings begin with a unique prefix
using the format :samp:`${identifier}$`.

Unfortunately, there is no specification document for this format.
Instead, it exists in *de facto* form only; the following
is an attempt to roughly identify the guidelines followed
by the modular crypt format hashes:

1. Hash strings must use only 7-bit ascii characters.

   This is not strictly enforced at all;
   for example Linux will accept 8-bit characters
   within hash salt strings. However, **no** known
   system generates hashes violating this rule;
   and no such test vectors exist either,
   so it can probably be assumed to be a case
   of "permissive in what you accept, strict in what you generate".

2. Hash strings should always start with the prefix :samp:`${identifier}$`,
   where :samp:`{identifier}` is a short string uniquely identifying
   hashes generated by that algorithm, using only lower case ascii
   letters, numbers, and hyphens.

   Initially, most schemes adhereing to this format
   only used a single digit to identify the hash
   (eg ``$1$`` for :class:`!md5_crypt`).
   Because of this, many systems only look at the first
   character when attempting to distinguish hashes.

   Despite this, as Unix systems have branched off,
   new hashes have been developed which used larger
   identifying strings (eg ``$sha1$`` for :class:`sha1_crypt`);
   so in general identifier strings should not be assumed to use a single character.

3. Aside from the prefix, hashes should contain only ascii letters,
   ascii numbers, and the characters in ``./``; though ``$``
   may be used as an internal field separator.

   This is the least adhered-to of any modular crypt format rule.
   Other characters (such as ``=``, ``,``) are sometimes
   used by various formats.

   The only hard and fast stricture
   is that ``:`` and non-printable characters be avoided,
   since this would interfere with parsing of /etc/passwd
   where these hashes are typically stored.

   Pretty much all modular-crypt-format hashes
   use ascii letters, numbers, ``.``, and ``/``
   to provide base64 encoding of their raw data,
   though the exact character value assignments vary between hashes
   (see :mod:`passlib.utils.h64`).

4. Hash schemes should put their "checksum" portion
   at the end of the hash, preferrably separated
   by a ``$``.

   This allows password hashes to be easily truncated
   to a "configuration string" containing just
   the identifying prefix, rounds, salt, etc.

   This string then encodes all the information
   generated needed to generate a new hash
   in order to verify a password, without
   having to perform excessive parsing.

   Most modular crypt format hashes follow this,
   though some (like :class:`~passlib.hash.bcrypt`) omit the ``$`` separator.

.. note::

    All of the above is guesswork based on examination of existing
    hashes and OS implementations; and was written merely
    to clarify the issue of what the "modular crypt format" is.
    It is drawn from no authoritative sources.

References
==========

.. [#shadow] Man page for Linux /etc/shadow - `<http://linux.die.net/man/5/shadow>`_
