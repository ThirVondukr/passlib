.. _password-hash-api:

======================
Password Hash API
======================

Motivation
==========
Passlib supports many different password hashing schemes.
A majority of them were originally designed to be used on a unix
system, follow some variant of the unix ``crypt()`` api,
and have are encoded using the :ref:`modular-crypt-format`.
Others were designed for use specific contexts only,
such as PostgreSQL.

Passlib was designed to provide a uniform interface to implementations
of all these schemes, as well as hide away as much of the implementation
detail as possible; both in order to make it easier to integrate password hashing
into new and existing applications. Because of these goals, some of the methods
required by the crypt handler api tend to overlap slightly,
in order to accomodate a wide variety of application requirements,
and other parts have been kept intentionally non-commital, in order to allow
flexibility of implementation.

All of the schemes built into passlib implement this interface;
most them as modules within the :mod:`passlib.hash` package.

Overview
========
A handler which implements a password hash may be a module, class, or instance
(though most of the ones builtin to Passlib are classes).
The only requirement is that it expose a minimum of the following attributes
and functions (for classes, the following functions must be static or class methods).

All handlers have the following three attributes:

    * ``name`` - unique identifier used to distinguish scheme within
    * ``setting_kwds`` - list of settings recognized by ``genconfig()`` and ``encrypt()``.
    * ``context_kwds`` - list of context specified keywords required by algorithm

All handlers have the following five functions:

    * ``encrypt(secret, **context_and_settings) -> hash`` - used for encrypting secret using specified options
    * ``identify(hash) -> True|False`` - used for identifying hash belonging to this algorithm
    * ``verify(secret, hash, **context)`` - used for verifying a secret against an existing hash

    * ``genconfig(**settings) -> configuration string`` - used for generating configuration strings.
    * ``genhash(secret, config, **context) -> hash`` - used for encrypting secret using configuration string or existing hash

Usage Examples
==============

.. todo::

    show some quick examples using bcrypt.

Informational Attributes
========================
.. attribute:: name

    A unique name used to identify
    the particular algorithm this handler implements.

    These names should consist only of lowercase a-z, the digits 0-9, and hyphens.

    .. note::

        All handlers built into passlib are implemented as modules
        whose path corresponds to the name, with an underscore replacing the hyphen.
        For example, ``des-crypt`` is stored as the module ``passlib.hash.des_crypt``.

.. attribute:: setting_kwds

    If the algorithm supports per-hash configuration
    (such as salts, variable rounds, etc), this attribute
    should contain a tuple of keywords corresponding
    to each of those configuration options.

    This should correspond with the keywords accepted
    by :func:`genconfig`, see that method for details.

    If no settings are supported, this attribute
    is an empty tuple.

.. attribute:: context_kwds

    Some algorithms require external contextual information
    in order to generate a checksum for a password.
    An example of this is Postgres' md5 algorithm,
    which requires the username to be provided
    (which it uses as a salt).

    This attribute should contain a tuple of keywords
    which should be passed into :func:`encrypt`, :func:`verify`,
    and :func:`genhash` in order to encrypt a password.

    Since most password hashes require no external information,
    this tuple will usually be empty.

Primary Interface
=================
The ``encrypt()``, ``identify()``, and ``verify()`` methods are designed
to provide an easy interface for applications to encrypt new passwords
and verify existing passwords, without having to deal with details such
as salt formats.

.. function:: encrypt(secret, \*\*settings_and_context)

    encrypt secret, returning resulting hash string.

    :arg secret:
        A string containing the secret to encode.

        Unicode behavior is specified on a per-hash basis,
        but the common case is to encode into utf-8
        before processing.

    :param kwds:
        All other keywords are algorithm-specified,
        and should be listed in :attr:`setting_kwds`
        and :attr:`context_kwds`.

        Common keywords include ``salt`` and ``rounds``.

    :raises ValueError:
        * if settings are invalid and not correctable.
          (eg: provided salt contains invalid characters / length).

        * if a context kwd contains an invalid value, or was required
          but omitted.

        * if secret contains forbidden characters (e.g: des-crypt forbids null characters).
          this should rarely occur, since most modern algorithms have no limitations
          on the types of characters.

    :returns:
        Hash encoded in algorithm-specified format.

.. function:: identify(hash)

    identify if a hash string belongs to this algorithm.

    :arg hash:
        the candidate hash string to check

    :returns:
        * ``True`` if input appears to be a hash string belonging to this algorithm.
        * ``True`` if input appears to be a configuration string belonging to this algorithm.
        * ``False`` if no input is specified
        * ``False`` if none of the above conditions was met.

    .. note::
        Some handlers may or may not return ``True`` for malformed hashes.
        Those that do will raise a ValueError once the hash is passed to :func:`verify`.
        Most handlers, however, will just return ``False``.

.. function:: verify(secret, hash, \*\*context)

    verify a secret against an existing hash.

    This checks if a secret matches against the one stored
    inside the specified hash.

    :param secret:
        A string containing the secret to check.
    :param hash:
        A string containing the hash to check against.

    :param context:
        Any additional keywords will be passed to the encrypt
        method. These should be limited to those listed
        in :attr:`context_kwds`.

    :raises TypeError:
        * if the secret is not a string.

    :raises ValueError:
        * if the hash not specified
        * if the hash does not match this algorithm's hash format
        * if the provided secret contains forbidden chars (see :func:`encrypt`)

    :returns:
        ``True`` if the secret matches, otherwise ``False``.

Secondary Interface
===================
While the primary interface is generally the most useful when integrating
password support into an application, those methods are for the most part
built on top of the secondary interface, which is somewhat simpler
for *implementing* new password schemes. It also happens to match
more closely with the crypt api of most unix systems,
and consists of two functions: ``genconfig()`` and ``genhash``.

.. function:: genconfig(\*\*settings)

    returns configuration string encoding settings for hash generation

    Many hashes have configuration options,  and support a format
    which encodes them into a single configuration string.
    (This configuration string is usually an abbreviated version of their
    encoded hash format, sans the actual checksum, and is commonly
    referred to as a ``salt string``, though it may contain much more
    than just a salt).

    This function takes in optional configuration options (a complete list
    of which should be found in :attr:`setting_kwds`), validates
    the inputs, fills in defaults where appropriate, and returns
    a configuration string.

    For algorithms which do not have any configuration options,
    this function should always return ``None``.

    While each algorithm may have it's own configuration options,
    the following keywords (if supported) should always have a consistent
    meaning:

    * ``salt`` - algorithm uses a salt. if passed into genconfig,
      should contain an encoded salt string of length and character set
      required by the specific handler.

      salt strings which are too small or have invalid characters
      should cause an error, salt strings which are too large
      should be truncated but accepted.

    * ``rounds`` - algorithm uses a variable number of rounds. if passed
      into genconfig, should contain an integer number of rounds
      (this may represent logarithmic rounds, eg bcrypt, or linear, eg sha-crypt).
      if the number of rounds is too small or too large, it should
      be clipped but accepted.

    :param settings:
        this function takes in keywords as specified in :attr:`setting_kwds`.
        commonly supported keywords include ``salt`` and ``rounds``.

    :raises ValueError:
        * if any configuration options are required, missing, AND
          a default value cannot be autogenerated.
          (for example: salt strings should be autogenerated if not specified).
        * if any configuration options are invalid, and cannot be
          normalized in a reasonble manner (eg: salt strings clipped to maximum size).

    :returns:
        the configuration string, or ``None`` if the algorithm does not support any configuration options.

.. function:: genhash(secret, config, \*\*context)

    encrypt secret to hash

    takes in a password, optional configuration string,
    and any required contextual information the algorithm needs,
    and returns the encoded hash strings.

    :arg secret: string containing the password to be encrypted
    :arg config:
        configuration string to use when encrypting secret.
        this can either be an existing hash that was previously
        returned by :meth:`genhash`, or a configuration string
        that was previously created by :meth:`genconfig`.

    :param context:
        All other keywords must be external contextual information
        required by the algorithm to create the hash. If any,
        these kwds must be specified in :attr:`context_kwds`.

    :raises TypeError:
        * if the configuration string is not provided
        * if required contextual information is not provided

    :raises ValueError:
        * if the configuration string is not in a recognized format.
        * if the secret contains a forbidden character (rare, but some algorithms have limitations, eg: forbidding null characters)
        * if the contextual information is invalid

    :returns:
        encoded hash matching specified secret, config, and context.

Optional Informational Attributes
=================================
Many of the handlers in passlib expose the following informational
attributes, though their presence and meaning is not uniform
across all handlers in passlib.

For schemes which support a variable number of rounds,
the following attributes are usually exposed
(applications can test by checking for ``getattr(handler,"default_rounds",None)>0``):

.. attribute:: default_rounds

    The default number of rounds that will be used if not
    explicitly set when calling :func:`encrypt` or :func:`genconfig`.

.. attribute:: min_rounds

    The minimum number of rounds the scheme allows.
    Specifying values below this will generally result
    in a warning, and ``min_rounds`` will be used instead.

.. attribute:: max_rounds

    The maximum number of rounds the scheme allows.
    Specifying values above this will generally result
    in a warning, and ``max_rounds`` will be used instead.

.. attribute:: rounds_cost

    Specifies how the rounds value affects the amount of time taken.
    Currently used values are:

    ``linear`` - time taken scales linearly with rounds value (eg: sha512_crypt)
    ``log2`` - time taken scales exponentially with rounds value (eg: bcrypt)

For schemes which support a salt,
the following attributes are usually exposed
(applications can test by checking for ``getattr(handler,"max_salt_chars",None)>0``):

.. attribute:: max_salt_chars

    maximum number of characters which will be *used*
    if a salt string is provided to :func:`genconfig` or :func:`encrypt`.
    must be positive integer if salts are supported,
    may be ``None`` or ``0`` if salts are not supported.

.. attribute:: min_salt_chars

    minimum number of characters required in salt string,
    if provided to :func:`genconfig` or :func:`encrypt`.
    must be non-negative integer.

.. attribute:: salt_charset

    string containing list of all characters which are allowed
    to be specified in salt parameter. usually `passlib.utils.h64.CHARS`.
