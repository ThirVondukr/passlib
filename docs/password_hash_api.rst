.. _password-hash-api:

=================
Password Hash API
=================

Overview
========
All of the hashes supported by PassLib are implemented using classes
which support an identical interface; this document describes that
interface in terms of a non-existent abstract class called :class:`!PasswordHash`.
All of the :doc:`supported password hashes <lib/passlib.hash>`
expose (at a minimum) the following methods and attributes:

The `required informational attributes`_
  These consist of the attributes :attr:`~PasswordHash.name`,
  :attr:`~PasswordHash.setting_kwds`, and :attr:`~PasswordHash.context_kwds`.
  They permit users and applications to detect what features a specific :class:`!PasswordHash`
  allows and/or requires.

The `application interface`_
  This consists of the :meth:`~PasswordHash.encrypt`,
  :meth:`~PasswordHash.identify`, and :meth:`~PasswordHash.verify` classmethods.
  Most applications will only need to make use of these methods.

The `crypt interface`_
  This consists of the :meth:`~PasswordHash.genconfig`,
  :meth:`~PasswordHash.genhash`. This mimics the standard unix crypt interface,
  but is not usually needed by applications.

The `optional informational attributes`_
  These attributes provide additional information
  about the capabilities and limitations of certain password hash schemes.

Usage
=====
While most uses of PassLib are done through a :class:`~passlib.context.CryptContext` class,
the various :class:`!PasswordHash` classes can be used directly to manipulate
passwords::

    >>> # for example, the SHA256-Crypt class:
    >>> from passlib.hash import sha256_crypt as sc

    >>> # using it to encrypt a password:
    >>> h = sc.encrypt("password")
    >>> h
    '$5$rounds=40000$HIo6SCnVL9zqF8TK$y2sUnu13gp4cv0YgLQMW56PfQjWaTyiHjVbXTgleYG9'

    >>> # subsequent calls to sc.encrypt() will generate a new salt:
    >>> sc.encrypt("password")
    '$5$rounds=40000$1JfxoiYM5Pxokyh8$ez8uV8jjXW7SjpaTg2vHJmx3Qn36uyZpjhyC9AfBi7B'

    >>> # the same, but with an explict number of rounds:
    >>> sc.encrypt("password", rounds=10000)
    '$5$rounds=10000$UkvoKJb8BPrLnR.D$OrUnOdr.IJx74hmyyzuRdr5k9lSXdkFxKmr7bLQTty5'

    >>> #the identify method can be used to determine the format of an unknown hash:
    >>> sc.identify(h)
    True

    >>> #check if some other hash is recognized (in this case, an MD5-Crypt hash)
    >>> sc.identify('$1$3azHgidD$SrJPt7B.9rekpmwJwtON31')
    False

    >>> #the verify method encapsulates all hash comparison logic for a class:
    >>> sc.verify("password", h)
    True
    >>> sc.verify("wrongpassword", h)
    False

.. _required-informational-attributes:

Required Informational Attributes
=================================
.. attribute:: PasswordHash.name

    A unique name used to identify
    the particular scheme this class implements.

    These names should consist only of lowercase a-z, the digits 0-9, and underscores.

    .. note::

        All handlers built into passlib are implemented as classes
        located under :samp:`passlib.hash.{name}`, where :samp:`{name}`
        is both the class name, and the value of the ``name`` attribute.
        This is not a requirement, and may not be true for externally-defined handers.

.. attribute:: PasswordHash.setting_kwds

    If the scheme supports per-hash configuration
    (such as salts, variable rounds, etc), this attribute
    should contain a tuple of keywords corresponding
    to each of those configuration options.

    This should list all the main configuration keywords accepted
    by :meth:`~PasswordHash.genconfig` and :meth:`~PasswordHash.encrypt`.

    If no configuration options are supported, this attribute should be an empty tuple.

    While each class may support a variety of options, each with their own meaning
    and semantics, the following keywords should have the same behavior
    across all schemes which use them:

    ``salt``
        If present, this means the algorithm contains some number of bits of salt
        which should vary with every new hash created.

        Providing this as a keyword should allow the application to select
        a specific salt string; though not only is this far from needed
        for most cases, the salt string's content constraints vary for each algorithm.

    ``rounds``
        If present, this means the algorithm allows for a variable number of rounds
        to be used, allowing the processor time required to be increased.

        Providing this as a keyword should allow the application to
        override the class' default number of rounds. While this
        must be a non-negative integer for all implementations,
        additional constraints may be present for each algorith
        (such as the cost varying on a linear or logarithmic scale).

    ``ident``
        If present, the class supports multiple formats for encoding
        the same hash. The class's documentation will generally list
        the allowed values, allowing alternate output formats to be selected.

.. attribute:: PasswordHash.context_kwds

    This attribute should contain a tuple of keywords
    which should be passed into :func:`encrypt`, :func:`verify`,
    and :func:`genhash` in order to encrypt a password.

    Some algorithms require external contextual information
    in order to generate a checksum for a password.
    An example of this is :doc:`Postgres' MD5 algorithm <lib/passlib.hash.postgres_md5>`,
    which requires the username to be provided when generating a hash
    (see that class for an example of how this works in pratice).

    Since most password hashes require no external information,
    this tuple will usually be empty, and references
    to context keywords can be ignored for all but a few classes.

    While each class may support a variety of options, each with their own meaning
    and semantics, the following keywords should have the same behavior
    across all schemes which use them:

    ``user``

        If present, the class requires a username be specified whenever
        performing a hash calculation (eg: postgres_md5 and oracle10).

.. _application-interface:

Application Interface
=====================
The :meth:`~PasswordHash.encrypt`, :meth:`~PasswordHash.identify`, and :meth:`~PasswordHash.verify` methods are designed
to provide an easy interface for applications. They allow encrypt new passwords
without having to deal with details such as salt generation, verifying
passwords without having to deal with hash comparison rules, and determining
which scheme a hash belongs to when multiple schemes are in use.

.. classmethod:: PasswordHash.encrypt(secret, \*\*settings_and_context)

    encrypt secret, returning resulting hash string.

    :arg secret:
        A string containing the secret to encode.

        Unicode behavior is specified on a per-hash basis,
        but the common case is to encode into utf-8
        before processing.

    :param settings_and_context:
        All other keywords are algorithm-specified,
        and should be listed in :attr:`~PasswordHash.setting_kwds`
        and :attr:`~PasswordHash.context_kwds`.

        Common settings keywords include ``salt`` and ``rounds``.

    :raises ValueError:
        * if settings are invalid and not correctable.
          (eg: provided salt contains invalid characters / length).

        * if a context kwd contains an invalid value, or was required
          but omitted.

        * if secret contains forbidden characters (e.g: des-crypt forbids null characters).
          this should rarely occur, since most modern algorithms have no limitations
          on the types of characters.

    :returns:
        Hash string, encoded in algorithm-specific format.

.. classmethod:: PasswordHash.identify(hash)

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
        Those that do will raise a ValueError once the hash is passed to :meth:`~PasswordHash.verify`.
        Most handlers, however, will just return ``False``.

.. classmethod:: PasswordHash.verify(secret, hash, \*\*context)

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
        in :attr:`~PasswordHash.context_kwds`.

    :raises TypeError:
        * if the secret is not a string.

    :raises ValueError:
        * if the hash not specified
        * if the hash does not match this algorithm's hash format
        * if the provided secret contains forbidden characters (see :meth:`~PasswordHash.encrypt`)

    :returns:
        ``True`` if the secret matches, otherwise ``False``.

.. _crypt-interface:

Crypt Interface
===============
While the primary interface is generally the most useful when integrating
password support into an application, those methods are for the most part
built on top of the crypt interface, which is somewhat simpler
for *implementing* new password schemes. It also happens to match
more closely with the crypt api of most unix systems,
and consists of two functions: :meth:`~PasswordHash.genconfig()``
and :meth:`~PasswordHash.genhash()``.

.. classmethod:: PasswordHash.genconfig(\*\*settings)

    returns configuration string encoding settings for hash generation

    Many hashes have configuration options,  and support a format
    which encodes them into a single configuration string.
    (This configuration string is usually an abbreviated version of their
    encoded hash format, sans the actual checksum, and is commonly
    referred to as a ``salt string``, though it may contain much more
    than just a salt).

    This function takes in optional configuration options (a complete list
    of which should be found in :attr:`~PasswordHash.setting_kwds`), validates
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
        this function takes in keywords as specified in :attr:`~PasswordHash.setting_kwds`.
        commonly supported keywords include ``salt`` and ``rounds``.

    :raises ValueError:
        * if any configuration options are required, missing, AND
          a default value cannot be autogenerated.
          (for example: salt strings should be autogenerated if not specified).
        * if any configuration options are invalid, and cannot be
          normalized in a reasonble manner (eg: salt strings clipped to maximum size).

    :returns:
        the configuration string, or ``None`` if the algorithm does not support any configuration options.

.. classmethod:: PasswordHash.genhash(secret, config, \*\*context)

    encrypt secret to hash

    takes in a password, optional configuration string,
    and any required contextual information the algorithm needs,
    and returns the encoded hash strings.

    :arg secret: string containing the password to be encrypted
    :arg config:
        configuration string to use when encrypting secret.
        this can either be an existing hash that was previously
        returned by :meth:`~PasswordHash.genhash`, or a configuration string
        that was previously created by :meth:`~PasswordHash.genconfig`.

    :param context:
        All other keywords must be external contextual information
        required by the algorithm to create the hash. If any,
        these kwds must be specified in :attr:`~PasswordHash.context_kwds`.

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
attributes, though their presence is not uniform
across all handlers in passlib.

.. todo::

    could change these to be required if the appropriate setting kwd is used.

Rounds Information
------------------
For schemes which support a variable number of rounds (ie, ``'rounds' in PasswordHash.setting_kwds``),
the following attributes are usually exposed.
(Applications can test for this suites' presence by checking if ``getattr(handler,"max_rounds",None)>0``)

.. attribute:: PasswordHash.default_rounds

    The default number of rounds that will be used if not
    explicitly set when calling :meth:`~PasswordHash.encrypt` or :meth:`~PasswordHash.genconfig`.

.. attribute:: PasswordHash.min_rounds

    The minimum number of rounds the scheme allows.
    Specifying values below this will generally result
    in a warning, and :attr:`~!PasswordHash.min_rounds` will be used instead.

.. attribute:: PasswordHash.max_rounds

    The maximum number of rounds the scheme allows.
    Specifying values above this will generally result
    in a warning, and :attr:`~!PasswordHash.max_rounds` will be used instead.

.. attribute:: PasswordHash.rounds_cost

    Specifies how the rounds value affects the amount of time taken.
    Currently used values are:

    ``linear``
        time taken scales linearly with rounds value (eg: :class:`~passlib.hash.sha512_crypt`)

    ``log2``
        time taken scales exponentially with rounds value (eg: :class:`~passlib.hash.bcrypt`)

Salt Information
----------------
For schemes which support a salt (ie, ``'salt' in PasswordHash.setting_kwds``),
the following attributes are usually exposed.
(Applications can test for this suites' presence by checking if ``getattr(handler,"max_salt_chars",None)>0``)

.. attribute:: PasswordHash.max_salt_chars

    maximum number of characters which will be *used*
    if a salt string is provided to :meth:`~PasswordHash.genconfig` or :meth:`~PasswordHash.encrypt`.
    must be positive integer if salts are supported,
    may be ``None`` or ``0`` if salts are not supported.

.. attribute:: PasswordHash.min_salt_chars

    minimum number of characters required in salt string,
    if provided to :meth:`~PasswordHash.genconfig` or :meth:`~PasswordHash.encrypt`.
    must be non-negative integer that is not greater than :attr:`~PasswordHash.max_salt_chars`.

.. attribute:: PasswordHash.salt_charset

    string containing list of all characters which are allowed
    to be specified in salt parameter.
    for most hashes, this is equal to `passlib.utils.h64.CHARS`.
