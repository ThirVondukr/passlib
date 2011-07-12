.. index::
    single: password hash api
    single: custom hash handler; requirements

.. currentmodule:: passlib.hash

.. _password-hash-api:

=================
Password Hash API
=================

Overview
========
All of the hashes supported by PassLib are implemented using classes [#otypes]_
which support an identical interface; this document describes that
interface in terms of a non-existent abstract class called :class:`!PasswordHash`.
All of the supported password hashes [#supported]_ provide the following methods and attributes:

:ref:`required-attributes`

  These consist of the attributes :attr:`~PasswordHash.name`,
  :attr:`~PasswordHash.setting_kwds`, and :attr:`~PasswordHash.context_kwds`.
  They permit users and applications to detect what features a specific :class:`!PasswordHash`
  allows and/or requires.

:ref:`application-methods`

  This interface consists of the :meth:`~PasswordHash.encrypt`,
  :meth:`~PasswordHash.identify`, and :meth:`~PasswordHash.verify` classmethods.
  These are the methods most applications will need to make use of.

:ref:`crypt-methods`

  This interface consists of the :meth:`~PasswordHash.genconfig`
  and :meth:`~PasswordHash.genhash` classmethods.
  These methods mimic the standard unix crypt interface,
  and are not usually needed by applications.

:ref:`optional-attributes`

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

.. _required-attributes:

Required Attributes
=================================
.. attribute:: PasswordHash.name

    A unique name used to identify
    the particular scheme this class implements.

    These names should consist only of lowercase a-z, the digits 0-9, and underscores.

    .. note::

        All handlers built into passlib are implemented as classes
        located under :samp:`passlib.hash.{name}`, where :samp:`{name}`
        is both the class name, and the value of the ``name`` attribute.
        This is not a requirement, and may not be true for
        externally-defined handlers.

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

        Additionally, this means
        :meth:`~PasswordHash.genconfig` and :meth:`~PasswordHash.encrypt`
        should both accept an optional ``salt`` keyword allowing the user
        to specify a bare salt string. Note that this feature is rarely
        needed, and the constraints on the size & content of this string
        will vary for each algorithm.

    ``salt_size``
        Most algorithms which support ``salt`` will auto-generate a salt string
        if none is provided. If this keyword is also present, it means it
        can be used to select the size of the auto-generated salt.
        If omitted, most algorithms will fall back to a default salt size.

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
    which requires the username be provided when generating a hash
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

.. _application-methods:

Application Methods
===================
The :meth:`~PasswordHash.encrypt`, :meth:`~PasswordHash.identify`, and :meth:`~PasswordHash.verify` methods are designed
to provide an easy interface for applications. They allow encrypt new passwords
without having to deal with details such as salt generation, verifying
passwords without having to deal with hash comparison rules, and determining
which scheme a hash belongs to when multiple schemes are in use.

.. classmethod:: PasswordHash.encrypt(secret, \*\*settings_and_context_kwds)

    encrypt secret, returning resulting hash string.

    :arg secret:
        A string containing the secret to encode.

        Unicode behavior is specified on a per-hash basis,
        but the common case is to encode into utf-8
        before processing.

    :param \*\*settings_and_context_kwds:
        All other keywords are algorithm-specified,
        and should be listed in :attr:`~PasswordHash.setting_kwds`
        and :attr:`~PasswordHash.context_kwds`.

        Common settings keywords include ``salt`` and ``rounds``.

    :raises ValueError:
        * if settings are invalid and handler cannot correct them.
          (eg: if a ``salt`` string is to short, this will
          cause an error; but a ``rounds`` value that's too large
          should be silently clipped).

        * if a context keyword contains an invalid value, or was required
          but omitted.

        * if secret contains forbidden characters (e.g: des-crypt forbids null characters).
          this should rarely occur, since most modern algorithms have no limitations
          on the types of characters.

    :raises TypeError: if :samp:`{secret}` is not a bytes or unicode instance.

    :returns:
        Hash string, using an algorithm-specific format.

.. classmethod:: PasswordHash.identify(hash)

    identify if a hash string belongs to this algorithm.

    :arg hash:
        the candidate hash string to check

    :returns:
        * ``True`` if input appears to be a hash string belonging to this algorithm.
        * ``True`` if input appears to be a configuration string belonging to this algorithm.
        * ``False`` if no input is an empty string or ``None``.
        * ``False`` if none of the above conditions was met.

    .. note::

        The goal of this method is positively identify the correct
        handler for a given hash, and do it as efficiently as possible.
        In order to accomplish this, many implementations perform only minimal
        validation of the candidate hashes. Thus, they may return ``True``
        for hashes which are identifiable, but malformed enough that
        a :exc:`ValueError` is raised when the string is passed to
        :func:`~PasswordHash.verify` or :func:`~PasswordHash.genhash`.
        Because of this, applications should rely on this method only for identification,
        not confirmation that a hash is correctly formed.

.. classmethod:: PasswordHash.verify(secret, hash, \*\*context_kwds)

    verify a secret against an existing hash.

    This checks if a secret matches against the one stored
    inside the specified hash.

    :param secret:
        A string containing the secret to check.
    :param hash:
        A string containing the hash to check against.

    :param \*\*context_kwds:
        Any additional keywords will be passed to the encrypt
        method. These should be limited to those listed
        in :attr:`~PasswordHash.context_kwds`.

    :raises TypeError: if :samp:`{secret}` is not a bytes or unicode instance.

    :raises ValueError:
        * if the hash not specified
        * if the hash does not match this algorithm's hash format
        * if the provided secret contains forbidden characters (see :meth:`~PasswordHash.encrypt`)

    :returns:
        ``True`` if the secret matches, otherwise ``False``.

.. _crypt-methods:

Crypt Methods
=============
While the application methods are generally the most useful when integrating
password support into an application, those methods are for the most part
built on top of the crypt interface, which is somewhat simpler
for *implementing* new password schemes. It also happens to match
more closely with the crypt api of most Unix systems,
and consists of two functions: :meth:`~PasswordHash.genconfig`
and :meth:`~PasswordHash.genhash`.

.. classmethod:: PasswordHash.genconfig(\*\*settings_kwds)

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

    :param \*\*settings_kwds:
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

.. classmethod:: PasswordHash.genhash(secret, config, \*\*context_kwds)

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

    :param \*\*context_kwds:
        All other keywords must be external contextual information
        required by the algorithm to create the hash. If any,
        these kwds must be specified in :attr:`~PasswordHash.context_kwds`.

    :raises TypeError:
        * if the configuration string is not provided
        * if required contextual information is not provided
        * if :samp:`{secret}` is not a bytes or unicode instance.

    :raises ValueError:
        * if the configuration string is not in a recognized format.
        * if the secret contains a forbidden character (rare, but some algorithms have limitations, eg: forbidding null characters)
        * if the contextual information is invalid

    :returns:
        encoded hash matching specified secret, config, and context.

.. _optional-attributes:

Optional Attributes
=================================
Many of the handlers expose the following informational
attributes (though their presence is not uniform or required
as of this version of Passlib).

.. todo::

    Consider making these attributes required for all hashes
    which support the appropriate keyword in :attr:`~PasswordHash.setting_kwds`.

.. _optional-rounds-attributes:

Rounds Information
------------------
For schemes which support a variable number of rounds (ie, ``'rounds' in PasswordHash.setting_kwds``),
the following attributes are usually exposed.
(Applications can test for this suites' presence by using :func:`~passlib.utils.has_rounds_info`)

.. attribute:: PasswordHash.max_rounds

    The maximum number of rounds the scheme allows.
    Specifying values above this will generally result
    in a warning, and :attr:`~!PasswordHash.max_rounds` will be used instead.
    Must be a positive integer.

.. attribute:: PasswordHash.min_rounds

    The minimum number of rounds the scheme allows.
    Specifying values below this will generally result
    in a warning, and :attr:`~!PasswordHash.min_rounds` will be used instead.
    Must be within ``range(0, max_rounds+1)``.

.. attribute:: PasswordHash.default_rounds

    The default number of rounds that will be used if not
    explicitly set when calling :meth:`~PasswordHash.encrypt` or :meth:`~PasswordHash.genconfig`.
    Must be within ``range(min_rounds, max_rounds+1)``.

.. attribute:: PasswordHash.rounds_cost

    Specifies how the rounds value affects the amount of time taken.
    Currently used values are:

    ``linear``
        time taken scales linearly with rounds value (eg: :class:`~passlib.hash.sha512_crypt`)

    ``log2``
        time taken scales exponentially with rounds value (eg: :class:`~passlib.hash.bcrypt`)

.. _optional-salt-attributes:

Salt Information
----------------
For schemes which support a salt (ie, ``'salt' in PasswordHash.setting_kwds``),
the following attributes are usually exposed.
(Applications can test for this suites' presence by using :func:`~passlib.utils.has_salt_info`)

.. attribute:: PasswordHash.max_salt_size

    maximum number of characters which will be used
    if a salt string is provided to :meth:`~PasswordHash.genconfig` or :meth:`~PasswordHash.encrypt`.
    must be one of:

    * A positive integer - it should accept and silently truncate
      any salt strings longer than this size.

    * ``None`` - the scheme should use all characters of a provided salt,
      no matter how large.

.. attribute:: PasswordHash.min_salt_size

    minimum number of characters required for any salt string
    provided to :meth:`~PasswordHash.genconfig` or :meth:`~PasswordHash.encrypt`.
    must be an integer within ``range(0,max_salt_size+1)``.

.. attribute:: PasswordHash.default_salt_size

    size of salts generated by genconfig
    when no salt is provided by caller.
    for most hashes, this defaults to :attr:`~PasswordHash.max_salt_size`.
    this value must be within ``range(min_salt_size, max_salt_size+1)``.

.. attribute:: PasswordHash.salt_chars

    string containing list of all characters which are allowed
    to be specified in salt parameter.
    for most :ref:`MCF <modular-crypt-format>` hashes,
    this is equal to :data:`passlib.utils.h64.CHARS`.

    this must be a :class:`!unicode` string if the salt is encoded,
    or (rarely) :class:`!bytes` if the salt is manipulating as unencoded raw bytes.

.. todo::

    This section lists the behavior for handlers which accept
    salt strings containing encoded characters.
    Some handlers may instead expect raw bytes for their salt keyword,
    and handle encoding / decoding them internally.
    It should be documented how these attributes
    behave in that situation.

..
    not yet documentated, want to make sure this is how we want to do things:

    .. attribute:: PasswordHash.default_salt_chars

        sequence of characters used to generated new salts
        when no salt is provided by caller.
        for most hashes, this is the same as :attr:`!PasswordHash.salt_chars`;
        but some hashes accept a much larger range of values
        than are typically used. This field allows
        the full range to be accepted, while only
        a select subset to be used for generation.

    xxx: what about a bits_per_salt_char or some such, so effective salt strength
    can be compared?

.. _hash-unicode-behavior:

Unicode Behavior
================

.. versionadded:: 1.5

Quick summary
-------------
For the application developer in a hurry:

* Passwords should be provided as :class:`unicode` if possible.
  While they may be provided as :class:`bytes`,
  in that case it is strongly suggested
  they be encoded using ``utf-8`` or ``ascii``.

* Passlib will always return hashes as native python strings.
  This means :class:`unicode` under Python 3,
  and ``ascii``-encoded :class:`bytes` under Python 2.

* Applications should provide hashes as :class:`unicode` if possible.
  However, ``ascii``-encoded :class:`bytes` are also accepted
  under Python 2.

The following sections detail the issues surrounding
encoding password hashes, and the behavior required
by handlers implementing this API.
It can be skipped by the uninterested.

Passwords
---------
Applications are strongly encouraged to provide passwords
as :class:`unicode`. Two situations where an application
might need to provide a password as :class:`bytes`:
the application isn't unicode aware (lots of python 2 apps),
or it needs to verify a password hash that used a specific encoding (eg ``latin-1``).
For either of these cases, application developers should consider
the following issues:

*  Most hashes in Passlib operate on a string of bytes.
   For handlers implementing such hashes,
   passwords provided as :class:`unicode` should be encoded to ``utf-8``,
   and passwords provided as :class:`bytes` should be treated as opaque.

   A few of these hashes officially specify this behavior;
   the rest have no preferred encoding at all,
   so this was chosen as a sensible standard behavior.
   Unless the underlying algorithm specifies an alternate policy,
   handlers should always encode unicode to ``utf-8``.

*  Because of the above behavior for :class:`unicode` inputs,
   applications which encode their passwords are urged
   to use ``utf-8`` or ``ascii``,
   so that hashes they generate with encoded bytes
   will verify correctly if/when they start using unicode.

   Applications which need to verify existing hashes
   using an alternate encoding such as ``latin-1``
   should be wary of this future "gotcha".

*  A few hashes operate on :class:`unicode` strings instead.
   For handlers implementing such hashes:
   passwords provided as :class:`unicode` should be handled as appropriate,
   and passwords provided as :class:`bytes` should be treated as ``utf-8``,
   and decoded.

   This behavior was chosen in order to be compatible with
   the common case (above), combined with the fact
   that applications should never need to use a specific
   encoding with these hashes, as they are natively unicode.

   (The only hashes in Passlib like this are
   :class:`~passlib.hash.oracle10` and :class:`~passlib.hash.nthash`)

Hashes
------
With the exception of plaintext passwords,
literally *all* of the hash formats surveyed by the Passlib authors
use only the characters found in 7-bit ``ascii``.
This has caused most password hashing code (in python and elsewhere)
to draw a very blurry line between :class:`unicode` and :class:`bytes`.
Because of that, the following behavior was dictated less
by design requirements, and more by compatibility
and ease of implementation issues:

*   Handlers should accept hashes as either :class:`unicode` or
    as ``ascii``-encoded :class:`bytes`.

    This behavior allows applications to provide hashes
    as unicode or as bytes, as they please; making
    (among other things) migration to Python 3 easier.

    The primary exception to this is handlers implementing
    plaintext passwords. The implementations in passlib generally
    use ``utf-8`` to encode unicode passwords,
    and reproduce existing passwords as opaque bytes.

*   Internally, it is recommended that handlers
    operate on :class:`unicode` for parsing / formatting
    purposes, and using :class:`bytes` only on decoded
    data to be passed directly into their digest routine.

*   Handlers should return hashes as native python strings.
    This means :class:`unicode` under Python 3,
    and ``ascii``-encoded :class:`bytes` under Python 2.

    This behavior was chosen to fit with Python 3's
    unicode-oriented philosophy, while retaining
    backwards compatibility with Passlib 1.4 and earlier
    under Python 2.

    Handlers should use the :func:`passlib.utils.to_hash_str` function
    to coerce their unicode hashes to whatever is appropriate
    for the platform before returning them.

.. rubric:: Footnotes

.. [#otypes]    While this specification is written referring to classes and classmethods,
                password hash handlers can be any type of object (instance, module, etc),
                so long as they offer attributes and functions with the required
                signatures. For example, some of the handlers in Passlib are
                instances of the :class:`~passlib.utils.handlers.PrefixWrapper` class.

.. [#supported] all supported password hashes, whether builtin or registered
                from an external source can be found in the :mod:`passlib.hash` module.
