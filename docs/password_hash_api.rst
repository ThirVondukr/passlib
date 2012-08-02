.. index::
    single: PasswordHash interface
    single: custom hash handler; requirements

.. module:: passlib.ifc
    :synopsis: abstract interfaces used by Passlib

.. _password-hash-api:

=============================================
Password Hash Interface
=============================================

Overview
========
While the exact options and behavior will vary between algorithms,
all of the hashes provided by Passlib use the same interface,
defined by the following abstract base class:

.. class:: PasswordHash()

    This class provides an abstract interface for
    an arbitrary password hashing algorithm.
    While it offers a number of methods and attributes,
    but most applications will only need the two primary methods:

    * :meth:`~PasswordHash.encrypt` - generate new salt, return hash of password.
    * :meth:`~PasswordHash.verify` - verify password against existing hash.

    While not needed by most applications, the following methods
    provide an interface that mimics the traditional Unix :func:`crypt`
    function:

    * :meth:`~PasswordHash.genconfig` - create configuration string from salt & other options.
    * :meth:`~PasswordHash.genhash` - hash password using existing hash or configuration string.

    One additional support method is provided:

    * :meth:`~PasswordHash.identify` - check if hash belongs to this algorithm.

    Each hash algorithm also provides a number of :ref:`informational attributes <informational-attributes>`,
    allowing programmatic inspection of it's options and parameter limits.

.. _password-hash-examples:

Usage Examples
==============
The following code shows how to use the primary
methods of the :class:`~passlib.ifc.PasswordHash` interface --
:meth:`~PasswordHash.encrypt` and :meth:`~PasswordHash.verify` --
using the :class:`~passlib.hash.sha256_crypt` hash as an example::

    >>> # import the handler class
    >>> from passlib.hash import sha256_crypt

    >>> # hash a password using the default settings:
    >>> hash = sha256_crypt.encrypt("password")
    >>> hash
    '$5$rounds=40000$HIo6SCnVL9zqF8TK$y2sUnu13gp4cv0YgLQMW56PfQjWaTyiHjVbXTgleYG9'

    >>> # note that each call to encrypt() generates a new salt,
    >>> # and thus the contents of the hash will differ, despite using the same password:
    >>> sha256_crypt.encrypt("password")
    '$5$rounds=40000$1JfxoiYM5Pxokyh8$ez8uV8jjXW7SjpaTg2vHJmx3Qn36uyZpjhyC9AfBi7B'

    >>> # if the hash supports a variable number of iterations (which sha256_crypt does),
    >>> # you can override the default value via the 'rounds' keyword:
    >>> sha256_crypt.encrypt("password", rounds=12345)
    '$5$rounds=12345$UeVpHaN2YFDwBoeJ$NJN8DwVZ4UfQw6.ijJZNWoZtk1Ivi5YfKCDsI2HzSq2'
               ^^^^^

    >>> # on the other end of things, the verify() method takes care of
    >>> # checking if a password matches an existing hash string:
    >>> sha256_crypt.verify("password", hash)
    True
    >>> sha256_crypt.verify("letmeinplz", hash)
    False

.. note::

    Whether a hash supports a particular configuration keywoard (such as ``rounds``)
    can be determined from it's documentation page; but also programmatically from
    it's :attr:`~PasswordHash.setting_kwds` attribute.

That concludes the most basic example, but there are a few more
common use-cases, such as how to use the :meth:`~PasswordHash.identify` method::

    >>> # attempting to call verify() with another algorithm's hash will result in a ValueError:
    >>> from passlib.hash import sha256_crypt, md5_crypt
    >>> other_hash = md5_crypt.encrypt("password")
    >>> sha256_crypt.verify("password", other_hash)
    Traceback (most recent call last):
        <traceback omitted>
    ValueError: not a valid sha256_crypt hash

    >>> # this can be prevented by using the identify method,
    >>> # determines whether a hash belongs to a given algorithm:
    >>> hash = sha256_crypt.encrypt("password")
    >>> sha256_crypt.identify(hash)
    True
    >>> sha256_crypt.identify(other_hash)
    False

While the initial :meth:`~PasswordHash.encrypt` example works for most hashes,
a small number of algorithms require you provide external data
(such as a username) every time a hash is calculated.
An example of this is the :class:`~passlib.hash.oracle10` algorithm::

    >>> # for oracle10, encrypt requires a username:
    >>> from passlib.hash import oracle10
    >>> hash = oracle10.encrypt("secret", user="admin")
    'B858CE295C95193F'

    >>> # the difference between this and something like the rounds setting (above)
    >>> # is that oracle10 also requires the username when verifying a hash:
    >>> oracle10.verify("secret", hash, user="admin")
    True

    >>> # if either the username OR password is wrong, verify() will fail:
    >>> oracle10.verify("secret", hash, user="wronguser")
    False
    >>> oracle10.verify("wrongpassword", hash, user="admin")
    False

    >>> # forgetting to include the username when it's required will cause a TypeError:
    >>> hash = oracle10.encrypt("password")
    Traceback (most recent call last):
        <traceback omitted>
    TypeError: user must be unicode or bytes, not None

.. note::

    Whether a hash requires external parameters (such as ``user``)
    can be determined from it's documentation page; but also programmatically from
    it's :attr:`~PasswordHash.context_kwds` attribute.

.. _primary-methods:

Primary Methods
===============
Most applications will only need to use two methods:
:meth:`~PasswordHash.encrypt` to generate new hashes, and :meth:`~PasswordHash.verify`
to check passwords against existing hashes.
These methods provide an easy interface for working with a password hash,
and abstract away details such as salt generation, hash normalization,
and hash comparison.

.. classmethod:: PasswordHash.encrypt(secret, \*\*kwds)

    Digest password using format-specific algorithm,
    returning resulting hash string.

    For most hashes supported by Passlib, this string will include
    an algorithm identifier, a copy of the salt (if applicable),
    and any other configuration information required to verify the password later.

    :type secret: unicode or bytes
    :arg secret: string containing the password to encode.

    :param \*\*kwds:

        All additional keywords are algorithm-specific, and will be listed
        in that hash's documentation; though many of the more common keywords
        are listed under :attr:`~PasswordHash.setting_kwds`
        and :attr:`~PasswordHash.context_kwds`.
        Examples of common keywords include ``rounds`` and ``salt_size``.

    :returns:
        Resulting hash of password, using an algorithm-specific format.

        This will always be an instance of :class:`!str`
        (i.e. :class:`unicode` under Python 3, ``ascii``-encoded :class:`bytes` under Python 2).

    :raises ValueError:

        * If a keyword's value is invalid (e.g. if a ``salt`` string
          is too small, or a ``rounds`` value is out of range).

        * If the ``secret`` contains characters forbidden by the handler
          (e.g. :class:`!des_crypt` forbids NULL characters).

    :raises TypeError:

        * if ``secret`` is not unicode or bytes.
        * if a keyword argument had an incorrect type.
        * if a required keyword was not provided.

    *(Note that the name of this method is a misnomer, password hashes
    are typically based on irreversible cryptographic operations,
    see* :issue:`21` *).*

    .. versionchanged:: 1.6
        Hashes now raise :exc:`TypeError` if a required keyword is missing,
        rather than :exc:`ValueError` like in previous releases; in order
        to conform with normal Python behavior.

    .. versionchanged:: 1.6
        Passlib is now much stricter about input validation: for example,
        out-of-range ``rounds`` values now cause an error instead of being
        clipped (though applications may set :ref:`relaxed=True <relaxed-keyword>`
        to restore the old behavior).

.. classmethod:: PasswordHash.verify(secret, hash, \*\*context_kwds)

    Verify a secret using an existing hash.

    This checks if a secret matches against the one stored
    inside the specified hash.

    :type secret: unicode or bytes
    :param secret:
        A string containing the password to check.

    :type secret: unicode or bytes
    :param hash:
        A string containing the hash to check against,
        such as returned by :meth:`~encrypt`.

        Hashes may be specified as :class:`!unicode` or
        ``ascii``-encoded :class:`!bytes`.

    :param \*\*kwds:
        Very few hashes will have additional keywords.

        The ones that do typically require external contextual information
        in order to calculate the digest. For these hashes,
        the values must match the ones passed to the original
        :meth:`~PasswordHash.encrypt` call when the hash was generated,
        or the password will not verify.

        These additional keywords are algorithm-specific, and will be listed
        in that hash's documentation; though the more common keywords
        are listed under :attr:`~PasswordHash.context_kwds`.
        Examples of common keywords include ``user``.

    :returns:
        ``True`` if the secret matches, otherwise ``False``.

    :raises TypeError:
        * if either *secret* or *hash* is not a unicode or bytes instance.
        * if the hash requires additional keywords which are not provided,
          or have the wrong type.

    :raises ValueError:
        * if *hash* does not match this algorithm's format.
        * if the secret contains forbidden characters (see
          :meth:`~PasswordHash.encrypt`).
        * if a configuration/salt string generated by :meth:`~PasswordHash.genconfig`
          is passed in as the value for *hash* (these strings look
          similar to a full hash, but typically lack the digest portion
          needed to verify a password).

    .. versionchanged:: 1.6
        This function now raises :exc:`ValueError` if a ``None`` or config string is provided
        instead of a proper hash; previous releases were inconsistent
        in their handling of these cases.

.. _hash-unicode-behavior:

.. note::

    Regarding unicode passwords & non-ASCII characters:

    For the majority of hash algorithms and use-cases, passwords should
    be provided as either :class:`!unicode` or ``utf-8``-encoded :class:`!bytes`.
    There are only two major exceptions:

    * Some systems have legacy hashes that were generated using a different
      character encoding. In this case, all :class:`!unicode` passwords
      should be encoded using the correct encoding before they are hashed;
      otherwise non-ASCII passwords may not :meth:`!verify` successfully.

    * For historical reasons, :class:`~passlib.hash.lmhash` uses ``cp437``
      as it's default encoding. It will handle :class:`!unicode` correctly;
      but non-ASCII passwords provided as :class:`!bytes` must either be encoded
      using ``"cp437"``, or :class:`!lmhash`'s ``encoding`` keyword must
      be set to indicate which encoding was used.

.. _crypt-methods:

.. rst-class:: html-toggle

Crypt Methods
=============
Taken together, the :meth:`~PasswordHash.genconfig` and :meth:`~PasswordHash.genhash`
are two tightly-coupled methods that mimic the standard Unix
"crypt" interface. The first method generates salt / configuration
strings from a set of settings, and the second hashes the password
using the provided configuration string.

.. seealso::

    Most applications will find :meth:`~PasswordHash.encrypt` much more useful,
    as it combines the functionality of these two methods into one.

.. classmethod:: PasswordHash.genconfig(\*\*setting_kwds)

    Returns a configuration string encoding settings for hash generation.

    This function takes in all the same :attr:`~PasswordHash.setting_kwds`
    as :meth:`~PasswordHash.encrypt`, fills in suitable defaults,
    and encodes the settings into a single "configuration" string,
    suitable passing to :meth:`~PasswordHash.genhash`.

    :param \*\*kwds:
        All additional keywords are algorithm-specific, and will be listed
        in that hash's documentation; though many of the more common keywords
        are listed under :attr:`~PasswordHash.setting_kwds`
        Examples of common keywords include ``salt`` and ``rounds``.

    :returns:
        A configuration string (as :class:`!str`), or ``None`` if the scheme
        does not support a separate configuration.

    :raises ValueError, TypeError:
        This function raises exceptions for the same
        reasons as :meth:`~PasswordHash.encrypt`.

    .. note::

        This configuration string is typically the same as the full hash string,
        except that it lacks the final portion containing the digested password.
        This is sometimes referred to as a "salt" string, though it typically
        contains much more than just the salt parameter.

.. classmethod:: PasswordHash.genhash(secret, config, \*\*context_kwds)

    Encrypt secret using specified configuration string.

    This takes in a password and a configuration string,
    and returns a hash for that password.

    :type secret: unicode or bytes
    :arg secret:
        string containing the password to be encrypted.

    :type config: unicode or bytes or ``None``
    :arg config:
        configuration string to use when encrypting secret.
        this can either be an existing hash that was previously
        returned by :meth:`~PasswordHash.genhash`, or a configuration string
        that was previously created by :meth:`~PasswordHash.genconfig`.

        ``None`` is accepted *only* for the hashes which lack a configuration
        string (for which :meth:`~PasswordHash.genconfig` always returns ``None``).

    :param \*\*kwds:
        Very few hashes will have additional keywords.

        The ones that do typically require external contextual information
        in order to calculate the digest. For these hashes,
        the values must match the ones passed to the original
        :meth:`~PasswordHash.encrypt` call when the hash was generated,
        or the password will not verify.

        These additional keywords are algorithm-specific, and will be listed
        in that hash's documentation; though the more common keywords
        are listed under ::attr:`~PasswordHash.context_kwds`.
        Examples of common keywords include ``user``.

    :returns:
        Encoded hash matching specified secret, config, and kwds.
        This will always be a native :class:`!str` instance.

    :raises ValueError, TypeError:
        This function raises exceptions for the same
        reasons as :meth:`~PasswordHash.encrypt`.

    .. warning::

        Traditionally, password verification using the "crypt" interface
        was done by testing if ``hash == genhash(password, hash)``.
        This test is only reliable for a handful of algorithms,
        as various hash representation issues may cause false results.
        Applications are strongly urged to use :meth:`~PasswordHash.verify` instead.

.. _support-methods:

Support Methods
===============
There is currently one additional support method, :meth:`~PasswordHash.identify`:

.. classmethod:: PasswordHash.identify(hash)

    Quickly identify if a hash string belongs to this algorithm.

    :type hash: unicode or bytes
    :arg hash:
        the candidate hash string to check

    :returns:
        * ``True`` if the input is a configuration string or hash string
           identifiable as belonging to this scheme (even if it's malformed).
        * ``False`` if the input does not belong to this scheme.

    :raises TypeError:
        if :samp:`{hash}` is not a unicode or bytes instance.

    .. note::

        Hashes which lack a reliable method of identification may incorrectly
        identify each-other's hashes (e.g. both :class:`~passlib.hash.lmhash`
        and :class:`~passlib.hash.nthash` hash consist 32 hexidecimal characters).

    .. seealso::

        If you are considering using this method to select from multiple
        algorithms in order to verify a password, you may be better served
        by the :ref:`CryptContext <context-overview>` class.

..
    the undocumented and experimental support methods currently include
    parsehash() and bitsize()

.. _informational-attributes:

Informational Attributes
========================

.. _general-attributes:

General Information
-------------------
Each hash provides a handful of informational attributes, allowing
programs to dynamically adapt to the requirements of different
hash algorithms. The following attributes should be defined for all
the hashes in passlib:

.. attribute:: PasswordHash.name

    Name uniquely identifying this hash.

    For the hashes built into Passlib, this will always match
    the location where it was imported from — :samp:`passlib.hash.{name}` —
    though externally defined hashes may not adhere to this.

    This should always be a :class:`!str` consisting of lowercase ``a-z``,
    the digits ``0-9``, and the underscore character ``_``.

.. attribute:: PasswordHash.setting_kwds

    Tuple listing the keywords supported by :meth:`~PasswordHash.encrypt`
    and :meth:`~PasswordHash.genconfig` that control hash generation, and which will
    be encoded into the resulting hash.

    This list commonly includes keywords for controlling salt generation,
    adjusting time-cost parameters, etc. Most of these settings are optional,
    and suitable defaults will be chosen if they are omitted (e.g. salts
    will be autogenerated).

    While the documentation for each hash should have a complete list of
    the specific settings the hash uses, the following keywords should have
    roughly the same behavior for all the hashes that support them:

    .. index::
        single: salt; PasswordHash keyword

    ``salt``
        Specifies a fixed salt string to use, rather than randomly
        generating one.

        This option is supported by most of the hashes in Passlib,
        though typically it isn't used, as random generation of a salt
        is usually the desired behavior.

        Hashes typically require this to be a :class:`!unicode` or
        :class:`!bytes` instance, with additional constraints
        appropriate to the algorithm.

    .. index::
        single: salt_size; PasswordHash keyword

    ``salt_size``

        Most algorithms which support the ``salt`` setting will
        autogenerate a salt when none is provided. Most of those hashes
        will also offer this option, which allows the caller to specify
        the size of salt which should be generated. If omitted,
        the hash's default salt size will be used.

        .. seealso:: the :ref:`salt info <salt-attributes>` attributes (below)

    .. index::
        single: rounds; PasswordHash keyword

    ``rounds``
        If present, this means the hash can vary the number
        of internal rounds used in some part of it's algorithm,
        allowing the calculation to take a variable amount of processor
        time, for increased security.

        While this is almost always a non-negative integer,
        additional constraints may be present for each algorithm
        (such as the cost varying on a linear or logarithmic scale).

        This value is typically omitted, in which case a default
        value will be used. The defaults for all the hashes in Passlib
        are periodically retuned to strike a balance between
        security and responsiveness.

        .. seealso:: the :ref:`rounds info <rounds-attributes>` attributes (below)

    .. index::
        single: ident; PasswordHash keyword

    ``ident``
        If present, the class supports multiple formats for encoding
        the same hash. The class's documentation will generally list
        the allowed values, allowing alternate output formats to be selected.

        Note that these values will typically correspond to different
        revision of the hash algorithm itself, and they may not all
        offer the same level of security.

    .. index::
        single: relaxed; PasswordHash keyword

    .. _relaxed-keyword:

    ``relaxed``
        By default, passing :meth:`~PasswordHash.encrypt` an invalid
        value will result in a :exc:`ValueError`. However, if ``relaxed=True``,
        Passlib will attempt to correct the error, and if successful,
        issue a :exc:`~passlib.exc.PasslibHashWarning` instead.
        This warning may then be filtered if desired.
        Correctable errors include (but aren not limited to): ``rounds``
        and ``salt_size`` values that are too low or too high, ``salt``
        strings that are too large, etc.

        This option is supported by most of the hashes in Passlib.

.. attribute:: PasswordHash.context_kwds

    Tuple listing the keywords supported by :meth:`~PasswordHash.encrypt`,
    :meth:`~PasswordHash.verify`, and :meth:`~PasswordHash.genhash` affect the hash, but are
    not encoded within it, and thus must be provided each time
    the hash is calculated.

    This list commonly includes a user account, http realm identifier,
    etc. Most of these keywords are required by the hashes which support them,
    as they are frequently used in place of an embedded salt parameter.
    This is typically an empty tuple for most of the hashes in passlib.

    While the documentation for each hash should have a complete list of
    the specific context keywords the hash uses,
    the following keywords should have roughly the same behavior
    for all the hashes that support them:

    .. index::
        single: user; PasswordHash keyword

    ``user``

        If present, the class requires a username be specified whenever
        performing a hash calculation (e.g.
        :class:`~passlib.hash.postgres_md5` and
        :class:`~passlib.hash.oracle10`).

    .. index::
        single: encoding; PasswordHash keyword

    ``encoding``

        Some hashes have poorly-defined or host-dependant unicode behavior,
        and properly hashing a non-ASCII password requires providing
        the correct encoding (:class:`~passlib.hash.lmhash` is perhaps the worst offender).
        Hashes which provide this keyword will always expose
        their default encoding programmatically via the
        :attr:`~PasswordHash.default_encoding` attribute.

.. _salt-attributes:

Salt Information
----------------
For schemes which support a salt string,
``"salt"`` should be listed in their :attr:`~PasswordHash.setting_kwds`,
and the following attributes should be defined:

.. attribute:: PasswordHash.max_salt_size

    The maximum number of bytes/characters allowed in the salt.
    Should either be a positive integer, or ``None`` (indicating
    the algorithm has no effective upper limit).

.. attribute:: PasswordHash.min_salt_size

    The minimum number of bytes/characters required for the salt.
    Must be an integer between 0 or :attr:`~PasswordHash.max_salt_size`.

.. attribute:: PasswordHash.default_salt_size

    The default salt size that will be used when generating a salt,
    assuming ``salt_size`` is not set explicitly. This is typically
    the same as :attr:`max_salt_size`,
    or a sane default if ``max_salt_size=None``.

.. attribute:: PasswordHash.salt_chars

    A unicode string containing all the characters permitted
    in a salt string.

    For most :ref:`modular-crypt-format` hashes,
    this is equal to :data:`passlib.utils.HASH64_CHARS`.
    For the rare hashes where the ``salt`` parameter must be specified
    in bytes, this will be a placeholder :class:`!bytes` object containing
    all 256 possible byte values.

..
    not yet documentated, want to make sure this is how we want to do things:

    .. attribute:: PasswordHash.default_salt_chars

        sequence of characters used to generate new salts.
        this is typically the same as :attr:`~PasswordHash.salt_chars`, but some
        hashes accept a larger-than-useful range, and this will
        contain only the "common" values used for generation.

.. _rounds-attributes:

Rounds Information
------------------
For schemes which support a variable number of iterations to adjust their time-cost,
``"rounds"`` should be listed in :attr:`~PasswordHash.setting_kwds`,
and the following attributes should be defined:

.. attribute:: PasswordHash.max_rounds

    The maximum number of rounds the scheme allows.
    Specifying a value beyond this will result in a :exc:`ValueError`.
    Will be a positive integer, or ``None`` (indicating
    the algorithm has no effective upper limit).

.. attribute:: PasswordHash.min_rounds

    The minimum number of rounds the scheme allows.
    Specifying a value below this will result in a :exc:`ValueError`.
    Will always be an integer between 0 and :attr:`~PasswordHash.max_rounds`.

.. attribute:: PasswordHash.default_rounds

    The default number of rounds that will be used if none is explicitly
    provided to :meth:`~PasswordHash.encrypt`.
    This will always be an integer between :attr:`~PasswordHash.min_rounds`
    and :attr:`~PasswordHash.max_rounds`.

.. attribute:: PasswordHash.rounds_cost

    While the cost parameter ``rounds`` is an integer, how it corresponds
    to the amount of time taken can vary between hashes. This attribute
    indicates the scale used by the hash:

    * ``"linear"`` - time taken scales linearly with rounds value
      (e.g. :class:`~passlib.hash.sha512_crypt`)
    * ``"log2"`` - time taken scales exponentially with rounds value
      (e.g. :class:`~passlib.hash.bcrypt`)

..
    todo: haven't decided if this is how I want the api look before
    formally publishing it in the documentation:

    .. _password-hash-backends:

    Multiple Backends
    =================
    .. note::

        For the most part, applications will not need this interface,
        outside of perhaps calling the :meth:`~PasswordHash.get_backend`
        to determine which the active backend.

    Some hashes provided by Passlib have multiple backends which they
    select from at runtime, to provide the fastest implementation available.
    Algorithms which offer multiple backends will expose the following
    methods and attributes:

    .. attribute:: PasswordHash.backends

        Tuple listing names of potential backends (which may or may not be available).
        If this attribute is not present, the hash does not support
        multiple backends.

        While the names of the backends are specific to the hash algorithm,
        the following standard names may be present:

        * ``"os_crypt"`` - backend which uses stdlib's :mod:`!crypt` module.
          this backend will not be available if the underlying host OS
          does not support the particular hash algorithm.

        * ``"builtin"`` - backend using pure-python implementation built into
          Passlib. All hashes will have this as their last backend, as a fallback.

    .. method:: PasswordHash.get_backend()

        This method should return the name of the currently active backend
        that will be used by :meth:`!encrypt` and :meth:`!verify`.

        :raises passlib.exc.MissingBackendError:
            in the rare case that *no* backends can be loaded.

    .. method:: PasswordHash.has_backend(backend)

        This method can be used to test if a specific backend is available.
        Returns ``True`` or ``False``.

    .. method:: PasswordHash.set_backend(backend)

        This method can be used to select a specific backend.
        The ``backend`` argument must be one of the backends listed
        in :attr:`~PasswordHash.backends`, or the special value ``"default"``.

        :raises passlib.exc.MissingBackendError:
            if the specified backend is not available.

.. index:: rounds; choosing the right value

.. _rounds-selection-guidelines:

Choosing the right rounds value
===============================
Passlib's default rounds settings attempt to be secure enough for
the average [#avgsys]_ system. But the "right" value for a given hash
is dependant on the server, it's cpu, it's expected load, and it's users.
Since larger values mean increased work for an attacker,
**the right** ``rounds`` **value for a given server should be the largest
possible value that doesn't cause intolerable delay for your users**.
For most public facing services, you can generally have signin
take upwards of 250ms - 400ms before users start getting annoyed.
For superuser accounts, it should take as much time as the admin can stand
(usually ~4x more delay than a regular account).

Passlib's ``default_rounds`` values are retuned every major release (at a minimum)
by taking a rough estimate of what an "average" system is capable of,
and setting all the ``default_rounds`` values to take ~300ms on such a system.
However, some older algorithms (e.g. :class:`~passlib.hash.bsdi_crypt`) are weak enough that
a tradeoff must be made, choosing "secure but intolerably slow" over "fast but unacceptably insecure".
For this reason, it is strongly recommended to not use a value lower than Passlib's default.

.. [#avgsys] For Passlib 1.6, all hashes were retuned to take ~250ms on a
   system with a 3 ghz 64 bit CPU.
