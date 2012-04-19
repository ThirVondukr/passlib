.. index:: CryptContext; constructor options

.. _cryptcontext-options:

=============================================
:mod:`passlib.context` - Constructor Options
=============================================

.. currentmodule:: passlib.context

The :class:`CryptContext` accepts a number of keyword options.
These can be provided to any of the CryptContext constructor methods,
as well as the :meth:`CryptContext.update` method, or any configuration
string or INI file passed to :meth:`CryptContext.load`.

The options are divided into two categories: "context options", which directly
affect the :class:`!CryptContext` object itself; and "hash options", which
affect the behavior of a particular password hashing scheme.

.. seealso::

    * :doc:`passlib.context-usage`

    * :doc:`passlib.context-interface`

Context Options
===============
The following keyword options directly affect the behavior
of the :class:`!CryptContext` instance itself:

``schemes``
    List of handler names and/or instances which the CryptContext should recognize.
    This is usually required.

    For use in INI files, this may also be specified as a single comma-separated string
    of handler names.

    Potential names can include the name of any class importable from the :mod:`passlib.hash` module.
    For example, to specify the :class:`passlib.hash.sha256_crypt` and the :class:`passlib.hash.des_crypt` schemes
    should be supported for your new context::

        >>> myctx = CryptContext(schemes=["sha256_crypt", "des_crypt"])

``deprecated``

    List of handler names which should be considered deprecated by the CryptContext.
    This should be a subset of the names of the handlers listed in *schemes*.
    This is optional, and if not specified, no handlers will be considered deprecated.

    For INI files, this may also be specified as a single comma-separated string
    of handler names.

    This is primarily used by :meth:`CryptContext.hash_needs_update`.
    If the application does not use this method, this option can be ignored.

    Example: ``deprecated=["des_crypt"]``.

``default``

    Specifies the name of the default handler to use when encrypting a new password.
    If no default is specified, the first handler listed in ``schemes`` will be used.
    Any name specified *must* be in the list of supported schemes (see the ``schemes`` kwd).

    Example: ``default="sha256_crypt"``.

.. _min-verify-time:

``min_verify_time``

    If specified, unsuccessful :meth:`CryptContext.verify` calls will take at
    least this many seconds. Specified in integer or fractional seconds.

    Example: ``min_verify_time=0.1``.

    .. deprecated:: 1.6 this option is not very useful, and will be removed
                    in version 1.8.

.. note::

    For symmetry with the format of the hash option keywords (below),
    all of the above context option keywords may also be specified
    using the format :samp:`context__{option}` (note double underscores).

.. note::

    To override context options for a particular :ref:`user category <user-categories>`,
    use the format :samp:`{category}__context__{option}`.

Hash Options
============
The following keyword option affect how a :class:`!CryptContext` instance
treats hashes belonging to a particular hash scheme,
as identified by the scheme's name.

All hash option keywords should be specified using the format :samp:`{hash}__{option}`
(note double underscores); where :samp:`{hash}` is the name of the hash's handler,
and :samp:`{option}` is the name of the specific options being set.

:samp:`{hash}__default_rounds`

    Sets the default number of rounds to use when generating new hashes (via :meth:`CryptContext.encrypt`).

    If not set, this will use an algorithm-specific default.
    For hashes which do not support a rounds parameter, this option is ignored.

:samp:`{hash}__vary_rounds`

    If specified along with :samp:`{hash}__default_rounds`,
    this will cause each new hash created by :meth:`CryptContext.encrypt`
    to have a rounds value random chosen from the range :samp:`{default_rounds} +/- {vary_rounds}`.

    This may be specified as an integer value, or as a string containing an integer
    with a percent suffix (eg: ``"10%"``). If specified as a percent,
    the amount varied will be calculated as a percentage of the :samp:`{default_rounds}` value.

    .. note::

        If this is specified as a percentage, and the hash algorithm
        uses a logarithmic rounds parameter, the amount varied
        will be calculated based on the effective number of linear rounds,
        not the actual rounds value.
        This allows ``vary_rounds`` to be given a default value for all hashes
        within a context, and behave sanely for both linear and logarithmic rounds parameters.

:samp:`{hash}__min_rounds`, :samp:`{hash}__max_rounds`

    Place limits on the number of rounds allowed for a specific hash.
    ``min_rounds`` defaults to 0, ``max_rounds`` defaults to unlimited.

    When encrypting new passwords with the specified hash (via :meth:`CryptContext.encrypt`),
    the number of rounds will be clipped to these boundaries.
    When checking for out-of-date hashes (via :meth:`CryptContext.hash_needs_update`),
    it will flag any whose rounds are outside the range specified as needing to be re-encrypted.
    For hashes which do not support a rounds parameter, these options are ignored.

    .. note::

        These are configurable per-context limits,
        they will be clipped by any hard limits set in the hash algorithm itself.

.. _passprep:

:samp:`{hash}__passprep`

    Normalize unicode passwords before passing them to the underlying
    hash algorithm. This is primarily useful if users are likely
    to use non-ascii characters in their password (e.g. vowels characters
    with accent marks), which unicode offers multiple representations for.

    This may be one of the following values:

    * ``"raw"`` - use all unicode inputs as-is (the default).
      unnormalized unicode input may not verify against a hash
      generated from normalized unicode input (or vice versa).

    * ``"saslprep"`` - run all passwords through the SASLPrep
      unicode normalization algorithm (:rfc:`4013`) before hashing.
      this is recommended for new deployments, particularly
      in non-ascii environments.

    * ``"saslprep,raw"`` - compatibility mode: encryption of new passwords
      will be run through SASLPrep; but verification will be done
      against the SASLPrep *and* raw versions of the password. This allows
      existing hashes that were generated from unnormalized input
      to continue to work.

    .. note::

        It is recommended to set this for all hashes via ``all__passprep``,
        instead of settings it per algorithm.

    .. note::

        Due to a missing :mod:`!stringprep` module, this feature
        is not available on Jython.

:samp:`{hash}__{setting}`

    Any other option values, which match the name of a parameter listed
    in the hash algorithm's ``handler.setting_kwds`` attribute,
    will be passed directly to that hash whenever :meth:`CryptContext.encrypt` is called.

    For security purposes, ``salt`` is *forbidden* from being used in this way.

    If ``rounds`` is specified directly, it will override the entire min/max/default_rounds framework.

.. note::

    Default options which will be applied to all hashes within the context
    can be specified using the special hash name ``all``. For example, ``all__vary_rounds="10%"``
    would set the ``vary_rounds`` option to ``"10%"`` for all hashes, unless
    it was overridden for a specific hash, such as by specifying ``sha256_crypt__vary_rounds="5%"``.
    This feature is generally only useful for the ``vary_rounds`` hash option.

.. _user-categories:

User Categories
===============
CryptContext offers an optional feature of "user categories":

User categories take the form of a string (eg: ``admin`` or ``guest``),
passed to the CryptContext when one of it's methods is called.
These may be set by an application to indicate the hash belongs
to a user account which should be treated according to a slightly
different set of configuration options from normal user accounts;
this may involve requiring a stronger hash scheme, a larger
number of rounds for that scheme, or just a longer verify time.

If an application wishes to use this feature, it all that is needed
is to prefix the name of any hash or context options with the name
of the category string it wants to use, and add an additional separator to the keyword:
:samp:`{category}__{hash}__{option}`` or :samp:`{category}__context__{option}`.

.. note::

    For implementation & predictability purposes,
    the context option ``schemes`` cannot be overridden per-category,
    though all other options are allowed. In most cases,
    the need to use a different hash for a particular category
    can instead be acheived by overridden the ``default`` context option.

Sample Config File
==================
A sample config file:

.. code-block:: ini

    [passlib]
    # configure what schemes the context supports
    # (note that the "context__" prefix is implied for these keys)
    schemes = md5_crypt, sha512_crypt, bcrypt
    deprecated = md5_crypt
    default = sha512_crypt

    # set some common options for all schemes
    # (this particular setting causes the rounds value to be varied
    # +/- 10% for each encrypt call)
    all__vary_rounds = 0.1

    # setup some hash-specific defaults
    sha512_crypt__min_rounds = 40000
    bcrypt__min_rounds = 10

    # create an "admin" category which uses bcrypt by default,
    #  and has stronger default cost
    admin__context__default = bcrypt
    admin__sha512_crypt__min_rounds = 100000
    admin__bcrypt__min_rounds = 13

This can be turned into a :class:`!CryptContext` via :meth:`CryptContext.from_path`,
or loaded into an existing object via :meth:`CryptContext.load`.

And the equivalent of the above, as a set of Python keyword options::

    dict(
        # configure what schemes the context supports
        # (note the "context__" prefix is implied for these keys)
        schemes = ["md5_crypt", "sha512_crypt", "bcrypt" ],
        deprecated = ["md5_crypt"],
        default = "sha512_crypt",

        # set some common options for all schemes
        # (this particular setting causes the rounds value to be varied
        # +/- 10% for each encrypt call)
        all__vary_rounds = 0.1,

        # setup some hash-specific defaults
        sha512_crypt__min_rounds = 40000,
        bcrypt__min_rounds = 10,

        # create a "admin" category which uses bcrypt by default,
        # and has stronger default cost
        admin__context__default = bcrypt,
        admin__sha512_crypt__min_rounds = 100000,
        admin__bcrypt__min_rounds = 13,
    )

This can be turned into a :class:`CryptContext` via the class constructor,
or loaded into an existing object via :meth:`CryptContext.load`.
