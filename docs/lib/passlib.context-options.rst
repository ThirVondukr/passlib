.. index::
    single: CryptContext; constructor options

.. _cryptcontext-options:

=============================================
:mod:`passlib.context` - CryptContext options
=============================================

.. currentmodule:: passlib.context

The :class:`CryptContext` accepts a number of keyword options.
These are divides into the "context options", which affect
the context instance directly, and the "hash options",
which affect the context treats a particular type of hash:

Context Options
===============
The following keyword options are accepted by both the :class:`CryptContext`
and :class:`CryptPolicy` constructors, and directly affect the behavior
of the :class:`!CryptContext` instance itself:

``schemes``
    List of handler names and/or instances which the CryptContext should recognize.
    This is usually required.

    For use in INI files, this may also be specified as a single comma-separated string
    of handler names.

    Any names specified must be registered globally with PassLib.

    Example: ``schemes=["sha256_crypt", "md5_crypt", "des_crypt"]``.

``deprecated``

    List of handler names which should be considered deprecated by the CryptContext.
    This should be a subset of the names of the handlers listed in schemes.
    This is optional, if not specified, no handlers will be considered deprecated.

    For use in INI files, this may also be specified as a single comma-separated string
    of handler names.

    This is primarily used by :meth:`CryptContext.hash_needs_update` and :meth:`CryptPolicy.handler_is_deprecated`.
    If the application does not use these methods, this option can be ignored.

    Example: ``deprecated=["des_crypt"]``.

``default``

    Specifies the name of the default handler to use when encrypting a new password.
    If no default is specified, the first handler listed in ``schemes`` will be used.

    Example: ``default="sha256_crypt"``.

``min_verify_time``

    If specified, all :meth:`CryptContext.verify` calls will take at least this many seconds.
    If set to an amount larger than the time used by the strongest hash in the system,
    this prevents an attacker from guessing the strength of particular hashes through timing measurements.

    Specified in integer or fractional seconds.

    Example: ``min_verify_time=0.1``.

.. note::

    For symmetry with the format of the hash option keywords (below),
    all of the above context option keywords may also be specified
    using the format :samp:`context__{option}` (note double underscores),
    or :samp:`context.{option}` within INI files.

.. note::

    To override context options for a particular :ref:`user category <user-categories>`,
    use the format :samp:`{category}__context__{option}`,
    or :samp:`{category}.context.{option}` within an INI file.

Hash Options
============
The following keyword options are accepted by both the :class:`CryptContext`
and :class:`CryptPolicy` constructors, and affect how a :class:`!CryptContext` instance
treats hashes belonging to a particular hash scheme, as identified by the hash's handler name.

All hash option keywords should be specified using the format :samp:`{hash}__{option}`
(note double underscores); where :samp:`{hash}` is the name of the hash's handler,
and :samp:`{option}` is the name of the specific options being set.
Within INI files, this may be specified using the alternate format :samp:`{hash}.{option}`.

:samp:`{hash}__default_rounds`

    Sets the default number of rounds to use when generating new hashes (via :meth:`CryptContext.encrypt`).

    If not set, this will use max rounds hash option (see below),
    or fall back to the algorithm-specified default.
    For hashes which do not support a rounds parameter, this option is ignored.

:samp:`{hash}__vary_rounds`

    if specified along with :samp:`{hash}__default_rounds`,
    this will cause each new hash created by :meth:`CryptContext.encrypt`
    to have a rounds value random chosen from the range :samp:`{default_rounds} +/- {vary_rounds}`.

    this may be specified as an integer value, or as a string containing an integer
    with a percent suffix (eg: ``"10%"``). if specified as a percent,
    the amount varied will be calculated as a percentage of the :samp:`{default_rounds}` value.

    The default passlib policy sets this to ``"10%"``.

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
:samp:`{category}__{hash}__{option}`` or ``{category}__context__{option}``.

.. note::

    For implementation & predictability purposes,
    the context option ``schemes`` cannot be overridden per-category,
    though all other options are allowed. In most cases,
    the need to use a different hash for a particular category
    can instead be acheived by overridden the ``default`` context option.

Default Policy
==============
PassLib defines a library-default policy, providing (hopefully) sensible defaults for new contexts.
When a new CryptContext is created, a policy is generated from it's constructor arguments, which is then composited
over the library-default policy. You may optionally override the default policy used by overriding the ``policy`` keyword
of CryptContext. This default policy object may be imported as :data:`passlib.context.default_policy`,
or viewed in the source code under ``$SOURCE/passlib/default.cfg``.

Sample Policy File
==================
A sample policy file::

    [passlib]
    #configure what schemes the context supports (note the "context." prefix is implied for these keys)
    schemes = md5_crypt, sha512_crypt, bcrypt
    deprecated = md5_crypt
    default = sha512_crypt
    min_verify_time = 0.1

    #set some common options for all schemes
    all.vary_rounds = 10%

    #setup some hash-specific defaults
    sha512_crypt.min_rounds = 40000
    bcrypt.min_rounds = 10

    #create a "admin" category, which uses bcrypt by default, and has stronger hashes
    admin.context.fallback = bcrypt
    admin.sha512_crypt.min_rounds = 100000
    admin.bcrypt.min_rounds = 13

And the equivalent as a set of python keyword options::

    dict(
        #configure what schemes the context supports (note the "context." prefix is implied for these keys)
        schemes = ["md5_crypt", "sha512_crypt", "bcrypt" ],
        deprecated = ["md5_crypt"],
        default = "sha512_crypt",
        min_verify_time = 0.1,

        #set some common options for all schemes
        all__vary_rounds = "10%",

        #setup some hash-specific defaults
        sha512_crypt__min_rounds = 40000,
        bcrypt__min_rounds = 10,

        #create a "admin" category, which uses bcrypt by default, and has stronger hashes
        admin__context__fallback = bcrypt
        admin__sha512_crypt__min_rounds = 100000
        admin__bcrypt__min_rounds = 13
    )
