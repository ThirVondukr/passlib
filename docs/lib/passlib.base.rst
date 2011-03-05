=============================================
:mod:`passlib.base` - Crypt Contexts
=============================================

.. currentmodule:: passlib.base

For more complex deployment scenarios than
the frontend functions described in :doc:`Quick Start </quickstart>`,
the CryptContext class exists...

.. autoclass:: CryptContext

Context Configuration Policy
============================
.. warning::

    This section's writing and design are still very much in flux.

Each CryptContext instance is extremely configuration through a wide range
of options. All of these options can be specified via the CryptContext
constructor, or by loading the configuration of a section of an ini file
(allowing an application's password policy to be specified externally).

All configuration options are stored in a CryptPolicy object,
which can be created in the following ways:

* passing in options as keywords to it's constructor
* loading options from a section of a :mod:`ConfigParser` ini file.
* compositing together existing CryptPolicy objects (this allows for default policies, application policies, and run-time policies)

Hash Configuration Options
==========================
Options for configuring a specific hash take the form of the name of
``{name}.{option}`` (eg ``sha512_crypt.default_rounds``); where ``{name}`` is usually the name of a password hash,
and ``{option}`` is one of the options specified below.
There are a few reserved hash names:
Any options of the form ``all.{option}`` will be inherited by all hashes
if they do not have a ``{hash}.{option}`` value overriding the default.
Any options of the form ``context.{option}`` will be treated as options for the context object itself,
and not for a specified hash. Any options of the form ``{option}`` are taken to implicitly
belong to the context, and are treated as if they started with the prefix ``context.``.
The remaining options -

``context.schemes``
    comma separated list of the schemes this context should recognize, specified by name.
    when a context is identifying hashes, it will check each scheme in this list
    in order. if this value is being specified programmatically,
    it may also be a python list containing a mixture of names
    and password hash handler objects.

``context.deprecated``
    comma separated list of the schemes which this context should recognize,
    generated hashes only if explicitly requested, and for which ``context.hash_needs_update()`` should return ``False``.
    if not specified, none are considered deprecated.
    this must be a subset of the names listed in context.schemes

``context.default``
    the default scheme context should use for generating new hashes.
    if not specified, the first entry in ``context.schemes`` is used.

``context.min_verify_time``
    if specified, all ``context.verify()`` calls will take at least this many seconds.
    if set to an amount larger than the time used by the strongest hash in the system,
    this prevents an attacker from guessing the strength of particular hashes remotely.
    (specified in fractional seconds).

``{hash}.min_rounds``, ``{hash}.max_rounds``

    place limits on the number of rounds allowed for a specific hash.

    * these are configurable per-context limits, hard limits set by algorithm are always applied
    * if min > max, max will be increased to equal min.
    * ``context.genconfig()`` or ``config.encrypt()`` - requests outside of these bounds will be clipped.
    * ``context.hash_needs_update()`` - existing hashes w/ rounds outside of range are not compliant
    * for hashes which do not have a rounds parameter, these values are ignored.

``{hash}.default_rounds``

    sets the default number of rounds to use when generating new hashes.

    * if this value is out side of per-policy min/max, it will be clipped just like user provided value.
    * ``context.genconfig()`` or ``config.encrypt()`` - if rounds are not provided explicitly, this value will be used.
    * for hashes which do not have a rounds parameter, this value is ignored.
    * if not specified, max_rounds is used if available, then min_rounds, then the algorithm default.

``{hash}.vary_rounds``

    [only applies if ``{hash}.default_rounds`` is specified and > 0]

    if specified, every time a new hash is created using {hash}/default_rounds for it's rounds value,
    the actual value used is generated at random, using default_rounds as a hint.

    * integer value - a value will be chosen using the formula ``randint(default_rounds-vary_rounds, default_rounds+vary_rounds)``.
    * integer value between 0 and 100 with ``%`` suffix - same as above, with integer value equal to ``vary_rounds*default_rounds/100``.
    * note that if algorithms indicate they use a logarthmic rounds parameter, the percent syntax equation uses ``log(vary_rounds*(2**default_rounds)/100,2)``,
      to permit a default value to be applicable to all schemes. XXX: this might be a bad / overly complex idea.

``{hash}.{setting}``
    any keys which match the name of a configuration parameter accepted by the hash
    will be used directly as default values.

    * for security purposes, ``salt`` is *forbidden* from being used in this way.
    * if ``rounds`` is specified directly, it will override the entire min/max/default_rounds framework.

``{hash}.{other}``
    any keys which do not fall under the above categories will be ignored

User Categories
===============
One frequent need is for certain categories of users (eg the root account)
to have more strigent password requirements than default users.
PassLib allows this by recognizing options of the format ``{category}.{name}.{option}``,
and allowing many of it's entry methods to accept an optional ``category`` parameter.

When one is specified, any ``{category}.{name}.{option}`` keywords in the configuration
will override any ``{name}.{option}`` keywords.

In order to simplify behavior and implementation, categories cannot override the ``context/schemes`` keyword,
though they may override the other context keys.

Default Policies
================
PassLib defines a library-default policy, updated perodically, providing (hopefully) sensible defaults for the various contexts.
When a new CryptContext is created, a policy is generated from it's constructor arguments, which is then composited
over the library-default policy. You may optionally override the default policy used by overriding the ``policy`` keyword
of CryptContext. This keyword accepts a single CryptPolicy object or string (which will be treated as an ini file to load);
it also accepts a list of CryptPolicys and/or strings, which will be composited together along with any constructor options.

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

    #create a "root" category, which uses bcrypt by default, and has stronger hashes
    root.context.fallback = bcrypt
    root.sha512_crypt.min_rounds = 100000
    root.bcrypt.min_rounds = 13

.. class:: CryptPolicy

    Stores configuration options for a CryptContext object.

    Policy objects can be constructed by the following methods:

    .. automethod:: from_path
    .. automethod:: from_string
    .. automethod:: from_source
    .. automethod:: from_sources

    .. method:: (constructor)

        You can specify options directly to the constructor.
        This accepts dot-seperated keywords such as found in the config file format,
        but for programmatic convience, it also accepts keys with ``.`` replaced with ``__``,
        allowing options to be specified programmatically in python.
