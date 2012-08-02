================================
New Application Quickstart Guide
================================

Need to quickly get password hash support added into your new application,
and don't have time to wade through pages of documentation,
comparing and constrasting all the different schemes? Read on...

Really Quick Start
==================
The fastest route is to use the preconfigured
:data:`~passlib.apps.custom_app_context` object.
It supports the :class:`~passlib.hash.sha256_crypt`
and :class:`~passlib.hash.sha512_crypt` schemes,
and defaults to 40000 hash iterations for increased strength.
For applications which want to quickly add password hashing,
all they need to do is the following::

    >>> # import the context under an app-specific name (so it can easily be replaced later)
    >>> from passlib.apps import custom_app_context as pwd_context

    >>> # encrypting a password...
    >>> hash = pwd_context.encrypt("somepass")

    >>> # verifying a password...
    >>> ok = pwd_context.verify("somepass", hash)

    >>> # [optional] encrypting a password for an admin account...
    >>> #            the custom_app_context is preconfigured so that
    >>> #            if the category is set to "admin" instead of None,
    >>> #            it uses a stronger setting of 80000 rounds:
    >>> hash = pwd_context.encrypt("somepass", category="admin")

For applications which started using this preset, but whose needs
have grown beyond it, it is recommended to create your own :mod:`CryptContext <passlib.context>`
instance; see below for more...

.. index:: Passlib; recommended hash algorithms

.. _recommended-hashes:

Choosing a Hash
================
*If you already know what hash algorithm(s) you want to use,
skip to the next section,* `Creating and Using a CryptContext`_.

If you'd like to set up a configuration that's right for your
application, the first thing to do is choose a password hashing scheme.
Passlib contains a large number of schemes, but most of them
should only be used when a specific format is explicitly required.
For new applications, there are really only three choices [#choices]_:

    * :class:`~passlib.hash.bcrypt`
    * :class:`~passlib.hash.sha512_crypt`
    * :class:`~passlib.hash.pbkdf2_sha512`

All three password hashes share the following properties:

    * no known vulnerabilties.
    * based on documented & widely reviewed algorithms.
    * basic algorithm has seen heavy scrutiny
      and use for at least 10 years.
    * public-domain or BSD-licensed reference implementations available.
    * in use across a number of OSes and/or a wide variety of applications.
    * variable rounds for configuring flexible cpu cost on a per-hash basis.
    * at least 96 bits of salt.

The following comparison should help you choose which hash is
most appropriate for your application; if in doubt,
any of these is a good choice, though PBKDF2 is probably the best
for portability.

.. rst-class:: html-toggle

Detailed Comparison of Choices
------------------------------

BCrypt
......
:class:`~passlib.hash.bcrypt`
is `based <http://www.usenix.org/event/usenix99/provos/provos_html/>`_
on the well-tested Blowfish cipher. In use since 1999,
it's the default hash on all BSD variants. If you want your application's
hashes to be readable by the native BSD crypt() function, this is the hash to use.
There is also an alternative LDAP-formatted version
(:class:`~passlib.hash.ldap_bcrypt`) available.

Issues: Neither the original Blowfish,
nor the modified version which BCrypt uses, have been NIST approved;
this matter of concern is what motivated the development of SHA512-Crypt.
As well, its rounds parameter is logarithmically scaled,
making it hard to fine-tune the amount of time taken to verify passwords;
which can be an issue for applications that handle a large number
of simultaneous logon attempts (e.g. web apps).

.. note::

    For BCrypt support on non-BSD systems,
    Passlib requires the C-extension provided by
    `py-bcrypt <http://code.google.com/p/py-bcrypt/>`_.
    (py-bcrypt does not currently support Python 3).

SHA512-Crypt
............
:class:`~passlib.hash.sha512_crypt` is
based on the well-tested :class:`~passlib.hash.md5_crypt`
algorithm. In use since 2008, it's the default hash on most Linux systems;
its direct ancestor :class:`!md5_crypt` has been in use since 1994 on most Unix systems.
If you want your application's hashes to be readable by the
native Linux crypt() function, this is the hash to use.
There is also :class:`~passlib.hash.sha256_crypt`, which may be faster
on 32 bit processors; as well as LDAP-formatted versions of these (
:class:`~passlib.hash.ldap_sha512_crypt` and
:class:`~passlib.hash.ldap_sha256_crypt`).

Issues: Like :class:`~passlib.hash.md5_crypt`, its algorithm
composes the underlying message digest hash in a baroque
and somewhat arbitrary set combinations.
So far this "kitchen sink" design has been successful in its
primary purpose: to prevent any attempts to create an optimized
version for use in a pre-computed or brute-force search.
However, this design also hampers analysis of the algorithm
for future flaws.

.. index:: Google App Engine; recommended hash algorithm

:class:`~passlib.hash.sha512_crypt` is probably the best choice for Google App Engine,
as Google's production servers appear to provide native support
via :mod:`crypt`, which will be used by Passlib.

.. note::

    References to this algorithm are frequently confused with a raw SHA-512 hash.
    While :class:`!sha512_crypt` uses the SHA-512 hash as a cryptographic primitive,
    the algorithm's resulting password hash is far more secure.

PBKDF2
......
:class:`~passlib.hash.pbkdf2_sha512` is a custom has format designed for Passlib.
However, it directly uses the
`PBKDF2 <http://tools.ietf.org/html/rfc2898#section-5.2>`_
key derivation function, which was standardized in 2000, and found across a
`wide variety <http://en.wikipedia.org/wiki/PBKDF2#Systems_that_use_PBKDF2>`_
of applications and platforms. Unlike the previous two hashes,
PBKDF2 has a simple and portable design,
which is resistant (but not immune) to collision and preimage attacks
on the underlying message digest.
There is also :class:`~passlib.hash.pbkdf2_sha256`, which may be faster
on 32 bit processors; as well as LDAP-formatted versions of these (
:class:`~passlib.hash.ldap_pbkdf2_sha512` and
:class:`~passlib.hash.ldap_pbkdf2_sha256`).

Issues: PBKDF2 has no security or portability issues.
However, it has only come into wide use as a password hash
in recent years; mainly hampered by the fact that there is no
standard format for encoding password hashes using this algorithm
(which is why Passlib has its own :ref:`custom format <mcf-pbkdf2-format>`).

.. note::

    Passlib strongly suggests installing
    the external M2Crypto package to speed up PBKDF2 calculations,
    though this is not required.

.. index:: SCrypt; status of

What about SCrypt?
..................
`SCrypt <http://www.tarsnap.com/scrypt.html>`_ is the leading contender
to be the next-generation password hash algorithm. It offers many advances
over all of the above hashes; the primary feature being that it has
a variable *memory* cost as well as time cost. It is incredibly well designed,
and looks to likely replace all the others in this section.

However, it is still young by comparison to the others; and has not been as throughly
tested, or widely implemented. The only Python wrapper that exists
does not even expose the underlying :func:`!scrypt` function,
but is rather a file encryption tool.
Due to these reasons, SCrypt has not yet been integrated into Passlib.

.. seealso:: :issue:`8` of the Passlib bugtracker, for the current status of Passlib's SCrypt support.

Creating and Using a CryptContext
=================================
One you've chosen what password hash(es) you want to use,
the next step is to define a :class:`~passlib.context.CryptContext` object
to manage your hashes, and relating configuration information.
Insert the following code into your application::

    #
    # import the CryptContext class, used to handle all hashing...
    #
    from passlib.context import CryptContext

    #
    # create a single global instance for your app...
    #
    pwd_context = CryptContext(
        # replace this list with the hash(es) you wish to support.
        # this example sets pbkdf2_sha256 as the default,
        # with support for legacy des_crypt hashes.
        schemes=["pbkdf2_sha256", "des_crypt" ],
        default="pbkdf2_sha256",

        # vary rounds parameter randomly when creating new hashes...
        all__vary_rounds = 0.1,

        # set the number of rounds that should be used...
        # (appropriate values may vary for different schemes,
        # and the amount of time you wish it to take)
        pbkdf2_sha256__default_rounds = 8000,
        )

To start using your CryptContext, import the context you created wherever it's needed::

    >>> # import context from where you defined it...
    >>> from myapp.model.security import pwd_context

    >>> # encrypting a password...
    >>> hash = pwd_context.encrypt("somepass")
    >>> hash
    '$pbkdf2-sha256$7252$qKFNyMYTmgQDCFDS.jRJDQ$sms3/EWbs4/3k3aOoid5azwq3HPZKVpUUrAsCfjrN6M'

    >>> # verifying a password...
    >>> pwd_context.verify("somepass", hash)
    True
    >>> pwd_context.verify("wrongpass", hash)
    False

.. seealso::

    * :mod:`passlib.hash` -- list of all hashes supported by passlib.
    * :ref:`CryptContext Overview & Tutorial <context-overview>` -- walkthrough of how to use the CryptContext class.
    * :ref:`CryptContext Reference <context-reference>` -- reference for the CryptContext api.

.. rubric:: Footnotes

.. [#choices] BCrypt, SHA-512 Crypt, and PBKDF2 are the most commonly
              used password hashes as of Aug 2012, when this document
              last updated. You should make sure you are reading a current
              copy of the Passlib documentation, in case the state
              of things has changed.
