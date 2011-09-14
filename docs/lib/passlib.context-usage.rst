.. index:: CryptContext; usage examples

.. _cryptcontext-examples:

====================================================
:mod:`passlib.context` - Usage Examples
====================================================

.. currentmodule:: passlib.context

This section gives examples on how to use the :class:`CryptContext` object
for a number of different use cases.

.. seealso::

    * :doc:`passlib.context-interface`

    * :doc:`passlib.context-options`

Basic Usage
===========
To start off with a simple example of how to create and use a CryptContext::

    >>> from passlib.context import CryptContext

    >>> #create a new context that only understands Md5Crypt & DesCrypt:
    >>> myctx = CryptContext([ "md5_crypt", "des_crypt" ])

    >>> #unless overidden, the first hash listed
    >>> #will be used as the default for encrypting
    >>> #(in this case, md5_crypt):
    >>> hash1 = myctx.encrypt("too many secrets")
    >>> hash1
    '$1$nH3CrcVr$pyYzik1UYyiZ4Bvl1uCtb.'

    >>> #the scheme may be forced explicitly,
    >>> #though it must be one of the ones recognized by the context:
    >>> hash2 = myctx.encrypt("too many secrets", scheme="des_crypt")
    >>> hash2
    'm9pvLj4.hWxJU'

    >>> #verification will autodetect the correct type of hash:
    >>> myctx.verify("too many secrets", hash1)
    True
    >>> myctx.verify("too many secrets", hash2)
    True
    >>> myctx.verify("too many socks", hash2)
    False

    >>> #you can also have it identify the algorithm in use:
    >>> myctx.identify(hash1)
    'md5_crypt'

    >>> #or just return the handler instance directly:
    >>> myctx.identify(hash1, resolve=True)
    <class 'passlib.handlers.md5_crypt.md5_crypt'>

.. _using-predefined-contexts:

Using Predefined CryptContexts
==============================
Passlib contains a number of pre-made :class:`!CryptContext` instances,
configured for various purposes
(see :mod:`passlib.apps` and :mod:`passlib.hosts`).
These can be used directly by importing them from passlib,
such as the following example:

    >>> from passlib.apps import ldap_context as pwd_context
    >>> pwd_context.encrypt("somepass")
    '{SSHA}k4Ap0wYJWMrkgNhptlntsPGETBBwEoSH'

However, applications which use the predefined contexts will frequently
find they need to modify the context in some way, such as selecting
a different default hash scheme. This is best done by importing
the original context, and then making an application-specific
copy; using the :meth:`CryptContext.replace` method to create
a mutated copy of the original object::

    >>> from passlib.apps import ldap_context
    >>> pwd_context = ldap_context.replace(default="ldap_md5_crypt")
    >>> pwd_context.encrypt("somepass")
    '{CRYPT}$1$Cw7t4sbP$dwRgCMc67mOwwus9m33z71'

Examining a CryptContext Instance
=================================
All configuration options for a :class:`!CryptContext` instance
are stored in a :class:`!CryptPolicy` instance accessible through
the :attr:`CryptContext.policy` attribute::

    >>> from passlib.context import CryptContext
    >>> myctx = CryptContext([ "md5_crypt", "des_crypt" ], deprecated="des_crypt")

    >>> #get a list of schemes recognized in this context:
    >>> myctx.policy.schemes()
    [ 'md5-crypt', 'bcrypt' ]

    >>> #get the default handler class :
    >>> myctx.policy.get_handler()
    <class 'passlib.handlers.md5_crypt.md5_crypt'>

See the :class:`CryptPolicy` class for more details on it's interface.

Full Integration Example
========================
The following is an extended example of how PassLib can be integrated into an existing
application to provide runtime policy changes, deprecated hash migration,
and other features. This is example uses a lot of different features,
and many developers will want to pick and choose what they need from this example.
The totality of this example is overkill for most simple applications.

Policy Configuration File
-------------------------

While it is possible to create a CryptContext instance manually, or to import an existing one,
applications with advanced policy requirements may want to create a hash policy file
(options show below are detailed in :ref:`cryptcontext-options`):

.. code-block:: ini

    ; the options file uses the INI file format,
    ; and passlib will only read the section named "passlib",
    ; so it can be included along with other application configuration.

    [passlib]

    ;setup the context to support pbkdf2_sha1, along with legacy md5_crypt hashes:
    schemes = pbkdf2_sha1, md5_crypt

    ;flag md5_crypt as deprecated
    ;   (existing md5_crypt hashes will be flagged as needs-updating)
    deprecated = md5_crypt

    ;set verify to always take at least 1/10th of a second
    min_verify_time = 0.1

    ;set boundaries for pbkdf2 rounds parameter
    ;   (pbkdf2 hashes outside this range will be flagged as needs-updating)
    pbkdf2_sha1.min_rounds = 10000
    pbkdf2_sha1.max_rounds = 50000

    ;set the default rounds to use when encrypting new passwords.
    ;the 'vary' field will cause each new hash to randomly vary
    ;from the default by the specified %.
    pbkdf2_sha1.default_rounds = 20000
    pbkdf2_sha1.vary_rounds = 10%%
        ; NOTE the '%' above has to be doubled due to configparser interpolation

    ;applications can choose to treat certain user accounts differently,
    ;by assigning different types of account to a 'user category',
    ;and setting special policy options for that category.
    ;this create a category named 'admin', which will have a larger default rounds value.
    admin.pbkdf2_sha1.min_rounds = 40000
    admin.pbkdf2_sha1.default_rounds = 50000

Initializing the CryptContext
-----------------------------
Applications which choose to use a policy file will typically want
to create the CryptContext at the module level, and then load
the configuration once the application starts:

1. Within a common module in your application (eg ``myapp.model.security``)::

        #
        #create a crypt context that can be imported and used wherever is needed...
        #the instance will be configured later.
        #
        from passlib.context import CryptContext
        user_pwd_context = CryptContext()

2. Within some startup function within your application::

        #
        #when the app starts, import the context from step 1 and
        #configure it... such as by loading a policy file (see above)
        #

        from myapp.model.security import user_pwd_context
        from passlib.context import CryptPolicy

        def myapp_startup():

            #
            # ... other code ...
            #

            # vars:
            #   policy_path - path to policy file defined in previous step
            #
            user_pwd_context.policy = CryptPolicy.from_path(policy_path)

            #
            #if you want to reconfigure the context without restarting the application,
            #simply repeat the above step at another point.
            #

            #
            # ... other code ...
            #

.. _context-encrypting-passwords:

Encrypting New Passwords
------------------------
When it comes time to create a new user's password, insert
the following code in the correct function::

    from myapp.model.security import user_pwd_context

    def handle_user_creation():

        #
        # ... other code ...
        #

        # vars:
        #   'secret' containing the putative password
        #   'category' containing a category assigned to the user account
        #

        hash = user_pwd_context.encrypt(secret, category=category)

        #... perform appropriate actions to store hash...

        #
        # ... other code ...
        #

.. note::

    In the above code, the 'category' kwd can be omitted entirely, *OR*
    set to a string matching a user category specified in the policy file.
    In the latter case, any category-specific policy settings will be enforced.
    For this example, assume it's ``None`` for most users, and ``"admin"`` for special users.
    this namespace is entirely application chosen, it just has to match the policy file.

    See :ref:`user-categories` for more details.

.. _context-verifying-passwords:

Verifying Existing Passwords
----------------------------
Finally, when it comes time to check a users' password, insert
the following code at the correct place::

    from myapp.model.security import user_pwd_context

    def handle_user_login():

        #
        # ... other code ...
        #

        #
        #vars:
        #   'hash' containing the specified user's hash,
        #   'secret' containing the putative password
        #   'category' containing a category assigned to the user account
        #
        #see note in "Encrypting New Passwords" about the category kwd
        #

        ok = user_pwd_context.verify(secret, hash, category=category)
        if not ok:
            #... password did not match. do mean things ...
            pass

        else:
            #... password matched ...
            #... do successful login actions ...
            pass

.. _context-migrating-passwords:

Verifying & Migrating Existing Passwords
----------------------------------------
The CryptContext object offers the ability to deprecate schemes,
set lower strength bounds, and then flag any existing hashes which
violate these limits.
Applications which want to re-encrypt any deprecated hashes
found in their database should use the following template
instead of the one found in the previous step::

    from myapp.model.security import user_pwd_context

    def handle_user_login():

        #
        # ... other code ...
        #

        #
        #this example both checks the user's password AND upgrades deprecated hashes...
        #given the following variables:
        #
        #vars:
        #   'hash' containing the specified user's hash,
        #   'secret' containing the putative password
        #   'category' containing a category assigned to the user account
        #
        #see note in "Encrypting New Passwords" about the category kwd
        #

        ok, new_hash = user_pwd_context.verify_and_update(secret, hash, category=category)
        if not ok:
            #... password did not match. do mean things ...
            pass

        else:
            #... password matched ...

            if new_hash:
                # old hash was deprecated by policy.

                # ... replace hash w/ new_hash for user account ...
                pass

            #... do successful login actions ...
