.. index:: CryptContext; usage examples, CryptContext; overview

.. _cryptcontext-overview:

==============================================
:mod:`passlib.context` - CryptContext Overview
==============================================

.. module:: passlib.context
    :synopsis: CryptContext class for managing multiple password hash schemes

Overview
========
Different storage contexts (eg: linux shadow files vs openbsd shadow files)
may use different sets and subsets of the available algorithms.
Similarly, over time, applications may need to deprecate password schemes
in favor of newer ones, or raise the number of rounds required
by existing hashes.

This module provides the :class:`CryptContext` class, which is designed
to handle (as much as possible) of these tasks for an application.
Essentially, a :class:`!CryptContext` instance contains a list
of hash handlers that it should recognize, along with information
about which ones are deprecated, which is the default,
and what configuration constraints an application has placed
on a particular hash.

.. seealso::

    * :doc:`passlib.context-interface` -- for a list of all class and instance methods

    * :doc:`passlib.context-options` -- for a list of all the keyword options accepted by these classes.

Usage Examples
==============

Basic Usage
-----------
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
    >>> hash2 = myctx.encrypt("too many secrets", scheme="des-crypt")
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

Policy Examination
------------------
If introspection of a :class:`!CryptContext` instance
is needed, all configuration options are stored in a :class:`CryptPolicy` instance accessible through
their ``policy`` attribute::

    >>> from passlib.context import CryptContext
    >>> myctx = CryptContext([ "md5_crypt", "des_crypt" ], deprecated="des_crypt")

    >>> #get a list of schemes recognized in this context:
    >>> myctx.policy.schemes()
    [ 'md5-crypt', 'bcrypt' ]

    >>> #get the default handler class :
    >>> myctx.policy.get_handler()
    <class 'passlib.handlers.md5_crypt.md5_crypt'>

Full Integration
----------------
The following is an extended example of how PassLib can be integrated into an existing
application to provide runtime policy changes, deprecated hash migration,
and other features. This is example uses a lot of different features,
and many developers will want to pick and choose what they need from this example.

Policy Options File
...................
Instead of creating a CryptContext instance manually,
or importing an existing one (eg :data:`~passlib.apps.custom_app_context`),
applications with advanced policy requirements may want to create a hash policy file
(options show below are detailed in :ref:`cryptcontext-options`)::

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
    pbkdf2_sha1.vary_rounds = 10%

    ;applications can choose to treat certain user accounts differently,
    ;by assigning different types of account to a 'user category',
    ;and setting special policy options for that category.
    ;this create a category named 'admin', which will have a larger default rounds value.
    admin.pbkdf2_sha1.min_rounds = 40000
    admin.pbkdf2_sha1.default_rounds = 50000

Integrating a CryptContext
--------------------------
Integrating a crypt context is merely a matter of adding the following
bits of code to your application.

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

            user_pwd_context.policy = CryptPolicy.from_path(path_to_policy_file)

            #
            #if you want to reconfigure the context without restarting the application,
            #simply repeat the above step at another point.
            #

            #
            # ... other code ...
            #


3. When it comes time to create a new user's password, insert
   the following code in the correct function::


        from myapp.model.security import user_pwd_context

        def handle_user_creation():

            #
            # ... other code ...
            #

            #
            #   'secret' containing the putative password
            #   'category' containing a category assigned to the user account
            #
            #the 'category' kwd can be omitted, OR:
            #set to a string matching a user category specified in the policy file,
            #in which case the category-specific policy settings will be enforced.
            #for this example, assume it's None for most users, and "admin" for special users.
            #this namespace is entirely application chosen, it just has to match the policy file.
            #

            hash = user_pwd_context.encrypt(secret, category=category)

            #... perform appropriate actions to store hash...

            #
            # ... other code ...
            #

4. Finally, when it comes time to check a users' password, insert
   the following code at the correct place::

        from myapp.model.security import user_pwd_context

        def handle_user_login():

            #
            # ... other code ...
            #

            #
            #this example both checks the user's password AND upgrades deprecated hashes...
            #given the following variables:
            #   'hash' containing the specified user's hash,
            #   'secret' containing the putative password
            #   'category' containing a category assigned to the user account
            #
            #see note in step 3 about the category kwd
            #


            ok, new_hash = user_pwd_context.verify_and_update(secret, hash, category=category)
            if not ok:
                #... password did not match. do mean things ...
            else:
                #... password matched ...

                if new_hash:
                    # old hash was deprecated by policy.

                    # ... replace hash w/ new_hash for user account ...

                #... do successful login actions ...

   For those who don't want to use any of the hash update features,
   the following template can be used instead::

        from myapp.model.security import user_pwd_context

        def handle_user_login():

            #
            # ... other code ...
            #

            ok = user_pwd_context.verify(secret, hash, category=category)
            if not ok:
                #... password did not match. do mean things ...
            else:
                #... password matched ...
                #... do successful login actions ...
