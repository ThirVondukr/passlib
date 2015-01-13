================
Library Overview
================

Passlib is a collection of routines for managing password hashes
such as found in unix "shadow" files, as returned by stdlib's :func:`!crypt`,
as stored in mysql and postgres, and various other places.
Passlib's contents can be roughly grouped into three categories:
password hashes, password contexts, and utility functions.

Password Hashes
===============
All of the hash schemes supported by Passlib are implemented
as classes which can be imported from the :mod:`passlib.hash` module.
In turn, all of the hash classes implement a single uniform interface,
which is documented in detail and with usage examples in the
:ref:`password-hash-api` document.
However, many of these hashes are severely insecure, provided only for legacy
purposes, or are specialized in ways that are not generally useful.
If you are creating a new application and need to choose a password hash,
see the :doc:`new_app_quickstart`.

.. seealso::

    - :mod:`passlib.hash` -- all the hashes supported by Passlib.
    - :ref:`password-hash-api` -- documentation of the common PasswordHash interface.
    - :doc:`new_app_quickstart` -- choosing a hash for new applications.

Password Contexts
=================
Mature applications frequently have to deal with tables of existing password hashes.
Over time, they have to support a number of tasks:

* add support for new algorithms, and deprecate old ones,
* raise the time-cost settings for existing algorithms, as computing power increases,
* and do rolling upgrades of existing hashes to comply with these changes.
* hardcode these policies in the source, or spend time implementing
  a configuration language for them.

In these situations, loading and handling multiple hash algorithms becomes
complicated and tedious. The :mod:`passlib.context` module provides a single class,
:class:`!CryptContext`, which attempts to solve all of these problems,
or at least relieve applications developers of (most of) the burden.
This class handles managing multiple password hash schemes,
deprecation & migration of old hashes, and supports a simple configuration
language that can be serialized to an INI file.

.. seealso::

    * :ref:`CryptContext Tutorial <context-tutorial>` -- complete walkthrough of the CryptContext class.
    * :ref:`CryptContext API Reference <context-reference>` -- full method and attribute documentation.

Application Helpers
===================
Passlib also provides a number of pre-configured :class:`!CryptContext` instances
in order to get users started quickly:

    * :mod:`passlib.apps` -- contains pre-configured
      instances for managing hashes used by Postgres, Mysql, and LDAP, and others.

    * :mod:`passlib.hosts` -- contains pre-configured
      instances for managing hashes as found in the /etc/shadow files
      on Linux and BSD systems.

Passlib also contains a couple of additional modules which provide
support for certain application-specific tasks:

    * :mod:`passlib.apache` -- classes for managing htpasswd and htdigest files.

    * :mod:`passlib.ext.django` -- Django plugin which monkeypatches support for (almost) any hash in Passlib.

Utility Functions
=================
Additionally, Passlib contains a number of modules which are used internally
to implement the all of the other features. These may change between major
releases, and won't be needed by most users of Passlib. They are documented
mainly to aid in examining the source.

    * :mod:`passlib.exc` -- all the custom errors & warnings used by Passlib.
    * :mod:`passlib.registry` -- functions for registering password hash algorithms.
    * :mod:`passlib.utils` -- support functions for implementing password hashes.
