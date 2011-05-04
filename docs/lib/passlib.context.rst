.. index:: CryptContext; usage examples, CryptContext; overview

.. _cryptcontext-overview:

==============================================
:mod:`passlib.context` - CryptContext Overview
==============================================

.. module:: passlib.context
    :synopsis: CryptContext class for managing multiple password hash schemes

Motivation
==========
Though there is a wide range of password hashing schemes,
within a specific context (like a linux "shadow" file)
only a select list of schemes will be used.
As time goes on, new schemes are added and made the default,
the strength of existing schemes is tweaked, and other schemes are deprecated entirely.
Throughout all this, existing password hashes that don't comply
with the new policies must be detected and rehashed using the
new default configuration. In order to automate as much of these tasks as possible,
this module provides the :class:`CryptContext` class.

Essentially, a :class:`!CryptContext` instance contains a list
of hash handlers that it should recognize, along with information
about which ones are deprecated, which is the default,
and what configuration constraints an application has placed
on a particular scheme. While contexts can be created explicitly,
Passlib also offers a number of predefined :class:`!CryptContext` instances
which can be used out-of-the box (see :mod:`passlib.apps` and :mod:`passlib.hosts`),
or :ref:`modified <using-predefined-contexts>` to suit the application.

Subtopics
=========
New users should see the usage examples
in the next section to get a feel for how the :class:`!CryptContext` class works.

.. toctree::
    :maxdepth: 1

    passlib.context-usage
    passlib.context-interface
    passlib.context-options
