==========================================
PassLib |release| documentation
==========================================

Introduction
============
PassLib is a library for encrypting, verifying, and managing password hashes.
It supports over 20 current and historical password hash schemes.
It can be used for a variety of purposes:

* cross-platform replacement for stdlib's ``crypt()``.
* encrypting & verifying most known hash formats used by:
    - Linux & BSD shadow files
    - Apache htpasswd & htdigest files
    - MySQL, PostgreSQL, Oracle user account tables
    - LDAP
* drop-in password hashing for new python applications.
* building a configurable hashing policy
  for python applications to migrate existing hashing schemes.

Quick Links
===========

* See the :doc:`Library Overview <overview>` for more details about passlib.

* See the :doc:`Installation Instructions <install>` to get PassLib installed on your system.

* See the :mod:`passlib.hash <passlib.hash>` module for a complete list of supported hash algorithms.
