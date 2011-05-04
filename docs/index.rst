==========================================
PassLib |release| documentation
==========================================

Welcome
=======
Passlib is a password hashing library for Python, which provides cross-platform
implementations of over 20 password hashing algorithms;
as well as a framework for managing and migrating existing password hashes.
It's designed to be useful for a large range of tasks...

* as a cross-platform replacement for stdlib's :func:`!crypt` --> :data:`~passlib.hosts.host_context`.

* encrypting & verifying most hash formats used by:
    - Linux & BSD shadow files --> :mod:`passlib.hosts`
    - Apache htpasswd & htdigest files --> :mod:`passlib.apache`
    - MySQL, PostgreSQL, and Oracle user account tables
    - OpenLDAP password hashes
    - Many other applications --> :mod:`passlib.apps`.

* drop-in password hash support for new python applications --> :data:`~passlib.apps.custom_app_context`.

* building a configurable hashing policy
  for python applications to migrate existing hashing schemes --> :mod:`passlib.context`.

See the :doc:`library overview <overview>` for more details and usage examples.

Quick Links
===========

.. raw:: html

    <table class="contentstable" align="center">
    <tr>
        <td width="50%" valign="top">
            <p class="biglink">
                <a class="biglink" href="overview.html">Library Overview</a><br>
                <span class="linkdescr">describes how Passlib is laid out</span>
            </p>

            <p class="biglink">
                <a class="biglink" href="lib/passlib.hash.html"><i>passlib.hash</i> module</a><br>
                <span class="linkdescr">complete list of supported password hash algorithms</span>
            </p>
        </td>
        <td width="50%" valign="top">
            <p class="biglink">
                <a class="biglink" href="install.html">Installation</a><br>
                <span class="linkdescr">requirements and installation instructions</span>
            </p>

            <p class="biglink">
                <a class="biglink" href="history.html">Changelog</a><br>
                <span class="linkdescr">history of current and past releases</span>
            </p>
    </tr>
    </table>

Online Resources
================

.. rst-class:: html-plain-table

=============== ===================================================
**Homepage**:   `<http://code.google.com/p/passlib>`_
**Docs**:       `<http://packages.python.org/passlib>`_
**Discussion**: `<http://groups.google.com/group/passlib-users>`_

**PyPI**:       `<http://pypi.python.org/pypi/passlib>`_
**Downloads**:  `<http://code.google.com/p/passlib/downloads>`_
**Source**:     `<http://code.google.com/p/passlib/source>`_
=============== ===================================================
