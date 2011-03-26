==========================================
PassLib |release| documentation
==========================================

Introduction
============
PassLib is a library for encrypting, verifying, and managing password hashes.
It supports over 20 different password hash schemes.
It can be used for a variety of purposes:

* cross-platform replacement for stdlib's :func:`!crypt`.
* encrypting & verifying most known hash formats used by:
    - Linux & BSD shadow files
    - Apache htpasswd & htdigest files
    - MySQL, PostgreSQL, and Oracle user account tables
    - LDAP style password hashes
* drop-in password hash support for new python applications.
* building a configurable hashing policy
  for python applications to migrate existing hashing schemes.

See the library overview for usage examples.

Quick Links
===========

.. raw:: html

    <table class="contentstable" align="center">
    <tr>
        <td width="50%" valign="top">
            <p class="biglink">
                <a class="biglink" href="overview.html">Library Overview</a><br>
                <span class="linkdescr">describes how PassLib is laid out</span>
            </p>

            <p class="biglink">
                <a class="biglink" href="install.html">Installation</a><br>
                <span class="linkdescr">requirements and installation instructions</span>
            </p>

            <p class="biglink">
                <a class="biglink" href="lib/passlib.hash.html"><i>passlib.hash</i> module</a><br>
                <span class="linkdescr">complete list of supported password hash algorithms</span>
            </p>
        </td>
    </tr>
    </table>

Online Resources
================
* **Homepage**:   `<http://code.google.com/p/passlib>`_
* **Docs**:       `<http://packages.python.org/passlib>`_
* **Discussion**: `<http://groups.google.com/group/passlib-users>`_

* **Downloads**:   `<http://code.google.com/p/passlib/downloads>`_
* **PyPI**:       `<http://pypi.python.org/pypi/passlib>`_
* **Source**:     `<http://code.google.com/p/passlib/source>`_
