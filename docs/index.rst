==========================================
PassLib |release| documentation
==========================================

Welcome
=======
Passlib is a password hashing library for Python 2 & 3,
which provides cross-platform implementations of over 20 password hashing algorithms,
as well as a framework for managing existing password hashes.
It's designed to be useful for a large range of tasks, including:

* quick-start password hashing for new python applications ~
  :doc:`quickstart guide <new_app_quickstart>`

* constructing a configurable hashing policy
  to match the needs of any python application ~
  :data:`passlib.context`

* reading & writing Apache htpasswd / htdigest files ~
  :mod:`passlib.apache`

* creating & verifying hashes used by MySQL, PostgreSQL, OpenLDAP,
  and other applications ~
  :mod:`passlib.apps`

* creating & verifying hashes found in Unix "shadow" files ~
  :data:`passlib.hosts`

See the library overview for more details and usage examples.

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
                <a class="biglink" href="install.html">Installation</a><br>
                <span class="linkdescr">requirements and installation instructions</span>
            </p>
        </td>
        <td width="50%" valign="top">
            <p class="biglink">
                <a class="biglink" href="lib/passlib.hash.html">Supported Hashes</a><br>
                <span class="linkdescr">complete list of supported password hash algorithms</span>
            </p>

            <p class="biglink">
                <a class="biglink" href="history.html">Changelog</a><br>
                <span class="linkdescr">history of current and past releases</span>
            </p>
        </td>
    </tr>
    </table>

Online Resources
================

    .. rst-class:: html-plain-table

    ================ ===================================================
    **Homepage**:    `<http://passlib.googlecode.com>`_
    **Online Docs**: `<http://packages.python.org/passlib>`_
    **Discussion**:  `<http://groups.google.com/group/passlib-users>`_
    ---------------- ---------------------------------------------------
    ---------------- ---------------------------------------------------
    **PyPI**:        `<http://pypi.python.org/pypi/passlib>`_
    **Downloads**:   `<http://code.google.com/p/passlib/downloads>`_
    **Source**:      `<http://code.google.com/p/passlib/source>`_
    ================ ===================================================
