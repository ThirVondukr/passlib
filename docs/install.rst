============
Installation
============

.. index:: Google App Engine; compatibility

Supported Platforms
===================
Passlib requires Python 2 (>= 2.5) or Python 3.
It is known to work with the following Python implementations:

* CPython 2 -- v2.5 or newer.
* CPython 3 -- all versions.
* PyPy -- v1.5 or newer.
* Jython -- v2.5 or newer.

Passlib should work with all operating systems and enviroments,
as it contains builtin fallbacks
for almost all OS-dependant features.
Google App Engine is supported as well.

.. _optional-libraries:

Optional Libraries
==================
* `py-bcrypt <http://code.google.com/p/py-bcrypt/>`_ or
  `bcryptor <https://bitbucket.org/ares/bcryptor/overview>`_

   If either of these packages are installed, they will be used to provide
   support for the BCrypt hash algorithm.
   This is required if you want to handle BCrypt hashes,
   and your OS does not provide native BCrypt support
   via stdlib's :mod:`!crypt` (which includes pretty much all non-BSD systems).

* `M2Crypto <http://chandlerproject.org/bin/view/Projects/MeTooCrypto>`_

   If installed, M2Crypto will be used to accelerate some internal
   functions used by PBKDF2-based hashes, but it is not required
   even in that case.

Installation Instructions
=========================
To install from PyPi using :command:`pip`::

    pip install passlib

To install from PyPi using :command:`easy_install`::

    easy_install passlib

To install from the source using :command:`setup.py`::

    python setup.py install

.. index::
    pair: environmental variable; PASSLIB_TEST_MODE

.. rst-class:: html-toggle

Testing
=======
Passlib contains a comprehensive set of unittests (about 38% of the total code),
which provide nearly complete coverage, and verification of the hash
algorithms using multiple external sources (if detected at runtime).
All unit tests are contained within the :mod:`passlib.tests` subpackage,
and are designed to be run using the
`Nose <http://somethingaboutorange.com/mrl/projects/nose>`_ unit testing library.

Once Passlib and Nose have been installed, the main suite of tests may be run from the source directory::

    nosetests --tests passlib/tests

To run the full test suite, which includes internal cross-checks and mock-testing
of features not provided natively by the host OS::

    PASSLIB_TEST_MODE="full" nosetests --tests passlib/tests

Tests may also be run via ``setup.py test`` or the included ``tox.ini`` file.

.. rst-class:: html-toggle

Building the Documentation
==========================
The latest copy of this documentation should always be available
online at `<http://packages.python.org/passlib>`_.
If you wish to generate your own copy of the documentation,
you will need to:

1. Install `Sphinx <http://sphinx.pocoo.org/>`_ (1.1 or newer)
2. Install the `Cloud Sphinx Theme <http://packages.python.org/cloud_sptheme>`_ (1.4 or newer).
3. Download the Passlib source
4. From the Passlib source directory, run :samp:`python setup.py build_sphinx`.
5. Once Sphinx completes it's run, point a web browser to the file at :samp:`{SOURCE}/build/sphinx/html/index.html`
   to access the Passlib documentation in html format.
6. Alternately, steps 4 & 5 can be replaced by running :samp:`python setup.py docdist`,
   which will build a zip file of the documentation in :samp:`{SOURCE}/dist`.
