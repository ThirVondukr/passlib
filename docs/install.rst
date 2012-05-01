============
Installation
============

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
* `py-bcrypt <http://www.mindrot.org/projects/py-bcrypt/>`_ or
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
To download and install using :command:`easy_install`::

    easy_install passlib

To download and install using :command:`pip`::

    pip install passlib

To install from a source directory using :command:`setup.py`::

    python setup.py install

.. rst-class:: html-toggle

Testing
=======
Passlib contains a comprehensive set of unittests providing nearly complete coverage.
All unit tests are contained within the :mod:`passlib.tests` subpackage,
and are designed to be run using the
`Nose <http://somethingaboutorange.com/mrl/projects/nose>`_ unit testing library.

Once Passlib and Nose have been installed, the tests may be run from the source directory::

    # to run the full passlib test suite...
    PASSLIB_TEST_MODE="full" nosetests -v --tests passlib/tests

Tests may also be run via ``setup.py test`` or the included ``tox.ini`` file.

.. note::

    Due to the critical nature of password hashing, Passlib's unittest framework
    is rather extensive, covering the behavior of all the classes, 8-bit
    test vectors for all supported hashes, and some primitive fuzz testing;
    it occupies ~38% of the Passlib codebase. Because of this, the full test
    suite make take some time to run. Setting ``PASSLIB_TEST_MODE`` to
    ``"quick"`` or ``"default"`` will speed things up.

.. rst-class:: html-toggle

Documentation
=============
The latest copy of this documentation should always be available
online at `<http://packages.python.org/passlib>`_.

If you wish to generate your own copy of the documentation,
you will need to:

1. Install `Sphinx <http://sphinx.pocoo.org/>`_ (1.0 or better)
2. Install the `Cloud Sphinx Theme <http://packages.python.org/cloud_sptheme>`_.
3. Download the Passlib source
4. From the Passlib source directory, run :samp:`python setup.py build_sphinx`.
5. Once Sphinx completes it's run, point a web browser to the file at :samp:`{$SOURCE}/build/sphinx/html/index.html`
   to access the Passlib documentation in html format.
6. Alternately, steps 4 & 5 can be replaced by running :samp:`python setup.py docdist`,
   which will build a zip file of the documentation in :samp:`{$SOURCE}/dist`.
