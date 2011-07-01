============
Installation
============

Supported Platforms
===================
Passlib requires Python 2 (>= 2.5) or Python 3.
It should work with the following Python implementations:

* CPython 2 -- 2.5 or newer.
* CPython 3 -- all versions.
* PyPy -- 1.5 or newer.
* Jython -- 2.5 or newer.

Passlib should work with all operating systems,
as it contains builtin fallbacks
for almost all OS-dependant features.

Optional Libraries
==================
* `py-bcrypt <http://www.mindrot.org/projects/py-bcrypt/>`_ or
  `bcryptor <https://bitbucket.org/ares/bcryptor/overview>`_

   If either of these packages are installed, they will be used to provide
   support for the BCrypt hash algorithm.
   This is required if you want to handle BCrypt hashes,
   and your OS does not provide native BCrypt support
   via stdlib's :mod:`!crypt` (this is pretty much all non-BSD systems).

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

.. note::

    Passlib's source ships as Python 2 code,
    and the setup script invokes the :command:`2to3` tool + a preprocessor
    to translate the source to Python 3 code at install time.
    Aside from this internal detail,
    installation under Python 3
    should be identical to that of Python 2.

Testing
=======
PassLib contains a comprehensive set of unittests providing nearly complete coverage.
All unit tests are contained within the :mod:`passlib.tests` subpackage,
and are designed to be run using the
`Nose <http://somethingaboutorange.com/mrl/projects/nose>`_ unit testing library.

Once PassLib and Nose have been installed, the tests may be run from the source directory::

    # to run the platform-relevant tests...
    nosetests -v passlib/tests

    # to run all tests...
    PASSLIB_TESTS="all" nosetests -v passlib/tests

    # to run nose with the optional coverage plugin...
    # (results will be in build/coverage)
    PASSLIB_TESTS="all" nosetests -v passlib/tests --with-coverage \
        --cover-package=passlib --cover-html --cover-html-dir build/coverage

(There will be a large proportion of skipped tests, this is normal).

Documentation
=============
The latest copy of this documentation should always be available
online at `<http://packages.python.org/passlib>`_.

If you wish to generate your own copy of the documentation,
you will need to:

1. install `Sphinx <http://sphinx.pocoo.org/>`_ (1.0 or better)
2. install the `Cloud Sphinx Theme <http://packages.python.org/cloud_sptheme>`_.
3. download the PassLib source
4. from the PassLib source directory, run :samp:`python docs/make.py clean html`.
5. Once Sphinx completes it's run, point a web browser to the file at :samp:`{$SOURCE}/docs/_build/html/index.html`
   to access the PassLib documentation in html format.
