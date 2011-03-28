============
Installation
============

Requirements
============
* Python 2.5 - 2.7 is required.

    .. note::

        PassLib has not been tested with Python 2.4 or earlier,
        and no guarantees are made about whether PassLib will work with those versions.

    .. note::

        Python 3.x is **not** yet supported, work is ongoing.

* `py-bcrypt <http://www.mindrot.org/projects/py-bcrypt/>`_ (optional)

   If installed, pybcrypt will be used to support the BCrypt hash algorithm.
   This is required if you want to handle BCrypt hashes,
   and stdlib :mod:`!crypt` does not support BCrypt
   (which is pretty much all non-BSD systems).

* `M2Crypto <http://chandlerproject.org/bin/view/Projects/MeTooCrypto>`_ (optional)

   If installed, M2Crypto will be used to accelerate some
   internal support functions, but it is not required.

PassLib is pure-python, and should be useable on all platforms.

Installing
==========
* To install from source directory using ``setup.py`` (requires Setuptools or Distribute)::

   python setup.py build
   sudo python setup.py install

* To install using easy_install::

   easy_install passlib

* To install using pip::

   pip install passlib

Testing
=======
PassLib contains a comprehensive set of unittests providing nearly complete coverage.
All unit tests are contained within the :mod:`passlib.tests` package,
and are designed to be run using the `Nose <http://somethingaboutorange.com/mrl/projects/nose>`_ unit testing library.

Once PassLib and Nose have been installed, the tests may be run from the source directory::

    # to run the platform-relevant tests...
    nosetests -v passlib/tests

    # to run all tests...
    PASSLIB_TESTS="all" nosetests -v passlib/tests

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
5. Once Sphinx completes it's run, point a web browser to the file at :samp:`docs/_build/html/index.html`
   to access the PassLib documentation in html format.
