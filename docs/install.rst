============
Installation
============

Requirements
============
PassLib currently has no external depedancies besides Python itself:

    * Python 2.5 or better is required.

        * PassLib has not been tested with Python 2.4 or earlier,
          and no guarantees are made about whether PassLib will work with them.

    * Python 3.x is **not** yet supported, work is ongoing.

The following libraries are not required, but will be used if found:

    stdlib's :mod:`!crypt` module

        :func:`!crypt()` will be used if present, and if the host
        OS supports the specific scheme in question. OS support is autodetected
        for the following schemes: des-crypt,  md5-crypt, bcrypt, sha256-crypt,
        and sha512-crypt.

    `py-bcrypt <http://www.mindrot.org/projects/py-bcrypt/>`_

        If installed, pybcrypt will be used to support the BCrypt hash algorithm.
        This is required if you want to handle BCrypt hashes,
        and stdlib :mod:`!crypt` does not support BCrypt
        (which is pretty much all non-BSD systems).

    `M2Crypto <http://chandlerproject.org/bin/view/Projects/MeTooCrypto>`_

        If installed, M2Crypto will be used to accelerate some
        internal support functions, but it is not required.

PassLib should be useable on all operating systems.

Installing
==========
PassLib can be installed with easy_install / pip, linked/copied into sys.path directly
from it's source directory, or installed using :samp:`{$SOURCE}/setup.py install`,
where :samp:`{$SOURCE}` is the path to the PassLib source directory.
PassLib is pure python, there is nothing to compile or configure.

Testing
=======
PassLib contains a comprehensive set of unittests providing nearly complete coverage.
All unit tests are contained within the :mod:`passlib.tests` package,
and are designed to be run using the `Nose <http://somethingaboutorange.com/mrl/projects/nose>`_ unit testing library.
Once PassLib and Nose have been installed::

    # to run the basic tests from the source directory...
    nosetests -v passlib/tests

    # to run ALL tests from the source directory...
    PASSLIB_TESTS="all" nosetests -v passlib/tests

Documentation
=============
The latest copy of this documentation should always be available
at the `PassLib homepage <http://www.assurancetechnologies.com/software/passlib>`_.

If you wish to generate your own copy of the documentation,
you will need to:

* install `Sphinx <http://sphinx.pocoo.org/>`_ (1.0 or better)
* install `astdoc <http://www.assurancetechnologies.com/software/astdoc>`_ (a bundle of custom sphinx themes & extensions
  used by Assurance Technologies).
* download the PassLib source
* run :samp:`python {$SOURCE}/docs/make.py clean html` (where :samp:`{$SOURCE}` is the path to the PassLib source directory).

Once Sphinx completes it's run, point a web browser to the file at :samp:`{$SOURCE}/docs/_build/html/index.html`
to access the PassLib documentation in html format.
