============
Installation
============

Requirements
============
PassLib currently has no external depedancies besides Python itself:

    * Python 2.5 or better is required.

        * PassLib has not been tested with Python 2.4 or earlier,
          and no guarantees are made about whether PassLib will work with them.

    * Python 3.x is **not** yet supported, work is ongoing (particularly, unicode issues).

The following libraries are not required, but will be used if found:

    * If installed, `py-bcrypt <http://www.mindrot.org/projects/py-bcrypt/>`_ will be
      used instead of PassLib's slower pure-python bcrypt implementation.
      *This is strongly recommended, as the builtin implementation is VERY slow*.

    * stdlib's :mod:`!crypt` module will be used if present, and if the host
      OS supports the specific scheme in question. OS support is autodetected
      for the following schemes: des-crypt,  md5-crypt, bcrypt, sha256-crypt,
      and sha512-crypt.

    * If installed, `M2Crypto <http://chandlerproject.org/bin/view/Projects/MeTooCrypto>`_ will be
      used to accelerate some internal support functions, but it is not required.

Installing
==========
PassLib can be installed with easy_install, linked/copied into sys.path directly
from it's source directory, or installed using :samp:`{$SOURCE}/setup.py install`,
where :samp:`{$SOURCE}` is the path to the PassLib source directory.
PassLib is pure python, there is nothing to compile or configure.

Testing
=======
PassLib contains a number of unittests (sadly, coverage is not yet complete).
All unit tests are contained within the :mod:`passlib.tests` package,
and are designed to be run using the `Nose <http://somethingaboutorange.com/mrl/projects/nose>`_ unit testing library.
Once PassLib and nose have been installed, you may run the following commands::

    #to run the basic passlib test suite:
    nosetests -v passlib.tests

    #to test all passlib backends, including inactive ones:
    export PASSLIB_TESTS=all
    nosetests passlib.tests

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
