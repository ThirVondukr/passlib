===============
Release History
===============

**1.3** (2011-03-25)

    * first public release
    * documentation completed
    * 99% unittest coverage
    * some refactoring and lots of bugfixes
    * added support for a number of addtional password schemes:
      bigcrypt, crypt16, sun md5 crypt, nthash, lmhash, oracle10 & 11,
      phpass, sha1, generic hex digests, ldap digests.

**1.2** (2011-01-06)

    * many bugfixes
    * global registry added
    * transitional release for applications using BPS library.
    * first truly functional release since splitting from BPS library (see below).

.. note::

    For all previous versions, PassLib did not exist independantly,
    but as a subpackage of *BPS*, an private & unreleased toolkit library.

**1.0** (2009-12-11)

    * CryptContext & CryptHandler framework
    * added support for: des-crypt, bcrypt (via pybcrypt), postgres, mysql
    * added unit tests

**0.5** (2008-05-10)

    * initial production version
    * consolidated from code scattered across multiple applications
    * MD5-Crypt, SHA256-Crypt, SHA512-Crypt support
