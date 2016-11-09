.. module:: passlib.pwd
    :synopsis: password generation helpers

=================================================
:mod:`passlib.pwd` -- Password generation helpers
=================================================

.. versionadded:: 1.7

.. todo::
    This module is still a work in progress, it's API may change
    before release. See module source for detailed todo list.

Password Generation
===================
.. warning::

    Before using these routines, be sure your system's RNG state is safe,
    and that you use a sufficiently high ``entropy`` value for
    the intended purpose.

.. autofunction:: genword(entropy=None, length=None, charset="ascii62", chars=None, returns=None)

.. autofunction:: genphrase(entropy=None, length=None, wordset="beale", words=None, sep=" ", returns=None)

Password Strength Estimation
============================
Passlib does not current offer any password strength estimation routines.
However, the (javascript-based) `ZXCVBN <https://github.com/dropbox/zxcvbn>`_
project is a very good choice for this purpose.  There are a few python
ports of this library, though as of 2016-11, none of them seem active and up to date.
