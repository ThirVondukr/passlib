.. module:: passlib.totp
    :synopsis: totp / two factor authentaction

=======================================================
:mod:`passlib.totp` -- TOTP / Two Factor Authentication
=======================================================

.. todo::

    This module is still a work in progress, it's API may change before release.

    Things left:

    * convert TOTP 'offset' to 'skew' (inverting sense)
    * TOTO & helper should track *next* counter, to match HTOP (as well as default reuse=False behavior)
    * finish unittests (there are a few cases left)
    * write narrative documentation
    * get api documentation formatted better (whether by getting nested sections integrated into TOC,
      or splitting nested sections out into separate sections / pages).
    * probably want a "beta" release of passlib so people can test this a bit before 1.7.0.

    Optional:

    * more verification against other TOTP servers & clients.
    * consider native pyqrcode integration (e.g. a ``to_qrcode()`` method)

.. versionadded:: 1.7

The :mod:`!passlib.totp` module provides a number of classes for implementing
two-factor authentication (2FA) using the TOTP / HOTP specifications.
This page provides a reference to all the classes and methods in this module.

.. seealso::

    * :ref:`TOTP Tutorial <totp-overview>` --
      overview of this module and walkthrough of how to use it.

.. rst-class:: emphasize-children

OTPContext
==========
.. autoclass:: OTPContext

.. autofunction:: generate_secret

Common Interface
================
.. autoclass:: BaseOTP()

TOTP (Timed-based tokens)
=========================
.. autoclass:: TOTP(key=None, format="base32", \*, new=False, \*\*kwds)

HOTP (Counter-based tokens)
===========================
.. note::

    HOTP is used much less frequently, since it's fragile
    (as it's much easier for the server & client to get out of sync in their token
    count). Unless you have a particular reason, you probably want :class:`TOTP` instead.

.. autoclass:: HOTP(key=None, format="base32", \*, new=False, \*\*kwds)

Support Classes
===============
.. autoclass:: TotpToken()
.. autoclass:: TotpMatch()
.. autoclass:: HotpMatch()

Deviations
==========

* The TOTP Spec [#totpspec]_ includes an param (``T0)``) providing an optional offset from the base time.
  Passlib omits this parameter (fixing it at ``0``), but so do pretty much all other TOTP implementations.

.. rubric:: Footnotes

.. [#hotpspec] HOTP Specification - :rfc:`4226`

.. [#totpspec] TOTP Specification - :rfc:`6238`

.. [#uriformat] Google's OTPAuth URI format -
       `<https://code.google.com/p/google-authenticator/wiki/KeyUriFormat>`_

