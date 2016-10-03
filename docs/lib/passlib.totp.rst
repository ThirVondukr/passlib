.. module:: passlib.totp
    :synopsis: totp / two factor authentaction

=======================================================
:mod:`passlib.totp` -- TOTP / Two Factor Authentication
=======================================================

.. versionadded:: 1.7

The :mod:`!passlib.totp` module provides a number of classes for implementing
two-factor authentication (2FA) using the TOTP [#totpspec]_ / HOTP [#hotpspec]_ specifications.
This page provides a reference to all the classes and methods in this module.

Passlib's OTP support is centered around two classes: :class:`TOTP` and :class:`HOTP`,
whose shared code is defined in the :class:`BaseOTP` class.  There are also
some additional helpers, including the :class:`OTPContext` class, which
helps to securely serialize TOTP secrets & state to a database.

.. seealso::

    * :ref:`TOTP Tutorial <totp-tutorial>` --
      overview of this module and walkthrough of how to use it.

.. rst-class:: emphasize-children

.. _baseotp-constructor-options:

BaseOTP (Shared Methods)
========================

BaseOTP – Constructor
---------------------
.. autoclass:: BaseOTP

.. _baseotp-client-provisioning:

BaseOTP – Client Provisioning (URIs & QRCodes)
----------------------------------------------
The configuration of any OTP object can be encoded into a URI [#uriformat]_,
suitable for configuring an OTP client such as Google Authenticator.

.. automethod:: BaseOTP.to_uri
.. automethod:: BaseOTP.from_uri
.. automethod:: BaseOTP.pretty_key

.. _baseotp-serialization:

BaseOTP – Serialization
-----------------------
While :class:`TOTP` and :class:`HOTP` instances can be used statelessly
to calculate token values, they can also be used in a persistent
manner, to handle tracking of previously used tokens, etc.  In this case,
they will need to be serialized to / from external storage, which
can be performed with the following methods:

.. attribute:: BaseOTP.changed

    Boolean flag set by all BaseOTP subclass methods which modify the internal state.
    if true, then something has changed in the object since it was created / loaded
    via :meth:`~BaseOTP.from_json`, and needs re-persisting via :meth:`~BaseOTP.to_json`.
    After which, your application may clear the flag, or discard the object, as appropriate.

.. automethod:: BaseOTP.to_json
.. automethod:: BaseOTP.to_dict
.. automethod:: BaseOTP.from_json

..
    Undocumented Helper Methods
    ---------------------------

    .. automethod:: BaseOTP.normalize_token

.. _baseotp-configuration-attributes:

BaseOTP – Configuration Attributes
----------------------------------
All the OTP objects offer the following attributes,
which correspond to the constructor options (above).
Most of this information will be serialized by :meth:`~BaseOTP.to_uri` and :meth:`~BaseOTP.to_json`:

.. autoattribute:: BaseOTP.key
.. autoattribute:: BaseOTP.hex_key
.. autoattribute:: BaseOTP.base32_key
.. autoattribute:: BaseOTP.label
.. autoattribute:: BaseOTP.issuer
.. autoattribute:: BaseOTP.digits
.. autoattribute:: BaseOTP.alg

.. rst-class:: emphasize-children

TOTP (Time-based tokens)
========================

TOTP – Constructor
------------------
.. autoclass:: TOTP(key=None, format="base32", \*, new=False, \*\*kwds)

TOTP – Client-Side Token Generation
-----------------------------------
.. automethod:: TOTP.generate

TOTP – Server-Side Token Verification
-------------------------------------
.. automethod:: TOTP.verify
.. automethod:: TOTP.consume

.. todo::

    Offer a resynchronization primitive which allows user to provide a large number of
    sequential tokens taken from a pre-determined time range (e.g.
    google's "emergency recovery code" style); or at current time, but with a much larger
    window (as referenced in the RFC).

TOTP – Provisioning & Serialization
-----------------------------------
:class:`!TOTP`'s provisioning & serialization methods are inherited from :class:`!BaseOTP`,
and are documented under:

* :ref:`BaseOTP Client Provisioning <baseotp-client-provisioning>`
* :ref:`BaseOTP Serialization <baseotp-serialization>`

..
    Undocumented Helper Methods
    ---------------------------

    .. automethod:: TOTP.normalize_time

.. _totp-configuration-attributes:

TOTP – Configuration Attributes
-------------------------------
In addition to the :ref:`BaseOTP Configuration Attributes <baseotp-configuration-attributes>`,
this class also offers the following extra attrs (which correspond to the extra constructor options):

.. autoattribute:: TOTP.period

TOTP – Internal State Attributes
--------------------------------
The following attributes are used to track the internal state of this generator,
and will be included in the output of :meth:`~BaseOTP.to_json`:

.. autoattribute:: TOTP.last_counter

.. attribute:: TOTP.changed

    boolean flag set by :meth:`~TOTP.advance` and :meth:`~TOTP.consume`
    to indicate that the object's internal state has been modified since creation.

(Note: All internal state attributes can be initialized via constructor options,
but this is mainly an internal / testing detail).

Support Classes
---------------
.. autoclass:: TotpToken()
.. autoclass:: TotpMatch()

.. rst-class:: emphasize-children

HOTP (Counter-based tokens)
===========================

HOTP – Constructor
------------------
.. note::

    HOTP is used much less frequently, since it's fragile
    (as it's much easier for the server & client to get out of sync in their token
    count). Unless you have a particular reason, you probably want :class:`TOTP` instead.

.. autoclass:: HOTP(key=None, format="base32", \*, new=False, \*\*kwds)

HOTP – Client-Side Token Generation
-----------------------------------
.. automethod:: HOTP.advance

HOTP – Server-Side Token Verification
-------------------------------------
.. automethod:: HOTP.verify
.. automethod:: HOTP.consume

HOTP – Provisioning & Serialization
-----------------------------------
:class:`!HOTP`'s provisioning & serialization methods are inherited from :class:`!BaseOTP`,
and are documented under:

* :ref:`BaseOTP Client Provisioning <baseotp-client-provisioning>`
* :ref:`BaseOTP Serialization <baseotp-serialization>`


HOTP – Internal State Attributes
--------------------------------
The following attributes are used to track the internal state of this generator,
and will be included in the output of :meth:`~BaseOTP.to_json`:

.. autoattribute:: HOTP.counter

.. attribute:: HOTP.changed

    Boolean flag set by :meth:`~HOTP.advance` and :meth:`~HOTP.consume`
    to indicate that the object's internal state has been modified since creation.

(Note: All internal state attribute can be initialized via constructor options,
but this is mainly an internal / testing detail).

Support Classes
---------------
.. autoclass:: HotpMatch()

OTPContext (Persistence Frontend)
=================================
.. autoclass:: OTPContext

Support Functions
=================
.. autofunction:: generate_secret(entropy=256)

.. function:: from_uri(uri)

    Create an HOTP / TOTP instance from a provisioning URI,
    such as generated by :meth:`BaseOTP.to_uri`.

    :returns:
        :class:`HTOP` or :class:`TOTP` instance, as appropriate

.. function:: from_json(json)

    Create an HOTP / TOTP instance from a JSON string,
    such as generated by :meth:`BaseOTP.to_json`.
    Also accepts a dict object with the same format,
    such as returned by :meth:`BaseOTP.to_dict`.

    :returns:
        :class:`HTOP` or :class:`TOTP` instance, as appropriate

Deviations
==========

* The TOTP Spec [#totpspec]_ includes an param (``T0)``) providing an optional offset from the base time.
  Passlib omits this parameter (fixing it at ``0``), but so do pretty much all other TOTP implementations.

.. rubric:: Footnotes

.. [#totpspec] TOTP Specification - :rfc:`6238`

.. [#hotpspec] HOTP Specification - :rfc:`4226`

.. [#uriformat] Google's OTPAuth URI format -
       `<https://github.com/google/google-authenticator/wiki/Key-Uri-Format>`_

