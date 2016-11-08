.. index:: TOTP; overview
.. index:: TOTP; usage examples
.. _totp-tutorial:

.. currentmodule:: passlib.totp

===================================
:mod:`passlib.totp` - TOTP Tutorial
===================================

Overview
========
The :mod:`passlib.totp` module provides a set of classes for adding
two-factor authentication (2FA) support into your application,
using the widely supported TOTP specification.

This module is designed to support a variety of use cases, including:

    * Creating & transferring TOTP keys to client devices.

    * Generating & verifying tokens.

    * Securely storing TOTP keys.

This walkthrough starts with the simpler cases, and builds up
to the more complex ones.

.. seealso:: The :mod:`passlib.totp` api reference,
    which lists all details of all the classes and methods mentioned here.

.. rst-class:: emphasize-children

Basic Usage
===========

Creating TOTP Instances
-----------------------
The first thing needed to setup TOTP for an account is for the server
to create a new key.  This can be done by creating a :class:`~passlib.totp.TOTP` instance
and instructing it to create a new key::

    >>> # create new instance with a randomly generated key
    >>> from passlib import totp
    >>> otp = totp.TOTP(new=True)

    >>> # the configuration and key can be accessed from attributes:
    >>> otp.base32_key
    'GVDOQ7NP6XPJWE4CWCLFFSXZH6DTAZWM'
    >>> otp.alg
    "sha1"
    >>> otp.period
    30

    >>> # if you want a non-standard alg or period, you can specify it via the constructor
    >>> otp2 = totp.TOTP(new=True, period=60, alg="sha256")

    >>> # You can also create TOTP instances from an existing key:
    >>> # (see TOTP's "key" and "format" options for more details)
    >>> otp3 = totp.TOTP(key='GVDOQ7NP6XPJWE4CWCLFFSXZH6DTAZWM')

.. seealso::

    For more details, see the :class:`~passlib.totp.TOTP` constructor,
    and the list of :ref:`TOTP attributes <totp-configuration-attributes>`.

Provisioning URIs
-----------------
Once a TOTP instance & key has been generated on the server,
it needs to be transferred to the client TOTP program for installation.
This can be done by having the client manually type the value of ``otp.base32_key``
into their application, along with any configuration options.

An easier method, widely used for smartphone-based TOTP clients, is Google Auth's `KeyUriFormat <https://github.com/google/google-authenticator/wiki/Key-Uri-Format>`_.
This defines a standard for encoding an TOTP key and configuration into a URI.
Once there, the URI can be transferred to the client by email, or (more frequently),
by encoding it into a visual qrcode, and presenting it to the user.  Many smartphone
TOTP applications support the user grabbing this configuration off the screen.

When transferring things this way, you will need to provide identifiers
for your application and the user, in order for the TOTP client to distinguish
this key from the others in it's database.  This is done via the "issue" and "label"
parameters of the :meth:`~passlib.totp.TOTP.to_uri` method:

    >>> # assume an existing TOTP instance has been created
    >>> from passlib import totp
    >>> otp = totp.TOTP(key='GVDOQ7NP6XPJWE4CWCLFFSXZH6DTAZWM')

    >>> # serialize the object to a URI,
    >>> # choosing an "issuer" label unique to your application (e.g. it's domain name)
    >>> # and a label that's meaningful within your application (e.g. the user name or email).
    >>> uri = otp.to_uri(label="demo-user", issuer="myapp.example.org")
    'otpauth://totp/demo-user?secret=GVDOQ7NP6XPJWE4CWCLFFSXZH6DTAZWM&issuer=myapp.example.org'

    >>> # this uri can encoded as a qrcode, using various qrcode libraries.
    >>> # an example, using PyQrCode <https://pypi.python.org/pypi/PyQRCode>,
    >>> # which will render the qrcode to the console:
    >>> import pyqrcode
    >>> print(pyqrcode.create(uri).terminal(quiet_zone=1))
    ... very large ascii-art qrcode omitted...

On the client side, passlib offers a helper method for loading from a provisioning
URI.  This can be useful for testing URI encoding & output:

    >>> # create new TOTP instance from a provisioning uri:
    >>> from passlib import totp
    >>> otp = totp.from_uri('otpauth://totp/demo-user?secret=GVDOQ7NP6XPJWE4CWCLFFSXZH6DTAZWM&issuer=myapp.example.org')
    >>> otp.base32_key
    'GVDOQ7NP6XPJWE4CWCLFFSXZH6DTAZWM'
    >>> otp.alg
    "sha1"
    >>> otp.period
    30

.. seealso::

    For more details, see the :meth:`~passlib.totp.TOTP.from_uri` constructor,
    and the :meth:`~passlib.totp.TOTP.to_uri` method.

Storing TOTP instances
----------------------
One disadvantage of :meth:`~TOTP.to_uri` and :func:`!from_uri` (above)
is that they're oriented towards helping a server configure a client device.
Server applications will still need to persist this information
to disk (whether a database, flat file, etc).  To help with this, passlib offers
a way to serialize OTP tokens to and from JSON: the :meth:`TOTP.to_json` method,
and the :meth:`passlib.totp.from_json` constructor::

    >>> # assume an existing TOTP instance has been created
    >>> from passlib import totp
    >>> otp = totp.TOTP(key='GVDOQ7NP6XPJWE4CWCLFFSXZH6DTAZWM')

    >>> # you can serialize it to json:
    >>> data = otp.to_json()
    >>> data
    '{"key":"GVDOQ7NP6XPJWE4CWCLFFSXZH6DTAZWM","type":"totp","v":1}'

    >>> # this can then stored in a database field, and deserialized as needed:
    >>> otp2 = totp.from_json(data)
    >>> otp.base32_key
    'GVDOQ7NP6XPJWE4CWCLFFSXZH6DTAZWM'
    >>> otp.alg
    "sha1"
    >>> otp.period
    30

For internal storage, these methods offer a couple of advantages over the URI format:
their output is relatively simple to inspect (e.g. in Postgres JSON columns),
and they support storing the keys in an encrypted fashion (see :ref:`totp-context-usage` below).

For cases where a python dictionary is more useful than a json string,
the :meth:`TOTP.to_dict` method returns a python dict identical to parsing
the output of :meth:`TOTP.to_json`.  This value can be reconstructed
via :func:`from_source`, which will autodetect whether the input
is a dictionary vs string.

.. seealso::

    For more details, see the :meth:`~passlib.totp.TOTP.from_source` constructor,
    and the :meth:`~passlib.totp.TOTP.to_json` method;
    as well as the stateful usage & OTPContext usage tutorials below.

Generating Tokens
-----------------
Finally, the whole point of TOTP: generating and verifying tokens.
The TOTP protocol generates a new time & key -dependant token every <period> seconds (usually 30).

Generating a totp token is done with the :meth:`TOTP.generate` method,
which returns a :class:`TotpToken` instance.  This object looks and acts
like a tuple of ``(token, expire_time)``, but offers some additional
informational attributes.

    >>> from passlib import totp
    >>> otp = TOTP(key='GVDOQ7NP6XPJWE4CWCLFFSXZH6DTAZWM')

    >>> # generate a TOTP token for the current timestamp
    >>> # (your output will vary based on system time)
    >>> otp.generate()
    <TotpToken token='589720' expire_time=1475342400>

    >>> # to get just the token, not the TotpToken instance...
    >>> otp.generate().token
    '359275'

    >>> # you can generate a token for a specific time as well...
    >>> otp.generate(time=1475338840).token
    '359275'

.. seealso::

    For more details, see the :meth:`TOTP.generate` method.

Verifying Tokens
----------------
In order for successful authentication, the user must generate the token
on the client, and provide it to your server before the period ends.

Since this there will always be a little transmission delay (and sometimes
client clock drift) TOTP verification usually uses a small verification window,
allowing a user to enter a token a few seconds after the period has ended.
This window is usually kept as small as possible, and in passlib defaults to 30 seconds.

To verify a token a user has provided, you can use the :meth:`TOTP.verify` method.
If unsuccessful, a :exc:`passlib.exc.TokenError` subclass will be raised.
If successful, this will return a :class:`TotpMatch` instance, with details about the match.
This object acts like a tuple of ``(counter, timestamp)``, but offers some additional
informational attributes.

    >>> # NOTE: all of the following was done at a fixed time, to make these
    >>> #       examples repeatable. in real-world use, you would omit the 'time' parameter
    >>> #       from all these calls.

    >>> # assuming TOTP key & config was deserialized from database store
    >>> from passlib import totp
    >>> otp = TOTP(key='GVDOQ7NP6XPJWE4CWCLFFSXZH6DTAZWM')

    >>> # user provides malformed token:
    >>> otp.verify('359', time=1475338840)
    ...
    MalformedTokenError: Token must have exactly 6 digits

    >>> # user provides token that isn't valid w/in time window:
    >>> otp.verify('123456', time=1475338840)
    ...
    InvalidTokenError: Token did not match

    >>> # user provides correct token
    >>> otp.verify('359275', time=1475338840)
    <TotpMatch counter=49177961 time=1475338840>

.. _totp-reuse-warning:

Warning about Token Reuse
.........................
Even if an attacker is able to observe a user entering a TOTP token,
it will do them no good once ``period + window`` seconds have passed (typically 60).
This is because the current time will now have advanced far enough that
:meth:`!TOTP.verify` will *never* match against the stolen token.

However, this leaves a small window in which the attacker can observe and replay
a token, successfully impersonating the user.
To prevent this, applications are strongly encouraged to record the
latest :attr:`TotpMatch.counter` value that's returned by the :meth:`!TOTP.verify` method.

This value should be stored per-user in a temporary cache for at least
``period + window`` seconds.  (This is typically 60 seconds, but for an exact value,
applications may check the :attr:`TotpMatch.cache_seconds` value returned by
the :meth:`!TOTP.verify` method).

Any subsequent calls to verify should check this cache,
and pass in that value to :meth:`!TOTP.verify`'s "last_counter" parameter
(or ``None`` if no value found).  Doing so will ensure that tokens
can only be used once, preventing replay attacks.

As an example::

    >>> # NOTE: all of the following was done at a fixed time, to make these
    >>> #       examples repeatable. in real-world use, you would omit the 'time' parameter
    >>> #       from all these calls.

    >>> # assuming TOTP key & config was deserialized from database store
    >>> from passlib.totp import TOTP
    >>> otp = TOTP(key='GVDOQ7NP6XPJWE4CWCLFFSXZH6DTAZWM')

    >>> # retrieve per-user counter from cache
    >>> last_counter = ...consult application cache...

    >>> # if user provides valid value, a TotpMatch object will be returned.
    >>> # (if they provide an invalid value, a TokenError will be raised).
    >>> match = otp.verify('359275', last_counter=last_counter, time=1475338830)
    >>> match.counter
    49177961
    >>> match.cache_seconds
    60

    >>> # application should now cache the new 'match.counter' value
    >>> # for at least 'match.cache_seconds'.

    >>> # now that last_counter has been properly updated: say that
    >>> # 10 seconds later attacker attempts to re-use token user just entered:
    >>> last_counter = 49177961
    >>> match = otp.verify('359275', last_counter=last_counter, time=1475338840)
    ...
    UsedTokenError: Token has already been used, please wait for another.

.. seealso::

    For more details, see the :meth:`TOTP.verify` method.

.. _totp-context-usage:

OTPContext Usage
================
.. todo:: document how OTPContext can be used to persist TOTP tokens securely.

Highlevel Quickstart
====================
The following is a guide for quickly getting TOTP support integrated into your
application, using passlib's highlevel :class:`OTPContext` helper class.

.. todo:: needs to write quickstart guide.

.. _totp-rate-limiting:

Why Rate Limiting is Critical
=============================

The :meth:`TOTP.verify` methods offers a ``window``
parameter, expanding the search range to account for the client getting
slightly out of sync.

While it's tempting to be user-friendly, and make this window as large as possible,
there is a security downside: Since any token within the window will be
treated as valid, the larger you make the window, the more likely it is
that an attacker will be able to guess the correct token by random luck.

Because of this, **it's critical for applications implementing OTP to rate-limit
the number of attempts on an account**, since an unlimited number of attempts
guarantees an attacker will be able to guess any given token.

The Gory Details
----------------
For TOTP, the formula is ``odds = guesses * (1 + 2 * window / period) / 10**digits``;
where ``window`` in this case is the :meth:`TOTP.verify` window (measured in seconds),
and ``period`` is the number of seconds before the token is rotated.

This formula can be inverted to give the maximum window we want to allow
for a given configuration, rate limit, and desired odds:
``max_window = floor((odds * 10**digits / guesses - 1) * period / 2)``.

For example (assuming TOTP with 7 digits and 30 second period),
if you want an attacker's odds to be no better than 1 in 10000,
and plan to lock an account after 4 failed attempts --
the maximum window you should use would be
``floor((1/10000 * 10**6 / 4 - 1) * 30 / 2)`` or 360 seconds.

..
    xxx: The above formulas are not accurate for 10 digit tokens, since the 10th
    digit takes on fewer values -- subtitute ``3e9`` instead of ``10**digits``
    in this case.