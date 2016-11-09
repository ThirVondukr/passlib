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

Example Walkthrough
===================
There are a number of different ways to integrate TOTP support into a server application.
The following is an outline one of way this can be done. A number of steps here can be done in multiple ways,
some of which will be more appropriate for different applications.

1. Secret Creation
------------------
First, generate a strong application secret to use when encrypting TOTP keys for storage.
Passlib offers a :meth:`generate_secret` method to help with this::

    >>> from passlib.totp import generate_secret
    >>> generate_secret()
    'pO7SwEFcUPvIDeAJr7INBj0TjsSZJr1d2ddsFL9r5eq'

This key should be assigned a numeric tag (e.g. "1", or an iso date such as "2016-11-10");
and should be stored in a file *separate* from your application's configuration.
Ideally, after this file has been loaded by the TOTP constructor below,
the application should give up access permission to the file.

Example file contents::

    2016-11-10: pO7SwEFcUPvIDeAJr7INBj0TjsSZJr1d2ddsFL9r5eq

2. App Initialization
---------------------
When your application is being initialized, create a TOTP factory which is configured
for your application, and is set up to use the application secrets.

    >>> from passlib.totp import TOTP
    >>> TotpFactory = TOTP.using(secrets_path='/path/to/secret/file/in/step/1')

Note that the ``TotpFactory`` instance returned by :meth:`TOTP.using` will actually be a subclass
of :class:`TOTP` itself, and has the same methods and attributes.  The main difference is that (because
an application secret has been provided), the TOTP key will automatically be encrypted / decrypted
when serializing to json.

3. Cache Initialization
-----------------------
While not *absolutely* required, it's strongly recommended to set up a per-user cache
which can store the last matched TOTP counter (an integer) for a period of a few minutes or so.
This helps protect a narrow window of time where TOTP would otherwise be vulnerable
to a replay attack (see below).

4. Provisioning
---------------
To set up a TOTP key for a new user, create a new TOTP instance, autogenerating a new key.
This should be rendered into a configuration URI, and transferred to the user's TOTP client
(typically by rendering it to a QR code).  This requires assigning an "issuer" string
to uniquely identify your application, and a "label" string to uniquely identify the user.

   >>> totp = TotpFactory.new()
   >>> uri = totp.to_uri(issuer="myapp.example.org", label="username")
   >>> uri
   'otpauth://totp/username?secret=D6RZI4ROAUQKJNAWQKYPN7W7LNV43GOT&issuer=myapp.example.org'
   >>> # uri can then be passed to a qrcode renderer (example below)

5. Persisting
-------------
Once the user has configured the TOTP uri on their client, and has entered a token
to prove it's configured correctly, you can store the TOTP in your database.
This can be done via the :meth:`TOTP.to_json` method:

    >>> totp.to_json()
    '{"enckey":{"c":14,"k":"FLEQC3VO6SIT3T7GN2GIG6ONPXADG5CZ","s":"UL2J4MZG4SONHOWXLKFQ","t":"1","v":1},"type":"totp","v":1}'

If there is no application secret configured, the key will not be encrypted,
and instead look like this::

    >>> totp.to_json()
    '{"key":"D6RZI4ROAUQKJNAWQKYPN7W7LNV43GOT","type":"totp","v":1}'

6. Verification
---------------
Whenever attempting to verify a token provided by the user,
load the serialized TOTP key from the database, as well as the last counter value
from the cache, and use the :meth:`TOTP.verify` method::

    >>> token = ... token string provided by user ...
    >>> source = ... load json from database ...
    >>> last_counter = ... load from cache ...
    >>> match = TotpFactory.verify(token, source, last_counter=last_counter)

6a. If this succeeds, it will return a :class:`TotpMatch` object containing details
about the match. This includes the "counter value" assigned to the token.
The value ``match.counter`` should be stored in a per-user cache for at least
``match.cache_seconds`` seconds, and retrieved for any future token validations
(cache_seconds will be 60 in the default configuration).

6b. Alternately, the match may fail, in which case one of the :exc:`~passlib.exc.TokenError`
subclasses will be thrown::

    >>> match = TotpFactory.verify(token, source, last_counter=last_counter)
    ...
    InvalidTokenError: Token did not match

*The remaining sections try to provide details of some of these steps,
as well as other related workflows.*

Creating TOTP Instances
=======================
The first thing needed to setup TOTP for an account is for the server
to create a new key.  This can be done by creating a :class:`~passlib.totp.TOTP` instance
and instructing it to create a new key::

    >>> # create new instance with a randomly generated key
    >>> from passlib.totp import TOTP
    >>> otp = TOTP.new()

    >>> # the configuration and key can be accessed from attributes:
    >>> otp.base32_key
    'GVDOQ7NP6XPJWE4CWCLFFSXZH6DTAZWM'
    >>> otp.alg
    "sha1"
    >>> otp.period
    30

    >>> # if you want a non-standard alg or period, you can specify it via the constructor
    >>> otp2 = TOTP(new=True, period=60, alg="sha256")

    >>> # You can also create TOTP instances from an existing key:
    >>> # (see TOTP's "key" and "format" options for more details)
    >>> otp3 = TOTP(key='GVDOQ7NP6XPJWE4CWCLFFSXZH6DTAZWM')

.. seealso::

    For more details, see the :class:`~passlib.totp.TOTP` constructor,
    and the list of :ref:`TOTP attributes <totp-configuration-attributes>`.

Configuring Client Applications
===============================
Once a TOTP instance & key has been generated on the server,
it needs to be transferred to the client TOTP program for installation.
This can be done by having the user manually type the value of ``otp.base32_key``
into their application, along with any configuration options.

An easier method, widely used for smartphone-based TOTP clients, is Google Auth's `KeyUriFormat <https://github.com/google/google-authenticator/wiki/Key-Uri-Format>`_.
This defines a standard for encoding an TOTP key and configuration into a URI.
Once there, the URI can be transferred to the client by email, or (more frequently),
by encoding it into a visual qrcode, and presenting it to the user visually.  Many smartphone
TOTP applications support the user importing this information via the smartphone's camera.

When transferring the TOTP configuration this way, you will need to provide unique identifiers
for both your application, and the user's account.  This allows TOTP clients to distinguish
this key from the others in it's database.  This can be done via the "issuer" and "label"
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
======================
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
    as well as the stateful usage & AppWallet usage tutorials below.

Generating Tokens (Client-Side Only)
====================================
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
================
In order for successful authentication, the user must generate the token
on the client, and provide it to your server before the period ends.

Since this there will always be a little transmission delay (and sometimes
client clock drift) TOTP verification usually uses a small verification window,
allowing a user to enter a token a few seconds after the period has ended.
This window is usually kept as small as possible, and in passlib defaults to 30 seconds.

To verify a token a user has provided, you can use the :meth:`TOTP.match` method.
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
    >>> otp.match('359', time=1475338840)
    ...
    MalformedTokenError: Token must have exactly 6 digits

    >>> # user provides token that isn't valid w/in time window:
    >>> otp.match('123456', time=1475338840)
    ...
    InvalidTokenError: Token did not match

    >>> # user provides correct token
    >>> otp.match('359275', time=1475338840)
    <TotpMatch counter=49177961 time=1475338840>

As a further optimization, the :meth:`TOTP.verify` method allows deserializing
and matching a token in a single step.  Not nly does this save a little code,
it has a signature much more similar to that of Passlib's :meth:`passlib.ifc.PasswordHash.verify`.

Typically applications will provide the TOTP key in whatever format it's stored by the server.
This will usually be a JSON string (as output by :meth:`TOTP.to_json`), but can be any
format accepted by :meth:`TOTP.from_source`.
As an example:

    >>> # application loads json-serialized TOTP key
    >>> from passlib.totp import TOTP
    >>> totp_source = '{"v": 1, "type": "totp", "key": "otxl2f5cctbprpzx"}'

    >>> # parse & match the token in a single call
    >>> match = TOTP.verify('123456', totp_source)

.. seealso::

    For more details, see the :meth:`TOTP.match` and :meth:`TOTP.verify` methods.

.. _totp-reuse-warning:

Preventing Token Reuse
----------------------
Even if an attacker is able to observe a user entering a TOTP token,
it will do them no good once ``period + window`` seconds have passed (typically 60).
This is because the current time will now have advanced far enough that
:meth:`!TOTP.match` will *never* match against the stolen token.

However, this leaves a small window in which the attacker can observe and replay
a token, successfully impersonating the user.
To prevent this, applications are strongly encouraged to record the
latest :attr:`TotpMatch.counter` value that's returned by the :meth:`!TOTP.match` method.

This value should be stored per-user in a temporary cache for at least
``period + window`` seconds.  (This is typically 60 seconds, but for an exact value,
applications may check the :attr:`TotpMatch.cache_seconds` value returned by
the :meth:`!TOTP.match` method).

Any subsequent calls to verify should check this cache,
and pass in that value to :meth:`!TOTP.match`'s "last_counter" parameter
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
    >>> match = otp.match('359275', last_counter=last_counter, time=1475338830)
    >>> match.counter
    49177961
    >>> match.cache_seconds
    60

    >>> # application should now cache the new 'match.counter' value
    >>> # for at least 'match.cache_seconds'.

    >>> # now that last_counter has been properly updated: say that
    >>> # 10 seconds later attacker attempts to re-use token user just entered:
    >>> last_counter = 49177961
    >>> match = otp.match('359275', last_counter=last_counter, time=1475338840)
    ...
    UsedTokenError: Token has already been used, please wait for another.

.. seealso::

    For more details, see the :meth:`TOTP.match` method.

.. _totp-rate-limiting:

Why Rate-Limiting is Critical
-----------------------------

The :meth:`TOTP.match` method offers a ``window``
parameter, expanding the search range to account for the client getting
slightly out of sync.

While it's tempting to be user-friendly, and make this window as large as possible,
there is a security downside: Since any token within the window will be
treated as valid, the larger you make the window, the more likely it is
that an attacker will be able to guess the correct token by random luck.

Because of this, **it's critical for applications implementing OTP to rate-limit
the number of attempts on an account**, since an unlimited number of attempts
guarantees an attacker will be able to guess any given token.

Quick Example
.............
For TOTP, the formula is ``odds = guesses * (1 + 2 * window / period) / 10**digits``;
where ``window`` in this case is the :meth:`TOTP.match` window (measured in seconds),
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

.. _totp-context-usage:

Securely Storing TOTP Instances
===============================
.. todo:: document how AppWallet can be used to persist TOTP tokens securely.
          include TOTP.using() in this section.

