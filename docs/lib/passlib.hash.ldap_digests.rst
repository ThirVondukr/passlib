===========================================================
:samp:`passlib.hash.ldap_{digest}` - LDAP / RFC2307 Digests
===========================================================

.. currentmodule:: passlib.hash

PassLib provides support for a most of the hashes
used by LDAP, as stored in the :rfc:`2307` format.
This includes ``{MD5}``, ``{SMD5}``, ``{SHA}``, ``{SSHA}``.
Many of these schemes are somewhat to very insecure,
and should not be used except when required.

.. note::

    The ``{CRYPT}`` scheme is not yet supported by PassLib.

Usage
=====
These classes all wrap the underlying hashlib implementations,
and are mainly useful only for plugging them into a :class:`~passlib.context.CryptContext`.
However, they can be used directly as follows::

    >>> from passlib.hash import ldap_salted_md5 as lsm

    >>> #encrypt password
    >>> h = lsm.encrypt("password")
    >>> h
    '{SMD5}OqsUXNHIhHbznxrqHoIM+ZT8DmE='

    >>> hs.identify(h) #check if hash is recognized
    True
    >>> hs.identify('JQMuyS6H.AGMo') #check if some other hash is recognized
    False

    >>> hs.verify("password", h) #verify correct password
    True
    >>> hs.verify("secret", h) #verify incorrect password
    False

Interface
=========
.. autoclass:: ldap_md5()
.. autoclass:: ldap_salted_md5()
.. autoclass:: ldap_sha1()
.. autoclass:: ldap_salted_sha1()
.. autoclass:: ldap_plaintext()

.. rst-class:: html-toggle

Format & Algorithm
==================
All of these classes follow a single basic format [#rfc]_:

ldap_md5

    These hashes have the format :samp:`{{MD5}}{checksum}`,
    where :samp:`{checksum}` is the base64 encoding
    of the raw MD5 digest of the password.
    An example hash (of ``password``) is ``{MD5}X03MO1qnZdYdgyfeuILPmQ==``.

ldap_salted_md5

    These hashes have the format :samp:`{{SMD5}}{data}`;
    where :samp:`{data}` is the base64 encoding of :samp:`{checksum}{salt}`;
    and in turn :samp:`{salt}` is a 4 byte binary salt,
    and :samp:`{checksum}` is the raw MD5 digest of the
    the string :samp:`{password}{salt}`.

    An example hash (of ``password``) is ``{SMD5}jNoSMNY0cybfuBWiaGlFw3Mfi/U=``.
    After decoding, this results in a raw salt string ``s\x1f\x8b\xf5``,
    and a raw MD5 checksum of ``\x8c\xda\x120\xd64s&\xdf\xb8\x15\xa2hiE\xc3``.

ldap_sha1

    These hashes have the format :samp:`{{MD5}}{checksum}`,
    where :samp:`{checksum}` is the base64 encoding
    of the raw MD5 digest of the password.
    An example hash (of ``password``) is ``{SHA}W6ph5Mm5Pz8GgiULbPgzG37mj9g=``.

ldap_salted_sha1

    These hashes have the format :samp:`{{SSHA}}{data}`;
    where :samp:`{data}` is the base64 encoding of :samp:`{checksum}{salt}`;
    and in turn :samp:`{salt}` is a 4 byte binary salt,
    and :samp:`{checksum}` is the raw SHA1 digest of the
    the string :samp:`{password}{salt}`.

    An example hash (of ``password``) is ``{SSHA}pKqkNr1tq3wtQqk+UcPyA3HnA2NsU5NJ``.
    After decoding, this results in a raw salt string ``lS\x93I``,
    and a raw SHA1 checksum of ``\xa4\xaa\xa46\xbdm\xab|-B\xa9>Q\xc3\xf2\x03q\xe7\x03c``.

References
==========

.. [#pwd] The manpage for :command:`slappasswd` - `<http://gd.tuwien.ac.at/linuxcommand.org/man_pages/slappasswd8.html>`_.

.. [#rfc] The basic format for these hashes is laid out in RFC 2307 - `<http://www.ietf.org/rfc/rfc2307.txt>`_
