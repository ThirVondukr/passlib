==============================================================
:samp:`passlib.hash.hex_{digest}` - Generic Hexdecimal Digests
==============================================================

.. currentmodule:: passlib.hash

Some existing applications store passwords by storing them using
hexidecimal-encoded message digests, such as MD5 or SHA1.
Such schemes are *extremely* vulnerable to pre-computed brute-force attacks,
and should not be used in new applications. However, for the sake
of backwards compatibility when converting existing applications,
PassLib provides wrappers for few of the common hashes.

Usage
=====
These classes all wrap the underlying hashlib implementations,
and are mainly useful only for plugging them into a :class:`~passlib.context.CryptContext`.
However, they can be used directly as follows::

    >>> from passlib.hash import hex_sha1 as hs

    >>> #encrypt password
    >>> h = hs.encrypt("password")
    >>> h
    '5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8'

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
.. autoclass:: hex_md4()
.. autoclass:: hex_md5()
.. autoclass:: hex_sha1()
.. autoclass:: hex_sha256()
.. autoclass:: hex_sha512()

Format & Algorithm
==================
All of these classes just report the result of the specified digest,
encoded as a series of lowercase hexidecimal characters;
though upper case is accepted as input.
