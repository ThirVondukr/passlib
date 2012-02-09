===================================================================
:class:`passlib.hash.scram` - SCRAM Hash
===================================================================

.. currentmodule:: passlib.hash

SCRAM is a password-based challenge response protocol defined by :rfc:`5802`.
While Passlib does not provide an implementation of SCRAM, applications
which use SCRAM on the server side frequently need a way to store
user passwords in a secure format that can be used to authenticate users over
SCRAM.

To accomplish this, Passlib provides the following
:ref:`modular-crypt-format`-compatible password hash scheme which uses the
``"$scram$"`` identifier. This format encodes a salt, rounds settings, and one
or more :func:`~passlib.utils.pbkdf2.pbkdf2` digests, one digest for each
of the hash algorithms the server wishes to support over SCRAM.

Since this format is PBKDF2-based, it has equivalent security to
Passlib's other :doc:`pbkdf2 hashes <passlib.hash.pbkdf2_digest>`,
and can be used to authenticate users using either the SCRAM-specific class
methods documentated below, or the normal :ref:`password-hash-api`.

.. note::

    If you aren't working with the SCRAM protocol, you probably
    don't need to use this hash format.

Usage
=====
This class can be used like any other Passlib hash, as follows::

    >>> from passlib.hash import scram

    >>> #generate new salt, encrypt password against default list of algorithms
    >>> h = scram.encrypt("password")
    >>> h # (output split over multiple lines for readability)
    '$scram$6400$.Z/znnNOKWUsBaCU$sha-1=cRseQyJpnuPGn3e6d6u6JdJWk.0,sha-256=5G\
    cjEbRaUIIci1r6NAMdI9OPZbxl9S5CFR6la9CHXYc,sha-512=.DHbIm82ajXbFR196Y.9Ttbs\
    gzvGjbMeuWCtKve8TPjRMNoZK9EGyHQ6y0lW9OtWdHZrDZbBUhB9ou./VI2mlw'

    >>> #same, but with explict number of rounds
    >>> scram.encrypt("password", rounds=8000)
    '$scram$8000$Y0zp/R/DeO89h/De$sha-1=eE8dq1f1P1hZm21lfzsr3CMbiEA,sha-256=Nf\
    kaDFMzn/yHr/HTv7KEFZqaONo6psRu5LBBFLEbZ.o,sha-512=XnGG11X.J2VGSG1qTbkR3FVr\
    9j5JwsnV5Fd094uuC.GtVDE087m8e7rGoiVEgXnduL48B2fPsUD9grBjURjkiA'

    >>> #check if hash is recognized
    >>> scram.identify(h)
    True
    >>> #check if some other hash is recognized
    >>> scram.identify('$1$3azHgidD$SrJPt7B.9rekpmwJwtON31')
    False

    >>> #verify correct password
    >>> scram.verify("password", h)
    True
    >>> scram.verify("secret", h) #verify incorrect password
    False

Additionally, this class provides a number of useful methods
for SCRAM-specific actions::

    >>> from passlib.hash import scram
    >>> # generate new salt, encrypt password against default list of algorithms
    >>> scram.encrypt("password")
    '$scram$6400$.Z/znnNOKWUsBaCU$sha-1=cRseQyJpnuPGn3e6d6u6JdJWk.0,sha-256=5G\
    cjEbRaUIIci1r6NAMdI9OPZbxl9S5CFR6la9CHXYc,sha-512=.DHbIm82ajXbFR196Y.9Ttbs\
    gzvGjbMeuWCtKve8TPjRMNoZK9EGyHQ6y0lW9OtWdHZrDZbBUhB9ou./VI2mlw'

    >>> # generate new salt, encrypt password against specific list of algorithms
    >>> # and choose explicit number of rounds
    >>> h = scram.encrypt("password", rounds=1000, algs="sha-1,sha-256,md5")
    >>> h
    '$scram$1000$RsgZo7T2/l8rBUBI$md5=iKsH555d3ctn795Za4S7bQ,sha-1=dRcE2AUjALLF\
    tX5DstdLCXZ9Afw,sha-256=WYE/LF7OntriUUdFXIrYE19OY2yL0N5qsQmdPNFn7JE'

    >>> # given a scram hash, retrieve the information SCRAM needs
    >>> # to authenticate using a specific mechanism -
    >>> # returns salt, rounds, digest
    >>> scram.extact_digest_info(h, "sha-1")
    ('F\xc8\x19\xa3\xb4\xf6\xfe_+\x05@H',
     1000,
     'u\x17\x04\xd8\x05#\x00\xb2\xc5\xb5~C\xb2\xd7K\tv}\x01\xfc')

    >>> # given a scram hash, return list of digest algs present
    >>> scram.extract_digest_algs(h)
    ["md5", "sha-1", "sha-256"]

    >>> # and a standalone helper that can calculate the SaltedPassword
    >>> # portion of the SCRAM protocol, taking care of SASLPrep as well.
    >>> scram.derive_digest("password", b'\x01\x02\x03', 1000, "sha-1")
    b'k\x086vg\xb3\xfciz\xb4\xb4\xe2JRZ\xaet\xe4`\xe7'

Interface
=========
.. autoclass:: scram()

.. rst-class:: html-toggle

Format & Algorithm
==================
An example scram hash (of the string ``password``) is::

    $scram$6400$.Z/znnNOKWUsBaCU$sha-1=cRseQyJpnuPGn3e6d6u6JdJWk.0,sha-256=5G
    cjEbRaUIIci1r6NAMdI9OPZbxl9S5CFR6la9CHXYc,sha-512=.DHbIm82ajXbFR196Y.9Ttb
    sgzvGjbMeuWCtKve8TPjRMNoZK9EGyHQ6y0lW9OtWdHZrDZbBUhB9ou./VI2mlw'

An scram hash string has the format :samp:`$scram${rounds}${salt}${alg1}={digest1},{alg2}={digest2},{...}`, where:

* ``$scram$`` is the prefix used to identify Passlib scram hashes,
  following the :ref:`modular-crypt-format`

* :samp:`{rounds}` is the decimal number of rounds to use (6400 in the example).

* :samp:`{salt}` is a base64 encoded salt string (``.Z/znnNOKWUsBaCU`` in the example).

* :samp:`{alg}` is a lowercase IANA hash function name, which should
  match the digest in the SCRAM mechanism name.

* :samp:`{digest}` is a base64 digest for the specific algorithm.
  Digests for ``sha-1``, ``sha-256``, and ``sha-512`` are present in the example.

* There will be one or more :samp:`{alg}={digest}` pairs, separated by a comma;
  per the SCRAM specification, the algorithm ``sha-1`` should always be present.

There is also an alternate format :samp:`$scram${rounds}${salt}${alg}{,...}`
which is used to represent a configuration string that doesn't contain
any digests.

The algorithm used to calculate each digest is::

    pbkdf2(salsprep(password).encode("utf-8"), salt, rounds, -1, alg)

...as laid out in the SCRAM specification. All digests
verify against the same password, or the hash should be considered malformed.

.. note::

    This format is similar in spirit to the LDAP storage format for SCRAM hashes,
    defined in :rfc:`5803`, except that it encodes everything into a single
    string, and does not have any storage requirements (outside of the ability
    to store 512+ character ascii strings).
