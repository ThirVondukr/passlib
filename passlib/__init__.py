"""passlib - suite of password hashing & generation routinges"""

__version__ = "1.3"

#=========================================================
#quickstart interface
#=========================================================
##from passlib.unix import default_context
##
##def identify(hash, name=True):
##    """Identify algorithm which generated a password hash.
##
##    :arg hash:
##        The hash string to identify.
##    :param name:
##        If ``True``, this function will return a name identifying the hash algorithm (the default).
##        If ``False``, it will return the handler object associated with that algorithm.
##
##    The following algorithms are currently recognized:
##
##        =================== ================================================
##        Name                Description
##        ------------------- ------------------------------------------------
##        ``"des-crypt"``    the historical unix crypt algorithm based on DES
##
##        ``"md5-crypt"``     the md5-crypt algorithm, usually identified
##                            by the prefix ``$1$`` in unix shadow files.
##
##        ``"bcrypt"``        the openbsd blowfish-crypt algorithm,
##                            usually identified by the prefixes ``$2$`` or ``$2a$``
##                            in unix shadow files.
##
##        ``"sha256-crypt"``  the 256-bit version of the sha-crypt algorithm,
##                            usually identified by the prefix ``$5$``
##                            in unix shadow files.
##
##        ``"sha512-crypt"``  the 512-bit version of the sha-crypt algorithm,
##                            usually identified by the prefix ``$6$``
##                            in unix shadow files.
##        =================== ================================================
##
##    :returns:
##        The name of the hash, or ``None`` if the hash could not be identified.
##        (The return may be altered by the *resolve* keyword).
##
##    .. note::
##        This is a convience wrapper for ``pwhash.default_context.identify(hash)``.
##    """
##    return default_context.identify(hash, name=name)
##
##def encrypt(secret, alg=None, **kwds):
##    """Encrypt secret using a password hash algorithm.
##
##    :type secret: str
##    :arg secret:
##        String containing the secret to encrypt
##
##    :type alg: str|None
##    :param alg:
##        Optionally specify the name of the algorithm to use.
##        If no algorithm is specified, an attempt is made
##        to guess from the hash string. If no hash string
##        is specified, sha512-crypt will be used.
##        See :func:`identify` for a list of algorithm names.
##
##    All other keywords are passed on to the specific password algorithm
##    being used to encrypt the secret.
##
##    :type rounds: int
##    :param rounds:
##        For the sha256-crypt and sha512-crypt algorithms,
##        this option lets you specify the number of rounds
##        of encryption to use. For the bcrypt algorithm,
##        this option lets you specify the log-base-2 of
##        the number of rounds of encryption to use.
##
##        For all three of these algorithms, you can either
##        specify a positive integer, or one of the strings
##        "fast", "medium", "slow" to choose a preset number
##        of rounds corresponding to an appropriate level
##        of encryption.
##
##    :returns:
##        The secret as encoded by the specified algorithm and options.
##    """
##    return default_context.encrypt(secret, alg=alg, **kwds)
##
##def verify(secret, hash, alg=None):
##    """verify a secret against an existing hash.
##
##    This checks if a secret matches against the one stored
##    inside the specified hash. By default this uses :func:`encrypt`
##    to re-crypt the secret, and compares it to the provided hash;
##    though some algorithms may implement this in a more efficient manner.
##
##    :type secret: str
##    :arg secret:
##        A string containing the secret to check.
##
##    :type hash: str
##    :param hash:
##        A string containing the hash to check against.
##
##    :type alg: str|None
##    :param alg:
##        Optionally specify the name of the algorithm to use.
##        If no algorithm is specified, an attempt is made
##        to guess from the hash string. If it can't be
##        identified, a ValueError will be raised.
##        See :func:`identify` for a list of algorithm names.
##
##    :returns:
##        ``True`` if the secret matches, otherwise ``False``.
##    """
##    return default_context.verify(secret, hash, alg=alg)

#=========================================================
#eof
#=========================================================
