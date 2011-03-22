"""passlib.handlers.digests - plain hash digests
"""
#=========================================================
#imports
#=========================================================
#core
import hashlib
import logging; log = logging.getLogger(__name__)
from warnings import warn
#site
#libs
from passlib.utils.md4 import md4
from passlib.utils.handlers import SimpleHandler
#pkg
#local
__all__ = [
    "create_hex_hash",
    "hex_md4",
    "hex_md5",
    "hex_sha1",
    "hex_sha256",
    "hex_sha512",
]

#=========================================================
#helpers for hexidecimal hashes
#=========================================================
class HexDigestHash(SimpleHandler):
    "this provides a template for supporting passwords stored as plain hexidecimal hashes"
    setting_kwds = ()
    context_kwds = ()

    _hash = None
    checksum_chars = None
    checksum_charset = "0123456789abcdef"

    @classmethod
    def identify(cls, hash):
        cc = cls.checksum_charset
        return bool(hash) and len(hash) == cls.checksum_chars and all(c in cc for c in hash)

    @classmethod
    def genhash(cls, secret, hash):
        if secret is None:
            raise TypeError, "no secret provided"
        if isinstance(secret, unicode):
            secret = secret.encode("utf-8")
        if hash is not None and not cls.identify(hash):
            raise ValueError, "not a %s hash" % (cls.name,)
        return cls._hash(secret).hexdigest()

    @classmethod
    def verify(cls, secret, hash):
        if hash is None:
            raise ValueError, "no hash specified"
        return cls.genhash(secret, hash) == hash.lower()

def create_hex_hash(hash):
    h = hash()
    name = 'hex_' + h.name
    return type(name, (HexDigestHash,), dict(
        name=name,
        _hash=hash,
        checksum_chars=h.digest_size*2,
        __doc__="""This class implements a plain hexidecimal %s hash, and follows the :ref:`password-hash-api`.

It supports no optional or contextual keywords.
""" % (h.name,)
    ))

#=========================================================
#predefined handlers
#=========================================================
hex_md4 = create_hex_hash(md4)
hex_md5 = create_hex_hash(hashlib.md5)
hex_sha1 = create_hex_hash(hashlib.sha1)
hex_sha256 = create_hex_hash(hashlib.sha256)
hex_sha512 = create_hex_hash(hashlib.sha512)

#=========================================================
#eof
#=========================================================
