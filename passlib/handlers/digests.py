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
from passlib.utils import handlers as uh, to_hash_str, bytes
from passlib.utils.md4 import md4
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
class HexDigestHash(uh.StaticHandler):
    "this provides a template for supporting passwords stored as plain hexidecimal hashes"
    _hash_func = None #required - hash function
    checksum_size = None #required - size of encoded digest
    checksum_chars = uh.HEX_CHARS

    @classmethod
    def identify(cls, hash):
        if not hash:
            return False
        if isinstance(hash, bytes):
            try:
                hash = hash.decode("ascii")
            except UnicodeDecodeError:
                return False
        cc = cls.checksum_chars
        return len(hash) == cls.checksum_size and all(c in cc for c in hash)

    @classmethod
    def genhash(cls, secret, hash):
        if hash is not None and not cls.identify(hash):
            raise ValueError("not a %s hash" % (cls.name,))
        if secret is None:
            raise TypeError("no secret provided")
        if isinstance(secret, unicode):
            secret = secret.encode("utf-8")
        return to_hash_str(cls._hash_func(secret).hexdigest())

    @classmethod
    def _norm_hash(cls, hash):
        if isinstance(hash, bytes):
            hash = hash.decode("ascii")
        return hash.lower()

def create_hex_hash(hash, digest_name):
    #NOTE: could set digest_name=hash.name for cpython, but not for some other platforms.
    h = hash()
    name = "hex_" + digest_name
    return type(name, (HexDigestHash,), dict(
        name=name,
        _hash_func=staticmethod(hash), #sometimes it's a function, sometimes not. so wrap it.
        checksum_size=h.digest_size*2,
        __doc__="""This class implements a plain hexidecimal %s hash, and follows the :ref:`password-hash-api`.

It supports no optional or contextual keywords.
""" % (digest_name,)
    ))

#=========================================================
#predefined handlers
#=========================================================
hex_md4     = create_hex_hash(md4,              "md4")
hex_md5     = create_hex_hash(hashlib.md5,      "md5")
hex_sha1    = create_hex_hash(hashlib.sha1,     "sha1")
hex_sha256  = create_hex_hash(hashlib.sha256,   "sha256")
hex_sha512  = create_hex_hash(hashlib.sha512,   "sha512")

#=========================================================
#eof
#=========================================================
