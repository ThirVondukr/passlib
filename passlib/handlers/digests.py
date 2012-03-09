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
from passlib.utils import to_native_str, to_bytes
from passlib.utils.compat import bascii_to_str, bytes, unicode, str_to_uascii
import passlib.utils.handlers as uh
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
    #=========================================================
    # class attrs
    #=========================================================
    _hash_func = None # hash function to use - filled in by create_hex_hash()
    checksum_size = None # filled in by create_hex_hash()
    checksum_chars = uh.HEX_CHARS

    #=========================================================
    # methods
    #=========================================================
    @classmethod
    def _norm_hash(cls, hash):
        return hash.lower()

    def _calc_checksum(self, secret):
        secret = to_bytes(secret, "utf-8", errname="secret")
        return str_to_uascii(self._hash_func(secret).hexdigest())

    #=========================================================
    # eoc
    #=========================================================

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
