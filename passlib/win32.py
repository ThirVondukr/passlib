"""passlib.win32 - MS Windows support

the LMHASH and NTHASH algorithms are used in various windows related contexts,
but generally not in a manner compatible with how passlib is structured.

in particular, they have no identifying marks, both being
32 bytes of binary data. thus, they can't be easily identified
in a context with other hashes, so a CryptHandler hasn't been defined for them.

this module provided two functions to aid in any use-cases which exist.

.. warning::

    these functions should not be used for new code unless an existing
    system requires them, they are both known broken,
    and are beyond insecure on their own.

.. autofunction:: raw_lmhash
.. autofunction:: raw_nthash

See also :mod:`passlib.hash.nthash`.
"""
#=========================================================
#imports
#=========================================================
#core
from binascii import hexlify
#site
#pkg
from passlib.utils.des import des_encrypt_block
from passlib.hash import nthash
#local
__all__ = [
    "nthash",
    "raw_lmhash",
    "raw_nthash",
]
#=========================================================
#helpers
#=========================================================
LM_MAGIC = "KGS!@#$%"

raw_nthash = nthash.raw_nthash

def raw_lmhash(secret, hex=False):
    "encode password using des-based LMHASH algorithm; returns string of raw bytes"
    #XXX: encoding should be oem ascii
    ns = secret.upper()[:14] + "\x00" * (14-len(secret))
    out = des_encrypt_block(ns[:7], LM_MAGIC) + des_encrypt_block(ns[7:], LM_MAGIC)
    return hexlify(out) if hex else out

#=========================================================
#eoc
#=========================================================
