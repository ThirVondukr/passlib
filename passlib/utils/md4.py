"""
passlib.utils.md4 - DEPRECATED MODULE, WILL BE REMOVED IN 2.0

MD4 should now be looked up through ``passlib.crypto.digest.lookup_hash("md4").const``,
which provides unified handling stdlib implementation (if present).
"""

from warnings import warn

from passlib.crypto.digest import lookup_hash

warn(
    "the module 'passlib.utils.md4' is deprecated as of Passlib 1.7, "
    "and will be removed in Passlib 2.0, please use "
    "'lookup_hash(\"md4\").const()' from 'passlib.crypto' instead",
    DeprecationWarning,
)

__all__ = ["md4"]

# this should use hashlib version if available,
# and fall back to builtin version.

md4 = lookup_hash("md4").const
del lookup_hash
