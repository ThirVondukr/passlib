"""Roundup issue tracker hashes"""

import passlib.utils.handlers as uh

# local
__all__ = [
    "roundup_plaintext",
    "ldap_hex_md5",
    "ldap_hex_sha1",
]

roundup_plaintext = uh.PrefixWrapper(
    "roundup_plaintext", "plaintext", prefix="{plaintext}", lazy=True
)

# NOTE: these are here because they're currently only known to be used by roundup
ldap_hex_md5 = uh.PrefixWrapper("ldap_hex_md5", "hex_md5", "{MD5}", lazy=True)
ldap_hex_sha1 = uh.PrefixWrapper("ldap_hex_sha1", "hex_sha1", "{SHA}", lazy=True)
