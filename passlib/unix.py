"""passlib.unix
"""
#=========================================================
#imports
#=========================================================
#pkg
from passlib.base import CryptContext, register_crypt_handler
from passlib.utils.drivers import CryptHandler
#local
__all__ = [
    "default_context",
    "linux_context",
    "bsd_context",
        "openbsd_context",
        "netbsd_context",
        "freebsd_context",

    "UnixDisabledHandler",
]
#=========================================================
#helpers
#=========================================================
class UnixDisabledHandler(CryptHandler):
    """fake crypt handler which handles special (non-hash) strings found in /etc/shadow

    unix shadow files sometimes have "!" or "*" characters indicating logins are disabled.
    linux also prepends "!" to valid hashes to indicate a password is disabled.

    this is a fake password hash, designed to recognize those values,
    and return False for all verify attempts.
    """
    name = "unix_disabled"
    setting_kwds = ()
    context_kwds = ()

    @classmethod
    def genconfig(cls):
        return None

    @classmethod
    def genhash(cls, secret, config):
        return "!"

    @classmethod
    def identify(cls, hash):
        return not hash or hash == "*" or hash.startswith("!")

    @classmethod
    def verify(cls, secret, hash):
        return False

register_crypt_handler(UnixDisabledHandler)

#TODO: UnknownCryptHandler - given hash, detect if system crypt recognizes it,
# allowing for pass-through for unknown ones.

#=========================================================
#build default context objects
#=========================================================

#default context for quick use.. recognizes common algorithms, uses SHA-512 as default
#er... should we promote bcrypt as default?
default_context = CryptContext(["unix_disabled", "des_crypt", "md5_crypt", "bcrypt", "sha256_crypt", "sha512_crypt"])

#=========================================================
#some general os-context helpers (these may not match your os policy exactly, but are generally useful)
#=========================================================


#referencing linux shadow...
# linux - des,md5, sha256, sha512

linux_context = CryptContext([ "unix_disabled", "des_crypt", "md5_crypt", "sha256_crypt", "sha512_crypt" ])

#referencing source via -http://fxr.googlebit.com
# freebsd 6,7,8 - des, md5, bcrypt, nthash
# netbsd - des, ext, md5, bcrypt, sha1
# openbsd - des, ext, md5, bcrypt
bsd_context = CryptContext(["unix_disabled",  "nthash", "des_crypt", "ext_des_crypt", "md5_crypt", "bcrypt"])
freebsd_context = CryptContext([ "unix_disabled",  "des_crypt", "nthash", "md5_crypt", "bcrypt"])
openbsd_context = CryptContext([ "unix_disabled",  "des_crypt", "ext_des_crypt", "md5_crypt", "bcrypt"])
netbsd_context = CryptContext([ "unix_disabled",  "des_crypt", "ext_des_crypt", "md5_crypt", "bcrypt", "sha1_crypt"])

#=========================================================
#eof
#=========================================================
