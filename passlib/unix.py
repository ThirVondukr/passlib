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

#TODO: replace this with a "generic-reject" (also add a "generic-allow")

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
##default_context = CryptContext(["sha512_crypt",  "sha256_crypt", "bcrypt", "md5_crypt", "des_crypt", "unix_disabled" ])

#=========================================================
#some general os-context helpers (these may not match your os policy exactly, but are generally useful)
#=========================================================


#referencing linux shadow...
# linux - des,md5, sha256, sha512

linux_context = CryptContext([ "sha512_crypt", "sha256_crypt", "md5_crypt", "des_crypt", "unix_disabled" ])

#referencing source via -http://fxr.googlebit.com
# freebsd 6,7,8 - des, md5, bcrypt, nthash
# netbsd - des, ext, md5, bcrypt, sha1
# openbsd - des, ext, md5, bcrypt
bsd_context = CryptContext(["bcrypt",  "md5_crypt", "bsdi_crypt", "des_crypt", "nthash", "unix_disabled" ])
freebsd_context = CryptContext([  "bcrypt", "md5_crypt", "nthash", "des_crypt", "unix_disabled" ])
openbsd_context = CryptContext([ "bcrypt", "md5_crypt", "bsdi_crypt", "des_crypt", "unix_disabled" ])
netbsd_context = CryptContext([  "bcrypt", "sha1_crypt", "md5_crypt", "bsdi_crypt", "des_crypt", "unix_disabled" ])


#aix3
#aix4
#atheos
#beos5
#darwin
#freebsd2
#freebsd3
#freebsd4
#freebsd5
#freebsd6
#freebsd7
#generic
#hp-ux11
#irix5
#irix6
#linux2
#mac
#netbsd1
#next3
#os2emx
#riscos
#sunos5
#unixware7

#=========================================================
#eof
#=========================================================
