"""passlib.hosts"""
#=========================================================
#imports
#=========================================================
#pkg
from passlib.context import CryptContext
#local
__all__ = [
    "default_context",
    "linux_context", "linux2_context",
    "bsd_context",
        "openbsd_context",
        "netbsd_context",
        "freebsd_context",

]

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

linux_context = linux2_context = CryptContext([ "sha512_crypt", "sha256_crypt", "md5_crypt", "des_crypt", "unix_fallback" ])

#referencing source via -http://fxr.googlebit.com
# freebsd 6,7,8 - des, md5, bcrypt, nthash
# netbsd - des, ext, md5, bcrypt, sha1
# openbsd - des, ext, md5, bcrypt
bsd_context = CryptContext(["bcrypt",  "md5_crypt", "bsdi_crypt", "des_crypt", "nthash", "unix_fallback" ])
freebsd_context = CryptContext([ "bcrypt", "md5_crypt", "nthash", "des_crypt", "unix_fallback" ])
openbsd_context = CryptContext([ "bcrypt", "md5_crypt", "bsdi_crypt", "des_crypt", "unix_fallback" ])
netbsd_context = CryptContext([ "bcrypt", "sha1_crypt", "md5_crypt", "bsdi_crypt", "des_crypt", "unix_fallback" ])


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
