"""passlib.hosts"""
#=========================================================
#imports
#=========================================================
#core
import sys
#pkg
from passlib.context import CryptContext
#local
__all__ = [
    "linux_context", "linux2_context",
    "openbsd_context",
    "netbsd_context",
    "freebsd_context",
    "host_context",
]

#=========================================================
#linux support
#=========================================================

#known platform names - linux2

linux_context = linux2_context = CryptContext(
    schemes = [ "sha512_crypt", "sha256_crypt", "md5_crypt",
               "des_crypt", "unix_fallback" ],
    deprecated = [ "des_crypt" ],
    )

#=========================================================
#bsd support
#=========================================================

#known platform names -
#   freebsd2
#   freebsd3
#   freebsd4
#   freebsd5
#   freebsd6
#   freebsd7
#
#   netbsd1

#referencing source via -http://fxr.googlebit.com
# freebsd 6,7,8 - des, md5, bcrypt, nthash
# netbsd - des, ext, md5, bcrypt, sha1
# openbsd - des, ext, md5, bcrypt

freebsd_context = CryptContext([ "bcrypt", "md5_crypt", "nthash", "des_crypt", "unix_fallback" ])
openbsd_context = CryptContext([ "bcrypt", "md5_crypt", "bsdi_crypt", "des_crypt", "unix_fallback" ])
netbsd_context = CryptContext([ "bcrypt", "sha1_crypt", "md5_crypt", "bsdi_crypt", "des_crypt", "unix_fallback" ])

#=========================================================
#current host
#=========================================================

#context we fall back to if not on a unix system,
#or if we don't recognize platform
fallback_context = CryptContext(["unix_fallback"])

if sys.platform == "linux2":
    host_context = linux2_context
elif sys.platform.startswith("freebsd"):
    host_context = freebsd_context
elif sys.platform.startswith("netbsd"):
    host_context = netbsd_context
elif sys.platform.startswith("openbsd"):
    host_context = openbsd_context
else:
    host_context = fallback_context

#=========================================================
#other platforms
#=========================================================

#known platform strings -
#aix3
#aix4
#atheos
#beos5
#darwin
#generic
#hp-ux11
#irix5
#irix6
#mac
#next3
#os2emx
#riscos
#sunos5
#unixware7

#=========================================================
#eof
#=========================================================
