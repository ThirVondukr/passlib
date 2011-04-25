"""passlib.apps"""
#=========================================================
#imports
#=========================================================
#core
import logging; log = logging.getLogger(__name__)
from itertools import chain
#site
#libs
from passlib import hash
from passlib.context import LazyCryptContext
from passlib.utils import sys_bits
#pkg
#local
__all__ = [
    'custom_app_context',
    'ldap_context', 'ldap_nocrypt_context',
    'mysql_context', 'mysql4_context', 'mysql3_context',
    'phpass_context',
    'phpbb3_context',
    'postgres_context',
]

#=========================================================
#for quickly bootstrapping new custom applications
#=========================================================
custom_app_context = LazyCryptContext(
    #choose some reasonbly strong schemes
    schemes=["sha512_crypt", "sha256_crypt"],

    #set some useful global options
    min_verify_time = .125,
    all__vary_rounds = "10%",
    default="sha256_crypt" if sys_bits < 64 else "sha512_crypt",

    #set a good starting point for rounds selection
    sha512_crypt__default_rounds = 40000,
    sha256_crypt__default_rounds = 40000,

    #if the admin user category is selected, make a much stronger hash,
    admin__sha512_crypt__default_rounds = 80000,
    admin__sha256_crypt__default_rounds = 80000,
    )

#=========================================================
#ldap
#=========================================================
std_ldap_schemes = ["ldap_salted_sha1", "ldap_salted_md5",
                      "ldap_sha1", "ldap_md5",
                      "ldap_plaintext" ]

#create context with all std ldap schemes EXCEPT crypt
ldap_nocrypt_context = LazyCryptContext(std_ldap_schemes)

#create context with all possible std ldap + ldap crypt schemes
def _iter_ldap_crypt_schemes():
    from passlib.utils import unix_crypt_schemes
    return ('ldap_' + name for name in unix_crypt_schemes)

def _iter_ldap_schemes():
    "helper which iterates over supported std ldap schemes"
    return chain(std_ldap_schemes, _iter_ldap_crypt_schemes())
ldap_context = LazyCryptContext(_iter_ldap_schemes())

###create context with all std ldap schemes + crypt schemes for localhost
##def _iter_host_ldap_schemes():
##    "helper which iterates over supported std ldap schemes"
##    from passlib.handlers.ldap_digests import get_host_ldap_crypt_schemes
##    return chain(std_ldap_schemes, get_host_ldap_crypt_schemes())
##ldap_host_context = LazyCryptContext(_iter_host_ldap_schemes())

#=========================================================
#mysql
#=========================================================
mysql3_context = LazyCryptContext(["mysql323"])
mysql4_context = LazyCryptContext(["mysql41", "mysql323"], deprecated="mysql323")
mysql_context = mysql4_context #tracks latest mysql version supported

#=========================================================
#postgres
#=========================================================
postgres_context = LazyCryptContext(["postgres_md5"])

#=========================================================
#phpass & variants
#=========================================================
phpass_context = LazyCryptContext(
    schemes=["bcrypt", "bsdi_crypt", "phpass",],
    default="bcrypt" if hash.bcrypt.has_backend() else "bsdi_crypt",
    )

phpbb3_context = LazyCryptContext(["phpass"], phpass__ident="H")

#TODO: support the drupal phpass variants (see phpass homepage)

#=========================================================
#roundup
#=========================================================

_std_roundup_schemes = [ "ldap_hex_sha1", "ldap_hex_md5", "ldap_des_crypt", "roundup_plaintext" ]
roundup10 = roundup_context = LazyCryptContext(_std_roundup_schemes)

#this roundup hasn't been released yet, may have diff version...
#roundup_context = roundup15_context = LazyCryptContext(_std_roundup_schemes + [ "roundup_pbkdf2_sha1" ])

#=========================================================
# eof
#=========================================================
