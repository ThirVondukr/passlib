"""passlib.apps"""
#=========================================================
#imports
#=========================================================
#core
import logging; log = logging.getLogger(__name__)
#site
#libs
from passlib import hash
from passlib.context import CryptContext
from passlib.utils import sys_bits
#pkg
#local
__all__ = [
    'custom_app_context',
    'postgres_context',
    'ldap_context',
    #mssql
    'mysql_context', 'mysql4_context', 'mysql3_context',
    #oracle
]

#=========================================================
#for quickly bootstrapping new custom applications
#=========================================================
custom_app_context = CryptContext(
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
#TODO: support ldap_crypt
ldap_context = CryptContext(["ldap_salted_sha1", "ldap_salted_md5", "ldap_sha1", "ldap_md5", "ldap_plaintext" ])

#=========================================================
#mysql
#=========================================================
mysql3_context = CryptContext(["mysql323"])
mysql4_context = CryptContext(["mysql41", "mysql323"], deprecated="mysql323")
mysql_context = mysql4_context #tracks latest mysql version supported

#=========================================================
#postgres
#=========================================================
postgres_context = CryptContext(["postgres_md5"])

#=========================================================
#phpass
#=========================================================
#TODO: support phpass_context (and don't use bcrypt as default if not available)

phpass_context = CryptContext(
    schemes=["bcrypt", "bsdi_crypt", "phpass",],
    default="bcrypt" if hash.bcrypt.has_backend() else "bsdi_crypt",
    )

phpbb3_context = CryptContext(["phpass"], phpass__ident="H")

#TODO: support the drupal phpass variants (see phpass homepage)

#=========================================================
# eof
#=========================================================
