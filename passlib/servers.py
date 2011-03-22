"""passlib.servers"""
#=========================================================
#imports
#=========================================================
#core
import platform
import logging; log = logging.getLogger(__name__)
#site
#libs
from passlib.context import CryptContext
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
_is32 = platform.architecture()[0] == '32bit'

custom_app_context = CryptContext(
    schemes=["sha512_crypt", "sha256_crypt"],
    default="sha256_crypt" if _is32 else "sha512_crypt",
    sha512_crypt__default_rounds = 40000,
    sha256_crypt__default_rounds = 40000,
    all__vary_rounds = "10%",
    )

#=========================================================
#ldap
#=========================================================
#TODO: support ldap_crypt
ldap_context = CryptContext(["ldap_salted_sha1", "ldap_salted_md5", "ldap_sha1", "ldap_md5", "ldap_cleartext" ])

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
# eof
#=========================================================
