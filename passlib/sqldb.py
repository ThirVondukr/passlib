"""passlib - implementation of various password hashing functions"""
#=========================================================
#imports
#=========================================================
#core
import logging; log = logging.getLogger(__name__)
#site
#libs
from passlib.base import CryptContext
#pkg
#local
__all__ = [
    #postgres
    'postgres_md5',
    'postgres_context',

    #mysql
    'mysql323',
    'mysql41',
    'mysql3_context',
    'mysql_context'
]

#=========================================================
#postgres
#=========================================================
from passlib.drivers.postgres import postgres_md5
postgres_context = CryptContext([postgres_md5])

#=========================================================
#mysql
#=========================================================
from passlib.drivers.mysql import mysql323, mysql41
mysql3_context = CryptContext([mysql323])
mysql_context = mysql4 = CryptContext([mysql41, mysql323])

#=========================================================
#TODO:
#=========================================================
#oracle
#mssql

#=========================================================
# eof
#=========================================================
