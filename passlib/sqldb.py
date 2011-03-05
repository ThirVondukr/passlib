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
    'postgres_plaintext',
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
from passlib.drivers.postgres import postgres_plaintext, postgres_md5
postgres_context = CryptContext([postgres_plaintext, postgres_md5])

#=========================================================
#mysql
#=========================================================
from passlib.drivers.mysql import mysql323, mysql41
mysql3_context = CryptContext([mysql323])
mysql_context = CryptContext([mysql41, mysql323])

#=========================================================
#TODO:
#=========================================================
#oracle - http://www.notesbit.com/index.php/scripts-oracle/oracle-11g-new-password-algorithm-is-revealed-by-seclistsorg/

#=========================================================
# eof
#=========================================================
