"""
apache support

http://httpd.apache.org/docs/2.2/misc/password_encryptions.html
http://httpd.apache.org/docs/2.0/programs/htpasswd.html
NOTE: digest format is md5(user ":" realm ":" passwd).hexdigest()
    file is "user:realm:hash"
"""
#=========================================================
#imports
#=========================================================
from __future__ import with_statement
#core
import logging; log = logging.getLogger(__name__)
#site
#libs
from passlib.drivers.import postgres_md5
from passlib.base import CryptContext
#pkg
#local
__all__ = [
    'postgres_md5',
    'postgres_context',
]

#=========================================================
#db contexts
#=========================================================
postgres_context = CryptContext([postgres_md5])

#=========================================================
# eof
#=========================================================
