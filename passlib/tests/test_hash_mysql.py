"""tests for passlib.pwhash -- (c) Assurance Technologies 2003-2009"""
#=========================================================
#imports
#=========================================================
from __future__ import with_statement
#core
import hashlib
from logging import getLogger
#site
#pkg
from passlib.tests.handler_utils import _HandlerTestCase
from passlib.hash.mysql import MySQL_323, MySQL_41
#module
log = getLogger(__name__)

#=========================================================
#database hashes
#=========================================================
class MySQL_323Test(_HandlerTestCase):
    handler = MySQL_323

    #remove single space from secrets, since mysql-323 ignores all whitespace (?!)
    standard_secrets = [ x for x in _HandlerTestCase.standard_secrets if x != ' ' ]

    known_correct = (
        ('mypass', '6f8c114b58f2ce9e'),
    )
    known_invalid = [
        #bad char in otherwise correct hash
        '6z8c114b58f2ce9e',
    ]

    def test_whitespace(self):
        "check whitespace is ignored per spec"
        h = self.do_encrypt("mypass")
        h2 = self.do_encrypt("my pass")
        self.assertEqual(h, h2)

class MySQL_41Test(_HandlerTestCase):
    handler = MySQL_41
    known_correct = (
        ('mypass', '*6C8989366EAF75BB670AD8EA7A7FC1176A95CEF4'),
    )
    known_invalid = [
        #bad char in otherwise correct hash
        '*6Z8989366EAF75BB670AD8EA7A7FC1176A95CEF4',
    ]

#=========================================================
#EOF
#=========================================================
