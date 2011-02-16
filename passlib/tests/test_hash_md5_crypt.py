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
from passlib.tests.handler_utils import _HandlerTestCase, create_backend_case
from passlib.tests.utils import enable_option
from passlib.hash.md5_crypt import Md5Crypt, AprMd5Crypt
#module
log = getLogger(__name__)

#=========================================================
#md5 crypt
#=========================================================
class Md5CryptTest(_HandlerTestCase):
    handler = Md5Crypt

    known_correct = (
        ('', '$1$dOHYPKoP$tnxS1T8Q6VVn3kpV8cN6o.'),
        (' ', '$1$m/5ee7ol$bZn0kIBFipq39e.KDXX8I0'),
        ('test', '$1$ec6XvcoW$ghEtNK2U1MC5l.Dwgi3020'),
        ('Compl3X AlphaNu3meric', '$1$nX1e7EeI$ljQn72ZUgt6Wxd9hfvHdV0'),
        ('4lpHa N|_|M3r1K W/ Cur5Es: #$%(*)(*%#', '$1$jQS7o98J$V6iTcr71CGgwW2laf17pi1'),
        ('test', '$1$SuMrG47N$ymvzYjr7QcEQjaK5m1PGx1'),
        )

    known_identified_invalid = [
        #bad char in otherwise correct hash
        '$1$dOHYPKoP$tnxS1T8Q6VVn3kpV8cN6o!',
        ]

BuiltinMd5CryptTest = create_backend_case(Md5CryptTest, "builtin")

#=========================================================
#apr md5 crypt
#=========================================================
class AprMd5CryptTest(_HandlerTestCase):
    handler = AprMd5Crypt

    #values taken from http://httpd.apache.org/docs/2.2/misc/password_encryptions.html
    known_correct = (
        ('myPassword', '$apr1$r31.....$HqJZimcKQFAMYayBlzkrA/'),
        )

    known_identified_invalid = [
        #bad char in otherwise correct hash
        '$apr1$r31.....$HqJZimcKQFAMYayBlzkrA!'
        ]

#=========================================================
#EOF
#=========================================================
