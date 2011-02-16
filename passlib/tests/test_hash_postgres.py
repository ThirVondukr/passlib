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
from passlib.hash.postgres import PostgresMD5
#module
log = getLogger(__name__)

#=========================================================
#database hashes
#=========================================================
class PostgresMD5CryptTest(_HandlerTestCase):
    handler = PostgresMD5
    known_correct = [
        # ((secret,user),hash)
        (('mypass', 'postgres'), 'md55fba2ea04fd36069d2574ea71c8efe9d'),
        (('mypass', 'root'), 'md540c31989b20437833f697e485811254b'),
        (("testpassword",'testuser'), 'md5d4fc5129cc2c25465a5370113ae9835f'),
    ]
    known_invalid = [
        #bad 'z' char in otherwise correct hash
        'md54zc31989b20437833f697e485811254b',
    ]

    #NOTE: used to support secret=(password, user) format, but removed it for now.
    ##def test_tuple_mode(self):
    ##    "check tuple mode works for encrypt/verify"
    ##    self.assertEquals(self.handler.encrypt(('mypass', 'postgres')),
    ##        'md55fba2ea04fd36069d2574ea71c8efe9d')
    ##    self.assertEquals(self.handler.verify(('mypass', 'postgres'),
    ##        'md55fba2ea04fd36069d2574ea71c8efe9d'), True)

    def test_user(self):
        "check user kwd is required for encrypt/verify"
        self.assertRaises(TypeError, self.handler.encrypt, 'mypass')
        self.assertRaises(TypeError, self.handler.verify, 'mypass', 'md55fba2ea04fd36069d2574ea71c8efe9d')

    def do_concat(self, secret, prefix):
        if isinstance(secret, tuple):
            secret, user = secret
            secret = prefix + secret
            return secret, user
        else:
            return prefix + secret

    def do_encrypt(self, secret, **kwds):
        if isinstance(secret, tuple):
            secret, user = secret
        else:
            user = 'default'
        assert 'user' not in kwds
        kwds['user'] = user
        return self.handler.encrypt(secret, **kwds)

    def do_verify(self, secret, hash):
        if isinstance(secret, tuple):
            secret, user = secret
        else:
            user = 'default'
        return self.handler.verify(secret, hash, user=user)

#=========================================================
#EOF
#=========================================================
