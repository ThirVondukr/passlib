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
from passlib.tests.utils import TestCase, enable_option
from passlib.tests.handler_utils import _HandlerTestCase
from passlib.hash.des_crypt import DesCrypt, ExtDesCrypt
#module
log = getLogger(__name__)

#=========================================================
#test frontend class
#=========================================================
class DesCryptTest(_HandlerTestCase):
    "test DesCrypt algorithm"
    handler = DesCrypt
    secret_chars = 8

    #TODO: test

    known_correct = (
        #secret, example hash which matches secret
        ('', 'OgAwTx2l6NADI'),
        (' ', '/Hk.VPuwQTXbc'),
        ('test', 'N1tQbOFcM5fpg'),
        ('Compl3X AlphaNu3meric', 'um.Wguz3eVCx2'),
        ('4lpHa N|_|M3r1K W/ Cur5Es: #$%(*)(*%#', 'sNYqfOyauIyic'),
        ('AlOtBsOl', 'cEpWz5IUCShqM'),
        (u'hell\u00D6', 'saykDgk3BPZ9E'),
        )
    known_invalid = [
        #bad char in otherwise correctly formatted hash
        '!gAwTx2l6NADI',
        ]

if enable_option("all-backends") and DesCrypt.get_backend() != "builtin":

    class BuiltinDesCryptTest(DesCryptTest):
        case_prefix = "des-crypt (builtin backend)"

        def setUp(self):
            self.tmp = self.handler.get_backend()
            self.handler.set_backend("builtin")

        def cleanUp(self):
            self.handler.set_backend(self.tmp)

#=========================================================
#bsdi crypt
#=========================================================
class ExtDesCryptTest(_HandlerTestCase):
    "test ExtDesCrypt algorithm"
    handler = ExtDesCrypt
    known_correct = [
        (" ", "_K1..crsmZxOLzfJH8iw"),
        ("my", '_KR/.crsmykRplHbAvwA'), #<- to detect old 12-bit rounds bug
        ("my socra", "_K1..crsmf/9NzZr1fLM"),
        ("my socrates", '_K1..crsmOv1rbde9A9o'),
        ("my socrates note", "_K1..crsm/2qeAhdISMA"),
    ]
    known_invalid = [
        #bad char in otherwise correctly formatted hash
       "_K1.!crsmZxOLzfJH8iw"
    ]

#=========================================================
#EOF
#=========================================================
