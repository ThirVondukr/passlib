"""tests for passlib.win32 -- (c) Assurance Technologies 2003-2009"""
#=========================================================
#imports
#=========================================================
#core
from binascii import hexlify
#site
#pkg
from passlib.tests.utils import TestCase
#module
import passlib.win32 as mod

#=========================================================
#
#=========================================================
class UtilTest(TestCase):
    "test util funcs in passlib.win32"

    ##test hashes from http://msdn.microsoft.com/en-us/library/cc245828(v=prot.10).aspx
    ## among other places

    def test_lmhash(self):
        for secret, hash in [
            ("OLDPASSWORD", u"c9b81d939d6fd80cd408e6b105741864"),
            ("NEWPASSWORD", u'09eeab5aa415d6e4d408e6b105741864'),
            ("welcome", u"c23413a8a1e7665faad3b435b51404ee"),
            ]:
            result = mod.raw_lmhash(secret, hex=True)
            self.assertEqual(result, hash)

    def test_nthash(self):
        for secret, hash in [
            ("OLDPASSWORD", u"6677b2c394311355b54f25eec5bfacf5"),
            ("NEWPASSWORD", u"256781a62031289d3c2c98c14f1efc8c"),
            ]:
            result = mod.raw_nthash(secret, hex=True)
            self.assertEqual(result, hash)

#=========================================================
#EOF
#=========================================================
