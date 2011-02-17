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
from passlib.base import CryptContext
from passlib.tests.utils import TestCase
from passlib.drivers.md5_crypt import Md5Crypt as AnotherHash
from passlib.tests.test_utils_drivers import UnsaltedHash, SaltedHash
#module
log = getLogger(__name__)

#
#FIXME: this unit test does not match the current CryptContext *at all*,
# and needs to be updated / rewritten to match new system
#

#=========================================================
#CryptContext
#=========================================================
class CryptContextTest(TestCase):
    "test CryptContext object's behavior"

    #=========================================================
    #0 constructor
    #=========================================================
    def test_00_constructor(self):
        "test CryptContext constructor using classes"
        #create crypt context
        cc = CryptContext([UnsaltedHash, SaltedHash, AnotherHash])

        #parse
        c, b, a = cc._handlers
        self.assertIs(a, UnsaltedHash)
        self.assertIs(b, SaltedHash)
        self.assertIs(c, AnotherHash)

    def test_01_constructor(self):
        "test CryptContext constructor using instances"
        #create crypt context
        a = UnsaltedHash
        b = SaltedHash
        c = AnotherHash
        cc = CryptContext([a,b,c])

        #verify elements
        self.assertEquals(list(cc._handlers), [c, b, a])

    #TODO: test constructor using names

    #=========================================================
    #1 list getters
    #=========================================================
    ##def test_10_getitem(self):
    ##    "test CryptContext.__getitem__[idx]"
    ##    #create crypt context
    ##    cc = CryptContext([UnsaltedHash, SaltedHash, AnotherHash])
    ##    a, b, c = cc
    ##
    ##    #verify len
    ##    self.assertEquals(len(cc), 3)
    ##
    ##    #verify getitem
    ##    self.assertEquals(cc[0], a)
    ##    self.assertEquals(cc[1], b)
    ##    self.assertEquals(cc[2], c)
    ##    self.assertEquals(cc[-1], c)
    ##    self.assertRaises(IndexError, cc.__getitem__, 3)

    ##def test_11_index(self):
    ##    "test CryptContext.index(elem)"
    ##    #create crypt context
    ##    cc = CryptContext([UnsaltedHash, SaltedHash, AnotherHash])
    ##    a, b, c = cc
    ##    d = AnotherHash()
    ##
    ##    self.assertEquals(cc.index(a), 0)
    ##    self.assertEquals(cc.index(b), 1)
    ##    self.assertEquals(cc.index(c), 2)
    ##    self.assertEquals(cc.index(d), -1)

    ##def test_12_contains(self):
    ##    "test CryptContext.__contains__(elem)"
    ##    #create crypt context
    ##    cc = CryptContext([UnsaltedHash, SaltedHash, AnotherHash])
    ##    a, b, c = cc
    ##    d = AnotherHash()
    ##
    ##    self.assertEquals(a in cc, True)
    ##    self.assertEquals(b in cc, True)
    ##    self.assertEquals(c in cc, True)
    ##    self.assertEquals(d in cc, False)

    #=========================================================
    #2 list setters
    #=========================================================
    ##def test_20_setitem(self):
    ##    "test CryptContext.__setitem__"
    ##    cc = CryptContext([UnsaltedHash, SaltedHash, AnotherHash])
    ##    a, b, c = cc
    ##    d = AnotherHash()
    ##    self.assertIsNot(c, d)
    ##    e = pwhash.Md5Crypt()
    ##
    ##    #check baseline
    ##    self.assertEquals(list(cc), [a, b, c])
    ##
    ##    #replace 0 w/ d should raise error (AnotherHash already in list)
    ##    self.assertRaises(KeyError, cc.__setitem__, 0, d)
    ##    self.assertEquals(list(cc), [a, b, c])
    ##
    ##    #replace 0 w/ e
    ##    cc[0] = e
    ##    self.assertEquals(list(cc), [e, b, c])
    ##
    ##    #replace 2 w/ d
    ##    cc[2] = d
    ##    self.assertEquals(list(cc), [e, b, d])
    ##
    ##    #replace -1 w/ c
    ##    cc[-1] = c
    ##    self.assertEquals(list(cc), [e, b, c])
    ##
    ##    #replace -2 w/ d should raise error
    ##    self.assertRaises(KeyError, cc.__setitem__, -2, d)
    ##    self.assertEquals(list(cc), [e, b, c])

    ##def test_21_append(self):
    ##    "test CryptContext.__setitem__"
    ##    cc = CryptContext([UnsaltedHash])
    ##    a, = cc
    ##    b = SaltedHash()
    ##    c = AnotherHash()
    ##    d = AnotherHash()
    ##
    ##    self.assertEquals(list(cc), [a])
    ##
    ##    #try append
    ##    cc.append(b)
    ##    self.assertEquals(list(cc), [a, b])
    ##
    ##    #and again
    ##    cc.append(c)
    ##    self.assertEquals(list(cc), [a, b, c])
    ##
    ##    #try append dup
    ##    self.assertRaises(KeyError, cc.append, d)
    ##    self.assertEquals(list(cc), [a, b, c])

    ##def test_20_insert(self):
    ##    "test CryptContext.insert"
    ##    cc = CryptContext([UnsaltedHash, SaltedHash, AnotherHash])
    ##    a, b, c = cc
    ##    d = AnotherHash()
    ##    self.assertIsNot(c, d)
    ##    e = pwhash.Md5Crypt()
    ##    f = pwhash.Sha512Crypt()
    ##    g = pwhash.UnixCrypt()
    ##
    ##    #check baseline
    ##    self.assertEquals(list(cc), [a, b, c])
    ##
    ##    #inserting d at 0 should raise error (AnotherHash already in list)
    ##    self.assertRaises(KeyError, cc.insert, 0, d)
    ##    self.assertEquals(list(cc), [a, b, c])
    ##
    ##    #insert e at start
    ##    cc.insert(0, e)
    ##    self.assertEquals(list(cc), [e, a, b, c])
    ##
    ##    #insert f at end
    ##    cc.insert(-1, f)
    ##    self.assertEquals(list(cc), [e, a, b, f, c])
    ##
    ##    #insert g at end
    ##    cc.insert(5, g)
    ##    self.assertEquals(list(cc), [e, a, b, f, c, g])

    #=========================================================
    #3 list dellers
    #=========================================================
    ##def test_30_remove(self):
    ##    cc = CryptContext([UnsaltedHash, SaltedHash, AnotherHash])
    ##    a, b, c = cc
    ##    d = AnotherHash()
    ##    self.assertIsNot(c, d)
    ##
    ##    self.assertEquals(list(cc), [a, b, c])
    ##
    ##    self.assertRaises(ValueError, cc.remove, d)
    ##    self.assertEquals(list(cc), [a, b, c])
    ##
    ##    cc.remove(a)
    ##    self.assertEquals(list(cc), [b, c])
    ##
    ##    self.assertRaises(ValueError, cc.remove, a)
    ##    self.assertEquals(list(cc), [b, c])

    ##def test_31_discard(self):
    ##    cc = CryptContext([UnsaltedHash, SaltedHash, AnotherHash])
    ##    a, b, c = cc
    ##    d = AnotherHash()
    ##    self.assertIsNot(c, d)
    ##
    ##    self.assertEquals(list(cc), [a, b, c])
    ##
    ##    self.assertEquals(cc.discard(d), False)
    ##    self.assertEquals(list(cc), [a, b, c])
    ##
    ##    self.assertEquals(cc.discard(a), True)
    ##    self.assertEquals(list(cc), [b, c])
    ##
    ##    self.assertEquals(cc.discard(a), False)
    ##    self.assertEquals(list(cc), [b, c])

    #=========================================================
    #4 list composition
    #=========================================================

    ##def test_40_add(self, lsc=False):
    ##    "test CryptContext + list"
    ##    #build and join cc to list
    ##    a = UnsaltedHash()
    ##    b = SaltedHash()
    ##    c = AnotherHash()
    ##    cc = CryptContext([a, b, c])
    ##    ls = [pwhash.Md5Crypt, pwhash.Sha512Crypt]
    ##    if lsc:
    ##        ls = CryptContext(ls)
    ##    cc2 = cc + ls
    ##
    ##    #verify types
    ##    self.assertIsInstance(cc, CryptContext)
    ##    self.assertIsInstance(cc2, CryptContext)
    ##    self.assertIsInstance(ls, CryptContext if lsc else list)
    ##
    ##    #verify elements
    ##    self.assertIsNot(cc, ls)
    ##    self.assertIsNot(cc, cc2)
    ##    self.assertIsNot(ls, cc2)
    ##
    ##    #verify cc
    ##    a, b, c = cc
    ##    self.assertIsInstance(a, UnsaltedHash)
    ##    self.assertIsInstance(b, SaltedHash)
    ##    self.assertIsInstance(c, AnotherHash)
    ##
    ##    #verify ls
    ##    d, e = ls
    ##    if lsc:
    ##        self.assertIsInstance(d, Md5Crypt)
    ##        self.assertIsInstance(e, Sha512Crypt)
    ##    else:
    ##        self.assertIs(d, Md5Crypt)
    ##        self.assertIs(e, Sha512Crypt)
    ##
    ##    #verify cc2
    ##    a2, b2, c2, d2, e2 = cc2
    ##    self.assertIs(a2, a)
    ##    self.assertIs(b2, b)
    ##    self.assertIs(c2, c)
    ##    if lsc:
    ##        self.assertIs(d2, d)
    ##        self.assertIs(e2, e)
    ##    else:
    ##        self.assertIsInstance(d2, Md5Crypt)
    ##        self.assertIsInstance(e2, Sha512Crypt)

    ##def test_41_add(self):
    ##    "test CryptContext + CryptContext"
    ##    self.test_40_add(lsc=True)

    ##def test_42_iadd(self, lsc=False):
    ##    "test CryptContext += list"
    ##    #build and join cc to list
    ##    a = UnsaltedHash()
    ##    b = SaltedHash()
    ##    c = AnotherHash()
    ##    cc = CryptContext([a, b, c])
    ##    ls = [Md5Crypt, Sha512Crypt]
    ##    if lsc:
    ##        ls = CryptContext(ls)
    ##
    ##    #baseline
    ##    self.assertEquals(list(cc), [a, b, c])
    ##    self.assertIsInstance(cc, CryptContext)
    ##    self.assertIsInstance(ls, CryptContext if lsc else list)
    ##    if lsc:
    ##        d, e = ls
    ##        self.assertIsInstance(d, Md5Crypt)
    ##        self.assertIsInstance(e, Sha512Crypt)
    ##
    ##    #add
    ##    cc += ls
    ##
    ##    #verify types
    ##    self.assertIsInstance(cc, CryptContext)
    ##    self.assertIsInstance(ls, CryptContext if lsc else list)
    ##
    ##    #verify elements
    ##    self.assertIsNot(cc, ls)
    ##
    ##    #verify cc
    ##    a2, b2, c2, d2, e2 = cc
    ##    self.assertIs(a2, a)
    ##    self.assertIs(b2, b)
    ##    self.assertIs(c2, c)
    ##    if lsc:
    ##        self.assertIs(d2, d)
    ##        self.assertIs(e2, e)
    ##    else:
    ##        self.assertIsInstance(d2, Md5Crypt)
    ##        self.assertIsInstance(e2, Sha512Crypt)
    ##
    ##    #verify ls
    ##    d, e = ls
    ##    if lsc:
    ##        self.assertIsInstance(d, Md5Crypt)
    ##        self.assertIsInstance(e, Sha512Crypt)
    ##    else:
    ##        self.assertIs(d, Md5Crypt)
    ##        self.assertIs(e, Sha512Crypt)

    ##def test_43_iadd(self):
    ##    "test CryptContext += CryptContext"
    ##    self.test_42_iadd(lsc=True)

    ##def test_44_extend(self):
    ##    a = UnsaltedHash()
    ##    b = SaltedHash()
    ##    c = AnotherHash()
    ##    cc = CryptContext([a, b, c])
    ##    ls = [Md5Crypt, Sha512Crypt]
    ##
    ##    cc.extend(ls)
    ##
    ##    a2, b2, c2, d2, e2 = cc
    ##    self.assertIs(a2, a)
    ##    self.assertIs(b2, b)
    ##    self.assertIs(c2, c)
    ##    self.assertIsInstance(d2, Md5Crypt)
    ##    self.assertIsInstance(e2, Sha512Crypt)
    ##
    ##    self.assertRaises(KeyError, cc.extend, [Sha512Crypt ])
    ##    self.assertRaises(KeyError, cc.extend, [Sha512Crypt() ])

    #=========================================================
    #5 basic crypt interface
    #=========================================================
    def test_50_lookup(self):
        "test CryptContext.lookup()"
        cc = CryptContext([UnsaltedHash, SaltedHash, AnotherHash])
        c, b, a = cc._handlers

        self.assertEquals(cc.lookup('unsalted_example'), a)
        self.assertEquals(cc.lookup('salted_example'), b)
        self.assertEquals(cc.lookup('md5_crypt'), c)
        self.assertEquals(cc.lookup('des_crypt'), None)

        ##self.assertEquals(cc.lookup(['unsalted']), a)
        ##self.assertEquals(cc.lookup(['md5_crypt']), None)
        ##self.assertEquals(cc.lookup(['unsalted', 'salted', 'md5_crypt']), b)

    #TODO: lookup required=True

    def test_51_identify(self):
        "test CryptContext.identify"
        cc = CryptContext([UnsaltedHash, SaltedHash, AnotherHash])
        c, b, a = cc._handlers

        for crypt in (a, b, c):
            h = crypt.encrypt("test")
            self.assertEquals(cc.identify(h), crypt)
            self.assertEquals(cc.identify(h, name=True), crypt.name)

        self.assertEquals(cc.identify('$1$232323123$1287319827'), None)
        self.assertEquals(cc.identify('$1$232323123$1287319827'), None)

        #make sure "None" is accepted
        self.assertEquals(cc.identify(None), None)

    def test_52_encrypt_and_verify(self):
        "test CryptContext.encrypt & verify"
        cc = CryptContext([UnsaltedHash, SaltedHash, AnotherHash])
        c, b, a = cc._handlers

        #check encrypt/id/verify pass for all algs
        for crypt in (a, b, c):
            h = cc.encrypt("test", scheme=crypt.name)
            self.assertEquals(cc.identify(h), crypt)
            self.assertEquals(cc.verify('test', h), True)
            self.assertEquals(cc.verify('notest', h), False)

        #check default alg
        h = cc.encrypt("test")
        self.assertEquals(cc.identify(h), c)

        #check verify using algs
        self.assertEquals(cc.verify('test', h, scheme='md5_crypt'), True)
        self.assertRaises(ValueError, cc.verify, 'test', h, scheme='salted_example')

    def test_53_encrypt_salting(self):
        "test CryptContext.encrypt salting options"
        cc = CryptContext([UnsaltedHash, SaltedHash, AnotherHash])
        c, b, a = cc._handlers
        self.assert_('salt' in c.setting_kwds)

        h = cc.encrypt("test")
        self.assertEquals(cc.identify(h), c)

        s = c.parse(h)
        del s['checksum']
        del s['salt']
        h2 = cc.encrypt("test", **s)
        self.assertEquals(cc.identify(h2), c)
        self.assertNotEquals(h2, h)

        s = c.parse(h)
        del s['checksum']
        h3 = cc.encrypt("test", **s)
        self.assertEquals(cc.identify(h3), c)
        self.assertEquals(h3, h)

    def test_54_verify_empty(self):
        "test CryptContext.verify allows hash=None"
        cc = CryptContext([UnsaltedHash, SaltedHash, AnotherHash])
        self.assertEquals(cc.verify('xxx', None), False)
        for crypt in cc._handlers:
            self.assertEquals(cc.verify('xxx', None, scheme=crypt.name), False)

#XXX: haven't decided if this should be part of protocol
##    def test_55_verify_empty_secret(self):
##        "test CryptContext.verify allows secret=None"
##        cc = CryptContext([UnsaltedHash, SaltedHash, AnotherHash])
##        h = cc.encrypt("test")
##        self.assertEquals(cc.verify(None,h), False)

    #=========================================================
    #6 crypt-enhanced list interface
    #=========================================================
    ##def test_60_getitem(self):
    ##    "test CryptContext.__getitem__[algname]"
    ##    #create crypt context
    ##    cc = CryptContext([UnsaltedHash, SaltedHash, AnotherHash])
    ##    a, b, c = cc
    ##
    ##    #verify getitem
    ##    self.assertEquals(cc['unsalted'], a)
    ##    self.assertEquals(cc['salted'], b)
    ##    self.assertEquals(cc['sample'], c)
    ##    self.assertRaises(KeyError, cc.__getitem__, 'md5_crypt')

    ##def test_61_get(self):
    ##    "test CryptContext.get(algname)"
    ##    #create crypt context
    ##    cc = CryptContext([UnsaltedHash, SaltedHash, AnotherHash])
    ##    a, b, c = cc
    ##
    ##    #verify getitem
    ##    self.assertEquals(cc.get('unsalted'), a)
    ##    self.assertEquals(cc.get('salted'), b)
    ##    self.assertEquals(cc.get('sample'), c)
    ##    self.assertEquals(cc.get('md5_crypt'), None)

    ##def test_62_index(self):
    ##    "test CryptContext.index(algname)"
    ##    #create crypt context
    ##    cc = CryptContext([UnsaltedHash, SaltedHash, AnotherHash])
    ##
    ##    #verify getitem
    ##    self.assertEquals(cc.index('unsalted'), 0)
    ##    self.assertEquals(cc.index('salted'), 1)
    ##    self.assertEquals(cc.index('sample'), 2)
    ##    self.assertEquals(cc.index('md5_crypt'), -1)

    ##def test_63_contains(self):
    ##    "test CryptContext.__contains__(algname)"
    ##    #create crypt context
    ##    cc = CryptContext([UnsaltedHash, SaltedHash, AnotherHash])
    ##    self.assertEquals('salted' in cc, True)
    ##    self.assertEquals('unsalted' in cc, True)
    ##    self.assertEquals('sample' in cc, True)
    ##    self.assertEquals('md5_crypt' in cc, False)

    ##def test_64_keys(self):
    ##    "test CryptContext.keys()"
    ##    cc = CryptContext([UnsaltedHash, SaltedHash, AnotherHash])
    ##    self.assertEquals(cc.keys(), ['unsalted', 'salted', 'sample'])

    ##def test_65_remove(self):
    ##    cc = CryptContext([UnsaltedHash, SaltedHash, AnotherHash])
    ##    a, b, c = cc
    ##
    ##    self.assertEquals(list(cc), [a, b, c])
    ##
    ##    self.assertRaises(KeyError, cc.remove, 'md5_crypt')
    ##    self.assertEquals(list(cc), [a, b, c])
    ##
    ##    cc.remove('unsalted')
    ##    self.assertEquals(list(cc), [b, c])
    ##
    ##    self.assertRaises(KeyError, cc.remove, 'unsalted')
    ##    self.assertEquals(list(cc), [b, c])

    ##def test_66_discard(self):
    ##    cc = CryptContext([UnsaltedHash, SaltedHash, AnotherHash])
    ##    a, b, c = cc
    ##
    ##    self.assertEquals(list(cc), [a, b, c])
    ##
    ##    self.assertEquals(cc.discard('md5_crypt'), False)
    ##    self.assertEquals(list(cc), [a, b, c])
    ##
    ##    self.assertEquals(cc.discard('unsalted'), True)
    ##    self.assertEquals(list(cc), [b, c])
    ##
    ##    self.assertEquals(cc.discard('unsalted'), False)
    ##    self.assertEquals(list(cc), [b, c])
    #=========================================================
    #eoc
    #=========================================================

#=========================================================
#EOF
#=========================================================
