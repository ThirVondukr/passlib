"""tests for passlib.pwhash -- (c) Assurance Technologies 2003-2009"""
#=========================================================
#imports
#=========================================================
from __future__ import with_statement
#core
import hashlib
from logging import getLogger
import os
import time
import warnings
import sys
#site
try:
    from pkg_resources import resource_filename
except ImportError:
    resource_filename = None
#pkg
from passlib import hash
from passlib.context import CryptContext, CryptPolicy, LazyCryptContext
from passlib.utils import to_bytes, to_unicode
import passlib.utils.handlers as uh
from passlib.tests.utils import TestCase, mktemp, catch_warnings, \
    gae_env, set_file
from passlib.registry import register_crypt_handler_path, has_crypt_handler, \
    _unload_handler_name as unload_handler_name
#module
log = getLogger(__name__)

#=========================================================
#
#=========================================================
class CryptPolicyTest(TestCase):
    "test CryptPolicy object"

    #TODO: need to test user categories w/in all this

    case_prefix = "CryptPolicy"

    #=========================================================
    #sample crypt policies used for testing
    #=========================================================

    #-----------------------------------------------------
    #sample 1 - average config file
    #-----------------------------------------------------
    #NOTE: copy of this is stored in file passlib/tests/sample_config_1s.cfg
    sample_config_1s = """\
[passlib]
schemes = des_crypt, md5_crypt, bsdi_crypt, sha512_crypt
default = md5_crypt
all.vary_rounds = 10%%
bsdi_crypt.max_rounds = 30000
bsdi_crypt.default_rounds = 25000
sha512_crypt.max_rounds = 50000
sha512_crypt.min_rounds = 40000
"""
    sample_config_1s_path = os.path.abspath(os.path.join(
        os.path.dirname(__file__), "sample_config_1s.cfg"))
    if not os.path.exists(sample_config_1s_path) and resource_filename:
        #in case we're zipped up in an egg.
        sample_config_1s_path = resource_filename("passlib.tests",
                                                  "sample_config_1s.cfg")

    #make sure sample_config_1s uses \n linesep - tests rely on this
    assert sample_config_1s.startswith("[passlib]\nschemes")

    sample_config_1pd = dict(
        schemes = [ "des_crypt", "md5_crypt", "bsdi_crypt", "sha512_crypt"],
        default = "md5_crypt",
        all__vary_rounds = "10%",
        bsdi_crypt__max_rounds = 30000,
        bsdi_crypt__default_rounds = 25000,
        sha512_crypt__max_rounds = 50000,
        sha512_crypt__min_rounds = 40000,
    )

    sample_config_1pid = {
        "schemes": "des_crypt, md5_crypt, bsdi_crypt, sha512_crypt",
        "default": "md5_crypt",
        "all.vary_rounds": "10%",
        "bsdi_crypt.max_rounds": 30000,
        "bsdi_crypt.default_rounds": 25000,
        "sha512_crypt.max_rounds": 50000,
        "sha512_crypt.min_rounds": 40000,
    }

    sample_config_1prd = dict(
        schemes = [ hash.des_crypt, hash.md5_crypt, hash.bsdi_crypt, hash.sha512_crypt],
        default = hash.md5_crypt,
        all__vary_rounds = "10%",
        bsdi_crypt__max_rounds = 30000,
        bsdi_crypt__default_rounds = 25000,
        sha512_crypt__max_rounds = 50000,
        sha512_crypt__min_rounds = 40000,
    )

    #-----------------------------------------------------
    #sample 2 - partial policy & result of overlay on sample 1
    #-----------------------------------------------------
    sample_config_2s = """\
[passlib]
bsdi_crypt.min_rounds = 29000
bsdi_crypt.max_rounds = 35000
bsdi_crypt.default_rounds = 31000
sha512_crypt.min_rounds = 45000
"""

    sample_config_2pd = dict(
        #using this to test full replacement of existing options
        bsdi_crypt__min_rounds = 29000,
        bsdi_crypt__max_rounds = 35000,
        bsdi_crypt__default_rounds = 31000,
        #using this to test partial replacement of existing options
        sha512_crypt__min_rounds=45000,
    )

    sample_config_12pd = dict(
        schemes = [ "des_crypt", "md5_crypt", "bsdi_crypt", "sha512_crypt"],
        default = "md5_crypt",
        all__vary_rounds = "10%",
        bsdi_crypt__min_rounds = 29000,
        bsdi_crypt__max_rounds = 35000,
        bsdi_crypt__default_rounds = 31000,
        sha512_crypt__max_rounds = 50000,
        sha512_crypt__min_rounds=45000,
    )

    #-----------------------------------------------------
    #sample 3 - just changing default
    #-----------------------------------------------------
    sample_config_3pd = dict(
        default="sha512_crypt",
    )

    sample_config_123pd = dict(
        schemes = [ "des_crypt", "md5_crypt", "bsdi_crypt", "sha512_crypt"],
        default = "sha512_crypt",
        all__vary_rounds = "10%",
        bsdi_crypt__min_rounds = 29000,
        bsdi_crypt__max_rounds = 35000,
        bsdi_crypt__default_rounds = 31000,
        sha512_crypt__max_rounds = 50000,
        sha512_crypt__min_rounds=45000,
    )

    #-----------------------------------------------------
    #sample 4 - category specific
    #-----------------------------------------------------
    sample_config_4s = """
[passlib]
schemes = sha512_crypt
all.vary_rounds = 10%%
default.sha512_crypt.max_rounds = 20000
admin.all.vary_rounds = 5%%
admin.sha512_crypt.max_rounds = 40000
"""

    sample_config_4pd = dict(
        schemes = [ "sha512_crypt" ],
         all__vary_rounds = "10%",
        sha512_crypt__max_rounds = 20000,
        admin__all__vary_rounds = "5%",
        admin__sha512_crypt__max_rounds = 40000,
        )

    #-----------------------------------------------------
    #sample 5 - to_string & deprecation testing
    #-----------------------------------------------------
    sample_config_5s = sample_config_1s + """\
deprecated = des_crypt
admin__context__deprecated = des_crypt, bsdi_crypt
"""

    sample_config_5pd = sample_config_1pd.copy()
    sample_config_5pd.update(
        deprecated = [ "des_crypt" ],
        admin__context__deprecated = [ "des_crypt", "bsdi_crypt" ],
    )

    sample_config_5pid = sample_config_1pid.copy()
    sample_config_5pid.update({
        "deprecated": "des_crypt",
        "admin.context.deprecated": "des_crypt, bsdi_crypt",
    })

    sample_config_5prd = sample_config_1prd.copy()
    sample_config_5prd.update({
        # XXX: should deprecated return the actual handlers in this case?
        #      would have to modify how policy stores info, for one.
        "deprecated": ["des_crypt"],
        "admin__context__deprecated": ["des_crypt", "bsdi_crypt"],
    })

    #=========================================================
    #constructors
    #=========================================================
    def test_00_constructor(self):
        "test CryptPolicy() constructor"
        policy = CryptPolicy(**self.sample_config_1pd)
        self.assertEqual(policy.to_dict(), self.sample_config_1pd)

        #check with bad key
        self.assertRaises(KeyError, CryptPolicy,
            schemes = [ "des_crypt", "md5_crypt", "bsdi_crypt", "sha512_crypt"],
            bad__key__bsdi_crypt__max_rounds = 30000,
            )

        #check with bad handler
        self.assertRaises(TypeError, CryptPolicy, schemes=[uh.StaticHandler])

        #check with multiple handlers
        class dummy_1(uh.StaticHandler):
            name = 'dummy_1'
        self.assertRaises(KeyError, CryptPolicy, schemes=[dummy_1, dummy_1])

        #with unknown deprecated value
        self.assertRaises(KeyError, CryptPolicy,
                          schemes=['des_crypt'],
                          deprecated=['md5_crypt'])

        #with unknown default value
        self.assertRaises(KeyError, CryptPolicy,
                          schemes=['des_crypt'],
                          default='md5_crypt')

    def test_01_from_path_simple(self):
        "test CryptPolicy.from_path() constructor"
        #NOTE: this is separate so it can also run under GAE

        #test preset stored in existing file
        path = self.sample_config_1s_path
        policy = CryptPolicy.from_path(path)
        self.assertEqual(policy.to_dict(), self.sample_config_1pd)

        #test if path missing
        self.assertRaises(EnvironmentError, CryptPolicy.from_path, path + 'xxx')

    def test_01_from_path(self):
        "test CryptPolicy.from_path() constructor with encodings"
        if gae_env:
            return self.skipTest("GAE doesn't offer read/write filesystem access")

        path = mktemp()

        #test "\n" linesep
        set_file(path, self.sample_config_1s)
        policy = CryptPolicy.from_path(path)
        self.assertEqual(policy.to_dict(), self.sample_config_1pd)

        #test "\r\n" linesep
        set_file(path, self.sample_config_1s.replace("\n","\r\n"))
        policy = CryptPolicy.from_path(path)
        self.assertEqual(policy.to_dict(), self.sample_config_1pd)

        #test with custom encoding
        uc2 = to_bytes(self.sample_config_1s, "utf-16", source_encoding="utf-8")
        set_file(path, uc2)
        policy = CryptPolicy.from_path(path, encoding="utf-16")
        self.assertEqual(policy.to_dict(), self.sample_config_1pd)

    def test_02_from_string(self):
        "test CryptPolicy.from_string() constructor"
        #test "\n" linesep
        policy = CryptPolicy.from_string(self.sample_config_1s)
        self.assertEqual(policy.to_dict(), self.sample_config_1pd)

        #test "\r\n" linesep
        policy = CryptPolicy.from_string(
            self.sample_config_1s.replace("\n","\r\n"))
        self.assertEqual(policy.to_dict(), self.sample_config_1pd)

        #test with unicode
        data = to_unicode(self.sample_config_1s)
        policy = CryptPolicy.from_string(data)
        self.assertEqual(policy.to_dict(), self.sample_config_1pd)

        #test with non-ascii-compatible encoding
        uc2 = to_bytes(self.sample_config_1s, "utf-16", source_encoding="utf-8")
        policy = CryptPolicy.from_string(uc2, encoding="utf-16")
        self.assertEqual(policy.to_dict(), self.sample_config_1pd)

        #test category specific options
        policy = CryptPolicy.from_string(self.sample_config_4s)
        self.assertEqual(policy.to_dict(), self.sample_config_4pd)

    def test_03_from_source(self):
        "test CryptPolicy.from_source() constructor"
        #pass it a path
        policy = CryptPolicy.from_source(self.sample_config_1s_path)
        self.assertEqual(policy.to_dict(), self.sample_config_1pd)

        #pass it a string
        policy = CryptPolicy.from_source(self.sample_config_1s)
        self.assertEqual(policy.to_dict(), self.sample_config_1pd)

        #pass it a dict (NOTE: make a copy to detect in-place modifications)
        policy = CryptPolicy.from_source(self.sample_config_1pd.copy())
        self.assertEqual(policy.to_dict(), self.sample_config_1pd)

        #pass it existing policy
        p2 = CryptPolicy.from_source(policy)
        self.assertIs(policy, p2)

        #pass it something wrong
        self.assertRaises(TypeError, CryptPolicy.from_source, 1)
        self.assertRaises(TypeError, CryptPolicy.from_source, [])

    def test_04_from_sources(self):
        "test CryptPolicy.from_sources() constructor"

        #pass it empty list
        self.assertRaises(ValueError, CryptPolicy.from_sources, [])

        #pass it one-element list
        policy = CryptPolicy.from_sources([self.sample_config_1s])
        self.assertEqual(policy.to_dict(), self.sample_config_1pd)

        #pass multiple sources
        policy = CryptPolicy.from_sources(
            [
            self.sample_config_1s_path,
            self.sample_config_2s,
            self.sample_config_3pd,
            ])
        self.assertEqual(policy.to_dict(), self.sample_config_123pd)

    def test_05_replace(self):
        "test CryptPolicy.replace() constructor"

        p1 = CryptPolicy(**self.sample_config_1pd)

        #check overlaying sample 2
        p2 = p1.replace(**self.sample_config_2pd)
        self.assertEqual(p2.to_dict(), self.sample_config_12pd)

        #check repeating overlay makes no change
        p2b = p2.replace(**self.sample_config_2pd)
        self.assertEqual(p2b.to_dict(), self.sample_config_12pd)

        #check overlaying sample 3
        p3 = p2.replace(self.sample_config_3pd)
        self.assertEqual(p3.to_dict(), self.sample_config_123pd)

    def test_06_forbidden(self):
        "test CryptPolicy() forbidden kwds"

        #salt not allowed to be set
        self.assertRaises(KeyError, CryptPolicy,
            schemes=["des_crypt"],
            des_crypt__salt="xx",
        )
        self.assertRaises(KeyError, CryptPolicy,
            schemes=["des_crypt"],
            all__salt="xx",
        )

        #schemes not allowed for category
        self.assertRaises(KeyError, CryptPolicy,
            schemes=["des_crypt"],
            user__context__schemes=["md5_crypt"],
        )

    #=========================================================
    #reading
    #=========================================================
    def test_10_has_schemes(self):
        "test has_schemes() method"

        p1 = CryptPolicy(**self.sample_config_1pd)
        self.assertTrue(p1.has_schemes())

        p3 = CryptPolicy(**self.sample_config_3pd)
        self.assertTrue(not p3.has_schemes())

    def test_11_iter_handlers(self):
        "test iter_handlers() method"

        p1 = CryptPolicy(**self.sample_config_1pd)
        s = self.sample_config_1prd['schemes']
        self.assertEqual(list(p1.iter_handlers()), s)

        p3 = CryptPolicy(**self.sample_config_3pd)
        self.assertEqual(list(p3.iter_handlers()), [])

    def test_12_get_handler(self):
        "test get_handler() method"

        p1 = CryptPolicy(**self.sample_config_1pd)

        #check by name
        self.assertIs(p1.get_handler("bsdi_crypt"), hash.bsdi_crypt)

        #check by missing name
        self.assertIs(p1.get_handler("sha256_crypt"), None)
        self.assertRaises(KeyError, p1.get_handler, "sha256_crypt", required=True)

        #check default
        self.assertIs(p1.get_handler(), hash.md5_crypt)

    def test_13_get_options(self):
        "test get_options() method"

        p12 = CryptPolicy(**self.sample_config_12pd)

        self.assertEqual(p12.get_options("bsdi_crypt"),dict(
            vary_rounds = "10%",
            min_rounds = 29000,
            max_rounds = 35000,
            default_rounds = 31000,
        ))

        self.assertEqual(p12.get_options("sha512_crypt"),dict(
            vary_rounds = "10%",
            min_rounds = 45000,
            max_rounds = 50000,
        ))

        p4 = CryptPolicy.from_string(self.sample_config_4s)
        self.assertEqual(p4.get_options("sha512_crypt"), dict(
            vary_rounds="10%",
            max_rounds=20000,
        ))

        self.assertEqual(p4.get_options("sha512_crypt", "user"), dict(
            vary_rounds="10%",
            max_rounds=20000,
        ))

        self.assertEqual(p4.get_options("sha512_crypt", "admin"), dict(
            vary_rounds="5%",
            max_rounds=40000,
        ))

    def test_14_handler_is_deprecated(self):
        "test handler_is_deprecated() method"
        pa = CryptPolicy(**self.sample_config_1pd)
        pb = CryptPolicy(**self.sample_config_5pd)

        self.assertFalse(pa.handler_is_deprecated("des_crypt"))
        self.assertFalse(pa.handler_is_deprecated(hash.bsdi_crypt))
        self.assertFalse(pa.handler_is_deprecated("sha512_crypt"))

        self.assertTrue(pb.handler_is_deprecated("des_crypt"))
        self.assertFalse(pb.handler_is_deprecated(hash.bsdi_crypt))
        self.assertFalse(pb.handler_is_deprecated("sha512_crypt"))

        #check categories as well
        self.assertTrue(pb.handler_is_deprecated("des_crypt", "user"))
        self.assertFalse(pb.handler_is_deprecated("bsdi_crypt", "user"))
        self.assertTrue(pb.handler_is_deprecated("des_crypt", "admin"))
        self.assertTrue(pb.handler_is_deprecated("bsdi_crypt", "admin"))

    def test_15_min_verify_time(self):
        pa = CryptPolicy()
        self.assertEqual(pa.get_min_verify_time(), 0)
        self.assertEqual(pa.get_min_verify_time('admin'), 0)

        pb = pa.replace(min_verify_time=.1)
        self.assertEqual(pb.get_min_verify_time(), .1)
        self.assertEqual(pb.get_min_verify_time('admin'), .1)

        pc = pa.replace(admin__context__min_verify_time=.2)
        self.assertEqual(pc.get_min_verify_time(), 0)
        self.assertEqual(pc.get_min_verify_time('admin'), .2)

        pd = pb.replace(admin__context__min_verify_time=.2)
        self.assertEqual(pd.get_min_verify_time(), .1)
        self.assertEqual(pd.get_min_verify_time('admin'), .2)

    #TODO: test this.
    ##def test_gen_min_verify_time(self):
    ##    "test get_min_verify_time() method"

    #=========================================================
    #serialization
    #=========================================================
    def test_20_iter_config(self):
        "test iter_config() method"
        p5 = CryptPolicy(**self.sample_config_5pd)
        self.assertEqual(dict(p5.iter_config()), self.sample_config_5pd)
        self.assertEqual(dict(p5.iter_config(resolve=True)), self.sample_config_5prd)
        self.assertEqual(dict(p5.iter_config(ini=True)), self.sample_config_5pid)

    def test_21_to_dict(self):
        "test to_dict() method"
        p5 = CryptPolicy(**self.sample_config_5pd)
        self.assertEqual(p5.to_dict(), self.sample_config_5pd)
        self.assertEqual(p5.to_dict(resolve=True), self.sample_config_5prd)

    def test_22_to_string(self):
        "test to_string() method"
        pa = CryptPolicy(**self.sample_config_5pd)
        s = pa.to_string() #NOTE: can't compare string directly, ordering etc may not match
        pb = CryptPolicy.from_string(s)
        self.assertEqual(pb.to_dict(), self.sample_config_5pd)

    #=========================================================
    #
    #=========================================================

#=========================================================
#CryptContext
#=========================================================
class CryptContextTest(TestCase):
    "test CryptContext object's behavior"
    case_prefix = "CryptContext"

    #=========================================================
    #constructor
    #=========================================================
    def test_00_constructor(self):
        "test constructor"
        #create crypt context using handlers
        cc = CryptContext([hash.md5_crypt, hash.bsdi_crypt, hash.des_crypt])
        c,b,a = cc.policy.iter_handlers()
        self.assertIs(a, hash.des_crypt)
        self.assertIs(b, hash.bsdi_crypt)
        self.assertIs(c, hash.md5_crypt)

        #create context using names
        cc = CryptContext(["md5_crypt", "bsdi_crypt", "des_crypt"])
        c,b,a = cc.policy.iter_handlers()
        self.assertIs(a, hash.des_crypt)
        self.assertIs(b, hash.bsdi_crypt)
        self.assertIs(c, hash.md5_crypt)

        #TODO: test policy & other options

    def test_01_replace(self):
        "test replace()"

        cc = CryptContext(["md5_crypt", "bsdi_crypt", "des_crypt"])
        self.assertIs(cc.policy.get_handler(), hash.md5_crypt)

        cc2 = cc.replace()
        self.assertIsNot(cc2, cc)
        self.assertIs(cc2.policy, cc.policy)

        cc3 = cc.replace(default="bsdi_crypt")
        self.assertIsNot(cc3, cc)
        self.assertIsNot(cc3.policy, cc.policy)
        self.assertIs(cc3.policy.get_handler(), hash.bsdi_crypt)

    def test_02_no_handlers(self):
        "test no handlers"

        #check constructor...
        cc = CryptContext()
        self.assertRaises(KeyError, cc.identify, 'hash', required=True)
        self.assertRaises(KeyError, cc.encrypt, 'secret')
        self.assertRaises(KeyError, cc.verify, 'secret', 'hash')

        #check updating policy after the fact...
        cc = CryptContext(['md5_crypt'])
        p = CryptPolicy(schemes=[])
        cc.policy = p

        self.assertRaises(KeyError, cc.identify, 'hash', required=True)
        self.assertRaises(KeyError, cc.encrypt, 'secret')
        self.assertRaises(KeyError, cc.verify, 'secret', 'hash')

    #=========================================================
    #policy adaptation
    #=========================================================
    sample_policy_1 = dict(
            schemes = [ "des_crypt", "md5_crypt", "nthash", "bsdi_crypt", "sha256_crypt"],
            deprecated = [ "des_crypt", ],
            default = "sha256_crypt",
            bsdi_crypt__max_rounds = 30,
            bsdi_crypt__default_rounds = 25,
            bsdi_crypt__vary_rounds = 0,
            sha256_crypt__max_rounds = 3000,
            sha256_crypt__min_rounds = 2000,
            sha256_crypt__default_rounds = 3000,
            nthash__ident = "NT",
    )

    def test_10_genconfig_settings(self):
        "test genconfig() honors policy settings"
        cc = CryptContext(policy=None, **self.sample_policy_1)

        # hash specific settings
        self.assertEqual(
            cc.genconfig(scheme="nthash"),
            '$NT$00000000000000000000000000000000',
            )
        self.assertEqual(
            cc.genconfig(scheme="nthash", ident="3"),
            '$3$$00000000000000000000000000000000',
            )

        # min rounds
        self.assertEqual(
            cc.genconfig(rounds=1999, salt="nacl"),
            '$5$rounds=2000$nacl$',
            )
        self.assertEqual(
            cc.genconfig(rounds=2001, salt="nacl"),
            '$5$rounds=2001$nacl$'
            )

        #max rounds
        self.assertEqual(
            cc.genconfig(rounds=2999, salt="nacl"),
            '$5$rounds=2999$nacl$',
            )
        self.assertEqual(
            cc.genconfig(rounds=3001, salt="nacl"),
            '$5$rounds=3000$nacl$'
            )

        #default rounds - specified
        self.assertEqual(
            cc.genconfig(scheme="bsdi_crypt", salt="nacl"),
            '_N...nacl',
            )

        #default rounds - fall back to max rounds
        self.assertEqual(
            cc.genconfig(salt="nacl"),
            '$5$rounds=3000$nacl$',
            )

        #default rounds - out of bounds
        cc2 = CryptContext(policy=cc.policy.replace(
            bsdi_crypt__default_rounds=35))
        self.assertEqual(
            cc2.genconfig(scheme="bsdi_crypt", salt="nacl"),
            '_S...nacl',
            )

        # default+vary rounds
        # this runs enough times the min and max *should* be hit,
        # though there's a faint chance it will randomly fail.
        from passlib.hash import bsdi_crypt as bc
        cc3 = CryptContext(policy=cc.policy.replace(
            bsdi_crypt__vary_rounds = 3))
        seen = set()
        for i in xrange(3*2*50):
            h = cc3.genconfig("bsdi_crypt", salt="nacl")
            r = bc.from_string(h).rounds
            seen.add(r)
        self.assertTrue(min(seen)==22)
        self.assertTrue(max(seen)==28)

        # default+vary % rounds
        # this runs enough times the min and max *should* be hit,
        # though there's a faint chance it will randomly fail.
        from passlib.hash import sha256_crypt as sc
        cc4 = CryptContext(policy=cc.policy.replace(
            all__vary_rounds = "1%"))
        seen = set()
        for i in xrange(30*50):
            h = cc4.genconfig(salt="nacl")
            r = sc.from_string(h).rounds
            seen.add(r)
        self.assertTrue(min(seen)==2970)
        self.assertTrue(max(seen)==3000) #NOTE: would be 3030, but clipped by max_rounds

    def test_11_encrypt_settings(self):
        "test encrypt() honors policy settings"
        cc = CryptContext(**self.sample_policy_1)

        # hash specific settings
        self.assertEqual(
            cc.encrypt("password", scheme="nthash"),
            '$NT$8846f7eaee8fb117ad06bdd830b7586c',
            )
        self.assertEqual(
            cc.encrypt("password", scheme="nthash", ident="3"),
            '$3$$8846f7eaee8fb117ad06bdd830b7586c',
            )

        # min rounds
        self.assertEqual(
            cc.encrypt("password", rounds=1999, salt="nacl"),
            '$5$rounds=2000$nacl$9/lTZ5nrfPuz8vphznnmHuDGFuvjSNvOEDsGmGfsS97',
            )
        self.assertEqual(
            cc.encrypt("password", rounds=2001, salt="nacl"),
            '$5$rounds=2001$nacl$8PdeoPL4aXQnJ0woHhqgIw/efyfCKC2WHneOpnvF.31'
            )

        #TODO:
        # max rounds
        # default rounds
        #       falls back to max, then min.
        #       specified
        #       outside of min/max range
        # default+vary rounds
        # default+vary % rounds

        #make sure default > max doesn't cause error when vary is set
        cc2 = cc.replace(sha256_crypt__default_rounds=4000)
        with catch_warnings():
            warnings.filterwarnings("ignore", "vary default rounds: lower bound > upper bound.*", UserWarning)
            self.assertEqual(
                cc2.encrypt("password", salt="nacl"),
                '$5$rounds=3000$nacl$oH831OVMbkl.Lbw1SXflly4dW8L3mSxpxDz1u1CK/B0',
                )

    def test_12_hash_needs_update(self):
        "test hash_needs_update() method"
        cc = CryptContext(**self.sample_policy_1)

        #check deprecated scheme
        self.assertTrue(cc.hash_needs_update('9XXD4trGYeGJA'))
        self.assertTrue(not cc.hash_needs_update('$1$J8HC2RCr$HcmM.7NxB2weSvlw2FgzU0'))

        #check min rounds
        self.assertTrue(cc.hash_needs_update('$5$rounds=1999$jD81UCoo.zI.UETs$Y7qSTQ6mTiU9qZB4fRr43wRgQq4V.5AAf7F97Pzxey/'))
        self.assertTrue(not cc.hash_needs_update('$5$rounds=2000$228SSRje04cnNCaQ$YGV4RYu.5sNiBvorQDlO0WWQjyJVGKBcJXz3OtyQ2u8'))

        #check max rounds
        self.assertTrue(not cc.hash_needs_update('$5$rounds=3000$fS9iazEwTKi7QPW4$VasgBC8FqlOvD7x2HhABaMXCTh9jwHclPA9j5YQdns.'))
        self.assertTrue(cc.hash_needs_update('$5$rounds=3001$QlFHHifXvpFX4PLs$/0ekt7lSs/lOikSerQ0M/1porEHxYq7W/2hdFpxA3fA'))

    #=========================================================
    #identify
    #=========================================================
    def test_20_basic(self):
        "test basic encrypt/identify/verify functionality"
        handlers = [hash.md5_crypt, hash.des_crypt, hash.bsdi_crypt]
        cc = CryptContext(handlers, policy=None)

        #run through handlers
        for crypt in handlers:
            h = cc.encrypt("test", scheme=crypt.name)
            self.assertEqual(cc.identify(h), crypt.name)
            self.assertEqual(cc.identify(h, resolve=True), crypt)
            self.assertTrue(cc.verify('test', h))
            self.assertTrue(not cc.verify('notest', h))

        #test default
        h = cc.encrypt("test")
        self.assertEqual(cc.identify(h), "md5_crypt")

        #test genhash
        h = cc.genhash('secret', cc.genconfig())
        self.assertEqual(cc.identify(h), 'md5_crypt')

        h = cc.genhash('secret', cc.genconfig(), scheme='md5_crypt')
        self.assertEqual(cc.identify(h), 'md5_crypt')

        self.assertRaises(ValueError, cc.genhash, 'secret', cc.genconfig(), scheme="des_crypt")

    def test_21_identify(self):
        "test identify() border cases"
        handlers = ["md5_crypt", "des_crypt", "bsdi_crypt"]
        cc = CryptContext(handlers, policy=None)

        #check unknown hash
        self.assertEqual(cc.identify('$9$232323123$1287319827'), None)
        self.assertRaises(ValueError, cc.identify, '$9$232323123$1287319827', required=True)

        #make sure "None" is accepted
        self.assertEqual(cc.identify(None), None)
        self.assertRaises(ValueError, cc.identify, None, required=True)

    def test_22_verify(self):
        "test verify() scheme kwd"
        handlers = ["md5_crypt", "des_crypt", "bsdi_crypt"]
        cc = CryptContext(handlers, policy=None)

        h = hash.md5_crypt.encrypt("test")

        #check base verify
        self.assertTrue(cc.verify("test", h))
        self.assertTrue(not cc.verify("notest", h))

        #check verify using right alg
        self.assertTrue(cc.verify('test', h, scheme='md5_crypt'))
        self.assertTrue(not cc.verify('notest', h, scheme='md5_crypt'))

        #check verify using wrong alg
        self.assertRaises(ValueError, cc.verify, 'test', h, scheme='bsdi_crypt')

    def test_23_verify_empty_hash(self):
        "test verify() allows hash=None"
        handlers = [hash.md5_crypt, hash.des_crypt, hash.bsdi_crypt]
        cc = CryptContext(handlers, policy=None)
        self.assertTrue(not cc.verify("test", None))
        for handler in handlers:
            self.assertTrue(not cc.verify("test", None, scheme=handler.name))

    def test_24_min_verify_time(self):
        "test verify() honors min_verify_time"
        #NOTE: this whole test assumes time.sleep() and time.time()
        #      have at least 1ms accuracy
        delta = .1
        min_delay = delta
        min_verify_time = min_delay + 2*delta
        max_delay = min_verify_time + 2*delta

        class TimedHash(uh.StaticHandler):
            "psuedo hash that takes specified amount of time"
            name = "timed_hash"
            delay = 0

            @classmethod
            def identify(cls, hash):
                return True

            @classmethod
            def genhash(cls, secret, hash):
                time.sleep(cls.delay)
                return hash or 'x'

        cc = CryptContext([TimedHash], min_verify_time=min_verify_time)

        def timecall(func, *args, **kwds):
            start = time.time()
            result = func(*args, **kwds)
            end = time.time()
            return end-start, result

        #verify hashing works
        TimedHash.delay = min_delay
        elapsed, _ = timecall(TimedHash.genhash, 'stub', 'stub')
        self.assertAlmostEqual(elapsed, min_delay, delta=delta)

        #ensure min verify time is honored
        elapsed, _ = timecall(cc.verify, "stub", "stub")
        self.assertAlmostEqual(elapsed, min_verify_time, delta=delta)

        #ensure taking longer emits a warning.
        TimedHash.delay = max_delay
        with catch_warnings(record=True) as wlog:
            warnings.simplefilter("always")
            elapsed, _ = timecall(cc.verify, "stub", "stub")
        self.assertAlmostEqual(elapsed, max_delay, delta=delta)
        self.assertEqual(len(wlog), 1)
        self.assertWarningMatches(wlog[0],
            message_re="CryptContext: verify exceeded min_verify_time")

    def test_25_verify_and_update(self):
        "test verify_and_update()"
        cc = CryptContext(**self.sample_policy_1)

        #create some hashes
        h1 = cc.encrypt("password", scheme="des_crypt")
        h2 = cc.encrypt("password", scheme="sha256_crypt")

        #check bad password, deprecated hash
        ok, new_hash = cc.verify_and_update("wrongpass", h1)
        self.assertFalse(ok)
        self.assertIs(new_hash, None)

        #check bad password, good hash
        ok, new_hash = cc.verify_and_update("wrongpass", h2)
        self.assertFalse(ok)
        self.assertIs(new_hash, None)

        #check right password, deprecated hash
        ok, new_hash = cc.verify_and_update("password", h1)
        self.assertTrue(ok)
        self.assertTrue(cc.identify(new_hash), "sha256_crypt")

        #check right password, good hash
        ok, new_hash = cc.verify_and_update("password", h2)
        self.assertTrue(ok)
        self.assertIs(new_hash, None)

    #=========================================================
    # other
    #=========================================================
    def test_90_bcrypt_normhash(self):
        "teset verify_and_update / hash_needs_update corrects bcrypt padding"
        # see issue 25.
        bcrypt = hash.bcrypt
        
        PASS1 = "loppux"
        BAD1  = "$2a$12$oaQbBqq8JnSM1NHRPQGXORm4GCUMqp7meTnkft4zgSnrbhoKdDV0C"
        GOOD1 = "$2a$12$oaQbBqq8JnSM1NHRPQGXOOm4GCUMqp7meTnkft4zgSnrbhoKdDV0C"
        ctx = CryptContext(["bcrypt"])
        
        with catch_warnings(record=True) as wlog:
            warnings.simplefilter("always")

            self.assertTrue(ctx.hash_needs_update(BAD1))
            self.assertFalse(ctx.hash_needs_update(GOOD1))
    
            if bcrypt.has_backend():            
                self.assertEquals(ctx.verify_and_update(PASS1,GOOD1), (True,None))
                self.assertEquals(ctx.verify_and_update("x",BAD1), (False,None))
                res = ctx.verify_and_update(PASS1, BAD1)
                self.assertTrue(res[0] and res[1] and res[1] != BAD1)

    #=========================================================
    #eoc
    #=========================================================

#=========================================================
#LazyCryptContext
#=========================================================
class dummy_2(uh.StaticHandler):
    name = "dummy_2"

class LazyCryptContextTest(TestCase):
    case_prefix = "LazyCryptContext"

    def setUp(self):
        unload_handler_name("dummy_2")

    def tearDown(self):
        unload_handler_name("dummy_2")

    def test_kwd_constructor(self):
        self.assertFalse(has_crypt_handler("dummy_2"))
        register_crypt_handler_path("dummy_2", "passlib.tests.test_context")

        cc = LazyCryptContext(iter(["dummy_2", "des_crypt"]), deprecated=["des_crypt"])

        self.assertFalse(has_crypt_handler("dummy_2", True))

        self.assertTrue(cc.policy.handler_is_deprecated("des_crypt"))
        self.assertEqual(cc.policy.schemes(), ["dummy_2", "des_crypt"])

        self.assertTrue(has_crypt_handler("dummy_2", True))

    def test_callable_constructor(self):
        self.assertFalse(has_crypt_handler("dummy_2"))
        register_crypt_handler_path("dummy_2", "passlib.tests.test_context")

        def create_policy(flag=False):
            self.assertTrue(flag)
            return CryptPolicy(schemes=iter(["dummy_2", "des_crypt"]), deprecated=["des_crypt"])

        cc = LazyCryptContext(create_policy=create_policy, flag=True)

        self.assertFalse(has_crypt_handler("dummy_2", True))

        self.assertTrue(cc.policy.handler_is_deprecated("des_crypt"))
        self.assertEqual(cc.policy.schemes(), ["dummy_2", "des_crypt"])

        self.assertTrue(has_crypt_handler("dummy_2", True))

#=========================================================
#EOF
#=========================================================
