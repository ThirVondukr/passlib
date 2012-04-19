"""test passlib.ext.django"""
#=========================================================
#imports
#=========================================================
from __future__ import with_statement
#core
import logging; log = logging.getLogger(__name__)
import sys
import warnings
#site
#pkg
from passlib.context import CryptContext
from passlib.apps import django_context
from passlib.ext.django import utils
from passlib.hash import sha256_crypt
from passlib.tests.utils import TestCase, unittest, ut_version, catch_warnings
import passlib.tests.test_handlers as th
from passlib.utils.compat import iteritems, get_method_function, unicode
from passlib.registry import get_crypt_handler
#module

#=========================================================
# import & configure django settings,
#=========================================================

try:
    from django.conf import settings, LazySettings
    has_django = True
except ImportError:
    settings = None
    has_django = False

has_django0 = False # are we using django 0.9?
has_django1 = False # are we using django >= 1.0?
has_django14 = False # are we using django >= 1.4?

if has_django:
    from django import VERSION
    log.debug("found django %r installation", VERSION)
    has_django0 = (VERSION < (1,0))
    has_django1 = (VERSION >= (1,0))
    has_django14 = (VERSION >= (1,4))

    if not isinstance(settings, LazySettings):
        #this could mean django has been configured somehow,
        #which we don't want, since test cases reset and manipulate settings.
        raise RuntimeError("expected django.conf.settings to be LazySettings: %r" % (settings,))

    #else configure a blank settings instance for our unittests
    if has_django0:
        if settings._target is None:
            from django.conf import UserSettingsHolder, global_settings
            settings._target = UserSettingsHolder(global_settings)
    else:
        if not settings.configured:
            settings.configure()
else:
    log.debug("django installation not found")

_NOTSET = object()

def update_settings(**kwds):
    for k,v in iteritems(kwds):
        if v is _NOTSET:
            if hasattr(settings, k):
                if has_django0:
                    delattr(settings._target, k)
                else:
                    delattr(settings, k)
        else:
            setattr(settings, k, v)

#=========================================================
# and prepare helper to skip all relevant tests
# if django isn't installed.
#=========================================================
def skipUnlessDjango(cls):
    "helper to skip class if django not present"
    if has_django:
        return cls
    if ut_version < 2:
        return None
    return unittest.skip("Django not installed")(cls)

#=========================================================
# mock user object
#=========================================================
if has_django:
    import django.contrib.auth.models as dam

    class FakeUser(dam.User):
        "stub user object for testing"
        #this mainly just overrides .save() to test commit behavior.

        saved_password = None

        def save(self):
            self.saved_password = self.password

#=========================================================
# helper contexts
#=========================================================

# simple context which looks NOTHING like django,
# so we can tell if patching worked.
simple_context = CryptContext(
    schemes = [ "md5_crypt", "des_crypt" ],
    default = "md5_crypt",
    deprecated = [ "des_crypt" ],
)

# some sample hashes
sample1 = 'password'
sample1_md5 = '$1$kAd49ifN$biuRAv1Tv0zGHyCv0uIqW.'
sample1_des = 'PPPTDkiCeu/jM'
sample1_sha1 = 'sha1$b215d$9ee0a66f84ef1ad99096355e788135f7e949bd41'

# context for testing category funcs
category_context = CryptContext(
    schemes = [ "sha256_crypt" ],
    sha256_crypt__default_rounds = 1000,
    staff__sha256_crypt__default_rounds = 2000,
    superuser__sha256_crypt__default_rounds = 3000,
)

def get_cc_rounds(**kwds):
    "helper for testing category funcs"
    user = FakeUser(**kwds)
    user.set_password("placeholder")
    return sha256_crypt.from_string(user.password).rounds

#=========================================================
# test utils
#=========================================================
class PatchTest(TestCase):
    "test passlib.ext.django.utils:set_django_password_context"

    descriptionPrefix = "passlib.ext.django utils"

    def assert_unpatched(self):
        "helper to ensure django hasn't been patched"
        state = utils._django_patch_state

        #make sure we aren't currently patched
        self.assertIs(state, None)

        #make sure nothing else patches django
        for func in [
            dam.check_password,
            dam.User.check_password,
            dam.User.set_password,
            ]:
            self.assertEqual(func.__module__, "django.contrib.auth.models")
        self.assertFalse(hasattr(dam.User, "password_context"))

    def assert_patched(self, context=_NOTSET):
        "helper to ensure django HAS been patched"
        state = utils._django_patch_state

        #make sure we're patched
        self.assertIsNot(state, None)

        #make sure our methods are exposed
        for func in [
            dam.check_password,
            dam.User.check_password,
            dam.User.set_password,
            ]:
            self.assertEqual(func.__module__, "passlib.ext.django.utils")

        #make sure methods match
        self.assertIs(dam.check_password, state['models_check_password'])
        self.assertIs(get_method_function(dam.User.check_password),
                      state['user_check_password'])
        self.assertIs(get_method_function(dam.User.set_password),
                      state['user_set_password'])

        #make sure context matches
        obj = dam.User.password_context
        self.assertIs(obj, state['context'])
        if context is not _NOTSET:
            self.assertIs(obj, context)

        #make sure old methods were stored
        for key in [
                "orig_models_check_password",
                "orig_user_check_password",
                "orig_user_set_password",
            ]:
            value = state[key]
            self.assertEqual(value.__module__, "django.contrib.auth.models")

    def setUp(self):
        #reset to baseline, and verify
        utils.set_django_password_context(None)
        self.assert_unpatched()

    def tearDown(self):
        #reset to baseline, and verify
        utils.set_django_password_context(None)
        self.assert_unpatched()

    def test_00_patch_control(self):
        "test set_django_password_context patch/unpatch"

        #check context=None has no effect
        utils.set_django_password_context(None)
        self.assert_unpatched()

        #patch to use stock django context
        utils.set_django_password_context(django_context)
        self.assert_patched(context=django_context)

        #try to remove patch
        utils.set_django_password_context(None)
        self.assert_unpatched()

        #patch to use stock django context again
        utils.set_django_password_context(django_context)
        self.assert_patched(context=django_context)

        #try to remove patch again
        utils.set_django_password_context(None)
        self.assert_unpatched()

    def test_01_patch_control_detection(self):
        "test set_django_password_context detection of foreign monkeypatches"
        def dummy():
            pass

        with catch_warnings(record=True) as wlog:
            #patch to use stock django context
            utils.set_django_password_context(django_context)
            self.assert_patched(context=django_context)
            self.consumeWarningList(wlog)

            #mess with User.set_password, make sure it's detected
            dam.User.set_password = dummy
            utils.set_django_password_context(django_context)
            self.assert_patched(context=django_context)
            self.consumeWarningList(wlog,
                        "^another library has patched.*User\.set_password$")

            #mess with user.check_password, make sure it's detected
            dam.User.check_password = dummy
            utils.set_django_password_context(django_context)
            self.assert_patched(context=django_context)
            self.consumeWarningList(wlog,
                        "^another library has patched.*User\.check_password$")

            #mess with user.check_password, make sure it's detected
            dam.check_password = dummy
            utils.set_django_password_context(django_context)
            self.assert_patched(context=django_context)
            self.consumeWarningList(wlog,
                        "^another library has patched.*models:check_password$")

    def test_01_patch_bad_types(self):
        "test set_django_password_context bad inputs"
        set = utils.set_django_password_context
        self.assertRaises(TypeError, set, "")

    def test_02_models_check_password(self):
        "test monkeypatched models.check_password()"

        # patch to use simple context
        utils.set_django_password_context(simple_context)
        self.assert_patched(context=simple_context)

        # check correct hashes pass
        self.assertTrue(dam.check_password(sample1, sample1_des))
        self.assertTrue(dam.check_password(sample1, sample1_md5))

        # check bad password fail w/ false
        self.assertFalse(dam.check_password('x', sample1_des))
        self.assertFalse(dam.check_password('x', sample1_md5))

        # and other hashes fail w/ error
        self.assertRaises(ValueError, dam.check_password, sample1, sample1_sha1)
        self.assertRaises(ValueError, dam.check_password, sample1, None)

    def test_03_check_password(self):
        "test monkeypatched User.check_password()"
        # NOTE: using FakeUser so we can test .save()
        user = FakeUser()

        # patch to use simple context
        utils.set_django_password_context(simple_context)
        self.assert_patched(context=simple_context)

        # test that blank hash is never accepted
        self.assertEqual(user.password, '')
        self.assertIs(user.saved_password, None)
        self.assertFalse(user.check_password('x'))

        # check correct secrets pass, and wrong ones fail
        user.password = sample1_md5
        self.assertTrue(user.check_password(sample1))
        self.assertFalse(user.check_password('x'))
        self.assertFalse(user.check_password(None))

        # none of that should have triggered update of password
        self.assertEqual(user.password, sample1_md5)
        self.assertIs(user.saved_password, None)

        #check unusable password
        if has_django1:
            user.set_unusable_password()
            self.assertFalse(user.has_usable_password())
            self.assertFalse(user.check_password(None))
            self.assertFalse(user.check_password(''))
            self.assertFalse(user.check_password(sample1))

    def test_04_check_password_migration(self):
        "test User.check_password() hash migration"
        # NOTE: using FakeUser so we can test .save()
        user = FakeUser()

        # patch to use simple context
        utils.set_django_password_context(simple_context)
        self.assert_patched(context=simple_context)

        # set things up with a password that needs migration
        user.password = sample1_des
        self.assertEqual(user.password, sample1_des)
        self.assertIs(user.saved_password, None)

        # run check with bad password...
        # shouldn't have migrated
        self.assertFalse(user.check_password('x'))
        self.assertFalse(user.check_password(None))

        self.assertEqual(user.password, sample1_des)
        self.assertIs(user.saved_password, None)

        # run check with correct password...
        # should have migrated to md5 and called save()
        self.assertTrue(user.check_password(sample1))

        self.assertTrue(user.password.startswith("$1$"))
        self.assertEqual(user.saved_password, user.password)

        # check resave doesn't happen
        user.saved_password = None
        self.assertTrue(user.check_password(sample1))
        self.assertIs(user.saved_password, None)

    def test_05_set_password(self):
        "test monkeypatched User.set_password()"
        user = FakeUser()

        # patch to use simple context
        utils.set_django_password_context(simple_context)
        self.assert_patched(context=simple_context)

        # sanity check
        self.assertEqual(user.password, '')
        self.assertIs(user.saved_password, None)
        if has_django1:
            self.assertTrue(user.has_usable_password())

        # set password
        user.set_password(sample1)
        self.assertTrue(user.check_password(sample1))
        self.assertEqual(simple_context.identify(user.password), "md5_crypt")
        self.assertIs(user.saved_password, None)

        #check unusable password
        user.set_password(None)
        if has_django1:
            self.assertFalse(user.has_usable_password())
        self.assertIs(user.saved_password, None)

    def test_06_get_category(self):
        "test default get_category function"
        func = utils.get_category
        self.assertIs(func(FakeUser()), None)
        self.assertEqual(func(FakeUser(is_staff=True)), "staff")
        self.assertEqual(func(FakeUser(is_superuser=True)), "superuser")
        self.assertEqual(func(FakeUser(is_staff=True,
                                        is_superuser=True)), "superuser")

    def test_07_get_category(self):
        "test set_django_password_context's get_category parameter"
        # test patch uses default get_category
        utils.set_django_password_context(category_context)
        self.assertEqual(get_cc_rounds(), 1000)
        self.assertEqual(get_cc_rounds(is_staff=True), 2000)
        self.assertEqual(get_cc_rounds(is_superuser=True), 3000)

        # test patch uses explicit get_category
        def get_category(user):
            return user.first_name or None
        utils.set_django_password_context(category_context, get_category)
        self.assertEqual(get_cc_rounds(), 1000)
        self.assertEqual(get_cc_rounds(first_name='other'), 1000)
        self.assertEqual(get_cc_rounds(first_name='staff'), 2000)
        self.assertEqual(get_cc_rounds(first_name='superuser'), 3000)

        # test patch can disable get_category
        utils.set_django_password_context(category_context, None)
        self.assertEqual(get_cc_rounds(), 1000)
        self.assertEqual(get_cc_rounds(first_name='other'), 1000)
        self.assertEqual(get_cc_rounds(first_name='staff', is_staff=True), 1000)
        self.assertEqual(get_cc_rounds(first_name='superuser', is_superuser=True), 1000)

PatchTest = skipUnlessDjango(PatchTest)

#=========================================================
# test django plugin
#=========================================================

django_hash_tests = [
                    th.hex_md5_test,
                    th.django_des_crypt_test,
                    th.django_salted_md5_test,
                    th.django_salted_sha1_test,
                     ]

default_hash_tests = django_hash_tests + [ th.builtin_sha512_crypt_test \
                                          or th.os_crypt_sha512_crypt_test ]

if has_django0:
    django_hash_tests.remove(th.django_des_crypt_test)

class PluginTest(TestCase):
    "test django plugin via settings"

    descriptionPrefix = "passlib.ext.django plugin"

    def setUp(self):
        super(PluginTest, self).setUp()

        # remove django patch now, and at end
        utils.set_django_password_context(None)
        self.addCleanup(utils.set_django_password_context, None)

        # ensure django settings are empty
        update_settings(
            PASSLIB_CONTEXT=_NOTSET,
            PASSLIB_GET_CATEGORY=_NOTSET,
        )

        # unload module so it's re-run when imported
        sys.modules.pop("passlib.ext.django.models", None)

    def check_hashes(self, tests, default_scheme, deprecated=[], load=True):
        """run through django api to verify patch is configured & functioning"""
        # load extension if it hasn't been already.
        if load:
            import passlib.ext.django.models

        # create fake user object
        user = FakeUser()

        # check new hashes constructed using default scheme
        user.set_password("stub")
        handler = get_crypt_handler(default_scheme)
        self.assertTrue(handler.identify(user.password),
                        "handler failed to identify hash: %r %r" %
                        (default_scheme, user.password))

        # run against hashes from tests...
        for test in tests:
            for secret, hash in test.iter_known_hashes():

                # check against valid password
                user.password = hash
                if has_django0 and isinstance(secret, unicode):
                    secret = secret.encode("utf-8")
                self.assertTrue(user.check_password(secret))
                if deprecated and test.handler.name in deprecated:
                    self.assertFalse(handler.identify(hash))
                    self.assertTrue(handler.identify(user.password))

                # check against invalid password
                user.password = hash
                self.assertFalse(user.check_password('x'+secret))
                if deprecated and test.handler.name in deprecated:
                    self.assertFalse(handler.identify(hash))
                    self.assertEqual(user.password, hash)

        # check disabled handling
        if has_django1:
            user.set_password(None)
            handler = get_crypt_handler("django_disabled")
            self.assertTrue(handler.identify(user.password))
            self.assertFalse(user.check_password('placeholder'))

    def check_django_stock(self, load=True):
        self.check_hashes(django_hash_tests,
                          "django_salted_sha1",
                          ["hex_md5"], load=load)

    def check_passlib_stock(self):
        self.check_hashes(default_hash_tests,
                          "sha512_crypt",
                          ["hex_md5", "django_salted_sha1",
                           "django_salted_md5",
                           "django_des_crypt",
                           ])

    def test_10_django(self):
        "test actual Django behavior has not changed"
        #NOTE: if this test fails,
        #      probably means newer version of Django,
        #      and passlib's policies should be updated.
        self.check_django_stock(load=False)

    def test_11_none(self):
        "test PASSLIB_CONTEXT=None"
        update_settings(PASSLIB_CONTEXT=None)
        self.check_django_stock(load=False)

    def test_12_string(self):
        "test PASSLIB_CONTEXT=string"
        update_settings(PASSLIB_CONTEXT=utils.STOCK_CTX)
        self.check_django_stock(load=False)

    def test_13_unset(self):
        "test unset PASSLIB_CONTEXT uses default"
        self.check_passlib_stock()

    def test_14_default(self):
        "test PASSLIB_CONTEXT = utils.DEFAULT_CTX"
        update_settings(PASSLIB_CONTEXT=utils.DEFAULT_CTX)
        self.check_passlib_stock()

    def test_15_default_alias(self):
        "test PASSLIB_CONTEXT = 'passlib-default'"
        update_settings(PASSLIB_CONTEXT="passlib-default")
        self.check_passlib_stock()

    def test_16_invalid(self):
        "test PASSLIB_CONTEXT = invalid type"
        update_settings(PASSLIB_CONTEXT=123)
        self.assertRaises(TypeError, __import__, 'passlib.ext.django.models')

    def test_20_categories(self):
        "test PASSLIB_GET_CATEGORY unset"
        update_settings(
            PASSLIB_CONTEXT=category_context.to_string(),
        )
        import passlib.ext.django.models

        self.assertEqual(get_cc_rounds(), 1000)
        self.assertEqual(get_cc_rounds(is_staff=True), 2000)
        self.assertEqual(get_cc_rounds(is_superuser=True), 3000)

    def test_21_categories_explicit(self):
        "test PASSLIB_GET_CATEGORY = function"
        def get_category(user):
            return user.first_name or None
        update_settings(
            PASSLIB_CONTEXT = category_context.to_string(),
            PASSLIB_GET_CATEGORY = get_category,
        )
        import passlib.ext.django.models

        self.assertEqual(get_cc_rounds(), 1000)
        self.assertEqual(get_cc_rounds(first_name='other'), 1000)
        self.assertEqual(get_cc_rounds(first_name='staff'), 2000)
        self.assertEqual(get_cc_rounds(first_name='superuser'), 3000)

    def test_22_categories_disabled(self):
        "test PASSLIB_GET_CATEGORY = None"
        update_settings(
            PASSLIB_CONTEXT = category_context.to_string(),
            PASSLIB_GET_CATEGORY = None,
        )
        import passlib.ext.django.models

        self.assertEqual(get_cc_rounds(), 1000)
        self.assertEqual(get_cc_rounds(first_name='other'), 1000)
        self.assertEqual(get_cc_rounds(first_name='staff', is_staff=True), 1000)
        self.assertEqual(get_cc_rounds(first_name='superuser', is_superuser=True), 1000)

PluginTest = skipUnlessDjango(PluginTest)

#=========================================================
#eof
#=========================================================
