"""test passlib.ext.django"""
#=========================================================
#imports
#=========================================================
from __future__ import with_statement
# core
import logging; log = logging.getLogger(__name__)
import sys
import warnings
# site
# pkg
from passlib.apps import django10_context, django14_context
from passlib.context import CryptContext
import passlib.exc as exc
from passlib.utils.compat import iteritems, unicode, get_method_function, u, PY3
from passlib.utils import memoized_property
from passlib.registry import get_crypt_handler
# tests
from passlib.tests.utils import TestCase, unittest, ut_version, catch_warnings
from passlib.tests.test_handlers import get_handler_case
# local

#=========================================================
# configure django settings for testcases
#=========================================================
from passlib.ext.django.utils import DJANGO_VERSION

# disable all Django integration tests under py3,
# since Django doesn't support py3 yet.
if PY3 and DJANGO_VERSION < (1,5):
    DJANGO_VERSION = ()

# convert django version to some cheap flags
has_django = bool(DJANGO_VERSION)
has_django0 = has_django and DJANGO_VERSION < (1,0)
has_django1 = DJANGO_VERSION >= (1,0)
has_django14 = DJANGO_VERSION >= (1,4)

# import and configure empty django settings
if has_django:
    from django.conf import settings, LazySettings

    if not isinstance(settings, LazySettings):
        # this probably means django globals have been configured already,
        # which we don't want, since test cases reset and manipulate settings.
        raise RuntimeError("expected django.conf.settings to be LazySettings: %r" % (settings,))

    # else configure a blank settings instance for the unittests
    if has_django0:
        if settings._target is None:
            from django.conf import UserSettingsHolder, global_settings
            settings._target = UserSettingsHolder(global_settings)
    elif not settings.configured:
        settings.configure()

#=========================================================
# support funcs
#=========================================================

# flag for update_settings() to remove specified key entirely
UNSET = object()

def update_settings(**kwds):
    """helper to update django settings from kwds"""
    for k,v in iteritems(kwds):
        if v is UNSET:
            if hasattr(settings, k):
                if has_django0:
                    delattr(settings._target, k)
                else:
                    delattr(settings, k)
        else:
            setattr(settings, k, v)

def skipUnlessDjango(cls):
    "helper to skip testcase if django not present"
    if has_django:
        return cls
    if ut_version < 2:
        return None
    return unittest.skip("Django not installed")(cls)

if has_django:
    if has_django14:
        import django.contrib.auth.hashers as hashers
    import django.contrib.auth.models as models

    class FakeUser(models.User):
        "mock user object for use in testing"
        # NOTE: this mainly just overrides .save() to test commit behavior.

        @memoized_property
        def saved_passwords(self):
            return []

        def pop_saved_passwords(self):
            try:
                return self.saved_passwords[:]
            finally:
                del self.saved_passwords[:]

        def save(self):
            self.saved_passwords.append(self.password)

# attrs we're patching in various modules.
_patched_attrs = ["set_password", "check_password",
                  "make_password", "get_hasher", "identify_hasher"]

def iter_patch_candidates():
    "helper to scan for monkeypatches"
    objs = [models, models.User]
    if has_django14:
        objs.append(hashers)
    for obj in objs:
        for attr in dir(obj):
            if attr.startswith("_"):
                continue
            value = getattr(obj, attr)
            value = get_method_function(value)
            source = getattr(value, "__module__", None)
            if source:
                yield obj, attr, source

config_keys = ["PASSLIB_CONFIG", "PASSLIB_CONTEXT", "PASSLIB_GET_CATEGORY"]

def create_mock_setter():
    state = []
    def setter(password):
        state.append(password)
    def popstate():
        try:
            return state[:]
        finally:
            del state[:]
    setter.popstate = popstate
    return setter

def has_backend(handler):
    return not hasattr(handler, "has_backend") or handler.has_backend()

#=========================================================
# sample config used by basic tests
#=========================================================

# simple context which looks NOTHING like django,
# so we can tell if patching worked.
simple_config = dict(
    schemes = [ "md5_crypt", "des_crypt" ],
    deprecated = [ "des_crypt" ],
)

# sample password
sample1 = 'password'

# some sample hashes using above config
sample1_md5 = '$1$kAd49ifN$biuRAv1Tv0zGHyCv0uIqW.'
sample1_des = 'PPPTDkiCeu/jM'
sample1_sha1 = 'sha1$b215d$9ee0a66f84ef1ad99096355e788135f7e949bd41'
empty_md5 = '$1$1.thfpQC$3bIi1iFVFxRQ6cZS7q/WR.'

#=========================================================
# work up stock django config
#=========================================================
if has_django14:
    # have to modify this a little -
    # all but pbkdf2_sha256 will be deprecated here,
    # whereas stock passlib policy is more permissive
    stock_config = django14_context.to_dict()
    stock_config['deprecated'] = ["django_pbkdf2_sha1", "django_bcrypt"] + stock_config['deprecated']
elif has_django1:
    stock_config = django10_context.to_dict()
else:
    # 0.9.6 config
    stock_config = dict(schemes=["django_salted_sha1", "django_salted_md5", "hex_md5"],
                 deprecated=["hex_md5"])

#=========================================================
# test utils
#=========================================================
class _ExtensionSupport(object):
    "support funcs for loading/unloading extension"

    def unload_extension(self):
        "helper to remove patches and unload extension"
        # remove patches and unload module
        mod = sys.modules.get("passlib.ext.django.models")
        if mod:
            mod._remove_patch()
            del sys.modules["passlib.ext.django.models"]
        # wipe config from django settings
        update_settings(**dict((key, UNSET) for key in config_keys))
        # check everything's gone
        self.assert_unpatched()

    def assert_unpatched(self):
        "test that django is in unpatched state"
        # make sure we aren't currently patched
        mod = sys.modules.get("passlib.ext.django.models")
        self.assertFalse(mod and mod._patched, "patch should not be enabled")

        # make sure no objects have been replaced, by checking __module__
        for obj, attr, source in iter_patch_candidates():
            if attr in _patched_attrs:
                self.assertTrue(source.startswith("django.contrib.auth."),
                                "obj=%r attr=%r was not reverted: %r" %
                                (obj, attr, source))
            else:
                self.assertFalse(source.startswith("passlib."),
                                "obj=%r attr=%r should not have been patched: %r" %
                                (obj, attr, source))

    def load_extension(self, check=True, **kwds):
        "helper to load extension with specified config & patch django"
        self.unload_extension()
        if check:
            config = kwds.get("PASSLIB_CONFIG") or kwds.get("PASSLIB_CONTEXT")
        for key in config_keys:
            kwds.setdefault(key, UNSET)
        update_settings(**kwds)
        import passlib.ext.django.models
        if check:
            self.assert_patched(context=config)

    def assert_patched(self, context=None):
        "helper to ensure django HAS been patched"
        # make sure we're currently patched
        mod = sys.modules.get("passlib.ext.django.models")
        self.assertTrue(mod and mod._patched, "patch should have been enabled")

        # make sure only the expected objects have been patched
        for obj, attr, source in iter_patch_candidates():
            if attr in _patched_attrs:
                self.assertTrue(source == "passlib.ext.django.models",
                                "obj=%r attr=%r should have been patched: %r" %
                                (obj, attr, source))
            else:
                self.assertFalse(source.startswith("passlib."),
                                "obj=%r attr=%r should not have been patched: %r" %
                                (obj, attr, source))

        # check context matches
        if context is not None:
            context = CryptContext._norm_source(context)
            self.assertEqual(mod.password_context.to_dict(resolve=True),
                             context.to_dict(resolve=True))

class DjangoExtensionTest(TestCase, _ExtensionSupport):
    """test the ``passlib.ext.django`` plugin"""
    descriptionPrefix = "passlib.ext.django plugin"

    #=========================================================
    # init
    #=========================================================
    def setUp(self):
        # reset to baseline, and verify it worked
        self.unload_extension()

        # and do the same when the test exits
        self.addCleanup(self.unload_extension)

    #=========================================================
    # monkeypatch testing
    #=========================================================
    def test_00_patch_control(self):
        "test set_django_password_context patch/unpatch"

        # check config="disabled"
        self.load_extension(PASSLIB_CONFIG="disabled", check=False)
        self.assert_unpatched()

        # check legacy config=None
        with catch_warnings(record=True) as wlog:
            self.load_extension(PASSLIB_CONFIG=None, check=False)
            self.consumeWarningList(wlog, ["PASSLIB_CONFIG=None is deprecated.*"])
            self.assert_unpatched()

        # try stock django 1.0 context
        self.load_extension(PASSLIB_CONFIG="django-1.0", check=False)
        self.assert_patched(context=django10_context)

        # try to remove patch
        self.unload_extension()

        # patch to use stock django 1.4 context
        self.load_extension(PASSLIB_CONFIG="django-1.4", check=False)
        self.assert_patched(context=django14_context)

        # try to remove patch again
        self.unload_extension()

    def test_01_overwrite_detection(self):
        "test detection of foreign monkeypatching"
        # NOTE: this sets things up, and spot checks two methods.
        #       this should be enough to verify patch manager is working.
        # TODO: test unpatch behavior honors flag.
        def dummy():
            pass

        with catch_warnings(record=True) as wlog:
            # patch to use simple context, should issue no warnings
            self.load_extension(PASSLIB_CONFIG=simple_config)
            self.consumeWarningList(wlog)
            from passlib.ext.django.models import _manager

            # mess with User.set_password, make sure it's detected
            orig = models.User.set_password
            models.User.set_password = dummy
            _manager.check_all()
            self.consumeWarningList(wlog,"another library has patched.*User\.set_password")
            models.User.set_password = orig

            # mess with models.check_password, make sure it's detected
            orig = models.check_password
            models.check_password = dummy
            _manager.check_all()
            self.consumeWarningList(wlog,"another library has patched.*models:check_password")
            models.check_password = orig

    def test_02_check_password(self):
        "test monkeypatched check_password() function"
        # patch to use simple context
        self.load_extension(PASSLIB_CONFIG=simple_config)
        check_password = models.check_password

        # check hashers module has same function
        if has_django14:
            self.assertIs(hashers.check_password, check_password)

        # check correct password returns True
        self.assertTrue(check_password(sample1, sample1_des))
        self.assertTrue(check_password(sample1, sample1_md5))

        # check bad password returns False
        self.assertFalse(check_password('x', sample1_des))
        self.assertFalse(check_password('x', sample1_md5))

        # check empty password returns False
        self.assertFalse(check_password(None, sample1_des))
        self.assertFalse(check_password('', sample1_des))
        if has_django14:
            # 1.4 and up reject empty passwords even if they'd match hash
            self.assertFalse(check_password('', empty_md5))
        else:
            self.assertTrue(check_password('', empty_md5))

        # test unusable hash returns False
        self.assertFalse(check_password(sample1, None))
        self.assertFalse(check_password(sample1, "!"))

        # check unsupported hash throws error
        self.assertRaises(ValueError, check_password, sample1, sample1_sha1)

    def test_03_check_password_migration(self):
        "test monkeypatched check_password() function's migration support"
        # check setter callback works (django 1.4 feature)
        self.load_extension(PASSLIB_CONFIG=simple_config)
        setter = create_mock_setter()
        check_password = models.check_password

        # correct pwd, deprecated hash
        self.assertTrue(check_password(sample1, sample1_des, setter=setter))
        self.assertEqual(setter.popstate(), [sample1])

        # wrong pwd, deprecated hash
        self.assertFalse(check_password('x', sample1_des, setter=setter))
        self.assertEqual(setter.popstate(), [])

        # correct pwd, preferred hash
        self.assertTrue(check_password(sample1, sample1_md5, setter=setter))
        self.assertEqual(setter.popstate(), [])

        # check preferred is ignored (django 1.4 feature)
        self.assertTrue(check_password(sample1, sample1_des, setter=setter,
                                           preferred='fooey'))
        self.assertEqual(setter.popstate(), [sample1])

    def test_04_user_check_password(self):
        "test monkeypatched User.check_password() method"
        # patch to use simple context
        self.load_extension(PASSLIB_CONFIG=simple_config)

        # test that blank hash is never accepted
        user = FakeUser()
        self.assertEqual(user.password, '')
        self.assertEqual(user.saved_passwords, [])
        self.assertRaises(ValueError, user.check_password, 'x')

        # check correct secrets pass, and wrong ones fail
        user = FakeUser()
        user.password = sample1_md5
        self.assertTrue(user.check_password(sample1))
        self.assertFalse(user.check_password('x'))
        self.assertFalse(user.check_password(None))
            # none of that should have triggered update of password
        self.assertEqual(user.password, sample1_md5)
        self.assertEqual(user.saved_passwords, [])

        # check empty password returns False
        user = FakeUser()
        user.password = sample1_md5
        self.assertFalse(user.check_password(None))
        self.assertFalse(user.check_password(''))
        user.password = empty_md5
        if has_django14:
            # 1.4 and up reject empty passwords even if they'd match hash
            self.assertFalse(user.check_password(''))
        else:
            self.assertTrue(user.check_password(''))

        #check unusable password
            # NOTE: not present under django 0.9, but our patch backports it.
        user = FakeUser()
        user.set_unusable_password()
        self.assertFalse(user.has_usable_password())
        self.assertFalse(user.check_password(None))
        self.assertFalse(user.check_password(''))
        self.assertFalse(user.check_password(sample1))
        self.assertEqual(user.saved_passwords, [])

    def test_05_user_check_password_migration(self):
        "test monkeypatched User.check_password() method's migration support"
        # patch to use simple context
        self.load_extension(PASSLIB_CONFIG=simple_config)

        # set things up with a password that needs migration
        user = FakeUser()
        user.password = sample1_des
        self.assertEqual(user.password, sample1_des)
        self.assertEqual(user.pop_saved_passwords(), [])

        # run check with wrong password... shouldn't have migrated
        self.assertFalse(user.check_password('x'))
        self.assertFalse(user.check_password(None))
        self.assertEqual(user.password, sample1_des)
        self.assertEqual(user.pop_saved_passwords(), [])

        # run check with correct password... should have migrated to md5 and called save()
        self.assertTrue(user.check_password(sample1))
        self.assertTrue(user.password.startswith("$1$"))
        self.assertEqual(user.pop_saved_passwords(), [user.password])

        # check re-migration doesn't happen
        orig = user.password
        self.assertTrue(user.check_password(sample1))
        self.assertEqual(user.password, orig)
        self.assertEqual(user.pop_saved_passwords(), [])

    def test_06_set_password(self):
        "test monkeypatched User.set_password() method"
        # patch to use simple context
        self.load_extension(PASSLIB_CONFIG=simple_config)
        from passlib.ext.django.models import password_context

        # sanity check
        user = FakeUser()
        self.assertEqual(user.password, '')
        self.assertEqual(user.pop_saved_passwords(), [])
        self.assertTrue(user.has_usable_password())

        # set password
        user.set_password(sample1)
        self.assertEqual(password_context.identify(user.password), "md5_crypt")
        self.assertTrue(user.check_password(sample1))
        self.assertEqual(user.pop_saved_passwords(), [])
        self.assertTrue(user.has_usable_password())

        # check unusable password
        user.set_password(None)
        self.assertFalse(user.has_usable_password())
        self.assertEqual(user.pop_saved_passwords(), [])

    def test_07_get_hasher(self):
        "test monkeypatched get_hasher() function"
        if not has_django14:
            raise self.skipTest("Django >= 1.4 not installed")
        # TODO: test this

    def test_08_identify_hasher(self):
        "test custom identify_hasher() function"
        if not has_django14:
            raise self.skipTest("Django >= 1.4 not installed")
        # TODO: test this

    def test_09_handler_wrapper(self):
        "test Hasher-compatible handler wrappers"
        if not has_django14:
            raise self.skipTest("Django >= 1.4 not installed")
        from passlib.ext.django.utils import get_passlib_hasher

        # should return native django hasher if available
        hasher = get_passlib_hasher("hex_md5")
        self.assertIs(hasher.__class__, hashers.UnsaltedMD5PasswordHasher)

        hasher = get_passlib_hasher("django_bcrypt")
        self.assertIs(hasher.__class__, hashers.BCryptPasswordHasher)

        # otherwise should return wrapper
        from passlib.hash import sha256_crypt
        hasher = get_passlib_hasher("sha256_crypt")
        self.assertEqual(hasher.algorithm, "passlib_sha256_crypt")
        encoded = hasher.encode("stub")
        self.assertTrue(sha256_crypt.verify("stub", encoded))
        self.assertTrue(hasher.verify("stub", encoded))
        self.assertFalse(hasher.verify("xxxx", encoded))

        # test wrapper accepts options
        encoded = hasher.encode("stub", "abcd"*4, iterations=1234)
        self.assertEqual(encoded, "$5$rounds=1234$abcdabcdabcdabcd$"
                                  "v2RWkZQzctPdejyRqmmTDQpZN6wTh7.RUy9zF2LftT6")
        self.assertEqual(hasher.safe_summary(encoded),
            {'algorithm': 'sha256_crypt',
             'salt': u('abcdab**********'),
             'iterations': 1234,
             'hash': u('v2RWkZ*************************************'),
             })

    #=========================================================
    # PASSLIB_CONFIG setting
    #=========================================================
    def test_10_stock(self):
        "test unloaded extension / actual django behavior"
        # test against stock django configuration before loading extension
        #NOTE: if this test fails, probably means newer version of Django,
        #      and that passlib's stock configs should be updated.
        self.check_config(stock_config, patched=False)

    def test_11_config_disabled(self):
        "test PASSLIB_CONFIG='disabled'"
        # test config=None (deprecated)
        with catch_warnings(record=True) as wlog:
            self.load_extension(PASSLIB_CONFIG=None,check=False)
            self.consumeWarningList(wlog, "PASSLIB_CONFIG=None is deprecated")
        self.assert_unpatched()

        # test disabled config
        self.load_extension(PASSLIB_CONFIG="disabled", check=False)
        self.assert_unpatched()

    def test_12_config_presets(self):
        "test PASSLIB_CONFIG='<preset>'"
        # test django presets
        self.load_extension(PASSLIB_CONTEXT="django-default", check=False)
        if has_django14:
            ctx = django14_context
        else:
            ctx = django10_context
        self.assert_patched(ctx)

        self.load_extension(PASSLIB_CONFIG="django-1.0", check=False)
        self.assert_patched(django10_context)

        self.load_extension(PASSLIB_CONFIG="django-1.4", check=False)
        self.assert_patched(django14_context)

    def test_13_config_defaults(self):
        "test PASSLIB_CONFIG default behavior"
        # check implicit default
        from passlib.ext.django.utils import PASSLIB_DEFAULT
        default = CryptContext.from_string(PASSLIB_DEFAULT)
        self.load_extension()
        self.check_config(default)

        # check default preset
        self.load_extension(PASSLIB_CONTEXT="passlib-default", check=False)
        self.assert_patched(PASSLIB_DEFAULT)

        # check explicit string
        self.load_extension(PASSLIB_CONTEXT=PASSLIB_DEFAULT, check=False)
        self.assert_patched(PASSLIB_DEFAULT)

    def test_14_config_invalid(self):
        "test PASSLIB_CONFIG type checks"
        update_settings(PASSLIB_CONTEXT=123, PASSLIB_CONFIG=UNSET)
        self.assertRaises(TypeError, __import__, 'passlib.ext.django.models')

    def check_config(self, context, patched=True):
        """run through django api to verify it's matches the specified config"""
        # XXX: this take a while to run. what could be trimmed?

        # setup helpers
        if isinstance(context, dict):
            context = CryptContext(**context)
        check_password = models.check_password
        if has_django14:
            from passlib.ext.django.utils import hasher_to_passlib_name, passlib_to_hasher_name
        setter = create_mock_setter()

        # check new hashes constructed using default scheme
        user = FakeUser()
        user.set_password("stub")
        default = context.handler()
        if has_backend(default):
            self.assertTrue(default.verify("stub", user.password))
        else:
            self.assertRaises(exc.MissingBackendError, default.verify, 'stub', user.password)

        # test module-level make_password
        if has_backend(default) and has_django14:
            hash = hashers.make_password('stub')
            self.assertTrue(default.verify('stub', hash))

        # run through known hashes for supported schemes
        for scheme in context.schemes():
            deprecated = context._is_deprecated_scheme(scheme)
            assert not (deprecated and scheme == default.name)
            try:
                testcase = get_handler_case(scheme)
            except exc.MissingBackendError:
                assert scheme == "bcrypt"
                continue
            if testcase.is_disabled_handler:
                continue
            handler = testcase.handler
            if not has_backend(handler):
                assert scheme == "django_bcrypt"
                continue
            for secret, hash in testcase.iter_known_hashes():
##                print [scheme, secret, hash, deprecated, scheme==default.name]
                other = 'stub'

                # store hash
                user = FakeUser()
                user.password = hash

                # check against invalid password
                self.assertFalse(user.check_password(other))
                self.assertEqual(user.password, hash)

                # empty passwords no longer accepted by django 1.4
                if not secret and has_django14:
                    self.assertFalse(user.check_password(secret))
                    self.assertFalse(check_password(secret, hash))
                    user.set_password(secret)
                    self.assertFalse(user.has_usable_password())
                    continue

                # check against valid password
                if has_django0 and isinstance(secret, unicode):
                    secret = secret.encode("utf-8")
                self.assertTrue(user.check_password(secret))

                # check if it upgraded the hash
                needs_update = context.needs_update(hash)
                if needs_update:
                    self.assertNotEqual(user.password, hash)
                    self.assertFalse(handler.identify(user.password))
                    self.assertTrue(default.identify(user.password))
                else:
                    self.assertEqual(user.password, hash)

                # test module-level check_password
                if has_django14 or patched:
                    self.assertTrue(check_password(secret, hash, setter=setter))
                    self.assertEqual(setter.popstate(), [secret] if needs_update else [])
                    self.assertFalse(check_password(other, hash, setter=setter))
                    self.assertEqual(setter.popstate(), [])
                elif scheme != "hex_md5":
                    # django 1.3 never called check_password() for hex_md5
                    self.assertTrue(check_password(secret, hash))
                    self.assertFalse(check_password(other, hash))

                # test module-level identify_hasher
                if has_django14 and patched:
                    self.assertTrue(hashers.is_password_usable(hash))
                    hasher = hashers.identify_hasher(hash)
                    name = hasher_to_passlib_name(hasher.algorithm)
                    self.assertEqual(name, scheme)

                # test module-level make_password
                if has_django14:
                    alg = passlib_to_hasher_name(scheme)
                    hash2 = hashers.make_password(secret, hasher=alg)
                    self.assertTrue(handler.verify(secret, hash2))

        # check disabled handling
        user = FakeUser()
        user.set_password(None)
        handler = get_crypt_handler("django_disabled")
        self.assertTrue(handler.identify(user.password))
        self.assertFalse(user.check_password('stub'))
        if has_django14 and patched:
            self.assertFalse(hashers.is_password_usable(user.password))
            self.assertRaises(ValueError, hashers.identify_hasher, user.password)

    #=========================================================
    # PASSLIB_GET_CATEGORY setting
    #=========================================================
    def test_20_category_setting(self):
        "test PASSLIB_GET_CATEGORY parameter"
        # define config where rounds can be used to detect category
        config = dict(
            schemes = ["sha256_crypt"],
            sha256_crypt__default_rounds = 1000,
            staff__sha256_crypt__default_rounds = 2000,
            superuser__sha256_crypt__default_rounds = 3000,
            )
        from passlib.hash import sha256_crypt

        def run(**kwds):
            "helper to take in user opts, return rounds used in password"
            user = FakeUser(**kwds)
            user.set_password("stub")
            return sha256_crypt.from_string(user.password).rounds

        # test default get_category
        self.load_extension(PASSLIB_CONFIG=config)
        self.assertEqual(run(), 1000)
        self.assertEqual(run(is_staff=True), 2000)
        self.assertEqual(run(is_superuser=True), 3000)

        # test patch uses explicit get_category function
        def get_category(user):
            return user.first_name or None
        self.load_extension(PASSLIB_CONTEXT=config,
                            PASSLIB_GET_CATEGORY=get_category)
        self.assertEqual(run(), 1000)
        self.assertEqual(run(first_name='other'), 1000)
        self.assertEqual(run(first_name='staff'), 2000)
        self.assertEqual(run(first_name='superuser'), 3000)

        # test patch can disable get_category entirely
        def get_category(user):
            return None
        self.load_extension(PASSLIB_CONTEXT=config,
                            PASSLIB_GET_CATEGORY=get_category)
        self.assertEqual(run(), 1000)
        self.assertEqual(run(first_name='other'), 1000)
        self.assertEqual(run(first_name='staff', is_staff=True), 1000)
        self.assertEqual(run(first_name='superuser', is_superuser=True), 1000)

    #=========================================================
    # eoc
    #=========================================================

DjangoExtensionTest = skipUnlessDjango(DjangoExtensionTest)

# hack up the some of the real django tests to run w/ extension loaded,
# to ensure we mimic their behavior.
if has_django14:
    from django.contrib.auth.tests.hashers import TestUtilsHashPass as _TestHashers
    class HashersTest(_TestHashers, _ExtensionSupport):
        def setUp(self):
            # omitted orig setup, loading hashers our own way
            self.load_extension(PASSLIB_CONTEXT=stock_config, check=False)
        def tearDown(self):
            self.unload_extension()
            super(HashersTest, self).tearDown()

#=========================================================
#eof
#=========================================================
