"""test passlib.ext.django"""
#=============================================================================
# imports
#=============================================================================
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
from passlib.tests.utils import TestCase, skipUnless, catch_warnings, TEST_MODE, has_active_backend
from passlib.tests.test_handlers import get_handler_case
# local

#=============================================================================
# configure django settings for testcases
#=============================================================================
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

#=============================================================================
# support funcs
#=============================================================================

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

if has_django:
    from django.contrib.auth.models import User

    class FakeUser(User):
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

#=============================================================================
# work up stock django config
#=============================================================================
if has_django14:
    # have to modify this a little -
    # all but pbkdf2_sha256 will be deprecated here,
    # whereas preconfigured passlib policy is more permissive
    stock_config = django14_context.to_dict()
    stock_config['deprecated'] = ["django_pbkdf2_sha1", "django_bcrypt"] + stock_config['deprecated']
elif has_django1:
    stock_config = django10_context.to_dict()
else:
    # 0.9.6 config
    stock_config = dict(schemes=["django_salted_sha1", "django_salted_md5", "hex_md5"],
                 deprecated=["hex_md5"])

#=============================================================================
# test utils
#=============================================================================
class _ExtensionSupport(object):
    "support funcs for loading/unloading extension"
    #===================================================================
    # support funcs
    #===================================================================
    @classmethod
    def _iter_patch_candidates(cls):
        """helper to scan for monkeypatches.

        returns tuple containing:
        * object (module or class)
        * attribute of object
        * value of attribute
        * whether it should or should not be patched
        """
        # XXX: this and assert_unpatched() could probably be refactored to use
        #      the PatchManager class to do the heavy lifting.
        from django.contrib.auth import models
        user_attrs = ["check_password", "set_password"]
        model_attrs = ["check_password"]
        objs = [(models, model_attrs), (models.User, user_attrs)]
        if has_django14:
            from django.contrib.auth import hashers
            model_attrs.append("make_password")
            objs.append((hashers, ["check_password", "make_password",
                                   "get_hasher", "identify_hasher"]))
        if has_django0:
            user_attrs.extend(["has_usable_password", "set_unusable_password"])
        for obj, patched in objs:
            for attr in dir(obj):
                if attr.startswith("_"):
                    continue
                value = obj.__dict__.get(attr, UNSET) # can't use getattr() due to GAE
                if value is UNSET and attr not in patched:
                    continue
                value = get_method_function(value)
                source = getattr(value, "__module__", None)
                if source:
                    yield obj, attr, source, (attr in patched)

    #===================================================================
    # verify current patch state
    #===================================================================
    def assert_unpatched(self):
        "test that django is in unpatched state"
        # make sure we aren't currently patched
        mod = sys.modules.get("passlib.ext.django.models")
        self.assertFalse(mod and mod._patched, "patch should not be enabled")

        # make sure no objects have been replaced, by checking __module__
        for obj, attr, source, patched in self._iter_patch_candidates():
            if patched:
                self.assertTrue(source.startswith("django.contrib.auth."),
                                "obj=%r attr=%r was not reverted: %r" %
                                (obj, attr, source))
            else:
                self.assertFalse(source.startswith("passlib."),
                                "obj=%r attr=%r should not have been patched: %r" %
                                (obj, attr, source))

    def assert_patched(self, context=None):
        "helper to ensure django HAS been patched, and is using specified config"
        # make sure we're currently patched
        mod = sys.modules.get("passlib.ext.django.models")
        self.assertTrue(mod and mod._patched, "patch should have been enabled")

        # make sure only the expected objects have been patched
        for obj, attr, source, patched in self._iter_patch_candidates():
            if patched:
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

    #===================================================================
    # load / unload the extension (and verify it worked)
    #===================================================================
    _config_keys = ["PASSLIB_CONFIG", "PASSLIB_CONTEXT", "PASSLIB_GET_CATEGORY"]

    def load_extension(self, check=True, **kwds):
        "helper to load extension with specified config & patch django"
        self.unload_extension()
        if check:
            config = kwds.get("PASSLIB_CONFIG") or kwds.get("PASSLIB_CONTEXT")
        for key in self._config_keys:
            kwds.setdefault(key, UNSET)
        update_settings(**kwds)
        import passlib.ext.django.models
        if check:
            self.assert_patched(context=config)

    def unload_extension(self):
        "helper to remove patches and unload extension"
        # remove patches and unload module
        mod = sys.modules.get("passlib.ext.django.models")
        if mod:
            mod._remove_patch()
            del sys.modules["passlib.ext.django.models"]
        # wipe config from django settings
        update_settings(**dict((key, UNSET) for key in self._config_keys))
        # check everything's gone
        self.assert_unpatched()

    #===================================================================
    # eoc
    #===================================================================

class _ExtensionTest(TestCase, _ExtensionSupport):
    def setUp(self):
        super(_ExtensionTest, self).setUp()

        self.require_TEST_MODE("default")

        if not has_django:
            raise self.skipTest("Django not installed")

        # reset to baseline, and verify it worked
        self.unload_extension()

        # and do the same when the test exits
        self.addCleanup(self.unload_extension)

#=============================================================================
# extension tests
#=============================================================================
class DjangoBehaviorTest(_ExtensionTest):
    "tests model to verify it matches django's behavior"
    descriptionPrefix = "verify django behavior"
    patched = False
    config = stock_config

    # NOTE: if this test fails, it means we're not accounting for
    #       some part of django's hashing logic, or that this is
    #       running against an untested version of django with a new
    #       hashing policy.

    @property
    def context(self):
        return CryptContext._norm_source(self.config)

    def assert_unusable_password(self, user):
        self.assertEqual(user.password, "!")
        if has_django1 or self.patched:
            self.assertFalse(user.has_usable_password())
        self.assertEqual(user.pop_saved_passwords(), [])

    def assert_valid_password(self, user, hash=UNSET, saved=None):
        if hash is UNSET:
            self.assertNotEqual(user.password, "!")
            self.assertNotEqual(user.password, None)
        else:
            self.assertEqual(user.password, hash)
        if has_django1 or self.patched:
            self.assertTrue(user.has_usable_password())
        self.assertEqual(user.pop_saved_passwords(),
                         [] if saved is None else [saved])

    def test_config(self):
        """test hashing interface

        this function is run against both the actual django code, to
        verify the assumptions of the unittests are correct;
        and run against the passlib extension, to verify it matches
        those assumptions.
        """
        patched, config = self.patched, self.config
        # this tests the following methods:
        #   User.set_password()
        #   User.check_password()
        #   make_password() -- 1.4 only
        #   check_password()
        #   identify_hasher()
        #   User.has_usable_password()
        #   User.set_unusable_password()
        # XXX: this take a while to run. what could be trimmed?

        #  TODO: get_hasher()

        #=======================================================
        # setup helpers & imports
        #=======================================================
        ctx = self.context
        setter = create_mock_setter()
        PASS1 = "toomanysecrets"
        WRONG1 = "letmein"

        if has_django14:
            from passlib.ext.django.utils import hasher_to_passlib_name, passlib_to_hasher_name
            from django.contrib.auth.hashers import check_password, make_password, is_password_usable
            if patched:
                from django.contrib.auth.hashers import identify_hasher
        else:
            from django.contrib.auth.models import check_password

        #=======================================================
        # make sure extension is configured correctly
        #=======================================================
        if patched:
            # contexts should match
            from passlib.ext.django.models import password_context
            self.assertEqual(password_context.to_dict(resolve=True),
                             ctx.to_dict(resolve=True))

            # should have patched both places
            if has_django14:
                from django.contrib.auth.models import check_password as check_password2
                self.assertIs(check_password2, check_password)

        #=======================================================
        # default algorithm
        #=======================================================
        # User.set_password() should use default alg
        user = FakeUser()
        user.set_password(PASS1)
        self.assertTrue(ctx.handler().verify(PASS1, user.password))
        self.assert_valid_password(user)

        # User.check_password() - n/a

        # make_password() should use default alg
        if has_django14:
            hash = make_password(PASS1)
            self.assertTrue(ctx.handler().verify(PASS1, hash))

        # check_password() - n/a

        #=======================================================
        # empty password behavior
        #=======================================================
        if has_django14:
            # NOTE: django 1.4 treats empty password as invalid

            # User.set_password() should set unusable flag
            user = FakeUser()
            user.set_password('')
            self.assert_unusable_password(user)

            # User.check_password() should never return True
            user = FakeUser()
            user.password = hash = ctx.encrypt("")
            self.assertFalse(user.check_password(""))
            self.assert_valid_password(user, hash)

            # make_password() should reject empty passwords
            self.assertEqual(make_password(""), "!")

            # check_password() should never return True
            self.assertFalse(check_password("", hash))

        else:
            # User.set_password() should use default alg
            user = FakeUser()
            user.set_password('')
            hash = user.password
            self.assertTrue(ctx.handler().verify('', hash))
            self.assert_valid_password(user, hash)

            # User.check_password() should return True
            self.assertTrue(user.check_password(""))
            self.assert_valid_password(user, hash)

            # no make_password()

            # check_password() should return True
            self.assertTrue(check_password("", hash))

        #=======================================================
        # 'unusable flag' behavior
        #=======================================================
        if has_django1 or patched:

            # sanity check via user.set_unusable_password()
            user = FakeUser()
            user.set_unusable_password()
            self.assert_unusable_password(user)

            # ensure User.set_password() sets flag
            user = FakeUser()
            user.set_password(None)
            self.assert_unusable_password(user)

            # User.check_password() should always fail
            self.assertFalse(user.check_password(None))
            self.assertFalse(user.check_password(''))
            self.assertFalse(user.check_password(PASS1))
            self.assertFalse(user.check_password(WRONG1))
            self.assert_unusable_password(user)

            # make_password() should also set flag
            if has_django14:
                self.assertEqual(make_password(None), "!")

            # check_password() should return False (didn't handle disabled under 1.3)
            if has_django14 or patched:
                self.assertFalse(check_password(PASS1, '!'))

            # identify_hasher() and is_password_usable() should reject it
            if has_django14:
                self.assertFalse(is_password_usable(user.password))
            if has_django14 and patched:
                self.assertRaises(ValueError, identify_hasher, user.password)

        #=======================================================
        # hash=None
        #=======================================================
        # User.set_password() - n/a

        # User.check_password() - returns False
        user = FakeUser()
        user.password = None
        if has_django14 or patched:
            self.assertFalse(user.check_password(PASS1))
        else:
            self.assertRaises(TypeError, user.check_password, PASS1)
        if has_django1 or patched:
            self.assertFalse(user.has_usable_password())

        # make_password() - n/a

        # check_password() - error
        if has_django14 or patched:
            self.assertFalse(check_password(PASS1, None))
        else:
            self.assertRaises(AttributeError, check_password, PASS1, None)

        # identify_hasher() - error
        if has_django14 and patched:
            self.assertRaises(TypeError, identify_hasher, None)

        #=======================================================
        # invalid hash values
        #=======================================================
        for hash in ("", "$789$foo"):
            # User.set_password() - n/a

            # User.check_password() - blank hash causes error
            user = FakeUser()
            user.password = hash
            if has_django14 or patched or hash:
                self.assertRaises(ValueError, user.check_password, PASS1)
            else:
                # django 1.3 returns False for empty hashes
                self.assertFalse(user.check_password(PASS1))
            self.assert_valid_password(user, hash) # '' counts as valid for some reason

            # make_password() - n/a

            # check_password() - error
            self.assertRaises(ValueError, check_password, PASS1, hash)

            # identify_hasher() - error
            if has_django14 and patched:
                self.assertRaises(ValueError, identify_hasher, hash)

        #=======================================================
        # run through all the schemes in the context,
        # testing various bits of per-scheme behavior.
        #=======================================================
        for scheme in ctx.schemes():
            #-------------------------------------------------------
            # setup constants & imports, pick a sample secret/hash combo
            #-------------------------------------------------------
            handler = ctx.handler(scheme)
            deprecated = ctx._is_deprecated_scheme(scheme)
            assert not deprecated or scheme != ctx.default_scheme()
            try:
                testcase = get_handler_case(scheme)
            except exc.MissingBackendError:
                assert scheme == "bcrypt"
                continue
            assert testcase.handler is handler
            if testcase.is_disabled_handler:
                continue
            if not has_active_backend(handler):
                assert scheme == "django_bcrypt"
                continue
            while True:
                secret, hash = testcase('setUp').get_sample_hash()
                if secret: # don't select blank passwords, special under django
                    break
            other = 'letmein'

            # User.set_password() - n/a

            #-------------------------------------------------------
            # User.check_password()+migration against known hash
            #-------------------------------------------------------
            user = FakeUser()
            user.password = hash

            # check against invalid password
            if has_django1 or patched:
                self.assertFalse(user.check_password(None))
            else:
                self.assertRaises(TypeError, user.check_password, None)
            ##self.assertFalse(user.check_password(''))
            self.assertFalse(user.check_password(other))
            self.assert_valid_password(user, hash)

            # check against valid password
            if has_django0 and isinstance(secret, unicode):
                secret = secret.encode("utf-8")
            self.assertTrue(user.check_password(secret))

            # check if it upgraded the hash
            needs_update = deprecated
            if needs_update:
                self.assertFalse(handler.identify(user.password))
                self.assertTrue(ctx.handler().verify(secret, user.password))
                self.assert_valid_password(user, saved=user.password)
            else:
                self.assert_valid_password(user, hash)

            # don't need to check rest for most deployments
            if TEST_MODE(max="default"):
                continue

            #-------------------------------------------------------
            # make_password() correctly selects algorithm
            #-------------------------------------------------------
            if has_django14:
                hash2 = make_password(secret, hasher=passlib_to_hasher_name(scheme))
                self.assertTrue(handler.verify(secret, hash2))

            #-------------------------------------------------------
            # check_password()+setter against known hash
            #-------------------------------------------------------
            if has_django14 or patched:
                # should call setter only if it needs_update
                self.assertTrue(check_password(secret, hash, setter=setter))
                self.assertEqual(setter.popstate(), [secret] if needs_update else [])

                # should not call setter
                self.assertFalse(check_password(other, hash, setter=setter))
                self.assertEqual(setter.popstate(), [])

                ### check preferred kwd is ignored (django 1.4 feature we don't support)
                ##self.assertTrue(check_password(secret, hash, setter=setter, preferred='fooey'))
                ##self.assertEqual(setter.popstate(), [secret])

            elif patched or scheme != "hex_md5":
                # django 1.3 never called check_password() for hex_md5
                self.assertTrue(check_password(secret, hash))
                self.assertFalse(check_password(other, hash))

            # TODO: get_hasher()

            #-------------------------------------------------------
            # identify_hasher() recognizes known hash
            #-------------------------------------------------------
            if has_django14 and patched:
                self.assertTrue(is_password_usable(hash))
                name = hasher_to_passlib_name(identify_hasher(hash).algorithm)
                self.assertEqual(name, scheme)

class ExtensionBehaviorTest(DjangoBehaviorTest):
    "test model to verify passlib.ext.django conforms to it"
    descriptionPrefix = "verify extension behavior"
    patched = True
    config = dict(
            schemes="sha256_crypt,md5_crypt,des_crypt",
            deprecated="des_crypt",
            )

    def setUp(self):
        super(ExtensionBehaviorTest, self).setUp()
        self.load_extension(PASSLIB_CONFIG=self.config)

class DjangoExtensionTest(_ExtensionTest):
    """test the ``passlib.ext.django`` plugin"""
    descriptionPrefix = "passlib.ext.django plugin"

    #===================================================================
    # monkeypatch testing
    #===================================================================
    def test_00_patch_control(self):
        "test set_django_password_context patch/unpatch"

        # check config="disabled"
        self.load_extension(PASSLIB_CONFIG="disabled", check=False)
        self.assert_unpatched()

        # check legacy config=None
        with self.assertWarningList("PASSLIB_CONFIG=None is deprecated"):
            self.load_extension(PASSLIB_CONFIG=None, check=False)
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
        # NOTE: this sets things up, and spot checks two methods,
        #       this should be enough to verify patch manager is working.
        # TODO: test unpatch behavior honors flag.

        # configure plugin to use sample context
        config = "[passlib]\nschemes=des_crypt\n"
        self.load_extension(PASSLIB_CONFIG=config)

        # setup helpers
        import django.contrib.auth.models as models
        from passlib.ext.django.models import _manager
        def dummy():
            pass

        # mess with User.set_password, make sure it's detected
        orig = models.User.set_password
        models.User.set_password = dummy
        with self.assertWarningList("another library has patched.*User\.set_password"):
            _manager.check_all()
        models.User.set_password = orig

        # mess with models.check_password, make sure it's detected
        orig = models.check_password
        models.check_password = dummy
        with self.assertWarningList("another library has patched.*models:check_password"):
            _manager.check_all()
        models.check_password = orig

    def test_02_handler_wrapper(self):
        "test Hasher-compatible handler wrappers"
        if not has_django14:
            raise self.skipTest("Django >= 1.4 not installed")
        from passlib.ext.django.utils import get_passlib_hasher
        from django.contrib.auth import hashers

        # should return native django hasher if available
        hasher = get_passlib_hasher("hex_md5")
        self.assertIsInstance(hasher, hashers.UnsaltedMD5PasswordHasher)

        hasher = get_passlib_hasher("django_bcrypt")
        self.assertIsInstance(hasher, hashers.BCryptPasswordHasher)

        # otherwise should return wrapper
        from passlib.hash import sha256_crypt
        hasher = get_passlib_hasher("sha256_crypt")
        self.assertEqual(hasher.algorithm, "passlib_sha256_crypt")

        # and wrapper should return correct hash
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

    #===================================================================
    # PASSLIB_CONFIG settings
    #===================================================================
    def test_11_config_disabled(self):
        "test PASSLIB_CONFIG='disabled'"
        # test config=None (deprecated)
        with self.assertWarningList("PASSLIB_CONFIG=None is deprecated"):
            self.load_extension(PASSLIB_CONFIG=None, check=False)
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
        self.assert_patched(PASSLIB_DEFAULT)

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

        self.unload_extension()
        update_settings(PASSLIB_CONFIG="missing-preset", PASSLIB_CONTEXT=UNSET)
        self.assertRaises(ValueError, __import__, 'passlib.ext.django.models')

    #===================================================================
    # PASSLIB_GET_CATEGORY setting
    #===================================================================
    def test_21_category_setting(self):
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

        # test bad value
        self.assertRaises(TypeError, self.load_extension, PASSLIB_CONTEXT=config,
                          PASSLIB_GET_CATEGORY='x')

    #===================================================================
    # eoc
    #===================================================================

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
    del _TestHashers

    HashersTest = skipUnless(TEST_MODE("default"),
                             "requires >= 'default' test mode")(HashersTest)

#=============================================================================
# eof
#=============================================================================
