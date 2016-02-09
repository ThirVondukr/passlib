"""test passlib.ext.django"""
#=============================================================================
# imports
#=============================================================================
# NOTE: double __future__ is workaround for py2.5.0 bug, 
#       per https://bitbucket.org/ecollins/passlib/issues/58#comment-20589295
from __future__ import with_statement
from __future__ import absolute_import
# core
import logging; log = logging.getLogger(__name__)
import sys
# site
# pkg
from passlib.apps import django10_context, django14_context, django16_context
from passlib.context import CryptContext
import passlib.exc as exc
from passlib.utils.compat import iteritems, unicode, get_method_function, u, PY3
from passlib.utils import memoized_property
# tests
from passlib.tests.utils import TestCase, skipUnless, TEST_MODE, has_active_backend
from passlib.tests.test_handlers import get_handler_case
# local

#=============================================================================
# configure django settings for testcases
#=============================================================================
from passlib.ext.django.utils import DJANGO_VERSION, MIN_DJANGO_VERSION

# whether we have supported django version
has_min_django = DJANGO_VERSION >= MIN_DJANGO_VERSION

# import and configure empty django settings
# NOTE: we don't want to set up entirety of django, so not using django.setup() directly.
#       instead, manually configuring the settings, and setting it up w/ no apps installed.
#       in future, may need to alter this so we call django.setup() after setting
#       DJANGO_SETTINGS_MODULE to a custom settings module w/ a dummy django app.
if has_min_django:
    #
    # initialize django settings manually
    #
    from django.conf import settings, LazySettings

    if not isinstance(settings, LazySettings):
        # this probably means django globals have been configured already,
        # which we don't want, since test cases reset and manipulate settings.
        raise RuntimeError("expected django.conf.settings to be LazySettings: %r" % (settings,))

    # else configure a blank settings instance for the unittests
    if not settings.configured:
        settings.configure()

    #
    # init django apps w/ NO installed apps.
    # NOTE: required for django >= 1.9, not compatible with django <= 1.6
    #
    if DJANGO_VERSION >= (1,7):
        from django.apps import apps
        apps.populate(["django.contrib.contenttypes", "django.contrib.auth"])

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
                delattr(settings, k)
        else:
            setattr(settings, k, v)

if has_min_django:
    from django.contrib.auth.models import User

    class FakeUser(User):
        """mock user object for use in testing"""
        # NOTE: this mainly just overrides .save() to test commit behavior.

        # NOTE: .Meta.app_label required for django >= 1.9, ignored for <= 1.6
        class Meta:
            app_label = __name__

        @memoized_property
        def saved_passwords(self):
            return []

        def pop_saved_passwords(self):
            try:
                return self.saved_passwords[:]
            finally:
                del self.saved_passwords[:]

        def save(self, update_fields=None):
            # NOTE: ignoring update_fields for test purposes
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

# build config dict that matches stock django
# TODO: move these to passlib.apps
if DJANGO_VERSION >= (1, 9):
    stock_rounds = 24000
elif DJANGO_VERSION >= (1, 8):
    stock_rounds = 20000
elif DJANGO_VERSION >= (1, 7):
    stock_rounds = 15000
else:  # 1.6
    stock_rounds = 12000

stock_config = django16_context.to_dict()
stock_config.update(
    deprecated="auto",
    django_pbkdf2_sha1__default_rounds=stock_rounds,
    django_pbkdf2_sha256__default_rounds=stock_rounds,
)

# override sample hashes used in test cases
from passlib.hash import django_pbkdf2_sha256
sample_hashes = dict(
    django_pbkdf2_sha256=("not a password", django_pbkdf2_sha256.encrypt("not a password",
                                 rounds=stock_config.get("django_pbkdf2_sha256__default_rounds")))
)

#=============================================================================
# test utils
#=============================================================================
class _ExtensionSupport(object):
    """support funcs for loading/unloading extension"""
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
        from django.contrib.auth import models, hashers
        user_attrs = ["check_password", "set_password"]
        model_attrs = ["check_password", "make_password"]
        hasher_attrs = ["check_password", "make_password", "get_hasher", "identify_hasher"]
        if DJANGO_VERSION >= (1,8):
            hasher_attrs.extend(["get_hashers"])
        objs = [(models, model_attrs),
                (models.User, user_attrs),
                (hashers, hasher_attrs),
        ]
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
        """test that django is in unpatched state"""
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
        """helper to ensure django HAS been patched, and is using specified config"""
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
        """helper to load extension with specified config & patch django"""
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
        """helper to remove patches and unload extension"""
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

# XXX: rename to ExtensionFixture?
class _ExtensionTest(TestCase, _ExtensionSupport):

    def setUp(self):
        super(_ExtensionTest, self).setUp()

        self.require_TEST_MODE("default")

        if not DJANGO_VERSION:
            raise self.skipTest("Django not installed")
        elif not has_min_django:
            raise self.skipTest("Django version too old")

        # reset to baseline, and verify it worked
        self.unload_extension()

        # and do the same when the test exits
        self.addCleanup(self.unload_extension)

#=============================================================================
# extension tests
#=============================================================================
class DjangoBehaviorTest(_ExtensionTest):
    """tests model to verify it matches django's behavior"""
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
        """check that user object is set to 'unusable password' constant"""
        self.assertTrue(user.password.startswith("!"))
        self.assertFalse(user.has_usable_password())
        self.assertEqual(user.pop_saved_passwords(), [])

    def assert_valid_password(self, user, hash=UNSET, saved=None):
        """check that user object has a usuable password hash.

        :param hash: optionally check it has this exact hash
        :param saved: check that mock commit history
                      for user.password matches this list
        """
        if hash is UNSET:
            self.assertNotEqual(user.password, "!")
            self.assertNotEqual(user.password, None)
        else:
            self.assertEqual(user.password, hash)
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

        has_identify_hasher = False
        from passlib.ext.django.utils import hasher_to_passlib_name, passlib_to_hasher_name
        from django.contrib.auth.hashers import check_password, make_password, is_password_usable
        # identify_hasher()
        #   django 1.4 -- not present
        #   django 1.5 -- present (added in django ticket 18184)
        #   passlib integration -- present even under 1.4
        from django.contrib.auth.hashers import identify_hasher
        has_identify_hasher = True

        #=======================================================
        # make sure extension is configured correctly
        #=======================================================
        if patched:
            # contexts should match
            from passlib.ext.django.models import password_context
            self.assertEqual(password_context.to_dict(resolve=True),
                             ctx.to_dict(resolve=True))

            # should have patched both places
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
        hash = make_password(PASS1)
        self.assertTrue(ctx.handler().verify(PASS1, hash))

        # check_password() - n/a

        #=======================================================
        # empty password behavior
        #=======================================================

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

        # sanity check via user.set_unusable_password()
        user = FakeUser()
        user.set_unusable_password()
        self.assert_unusable_password(user)

        # ensure User.set_password() sets unusable flag
        user = FakeUser()
        user.set_password(None)
        self.assert_unusable_password(user)

        # User.check_password() should always fail
        self.assertFalse(user.check_password(None))
        self.assertFalse(user.check_password('None'))
        self.assertFalse(user.check_password(''))
        self.assertFalse(user.check_password(PASS1))
        self.assertFalse(user.check_password(WRONG1))
        self.assert_unusable_password(user)

        # make_password() should also set flag
        self.assertTrue(make_password(None).startswith("!"))

        # check_password() should return False (didn't handle disabled under 1.3)
        self.assertFalse(check_password(PASS1, '!'))

        # identify_hasher() and is_password_usable() should reject it
        self.assertFalse(is_password_usable(user.password))
        if has_identify_hasher:
            self.assertRaises(ValueError, identify_hasher, user.password)

        #=======================================================
        # hash=None
        #=======================================================
        # User.set_password() - n/a

        # User.check_password() - returns False
        user = FakeUser()
        user.password = None
        self.assertFalse(user.check_password(PASS1))
        self.assertFalse(user.has_usable_password())

        # make_password() - n/a

        # check_password() - error
        self.assertFalse(check_password(PASS1, None))

        # identify_hasher() - error
        if has_identify_hasher:
            self.assertRaises(TypeError, identify_hasher, None)

        #=======================================================
        # empty & invalid hash values
        # NOTE: django 1.5 behavior change due to django ticket 18453
        # NOTE: passlib integration tries to match current django version
        #=======================================================
        for hash in ("", # empty hash
                     "$789$foo", # empty identifier
                     ):
            # User.set_password() - n/a

            # User.check_password()
            #   empty
            #   -----
            #   django 1.4 -- blank threw error (fixed in 1.5)
            #   django 1.5 -- blank hash returns False
            #
            #   invalid
            #   -------
            #   django 1.4 -- invalid hash threw error (fixed in 1.5)
            #   django 1.5 -- invalid hash returns False
            user = FakeUser()
            user.password = hash
            self.assertFalse(user.check_password(PASS1))

            # verify hash wasn't changed/upgraded during check_password() call
            self.assertEqual(user.password, hash)
            self.assertEqual(user.pop_saved_passwords(), [])

            # User.has_usable_password()
            self.assertFalse(user.has_usable_password())

            # make_password() - n/a

            # check_password()
            self.assertFalse(check_password(PASS1, hash))

            # identify_hasher() - throws error
            if has_identify_hasher:
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
                # TODO: move this above get_handler_case(),
                #       and omit MissingBackendError check.
                assert scheme in ["django_bcrypt", "django_bcrypt_sha256"], "%r scheme should always have active backend" % scheme
                continue
            try:
                secret, hash = sample_hashes[scheme]
            except KeyError:
                while True:
                    secret, hash = testcase('setUp').get_sample_hash()
                    if secret: # don't select blank passwords, especially under django 1.4/1.5
                        break
            other = 'dontletmein'

            # User.set_password() - n/a

            #-------------------------------------------------------
            # User.check_password()+migration against known hash
            #-------------------------------------------------------
            user = FakeUser()
            user.password = hash

            # check against invalid password
            self.assertFalse(user.check_password(None))
            ##self.assertFalse(user.check_password(''))
            self.assertFalse(user.check_password(other))
            self.assert_valid_password(user, hash)

            # check against valid password
            self.assertTrue(user.check_password(secret))

            # check if it upgraded the hash
            # NOTE: needs_update kept separate in case we need to test rounds.
            needs_update = deprecated
            if needs_update:
                self.assertNotEqual(user.password, hash)
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
            hash2 = make_password(secret, hasher=passlib_to_hasher_name(scheme))
            self.assertTrue(handler.verify(secret, hash2))

            #-------------------------------------------------------
            # check_password()+setter against known hash
            #-------------------------------------------------------
            # should call setter only if it needs_update
            self.assertTrue(check_password(secret, hash, setter=setter))
            self.assertEqual(setter.popstate(), [secret] if needs_update else [])

            # should not call setter
            self.assertFalse(check_password(other, hash, setter=setter))
            self.assertEqual(setter.popstate(), [])

            ### check preferred kwd is ignored (django 1.4 feature we don't support)
            ##self.assertTrue(check_password(secret, hash, setter=setter, preferred='fooey'))
            ##self.assertEqual(setter.popstate(), [secret])

            # TODO: get_hasher()

            #-------------------------------------------------------
            # identify_hasher() recognizes known hash
            #-------------------------------------------------------
            if has_identify_hasher:
                self.assertTrue(is_password_usable(hash))
                name = hasher_to_passlib_name(identify_hasher(hash).algorithm)
                self.assertEqual(name, scheme)

class ExtensionBehaviorTest(DjangoBehaviorTest):
    """test model to verify passlib.ext.django conforms to it"""
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
        """test set_django_password_context patch/unpatch"""

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
        """test detection of foreign monkeypatching"""
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
        """test Hasher-compatible handler wrappers"""
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
        encoded = hasher.encode("stub", "abcd"*4, rounds=1234)
        self.assertEqual(encoded, "$5$rounds=1234$abcdabcdabcdabcd$"
                                  "v2RWkZQzctPdejyRqmmTDQpZN6wTh7.RUy9zF2LftT6")
        self.assertEqual(hasher.safe_summary(encoded),
            {'algorithm': 'sha256_crypt',
             'salt': u('abcdab**********'),
             'rounds': 1234,
             'hash': u('v2RWkZ*************************************'),
             })

    #===================================================================
    # PASSLIB_CONFIG settings
    #===================================================================
    def test_11_config_disabled(self):
        """test PASSLIB_CONFIG='disabled'"""
        # test config=None (deprecated)
        with self.assertWarningList("PASSLIB_CONFIG=None is deprecated"):
            self.load_extension(PASSLIB_CONFIG=None, check=False)
        self.assert_unpatched()

        # test disabled config
        self.load_extension(PASSLIB_CONFIG="disabled", check=False)
        self.assert_unpatched()

    def test_12_config_presets(self):
        """test PASSLIB_CONFIG='<preset>'"""
        # test django presets
        self.load_extension(PASSLIB_CONTEXT="django-default", check=False)
        ctx = django16_context
        self.assert_patched(ctx)

        self.load_extension(PASSLIB_CONFIG="django-1.0", check=False)
        self.assert_patched(django10_context)

        self.load_extension(PASSLIB_CONFIG="django-1.4", check=False)
        self.assert_patched(django14_context)

    def test_13_config_defaults(self):
        """test PASSLIB_CONFIG default behavior"""
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
        """test PASSLIB_CONFIG type checks"""
        update_settings(PASSLIB_CONTEXT=123, PASSLIB_CONFIG=UNSET)
        self.assertRaises(TypeError, __import__, 'passlib.ext.django.models')

        self.unload_extension()
        update_settings(PASSLIB_CONFIG="missing-preset", PASSLIB_CONTEXT=UNSET)
        self.assertRaises(ValueError, __import__, 'passlib.ext.django.models')

    #===================================================================
    # PASSLIB_GET_CATEGORY setting
    #===================================================================
    def test_21_category_setting(self):
        """test PASSLIB_GET_CATEGORY parameter"""
        # define config where rounds can be used to detect category
        config = dict(
            schemes = ["sha256_crypt"],
            sha256_crypt__default_rounds = 1000,
            staff__sha256_crypt__default_rounds = 2000,
            superuser__sha256_crypt__default_rounds = 3000,
            )
        from passlib.hash import sha256_crypt

        def run(**kwds):
            """helper to take in user opts, return rounds used in password"""
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

#=============================================================================
# helpers for HashersTest below
#=============================================================================

from passlib.context import CryptContext
class ContextWithHook(CryptContext):
    """subclass which invokes update_hook(self) before major actions"""

    @staticmethod
    def update_hook(self):
        pass

    def encrypt(self, *args, **kwds):
        self.update_hook(self)
        return super(ContextWithHook, self).encrypt(*args, **kwds)

    def verify(self, *args, **kwds):
        self.update_hook(self)
        return super(ContextWithHook, self).verify(*args, **kwds)

    def needs_update(self, *args, **kwds):
        self.update_hook(self)
        return super(ContextWithHook, self).needs_update(*args, **kwds)

    def verify_and_update(self, *args, **kwds):
        self.update_hook(self)
        return super(ContextWithHook, self).verify_and_update(*args, **kwds)

#=============================================================================
# HashersTest --
# hack up the some of the real django tests to run w/ extension loaded,
# to ensure we mimic their behavior.
# however, the django tests were moved out of the package, and into a source-only location
# as of django 1.7. so we disable tests from that point on unless test-runner specifies
#=============================================================================

#
# try to load django's tests/auth_tests/test_hasher.py module,
# or note why we failed.
#

test_hashers_mod = None
hashers_skip_msg = None

if TEST_MODE(max="quick"):
    hashers_skip_msg = "requires >= 'default' test mode"

elif DJANGO_VERSION >= (1, 7):
    import os
    import sys
    source_path = os.environ.get("PASSLIB_TESTS_DJANGO_SOURCE_PATH")

    if source_path:
        if not os.path.exists(source_path):
            raise EnvironmentError("django source path not found: %r" % source_path)
        if not all(os.path.exists(os.path.join(source_path, name))
                   for name in ["django", "tests"]):
            raise EnvironmentError("invalid django source path: %r" % source_path)
        log.info("using django tests from source path: %r", source_path)
        tests_path = os.path.join(source_path, "tests")
        sys.path.insert(0, tests_path)
        from auth_tests import test_hashers as test_hashers_mod
        sys.path.remove(tests_path)

    else:
        hashers_skip_msg = "requires PASSLIB_TESTS_DJANGO_SOURCE_PATH to be set for django 1.7+"

elif DJANGO_VERSION >= (1, 6):
    from django.contrib.auth.tests import test_hashers as test_hashers_mod

elif DJANGO_VERSION:
    hashers_skip_msg = "django version too old"

else:
    hashers_skip_msg = "django not installed"

#
# if found module, create wrapper to run django's own tests w/ passlib monkeypatched in.
#
if test_hashers_mod:
    from passlib.utils.compat import get_unbound_method_function

    class HashersTest(test_hashers_mod.TestUtilsHashPass, _ExtensionSupport):
        """run django's hasher unittests against passlib's extension
        and workalike implementations"""

        # port patchAttr() helper method from passlib.tests.utils.TestCase
        patchAttr = get_unbound_method_function(TestCase.patchAttr)

        def setUp(self):
            #
            # install passlib.ext.django monkeypatches
            # NOTE: omitted orig setup, want to install our extension,
            #       and load hashers through it instead.
            #
            self.load_extension(PASSLIB_CONTEXT=stock_config, check=False)
            from passlib.ext.django.models import password_context
            from passlib.ext.django.utils import get_passlib_hasher

            #
            # update test module to use our versions of some hasher funcs
            #
            from django.contrib.auth import hashers
            for attr in ["make_password",
                         "check_password",
                         "identify_hasher",
                         "get_hasher"]:
                self.patchAttr(test_hashers_mod, attr, getattr(hashers, attr))

            #
            # django 1.4 tests expect empty django_des_crypt salt field
            #
            from passlib.hash import django_des_crypt
            self.patchAttr(django_des_crypt, "use_duplicate_salt", False)

            #
            # hack: need password_context to keep up to date with hasher.iterations
            #
            def update_hook(context):
                """called to sync hasher.rounds to crypt context before any operations"""
                for handler in context.schemes(resolve=True):
                    if 'rounds' not in handler.setting_kwds:
                        continue
                    hasher = get_passlib_hasher(handler, native_only=True)
                    if not hasher:
                        continue
                    rounds = getattr(hasher, "rounds", None) or \
                             getattr(hasher, "iterations", None)
                    if rounds is None:
                        continue
                    prefix = handler.name + "__"
                    context.update({prefix + "default_rounds": rounds,
                                    prefix + "min_rounds": rounds,
                                    prefix + "max_rounds": rounds})

            self.password_context = password_context
            self.patchAttr(password_context, "__class__", ContextWithHook)
            self.patchAttr(password_context, "update_hook", update_hook)

        # NOTE: omitting this test, since tries to reinitialize the hashers on top of our patch.
        test_pbkdf2_upgrade_new_hasher = lambda self: self.skipTest("omitted by passlib")

        def tearDown(self):
            self.unload_extension()
            super(HashersTest, self).tearDown()

else:
    # otherwise leave a stub so test log tells why test was skipped.

    class HashersTest(TestCase):

        def test_external_django_hasher_tests(self):
            """external django hasher tests"""
            raise self.skipTest(hashers_skip_msg)

#=============================================================================
# eof
#=============================================================================
