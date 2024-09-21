"""tests for passlib.hash -- (c) Assurance Technologies 2003-2009"""

# core
import sys
import warnings
from logging import getLogger

import pytest

import passlib.utils.handlers as uh

# site
# pkg
from passlib import exc, hash, registry
from passlib.registry import (
    _unload_handler_name as unload_handler_name,
)
from passlib.registry import (
    get_crypt_handler,
    list_crypt_handlers,
    register_crypt_handler,
    register_crypt_handler_path,
)
from tests.utils import TestCase

# module
log = getLogger(__name__)


# =============================================================================
# dummy handlers
#
# NOTE: these are defined outside of test case
#       since they're used by test_register_crypt_handler_path(),
#       which needs them to be available as module globals.
# =============================================================================
class dummy_0(uh.StaticHandler):
    name = "dummy_0"


class alt_dummy_0(uh.StaticHandler):
    name = "dummy_0"


dummy_x = 1


class RegistryTest(TestCase):
    descriptionPrefix = "passlib.registry"

    def setUp(self):
        super().setUp()

        # backup registry state & restore it after test.
        locations = dict(registry._locations)
        handlers = dict(registry._handlers)

        def restore():
            registry._locations.clear()
            registry._locations.update(locations)
            registry._handlers.clear()
            registry._handlers.update(handlers)

        self.addCleanup(restore)

    def test_hash_proxy(self):
        """test passlib.hash proxy object"""
        # check dir works
        dir(hash)

        # check repr works
        repr(hash)

        # check non-existent attrs raise error
        with pytest.raises(AttributeError):
            getattr(hash, "fooey")

        # GAE tries to set __loader__,
        # make sure that doesn't call register_crypt_handler.
        old = getattr(hash, "__loader__", None)
        test = object()
        hash.__loader__ = test
        assert hash.__loader__ is test
        if old is None:
            del hash.__loader__
            assert not hasattr(hash, "__loader__")
        else:
            hash.__loader__ = old
            assert hash.__loader__ is old

        # check storing attr calls register_crypt_handler
        class dummy_1(uh.StaticHandler):
            name = "dummy_1"

        hash.dummy_1 = dummy_1
        assert get_crypt_handler("dummy_1") is dummy_1

        # check storing under wrong name results in error
        with pytest.raises(ValueError):
            setattr(hash, "dummy_1x", dummy_1)

    def test_register_crypt_handler_path(self):
        """test register_crypt_handler_path()"""
        # NOTE: this messes w/ internals of registry, shouldn't be used publically.
        paths = registry._locations

        # check namespace is clear
        assert "dummy_0" not in paths
        assert not hasattr(hash, "dummy_0")

        # check invalid names are rejected
        with pytest.raises(ValueError):
            register_crypt_handler_path("dummy_0", ".test_registry")
        with pytest.raises(ValueError):
            register_crypt_handler_path(
                "dummy_0",
                __name__ + ":dummy_0:xxx",
            )
        with pytest.raises(ValueError):
            register_crypt_handler_path(
                "dummy_0",
                __name__ + ":dummy_0.xxx",
            )

        # try lazy load
        register_crypt_handler_path("dummy_0", __name__)
        assert "dummy_0" in list_crypt_handlers()
        assert "dummy_0" not in list_crypt_handlers(loaded_only=True)
        assert hash.dummy_0 is dummy_0
        assert "dummy_0" in list_crypt_handlers(loaded_only=True)
        unload_handler_name("dummy_0")

        # try lazy load w/ alt
        register_crypt_handler_path("dummy_0", __name__ + ":alt_dummy_0")
        assert hash.dummy_0 is alt_dummy_0
        unload_handler_name("dummy_0")

        # check lazy load w/ wrong type fails
        register_crypt_handler_path("dummy_x", __name__)
        with pytest.raises(TypeError):
            get_crypt_handler("dummy_x")

        # check lazy load w/ wrong name fails
        register_crypt_handler_path("alt_dummy_0", __name__)
        with pytest.raises(ValueError):
            get_crypt_handler("alt_dummy_0")
        unload_handler_name("alt_dummy_0")

        # TODO: check lazy load which calls register_crypt_handler (warning should be issued)

        sys.modules.pop("tests._test_bad_register", None)

        register_crypt_handler_path("dummy_bad", "tests._test_bad_register")
        with warnings.catch_warnings():
            warnings.filterwarnings("ignore", "xxxxxxxxxx", DeprecationWarning)
            h = get_crypt_handler("dummy_bad")
        from tests import _test_bad_register as tbr

        assert h is tbr.alt_dummy_bad

    def test_register_crypt_handler(self):
        """test register_crypt_handler()"""

        with pytest.raises(TypeError):
            register_crypt_handler({})

        with pytest.raises(ValueError):
            register_crypt_handler(
                type("x", (uh.StaticHandler,), dict(name=None)),
            )

        with pytest.raises(ValueError):
            register_crypt_handler(
                type("x", (uh.StaticHandler,), dict(name="AB_CD")),
            )

        with pytest.raises(ValueError):
            register_crypt_handler(
                type("x", (uh.StaticHandler,), dict(name="ab-cd")),
            )
        with pytest.raises(ValueError):
            register_crypt_handler(
                type("x", (uh.StaticHandler,), dict(name="ab__cd")),
            )
        with pytest.raises(ValueError):
            register_crypt_handler(
                type("x", (uh.StaticHandler,), dict(name="default")),
            )

        class dummy_1(uh.StaticHandler):
            name = "dummy_1"

        class dummy_1b(uh.StaticHandler):
            name = "dummy_1"

        assert "dummy_1" not in list_crypt_handlers()

        register_crypt_handler(dummy_1)
        register_crypt_handler(dummy_1)
        assert get_crypt_handler("dummy_1") is dummy_1

        with pytest.raises(KeyError):
            register_crypt_handler(dummy_1b)
        assert get_crypt_handler("dummy_1") is dummy_1

        register_crypt_handler(dummy_1b, force=True)
        assert get_crypt_handler("dummy_1") is dummy_1b

        assert "dummy_1" in list_crypt_handlers()

    def test_get_crypt_handler(self):
        """test get_crypt_handler()"""

        class dummy_1(uh.StaticHandler):
            name = "dummy_1"

        # without available handler
        with pytest.raises(KeyError):
            get_crypt_handler("dummy_1")
        assert get_crypt_handler("dummy_1", None) is None

        # already loaded handler
        register_crypt_handler(dummy_1)
        assert get_crypt_handler("dummy_1") is dummy_1

        with warnings.catch_warnings():
            warnings.filterwarnings(
                "ignore",
                "handler names should be lower-case, and use underscores instead of hyphens:.*",
                UserWarning,
            )

            # already loaded handler, using incorrect name
            assert get_crypt_handler("DUMMY-1") is dummy_1

            # lazy load of unloaded handler, using incorrect name
            register_crypt_handler_path("dummy_0", __name__)
            assert get_crypt_handler("DUMMY-0") is dummy_0

        # check system & private names aren't returned
        from passlib import hash

        hash.__dict__["_fake"] = "dummy"
        for name in ["_fake", "__package__"]:
            with pytest.raises(KeyError):
                get_crypt_handler(name)
            assert get_crypt_handler(name, None) is None

    def test_list_crypt_handlers(self):
        """test list_crypt_handlers()"""
        from passlib.registry import list_crypt_handlers

        # check system & private names aren't returned
        hash.__dict__["_fake"] = "dummy"
        for name in list_crypt_handlers():
            assert not name.startswith("_"), f"{name!r}: "
        unload_handler_name("_fake")

    def test_handlers(self):
        """verify we have tests for all builtin handlers"""
        from passlib.registry import list_crypt_handlers
        from tests.test_handlers import (
            conditionally_available_hashes,
            get_handler_case,
        )

        for name in list_crypt_handlers():
            # skip some wrappers that don't need independant testing
            if name.startswith("ldap_") and name[5:] in list_crypt_handlers():
                continue
            if name in ["roundup_plaintext"]:
                continue
            # check the remaining ones all have a handler
            try:
                assert get_handler_case(name)
            except exc.MissingBackendError:
                if (
                    name in conditionally_available_hashes
                ):  # expected to fail on some setups
                    continue
                raise
