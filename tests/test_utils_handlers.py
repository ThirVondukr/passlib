"""tests for passlib.hash -- (c) Assurance Technologies 2003-2009"""

import hashlib
import re
import warnings
from logging import getLogger

import pytest

import passlib.utils.handlers as uh
from passlib.exc import MissingBackendError
from passlib.hash import ldap_md5, sha256_crypt
from tests.utils import HandlerCase, TestCase
from tests.utils_ import no_warnings

# module
log = getLogger(__name__)


def _makelang(alphabet, size):
    """generate all strings of given size using alphabet"""

    def helper(size):
        if size < 2:
            for char in alphabet:
                yield char
        else:
            for char in alphabet:
                for tail in helper(size - 1):
                    yield char + tail

    return set(helper(size))


class SkeletonTest(TestCase):
    """test hash support classes"""

    def test_00_static_handler(self):
        """test StaticHandler class"""

        class d1(uh.StaticHandler):
            name = "d1"
            context_kwds = ("flag",)
            _hash_prefix = "_"
            checksum_chars = "ab"
            checksum_size = 1

            def __init__(self, flag=False, **kwds):
                super().__init__(**kwds)
                self.flag = flag

            def _calc_checksum(self, secret):
                return "b" if self.flag else "a"

        # check default identify method
        assert d1.identify("_a")
        assert d1.identify(b"_a")
        assert d1.identify("_b")

        assert not d1.identify("_c")
        assert not d1.identify(b"_c")
        assert not d1.identify("a")
        assert not d1.identify("b")
        assert not d1.identify("c")
        with pytest.raises(TypeError):
            d1.identify(None)
        with pytest.raises(TypeError):
            d1.identify(1)

        # check default genconfig method
        assert d1.genconfig() == d1.hash("")

        # check default verify method
        assert d1.verify("s", b"_a")
        assert d1.verify("s", "_a")
        assert not d1.verify("s", b"_b")
        assert not d1.verify("s", "_b")
        assert d1.verify("s", b"_b", flag=True)
        with pytest.raises(ValueError):
            d1.verify("s", b"_c")
        with pytest.raises(ValueError):
            d1.verify("s", "_c")

        # check default hash method
        assert d1.hash("s") == "_a"
        assert d1.hash("s", flag=True) == "_b"

    def test_10_identify(self):
        """test GenericHandler.identify()"""

        class d1(uh.GenericHandler):
            @classmethod
            def from_string(cls, hash):
                if isinstance(hash, bytes):
                    hash = hash.decode("ascii")
                if hash == "a":
                    return cls(checksum=hash)
                raise ValueError

        # check fallback
        with pytest.raises(TypeError):
            d1.identify(None)
        with pytest.raises(TypeError):
            d1.identify(1)
        assert not d1.identify("")
        assert d1.identify("a")
        assert not d1.identify("b")

        # check regexp
        d1._hash_regex = re.compile("@.")
        with pytest.raises(TypeError):
            d1.identify(None)
        with pytest.raises(TypeError):
            d1.identify(1)
        assert d1.identify("@a")
        assert not d1.identify("a")
        del d1._hash_regex

        # check ident-based
        d1.ident = "!"
        with pytest.raises(TypeError):
            d1.identify(None)
        with pytest.raises(TypeError):
            d1.identify(1)
        assert d1.identify("!a")
        assert not d1.identify("a")
        del d1.ident

    def test_11_norm_checksum(self):
        """test GenericHandler checksum handling"""

        # setup helpers
        class d1(uh.GenericHandler):
            name = "d1"
            checksum_size = 4
            checksum_chars = "xz"

        def norm_checksum(checksum=None, **k):
            return d1(checksum=checksum, **k).checksum

        # too small
        with pytest.raises(ValueError):
            norm_checksum("xxx")

        # right size
        assert norm_checksum("xxxx") == "xxxx"
        assert norm_checksum("xzxz") == "xzxz"

        # too large
        with pytest.raises(ValueError):
            norm_checksum("xxxxx")

        # wrong chars
        with pytest.raises(ValueError):
            norm_checksum("xxyx")

        # wrong type
        with pytest.raises(TypeError):
            norm_checksum(b"xxyx")

        # relaxed
        # NOTE: this could be turned back on if we test _norm_checksum() directly...
        # with self.assertWarningList("checksum should be str"):
        #    self.assertEqual(norm_checksum(b'xxzx', relaxed=True), u'xxzx')
        # self.assertRaises(TypeError, norm_checksum, 1, relaxed=True)

        # test _stub_checksum behavior
        assert d1()._stub_checksum == "xxxx"

    def test_12_norm_checksum_raw(self):
        """test GenericHandler + HasRawChecksum mixin"""

        class d1(uh.HasRawChecksum, uh.GenericHandler):
            name = "d1"
            checksum_size = 4

        def norm_checksum(*a, **k):
            return d1(*a, **k).checksum

        # test bytes
        assert norm_checksum(b"1234") == b"1234"

        # test str
        with pytest.raises(TypeError):
            norm_checksum("xxyx")

        # NOTE: this could be turned back on if we test _norm_checksum() directly...
        # self.assertRaises(TypeError, norm_checksum, u'xxyx', relaxed=True)

        # test _stub_checksum behavior
        assert d1()._stub_checksum == b"\x00" * 4

    def test_20_norm_salt(self):
        """test GenericHandler + HasSalt mixin"""

        # setup helpers
        class d1(uh.HasSalt, uh.GenericHandler):
            name = "d1"
            setting_kwds = ("salt",)
            min_salt_size = 2
            max_salt_size = 4
            default_salt_size = 3
            salt_chars = "ab"

        def norm_salt(**k):
            return d1(**k).salt

        def gen_salt(sz, **k):
            return d1.using(salt_size=sz, **k)(use_defaults=True).salt

        salts2 = _makelang("ab", 2)
        salts3 = _makelang("ab", 3)
        salts4 = _makelang("ab", 4)

        # check salt=None
        with pytest.raises(TypeError):
            norm_salt()
        with pytest.raises(TypeError):
            norm_salt(salt=None)
        assert norm_salt(use_defaults=True) in salts3

        # check explicit salts
        with no_warnings():
            # check too-small salts
            with pytest.raises(ValueError):
                norm_salt(salt="")
            with pytest.raises(ValueError):
                norm_salt(salt="a")

            # check correct salts
            assert norm_salt(salt="ab") == "ab"
            assert norm_salt(salt="aba") == "aba"
            assert norm_salt(salt="abba") == "abba"

            # check too-large salts
            with pytest.raises(ValueError):
                norm_salt(salt="aaaabb")

        # check generated salts
        with no_warnings():
            # check too-small salt size
            with pytest.raises(ValueError):
                gen_salt(0)
            with pytest.raises(ValueError):
                gen_salt(1)

            # check correct salt size
            assert gen_salt(2) in salts2
            assert gen_salt(3) in salts3
            assert gen_salt(4) in salts4

            # check too-large salt size
            with pytest.raises(ValueError):
                gen_salt(5)

        with pytest.warns(match="salt_size.*above max_salt_size"):
            assert gen_salt(5, relaxed=True) in salts4

        # test with max_salt_size=None
        del d1.max_salt_size
        with no_warnings():
            assert len(gen_salt(None)) == 3
            assert len(gen_salt(5)) == 5

    # TODO: test HasRawSalt mixin

    def test_30_init_rounds(self):
        """test GenericHandler + HasRounds mixin"""

        # setup helpers
        class d1(uh.HasRounds, uh.GenericHandler):
            name = "d1"
            setting_kwds = ("rounds",)
            min_rounds = 1
            max_rounds = 3
            default_rounds = 2

        # NOTE: really is testing _init_rounds(), could dup to test _norm_rounds() via .replace
        def norm_rounds(**k):
            return d1(**k).rounds

        # check rounds=None
        with pytest.raises(TypeError):
            norm_rounds()
        with pytest.raises(TypeError):
            norm_rounds(rounds=None)
        assert norm_rounds(use_defaults=True) == 2

        # check rounds=non int
        with pytest.raises(TypeError):
            norm_rounds(rounds=1.5)

        # check explicit rounds
        with no_warnings():
            # too small
            with pytest.raises(ValueError):
                norm_rounds(rounds=0)

            # just right
            assert norm_rounds(rounds=1) == 1
            assert norm_rounds(rounds=2) == 2
            assert norm_rounds(rounds=3) == 3

            # too large
            with pytest.raises(ValueError):
                norm_rounds(rounds=4)

        # check no default rounds
        d1.default_rounds = None
        with pytest.raises(TypeError):
            norm_rounds(use_defaults=True)

    def test_40_backends(self):
        """test GenericHandler + HasManyBackends mixin"""

        class d1(uh.HasManyBackends, uh.GenericHandler):
            name = "d1"
            setting_kwds = ()

            backends = ("a", "b")

            _enable_a = False
            _enable_b = False

            @classmethod
            def _load_backend_a(cls):
                if cls._enable_a:
                    cls._set_calc_checksum_backend(cls._calc_checksum_a)
                    return True
                return False

            @classmethod
            def _load_backend_b(cls):
                if cls._enable_b:
                    cls._set_calc_checksum_backend(cls._calc_checksum_b)
                    return True
                return False

            def _calc_checksum_a(self, secret):
                return "a"

            def _calc_checksum_b(self, secret):
                return "b"

        # test no backends
        with pytest.raises(MissingBackendError):
            d1.get_backend()
        with pytest.raises(MissingBackendError):
            d1.set_backend()
        with pytest.raises(MissingBackendError):
            d1.set_backend("any")
        with pytest.raises(MissingBackendError):
            d1.set_backend("default")
        assert not d1.has_backend()

        # enable 'b' backend
        d1._enable_b = True

        # test lazy load
        obj = d1()
        assert obj._calc_checksum("s") == "b"

        # test repeat load
        d1.set_backend("b")
        d1.set_backend("any")
        assert obj._calc_checksum("s") == "b"

        # test unavailable
        with pytest.raises(MissingBackendError):
            d1.set_backend("a")
        assert d1.has_backend("b")
        assert not d1.has_backend("a")

        # enable 'a' backend also
        d1._enable_a = True

        # test explicit
        assert d1.has_backend()
        d1.set_backend("a")
        assert obj._calc_checksum("s") == "a"

        # test unknown backend
        with pytest.raises(ValueError):
            d1.set_backend("c")
        with pytest.raises(ValueError):
            d1.has_backend("c")

        # test error thrown if _has & _load are mixed
        d1.set_backend("b")  # switch away from 'a' so next call actually checks loader

        class d2(d1):
            _has_backend_a = True

        with pytest.raises(AssertionError):
            d2.has_backend("a")

    def test_41_backends(self):
        """test GenericHandler + HasManyBackends mixin (deprecated api)"""
        warnings.filterwarnings(
            "ignore",
            category=DeprecationWarning,
            message=r".* support for \._has_backend_.* is deprecated.*",
        )

        class d1(uh.HasManyBackends, uh.GenericHandler):
            name = "d1"
            setting_kwds = ()

            backends = ("a", "b")

            _has_backend_a = False
            _has_backend_b = False

            def _calc_checksum_a(self, secret):
                return "a"

            def _calc_checksum_b(self, secret):
                return "b"

        # test no backends
        with pytest.raises(MissingBackendError):
            d1.get_backend()
        with pytest.raises(MissingBackendError):
            d1.set_backend()
        with pytest.raises(MissingBackendError):
            d1.set_backend("any")
        with pytest.raises(MissingBackendError):
            d1.set_backend("default")
        assert not d1.has_backend()

        # enable 'b' backend
        d1._has_backend_b = True

        # test lazy load
        obj = d1()
        assert obj._calc_checksum("s") == "b"

        # test repeat load
        d1.set_backend("b")
        d1.set_backend("any")
        assert obj._calc_checksum("s") == "b"

        # test unavailable
        with pytest.raises(MissingBackendError):
            d1.set_backend("a")
        assert d1.has_backend("b")
        assert not d1.has_backend("a")

        # enable 'a' backend also
        d1._has_backend_a = True

        # test explicit
        assert d1.has_backend()
        d1.set_backend("a")
        assert obj._calc_checksum("s") == "a"

        # test unknown backend
        with pytest.raises(ValueError):
            d1.set_backend("c")
        with pytest.raises(ValueError):
            d1.has_backend("c")

    def test_50_norm_ident(self):
        """test GenericHandler + HasManyIdents"""

        # setup helpers
        class d1(uh.HasManyIdents, uh.GenericHandler):
            name = "d1"
            setting_kwds = ("ident",)
            default_ident = "!A"
            ident_values = ("!A", "!B")
            ident_aliases = {"A": "!A"}

        def norm_ident(**k):
            return d1(**k).ident

        # check ident=None
        with pytest.raises(TypeError):
            norm_ident()
        with pytest.raises(TypeError):
            norm_ident(ident=None)
        assert norm_ident(use_defaults=True) == "!A"

        # check valid idents
        assert norm_ident(ident="!A") == "!A"
        assert norm_ident(ident="!B") == "!B"
        with pytest.raises(ValueError):
            norm_ident(ident="!C")

        # check aliases
        assert norm_ident(ident="A") == "!A"

        # check invalid idents
        with pytest.raises(ValueError):
            norm_ident(ident="B")

        # check identify is honoring ident system
        assert d1.identify("!Axxx")
        assert d1.identify("!Bxxx")
        assert not d1.identify("!Cxxx")
        assert not d1.identify("A")
        assert not d1.identify("")
        with pytest.raises(TypeError):
            d1.identify(None)
        with pytest.raises(TypeError):
            d1.identify(1)

        # check default_ident missing is detected.
        d1.default_ident = None
        with pytest.raises(AssertionError):
            norm_ident(use_defaults=True)

    # ===================================================================
    # experimental - the following methods are not finished or tested,
    # but way work correctly for some hashes
    # ===================================================================
    def test_91_parsehash(self):
        """test parsehash()"""
        # NOTE: this just tests some existing GenericHandler classes
        from passlib import hash

        #
        # parsehash()
        #

        # simple hash w/ salt
        result = hash.des_crypt.parsehash("OgAwTx2l6NADI")
        assert result == {"checksum": "AwTx2l6NADI", "salt": "Og"}

        # parse rounds and extra implicit_rounds flag
        h = "$5$LKO/Ute40T3FNF95$U0prpBQd4PloSGU0pnpM4z9wKn4vZ1.jsrzQfPqxph9"
        s = "LKO/Ute40T3FNF95"
        c = "U0prpBQd4PloSGU0pnpM4z9wKn4vZ1.jsrzQfPqxph9"
        result = hash.sha256_crypt.parsehash(h)
        assert result == dict(salt=s, rounds=5000, implicit_rounds=True, checksum=c)

        # omit checksum
        result = hash.sha256_crypt.parsehash(h, checksum=False)
        assert result == dict(salt=s, rounds=5000, implicit_rounds=True)

        # sanitize
        result = hash.sha256_crypt.parsehash(h, sanitize=True)
        assert result == dict(
            rounds=5000,
            implicit_rounds=True,
            salt="LK**************",
            checksum="U0pr***************************************",
        )

        # parse w/o implicit rounds flag
        result = hash.sha256_crypt.parsehash(
            "$5$rounds=10428$uy/jIAhCetNCTtb0$YWvUOXbkqlqhyoPMpN8BMe.ZGsGx2aBvxTvDFI613c3"
        )
        assert result == dict(
            checksum="YWvUOXbkqlqhyoPMpN8BMe.ZGsGx2aBvxTvDFI613c3",
            salt="uy/jIAhCetNCTtb0",
            rounds=10428,
        )

        # parsing of raw checksums & salts
        h1 = "$pbkdf2$60000$DoEwpvQeA8B4T.k951yLUQ$O26Y3/NJEiLCVaOVPxGXshyjW8k"
        result = hash.pbkdf2_sha1.parsehash(h1)
        assert result == dict(
            checksum=b';n\x98\xdf\xf3I\x12"\xc2U\xa3\x95?\x11\x97\xb2\x1c\xa3[\xc9',
            rounds=60000,
            salt=b"\x0e\x810\xa6\xf4\x1e\x03\xc0xO\xe9=\xe7\\\x8bQ",
        )

        # sanitizing of raw checksums & salts
        result = hash.pbkdf2_sha1.parsehash(h1, sanitize=True)
        assert result == dict(
            checksum="O26************************",
            rounds=60000,
            salt="Do********************",
        )

    def test_92_bitsize(self):
        """test bitsize()"""
        # NOTE: this just tests some existing GenericHandler classes
        from passlib import hash

        # no rounds
        assert hash.des_crypt.bitsize() == {"checksum": 66, "salt": 12}

        # log2 rounds
        assert hash.bcrypt.bitsize() == {"checksum": 186, "salt": 132}

        # linear rounds
        # NOTE: +3 comes from int(math.log(.1,2)),
        #       where 0.1 = 10% = default allowed variation in rounds
        self.patchAttr(hash.sha256_crypt, "default_rounds", 1 << (14 + 3))
        assert hash.sha256_crypt.bitsize() == {
            "checksum": 258,
            "rounds": 14,
            "salt": 96,
        }

        # raw checksum
        self.patchAttr(hash.pbkdf2_sha1, "default_rounds", 1 << (13 + 3))
        assert hash.pbkdf2_sha1.bitsize() == {
            "checksum": 160,
            "rounds": 13,
            "salt": 128,
        }

        # TODO: handle fshp correctly, and other glitches noted in code.
        ##self.assertEqual(hash.fshp.bitsize(variant=1),
        ##                {'checksum': 256, 'rounds': 13, 'salt': 128})


class dummy_handler_in_registry:
    """context manager that inserts dummy handler in registry"""

    def __init__(self, name):
        self.name = name
        self.dummy = type(
            "dummy_" + name,
            (uh.GenericHandler,),
            dict(
                name=name,
                setting_kwds=(),
            ),
        )

    def __enter__(self):
        from passlib import registry

        registry._unload_handler_name(self.name, locations=False)
        registry.register_crypt_handler(self.dummy)
        assert registry.get_crypt_handler(self.name) is self.dummy
        return self.dummy

    def __exit__(self, *exc_info):
        from passlib import registry

        registry._unload_handler_name(self.name, locations=False)


class PrefixWrapperTest(TestCase):
    """test PrefixWrapper class"""

    def test_00_lazy_loading(self):
        """test PrefixWrapper lazy loading of handler"""
        d1 = uh.PrefixWrapper("d1", "ldap_md5", "{XXX}", "{MD5}", lazy=True)

        # check base state
        assert d1._wrapped_name == "ldap_md5"
        assert d1._wrapped_handler is None

        # check loading works
        assert d1.wrapped is ldap_md5
        assert d1._wrapped_handler is ldap_md5

        # replace w/ wrong handler, make sure doesn't reload w/ dummy
        with dummy_handler_in_registry("ldap_md5"):
            assert d1.wrapped is ldap_md5

    def test_01_active_loading(self):
        """test PrefixWrapper active loading of handler"""
        d1 = uh.PrefixWrapper("d1", "ldap_md5", "{XXX}", "{MD5}")

        # check base state
        assert d1._wrapped_name == "ldap_md5"
        assert d1._wrapped_handler is ldap_md5
        assert d1.wrapped is ldap_md5

        # replace w/ wrong handler, make sure doesn't reload w/ dummy
        with dummy_handler_in_registry("ldap_md5"):
            assert d1.wrapped is ldap_md5

    def test_02_explicit(self):
        """test PrefixWrapper with explicitly specified handler"""

        d1 = uh.PrefixWrapper("d1", ldap_md5, "{XXX}", "{MD5}")

        # check base state
        assert d1._wrapped_name is None
        assert d1._wrapped_handler is ldap_md5
        assert d1.wrapped is ldap_md5

        # replace w/ wrong handler, make sure doesn't reload w/ dummy
        with dummy_handler_in_registry("ldap_md5"):
            assert d1.wrapped is ldap_md5

    def test_10_wrapped_attributes(self):
        d1 = uh.PrefixWrapper("d1", "ldap_md5", "{XXX}", "{MD5}")
        assert d1.name == "d1"
        assert d1.setting_kwds is ldap_md5.setting_kwds
        assert "max_rounds" not in dir(d1)

        d2 = uh.PrefixWrapper("d2", "sha256_crypt", "{XXX}")
        assert d2.setting_kwds is sha256_crypt.setting_kwds
        assert "max_rounds" in dir(d2)

    def test_11_wrapped_methods(self):
        d1 = uh.PrefixWrapper("d1", "ldap_md5", "{XXX}", "{MD5}")
        dph = "{XXX}X03MO1qnZdYdgyfeuILPmQ=="
        lph = "{MD5}X03MO1qnZdYdgyfeuILPmQ=="

        # genconfig
        assert d1.genconfig() == "{XXX}1B2M2Y8AsgTpgAmY7PhCfg=="

        # genhash
        with pytest.raises(TypeError):
            d1.genhash("password", None)
        assert d1.genhash("password", dph) == dph
        with pytest.raises(ValueError):
            d1.genhash("password", lph)

        # hash
        assert d1.hash("password") == dph

        # identify
        assert d1.identify(dph)
        assert not d1.identify(lph)

        # verify
        with pytest.raises(ValueError):
            d1.verify("password", lph)
        assert d1.verify("password", dph)

    def test_12_ident(self):
        # test ident is proxied
        h = uh.PrefixWrapper("h2", "ldap_md5", "{XXX}")
        assert h.ident == "{XXX}{MD5}"
        assert h.ident_values is None

        # test lack of ident means no proxy
        h = uh.PrefixWrapper("h2", "des_crypt", "{XXX}")
        assert h.ident is None
        assert h.ident_values is None

        # test orig_prefix disabled ident proxy
        h = uh.PrefixWrapper("h1", "ldap_md5", "{XXX}", "{MD5}")
        assert h.ident is None
        assert h.ident_values is None

        # test custom ident overrides default
        h = uh.PrefixWrapper("h3", "ldap_md5", "{XXX}", ident="{X")
        assert h.ident == "{X"
        assert h.ident_values is None

        # test custom ident must match
        h = uh.PrefixWrapper("h3", "ldap_md5", "{XXX}", ident="{XXX}A")
        with pytest.raises(ValueError):
            uh.PrefixWrapper("h3", "ldap_md5", "{XXX}", ident="{XY")
        with pytest.raises(ValueError):
            uh.PrefixWrapper("h3", "ldap_md5", "{XXX}", ident="{XXXX")

        # test ident_values is proxied
        h = uh.PrefixWrapper("h4", "phpass", "{XXX}")
        assert h.ident is None
        assert h.ident_values == ("{XXX}$P$", "{XXX}$H$")

        # test ident=True means use prefix even if hash has no ident.
        h = uh.PrefixWrapper("h5", "des_crypt", "{XXX}", ident=True)
        assert h.ident == "{XXX}"
        assert h.ident_values is None

        # ... but requires prefix
        with pytest.raises(ValueError):
            uh.PrefixWrapper("h6", "des_crypt", ident=True)

        # orig_prefix + HasManyIdent - warning
        with pytest.warns(match="orig_prefix.*may not work correctly"):
            h = uh.PrefixWrapper("h7", "phpass", orig_prefix="$", prefix="?")
        assert h.ident_values is None  # TODO: should output (u"?P$", u"?H$"))
        assert h.ident is None

    def test_13_repr(self):
        """test repr()"""
        h = uh.PrefixWrapper("h2", "md5_crypt", "{XXX}", orig_prefix="$1$")
        assert re.search(
            "(?x)^PrefixWrapper\\(\n                ['\"]h2['\"],\\s+\n                ['\"]md5_crypt['\"],\\s+\n                prefix=u?[\"']{XXX}['\"],\\s+\n                orig_prefix=u?[\"']\\$1\\$['\"]\n            \\)$",
            repr(h),
        )

    def test_14_bad_hash(self):
        """test orig_prefix sanity check"""
        # shoudl throw InvalidHashError if wrapped hash doesn't begin
        # with orig_prefix.
        h = uh.PrefixWrapper("h2", "md5_crypt", orig_prefix="$6$")
        with pytest.raises(ValueError):
            h.hash("test")


# =============================================================================
# sample algorithms - these serve as known quantities
# to test the unittests themselves, as well as other
# parts of passlib. they shouldn't be used as actual password schemes.
# =============================================================================
class UnsaltedHash(uh.StaticHandler):
    """test algorithm which lacks a salt"""

    name = "unsalted_test_hash"
    checksum_chars = uh.LOWER_HEX_CHARS
    checksum_size = 40

    def _calc_checksum(self, secret):
        if isinstance(secret, str):
            secret = secret.encode("utf-8")
        data = b"boblious" + secret
        return hashlib.sha1(data).hexdigest()


class SaltedHash(uh.HasSalt, uh.GenericHandler):
    """test algorithm with a salt"""

    name = "salted_test_hash"
    setting_kwds = ("salt",)

    min_salt_size = 2
    max_salt_size = 4
    checksum_size = 40
    salt_chars = checksum_chars = uh.LOWER_HEX_CHARS

    _hash_regex = re.compile("^@salt[0-9a-f]{42,44}$")

    @classmethod
    def from_string(cls, hash):
        if not cls.identify(hash):
            raise uh.exc.InvalidHashError(cls)
        if isinstance(hash, bytes):
            hash = hash.decode("ascii")
        return cls(salt=hash[5:-40], checksum=hash[-40:])

    def to_string(self):
        return f"@salt{self.salt}{self.checksum}"

    def _calc_checksum(self, secret):
        if isinstance(secret, str):
            secret = secret.encode("utf-8")
        data = self.salt.encode("ascii") + secret + self.salt.encode("ascii")
        return hashlib.sha1(data).hexdigest()


# TODO: provide data samples for algorithms
#       (positive knowns, negative knowns, invalid identify)

UPASS_TEMP = "\u0399\u03c9\u03b1\u03bd\u03bd\u03b7\u03c2"


class UnsaltedHashTest(HandlerCase):
    handler = UnsaltedHash

    known_correct_hashes = [
        ("password", "61cfd32684c47de231f1f982c214e884133762c0"),
        (UPASS_TEMP, "96b329d120b97ff81ada770042e44ba87343ad2b"),
    ]

    def test_bad_kwds(self):
        with pytest.raises(TypeError):
            UnsaltedHash(salt="x")
        with pytest.raises(TypeError):
            UnsaltedHash.genconfig(rounds=1)


class SaltedHashTest(HandlerCase):
    handler = SaltedHash

    known_correct_hashes = [
        ("password", "@salt77d71f8fe74f314dac946766c1ac4a2a58365482c0"),
        (UPASS_TEMP, "@salt9f978a9bfe360d069b0c13f2afecd570447407fa7e48"),
    ]

    def test_bad_kwds(self):
        stub = SaltedHash(use_defaults=True)._stub_checksum
        with pytest.raises(TypeError):
            SaltedHash(checksum=stub, salt=None)
        with pytest.raises(ValueError):
            SaltedHash(checksum=stub, salt="xxx")
