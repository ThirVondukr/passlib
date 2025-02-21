import hashlib
from binascii import hexlify
from unittest import skipUnless

import pytest

from passlib.crypto.digest import clear_lookup_hash_cache, lookup_hash

# site
# pkg
# module
from passlib.utils.compat import bascii_to_str
from tests.utils import TestCase

# local
__all__ = [
    "_Common_MD4_Test",
    "MD4_Builtin_Test",
    "MD4_SSL_Test",
]


class _Common_MD4_Test(TestCase):
    """common code for testing md4 backends"""

    vectors = [
        # input -> hex digest
        # test vectors from http://www.faqs.org/rfcs/rfc1320.html - A.5
        (b"", "31d6cfe0d16ae931b73c59d7e0c089c0"),
        (b"a", "bde52cb31de33e46245e05fbdbd6fb24"),
        (b"abc", "a448017aaf21d8525fc10ae87aa6729d"),
        (b"message digest", "d9130a8164549fe818874806e1c7014b"),
        (b"abcdefghijklmnopqrstuvwxyz", "d79e1c308aa5bbcdeea8ed63df412da9"),
        (
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
            "043f8582f241db351ce627e153e7f0e4",
        ),
        (
            b"12345678901234567890123456789012345678901234567890123456789012345678901234567890",
            "e33b4ddc9c38f2199c3e7b164fcc0536",
        ),
    ]

    def get_md4_const(self):
        """
        get md4 constructor --
        overridden by subclasses to use alternate backends.
        """
        return lookup_hash("md4").const

    def test_attrs(self):
        """informational attributes"""
        h = self.get_md4_const()()
        assert h.name == "md4"
        assert h.digest_size == 16
        assert h.block_size == 64

    def test_md4_update(self):
        """update() method"""
        md4 = self.get_md4_const()
        h = md4(b"")
        assert h.hexdigest() == "31d6cfe0d16ae931b73c59d7e0c089c0"

        h.update(b"a")
        assert h.hexdigest() == "bde52cb31de33e46245e05fbdbd6fb24"

        h.update(b"bcdefghijklmnopqrstuvwxyz")
        assert h.hexdigest() == "d79e1c308aa5bbcdeea8ed63df412da9"

        # reject unicode, hash should return digest of b''
        h = md4()
        with pytest.raises(TypeError):
            h.update("a")
        assert h.hexdigest() == "31d6cfe0d16ae931b73c59d7e0c089c0"

    def test_md4_hexdigest(self):
        """hexdigest() method"""
        md4 = self.get_md4_const()
        for input, hex in self.vectors:
            out = md4(input).hexdigest()
            assert out == hex

    def test_md4_digest(self):
        """digest() method"""
        md4 = self.get_md4_const()
        for input, hex in self.vectors:
            out = bascii_to_str(hexlify(md4(input).digest()))
            assert out == hex

    def test_md4_copy(self):
        """copy() method"""
        md4 = self.get_md4_const()
        h = md4(b"abc")

        h2 = h.copy()
        h2.update(b"def")
        assert h2.hexdigest() == "804e7f1c2586e50b49ac65db5b645131"

        h.update(b"ghi")
        assert h.hexdigest() == "c5225580bfe176f6deeee33dee98732c"


# ------------------------------------------------------------------------
# create subclasses to test various backends
# ------------------------------------------------------------------------


def has_native_md4():  # pragma: no cover -- runtime detection
    """
    check if hashlib natively supports md4.
    """
    try:
        hashlib.new("md4")
        return True
    except ValueError:
        # not supported - ssl probably missing (e.g. ironpython)
        return False


@skipUnless(has_native_md4(), "hashlib lacks ssl/md4 support")
class MD4_SSL_Test(_Common_MD4_Test):
    descriptionPrefix = "hashlib.new('md4')"

    # NOTE: we trust ssl got md4 implementation right,
    #       this is more to test our test is correct :)

    def setUp(self):
        super().setUp()

        # make sure we're using right constructor.
        assert self.get_md4_const().__module__ == "hashlib"


class MD4_Builtin_Test(_Common_MD4_Test):
    descriptionPrefix = "passlib.crypto._md4.md4()"

    def setUp(self):
        super().setUp()

        if has_native_md4():
            # Temporarily make lookup_hash() use builtin pure-python implementation,
            # by monkeypatching hashlib.new() to ensure we fall back to passlib's md4 class.
            orig = hashlib.new

            def wrapper(name, *args):
                if name == "md4":
                    raise ValueError("md4 disabled for testing")
                return orig(name, *args)

            self.patchAttr(hashlib, "new", wrapper)

            # flush cache before & after test, since we're mucking with it.
            clear_lookup_hash_cache()
            self.addCleanup(clear_lookup_hash_cache)

        # make sure we're using right constructor.
        assert self.get_md4_const().__module__ == "passlib.crypto._md4"
