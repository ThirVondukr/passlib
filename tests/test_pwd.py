import itertools

import pytest

from passlib.pwd import default_charsets, genphrase, genword
from tests.utils import TestCase

__all__ = [
    "UtilsTest",
]


class UtilsTest(TestCase):
    """test internal utilities"""

    descriptionPrefix = "passlib.pwd"

    def test_self_info_rate(self):
        """_self_info_rate()"""
        from passlib.pwd import _self_info_rate

        assert _self_info_rate("") == 0

        assert _self_info_rate("a" * 8) == 0

        assert _self_info_rate("ab") == 1
        assert _self_info_rate("ab" * 8) == 1

        assert _self_info_rate("abcd") == 2
        assert _self_info_rate("abcd" * 8) == 2
        assert _self_info_rate("abcdaaaa") == pytest.approx(1.5488, abs=1e-4)

        # def test_total_self_info(self):
        #     """_total_self_info()"""
        #     from passlib.pwd import _total_self_info
        #
        #     self.assertEqual(_total_self_info(""), 0)
        #
        #     self.assertEqual(_total_self_info("a" * 8), 0)
        #
        #     self.assertEqual(_total_self_info("ab"), 2)
        #     self.assertEqual(_total_self_info("ab" * 8), 16)
        #
        #     self.assertEqual(_total_self_info("abcd"), 8)
        #     self.assertEqual(_total_self_info("abcd" * 8), 64)
        #     self.assertAlmostEqual(_total_self_info("abcdaaaa"), 12.3904, places=4)


ascii_62 = default_charsets["ascii_62"]
hex = default_charsets["hex"]


class WordGeneratorTest(TestCase):
    """test generation routines"""

    descriptionPrefix = "passlib.pwd.genword()"

    def setUp(self):
        super().setUp()

        # patch some RNG references so they're reproducible.
        from passlib.pwd import SequenceGenerator

        self.patchAttr(SequenceGenerator, "rng", self.getRandom("pwd generator"))

    def assertResultContents(self, results, count, chars, unique=True):
        """check result list matches expected count & charset"""
        assert len(results) == count
        if unique:
            if unique is True:
                unique = count
            assert len(set(results)) == unique
        assert set("".join(results)) == set(chars)

    def test_general(self):
        """general behavior"""

        # basic usage
        result = genword()
        assert len(result) == 9

        # malformed keyword should have useful error.
        with pytest.raises(TypeError, match="(?i)unexpected keyword.*badkwd"):
            genword(badkwd=True)

    def test_returns(self):
        """'returns' keyword"""
        # returns=int option
        results = genword(returns=5000)
        self.assertResultContents(results, 5000, ascii_62)

        # returns=iter option
        gen = genword(returns=iter)
        results = [next(gen) for _ in range(5000)]

        self.assertResultContents(results, 5000, ascii_62)

        # invalid returns option
        with pytest.raises(TypeError):
            genword(returns="invalid-type")

    def test_charset(self):
        """'charset' & 'chars' options"""
        # charset option
        results = genword(charset="hex", returns=5000)
        self.assertResultContents(results, 5000, hex)

        # chars option
        # there are 3**3=27 possible combinations
        results = genword(length=3, chars="abc", returns=5000)
        self.assertResultContents(results, 5000, "abc", unique=27)

        # chars + charset
        with pytest.raises(TypeError):
            genword(chars="abc", charset="hex")

    # TODO: test rng option


simple_words = ["alpha", "beta", "gamma"]


class PhraseGeneratorTest(TestCase):
    """test generation routines"""

    descriptionPrefix = "passlib.pwd.genphrase()"

    def assertResultContents(self, results, count, words, unique=True, sep=" "):
        """check result list matches expected count & charset"""
        assert len(results) == count
        if unique:
            if unique is True:
                unique = count
            assert len(set(results)) == unique
        out = set(itertools.chain.from_iterable(elem.split(sep) for elem in results))
        assert out == set(words)

    def test_general(self):
        """general behavior"""

        # basic usage
        result = genphrase()
        assert len(result.split(" ")) == 4  # 48 / log(7776, 2) ~= 3.7 -> 4

        # malformed keyword should have useful error.
        with pytest.raises(TypeError, match="(?i)unexpected keyword.*badkwd"):
            genphrase(badkwd=True)

    def test_entropy(self):
        """'length' & 'entropy' keywords"""

        # custom entropy
        result = genphrase(entropy=70)
        assert len(result.split(" ")) == 6  # 70 / log(7776, 2) ~= 5.4 -> 6

        # custom length
        result = genphrase(length=3)
        assert len(result.split(" ")) == 3

        # custom length < entropy
        result = genphrase(length=3, entropy=48)
        assert len(result.split(" ")) == 4

        # custom length > entropy
        result = genphrase(length=4, entropy=12)
        assert len(result.split(" ")) == 4

    def test_returns(self):
        """'returns' keyword"""
        # returns=int option
        results = genphrase(returns=1000, words=simple_words)
        self.assertResultContents(results, 1000, simple_words)

        # returns=iter option
        gen = genphrase(returns=iter, words=simple_words)
        results = [next(gen) for _ in range(1000)]
        self.assertResultContents(results, 1000, simple_words)

        # invalid returns option
        with pytest.raises(TypeError):
            genphrase(returns="invalid-type")

    def test_wordset(self):
        """'wordset' & 'words' options"""
        # wordset option
        results = genphrase(words=simple_words, returns=5000)
        self.assertResultContents(results, 5000, simple_words)

        # words option
        results = genphrase(length=3, words=simple_words, returns=5000)
        self.assertResultContents(results, 5000, simple_words, unique=3**3)

        # words + wordset
        with pytest.raises(TypeError):
            genphrase(words=simple_words, wordset="bip39")
