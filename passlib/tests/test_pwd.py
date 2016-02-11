"""passlib.tests -- tests for passlib.pwd"""
#=============================================================================
# imports
#=============================================================================
# core
import itertools
import logging; log = logging.getLogger(__name__)
# site
# pkg
from passlib.tests.utils import TestCase
# local
__all__ = [
    "UtilsTest",
    "GenerateTest",
    "StrengthTest",
]

#=============================================================================
#
#=============================================================================
class UtilsTest(TestCase):
    """test internal utilities"""
    descriptionPrefix = "passlib.pwd"

    def test_self_info_rate(self):
        """_self_info_rate()"""
        from passlib.pwd import _self_info_rate

        self.assertEqual(_self_info_rate(""), 0)

        self.assertEqual(_self_info_rate("a" * 8), 0)

        self.assertEqual(_self_info_rate("ab"), 1)
        self.assertEqual(_self_info_rate("ab" * 8), 1)

        self.assertEqual(_self_info_rate("abcd"), 2)
        self.assertEqual(_self_info_rate("abcd" * 8), 2)
        self.assertAlmostEqual(_self_info_rate("abcdaaaa"), 1.5488, places=4)

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

    def test_max_average_entropy(self):
        """_max_average_entropy()"""
        from passlib.pwd import _max_self_info_rate as _mae, _self_info_rate as _ae

        # asize < 1
        self.assertRaises(ValueError, _mae, -1, 1)
        self.assertRaises(ValueError, _mae, 0, 1)

        # osize < 1
        self.assertRaises(ValueError, _mae, 4, -1)
        self.assertEqual(_mae(4, 0), 0)

        # no repetition (osize <= asize)
        self.assertEqual(_mae(4, 1), 0)
        self.assertEqual(_mae(4, 2), 1)  # _ae('ab')
        self.assertAlmostEqual(_mae(4, 3), _ae("abc"), places=5)
        self.assertEqual(_mae(4, 4), 2)  # _ae('abcd')

        # 1 repetition
        self.assertAlmostEqual(_mae(4, 5), _ae("abcd" + "a"), places=5)
        self.assertAlmostEqual(_mae(4, 6), _ae("abcd" + "ab"), places=5)
        self.assertAlmostEqual(_mae(4, 7), _ae("abcd" + "abc"), places=5)
        self.assertAlmostEqual(_mae(4, 8), _ae("abcd" * 2 ), places=5)

        # 2 repetitions
        self.assertAlmostEqual(_mae(4,  9), _ae("abcd" * 2 + "a"), places=5)
        self.assertAlmostEqual(_mae(4, 10), _ae("abcd" * 2 + "ab"), places=5)
        self.assertAlmostEqual(_mae(4, 11), _ae("abcd" * 2 + "abc"), places=5)
        self.assertAlmostEqual(_mae(4, 12), _ae("abcd" * 3), places=5)

    # def test_average_entropy_per_wordset_char(self):
    #     """_average_entropy_per_wordset_char()"""
    #     from passlib.pwd import _self_info_rate_per_char as _awe, _self_info_rate as _ae
    #
    #     self.assertEqual(_awe([]), 0)
    #     self.assertEqual(_awe(["a"]), 0)
    #     self.assertEqual(_awe(["a", "b"]), 1)
    #     self.assertEqual(_awe(["a", "b", "c", "d"]), 2)
    #
    #     self.assertEqual(_awe(["aa", "bb"]), 1)  # a=2/4, b=2/4
    #     self.assertEqual(_awe(["ab", "ba"]), 1)  # a=2/4, b=2/4
    #
    #     self.assertEqual(_awe(["ab", "ba", "ca", "da"]), 1.75)  # a=4/8, b=2/8, c=1/8, d=1/8

#=============================================================================
# word generation
#=============================================================================

# import subject
from passlib.pwd import genword, WordGenerator
ascii62 = WordGenerator.default_charsets['ascii62']
hex = WordGenerator.default_charsets['hex']

class WordGeneratorTest(TestCase):
    """test generation routines"""
    descriptionPrefix = "passlib.pwd.genword()"

    def assertResultContents(self, results, count, chars, unique=True):
        """check result list matches expected count & charset"""
        self.assertEqual(len(results), count)
        if unique:
            if unique is True:
                unique = count
            self.assertEqual(len(set(results)), unique)
        self.assertEqual(set("".join(results)), set(chars))

    def test_general(self):
        """general behavior"""

        # basic usage
        result = genword()
        self.assertEqual(len(result), 9)

        # malformed keyword should have useful error.
        self.assertRaisesRegex(TypeError, "(?i)unexpected keyword.*badkwd", genword, badkwd=True)

    def test_returns(self):
        """'returns' keyword"""
        # returns=int option
        results = genword(returns=5000)
        self.assertResultContents(results, 5000, ascii62)

        # returns=iter option
        gen = genword(returns=iter)
        results = [next(gen) for _ in range(5000)]
        self.assertResultContents(results, 5000, ascii62)

        # invalid returns option
        self.assertRaises(TypeError, genword, returns='invalid-type')

    def test_charset(self):
        """'charset' & 'chars' options"""
        # charset option
        results = genword(charset="hex", returns=5000)
        self.assertResultContents(results, 5000, hex)

        # chars option
        # there are 3**3=27 possible combinations
        results = genword(length=3, chars="abc", returns=5000, min_complexity=0)
        self.assertResultContents(results, 5000, "abc", unique=27)

        # chars + charset
        self.assertRaises(TypeError, genword, chars='abc', charset='hex')

    def test_min_complexity(self):
        """'min_complexity' option"""

        # test non-zero min_complexity.
        # should reject 'aaa' 'bbb' 'ccc' (0 avg entropy), leaving only 24
        results = genword(length=3, chars="abc", returns=5000, min_complexity=0.001)
        self.assertResultContents(results, 5000, "abc", unique=24)

        # test min_complexity=1 -- should only accept permutations of 'abc'
        results = genword(length=3, chars="abc", returns=5000, min_complexity=1)
        self.assertResultContents(results, 5000, "abc", unique=6)

    # TODO: test rng option

#=============================================================================
# phrase generation
#=============================================================================

# import subject
from passlib.pwd import genphrase, _load_wordset, PhraseGenerator
default_words = _load_wordset(PhraseGenerator.wordset)
dice_words = _load_wordset("diceware")
simple_words = ["alpha", "beta", "gamma"]

class PhraseGeneratorTest(TestCase):
    """test generation routines"""
    descriptionPrefix = "passlib.pwd.genphrase()"

    def assertResultContents(self, results, count, words, unique=True, sep=" "):
        """check result list matches expected count & charset"""
        self.assertEqual(len(results), count)
        if unique:
            if unique is True:
                unique = count
            self.assertEqual(len(set(results)), unique)
        out = set(itertools.chain.from_iterable(elem.split(sep) for elem in results))
        self.assertEqual(out, set(words))

    def test_general(self):
        """general behavior"""

        # basic usage
        result = genphrase()
        self.assertEqual(len(result.split(" ")), 4)  # 48 / log(7776, 2) ~= 3.7 -> 4

        # malformed keyword should have useful error.
        self.assertRaisesRegex(TypeError, "(?i)unexpected keyword.*badkwd", genphrase, badkwd=True)

    def test_entropy(self):
        """'length' & 'entropy' keywords"""

        # custom entropy
        result = genphrase(entropy=70)
        self.assertEqual(len(result.split(" ")), 6)  # 70 / log(7776, 2) ~= 5.4 -> 6

        # custom length
        result = genphrase(length=3)
        self.assertEqual(len(result.split(" ")), 3)

        # custom length < entropy
        result = genphrase(length=3, entropy=48)
        self.assertEqual(len(result.split(" ")), 4)

        # custom length > entropy
        result = genphrase(length=4, entropy=12)
        self.assertEqual(len(result.split(" ")), 4)

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
        self.assertRaises(TypeError, genphrase, returns='invalid-type')

    def test_wordset(self):
        """'wordset' & 'words' options"""
        # wordset option
        results = genphrase(words=simple_words, returns=5000)
        self.assertResultContents(results, 5000, simple_words)

        # words option
        results = genphrase(length=3, words=simple_words, returns=5000, min_complexity=0)
        self.assertResultContents(results, 5000, simple_words, unique=3**3 - 3)

        # words + wordset
        self.assertRaises(TypeError, genphrase, words=simple_words, wordset='diceware')

    def test_min_complexity(self):
        """'min_complexity' option"""

        # test non-zero min_complexity.
        # should reject repeats of 'alpha alpha alpha', etc (0 avg entropy)
        results = genphrase(length=3, words=simple_words, returns=1000, min_complexity=0.001)
        self.assertResultContents(results, 1000, simple_words, unique=3**3 - 3)

        # XXX: trusting this will work, it does for charsets --
        #      but min_chars requirement makes this take forever
        # # test min_complexity=1 -- should only accept permutations containing all symbols
        # results = genphrase(length=3, words=simple_words, returns=24, min_complexity=1)
        # self.assertResultContents(results, 24, simple_words, unique=6)  # =3!

    # def test_min_chars(self):
    #     """min_chars protection"""
    #     from passlib.pwd import _self_info_rate_per_char
    #
    #     # sanity check our wordset
    #     entropy_per_char = _self_info_rate_per_char(simple_words)
    #     self.assertAlmostEqual(entropy_per_char, 2.8352, places=4)
    #
    #     # create generator
    #     gen = PhraseGenerator(entropy=48, words=simple_words, sep="")
    #
    #     # sanity check: gen should target nearest multiple of entropy_per_symbol >= 48
    #     self.assertEqual(gen.entropy, 48)
    #     self.assertAlmostEqual(gen.effective_entropy, 49.1338, places=4)
    #     self.assertEqual(gen.length, 31)  # 48 / 1.58496
    #
    #     # given numbers above, anything less than 49.1338 / 2.8352 could be guessed
    #     # using a character based attack, w/o needing wordset
    #     self.assertEqual(gen.min_chars, 2)

#=============================================================================
# strength
#=============================================================================
# class StrengthTest(TestCase):
#     """test strength measurements"""
#     descriptionPrefix = "passlib.pwd"
#
#     reference = [
#         # (password, classify() output)
#
#         # "weak"
#         ("", 0),
#         ("0"*8, 0),
#         ("0"*48, 0),
#         ("1001"*2, 0),
#         ("123", 0),
#         ("123"*2, 0),
#         ("1234", 0),
#
#         # "somewhat weak"
#         ("12345", 1),
#         ("1234"*2, 1),
#         ("secret", 1),
#
#         # "not weak"
#         ("reallysecret", 2),
#         ("12345"*2, 2),
#         ("Eer6aiya", 2),
#     ]
#
#     def test_classify(self):
#         """classify()"""
#         from passlib.pwd import classify
#         for secret, result in self.reference:
#             self.assertEqual(classify(secret), result, "classify(%r):" % secret)

#=============================================================================
# eof
#=============================================================================
