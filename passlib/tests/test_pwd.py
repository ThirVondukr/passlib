"""passlib.tests -- tests for passlib.pwd"""
#=============================================================================
# imports
#=============================================================================
# core
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

    def test_average_entropy(self):
        "_average_entropy()"
        from passlib.pwd import _average_entropy

        self.assertEqual(_average_entropy(""), 0)
        self.assertEqual(_average_entropy("", True), 0)

        self.assertEqual(_average_entropy("a"*8), 0)
        self.assertEqual(_average_entropy("a"*8, True), 0)

        self.assertEqual(_average_entropy("ab"), 1)
        self.assertEqual(_average_entropy("ab"*8), 1)
        self.assertEqual(_average_entropy("ab", True), 2)
        self.assertEqual(_average_entropy("ab"*8, True), 16)

        self.assertEqual(_average_entropy("abcd"), 2)
        self.assertEqual(_average_entropy("abcd"*8), 2)
        self.assertAlmostEqual(_average_entropy("abcdaaaa"), 1.5488, delta=4)
        self.assertEqual(_average_entropy("abcd", True), 8)
        self.assertEqual(_average_entropy("abcd"*8, True), 64)
        self.assertAlmostEqual(_average_entropy("abcdaaaa", True), 12.3904, delta=4)

#=============================================================================
# generation
#=============================================================================
class GenerateTest(TestCase):
    """test generation routines"""
    descriptionPrefix = "passlib.pwd"

    def test_PhraseGenerator(self):
        """PhraseGenerator()"""
        from passlib.pwd import PhraseGenerator

        # test wordset can be any iterable
        # NOTE: there are 3**3=27 possible combinations,
        #       but internal code rejects 'aaa' 'bbb' 'ccc', leaving only 24
        results = PhraseGenerator(size=3, wordset=set("abc"))(5000)
        self.assertEqual(len(set(results)), 24)

#=============================================================================
# strength
#=============================================================================
class StrengthTest(TestCase):
    """test strength measurements"""
    descriptionPrefix = "passlib.pwd"

    reference = [
        # (password, classify() output)

        # "weak"
        ("", 0),
        ("0"*8, 0),
        ("0"*48, 0),
        ("1001"*2, 0),
        ("123", 0),
        ("123"*2, 0),
        ("1234", 0),

        # "somewhat weak"
        ("12345", 1),
        ("1234"*2, 1),
        ("secret", 1),

        # "not weak"
        ("reallysecret", 2),
        ("12345"*2, 2),
        ("Eer6aiya", 2),
    ]

    def test_classify(self):
        """classify()"""
        from passlib.pwd import classify
        for secret, result in self.reference:
            self.assertEqual(classify(secret), result, "classify(%r):" % secret)

#=============================================================================
# eof
#=============================================================================
