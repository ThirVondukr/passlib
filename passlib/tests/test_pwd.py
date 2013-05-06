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
    "StrengthTest"
]

#=============================================================================
# strength
#=============================================================================
class StrengthTest(TestCase):
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
