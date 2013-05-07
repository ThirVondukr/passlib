"""passlib.tests -- test passlib.totp"""
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
    "EngineTest",
]

#=============================================================================
# TOTP Engine
#=============================================================================
class EngineTest(TestCase):
    descriptionPrefix = "passlib.ext.totp.TOTPEngine"

    def test_basic(self):
        """reference vectors"""
        from passlib.totp import TotpEngine

        # NOTE: these are the defaults, but just to make our test case explicit.
        engine = TotpEngine(time_step=30, digits=6, prf="hmac-sha1")

        # verify counter is being calculated correctly
        engine.gentoken()

#=============================================================================
# eof
#=============================================================================
