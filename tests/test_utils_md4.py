import warnings

# site
# pkg
# module
from tests.test_crypto_builtin_md4 import _Common_MD4_Test

# local
__all__ = [
    "Legacy_MD4_Test",
]


class Legacy_MD4_Test(_Common_MD4_Test):
    descriptionPrefix = "passlib.utils.md4.md4()"

    def setUp(self):
        super().setUp()
        warnings.filterwarnings(
            "ignore", ".*passlib.utils.md4.*deprecated", DeprecationWarning
        )

    def get_md4_const(self):
        from passlib.utils.md4 import md4

        return md4
