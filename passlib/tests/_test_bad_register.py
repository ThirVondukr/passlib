"helper for method in test_registry.py"

from passlib.registry import register_crypt_handler
from passlib.utils.drivers import BaseHash

class dummy_bad(BaseHash):
    name = "dummy_bad"
    setting_kwds = ()

class alt_dummy_bad(BaseHash):
    name = "dummy_bad"
    setting_kwds = ()

register_crypt_handler(alt_dummy_bad)
