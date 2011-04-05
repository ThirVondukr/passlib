"helper for method in test_registry.py"

from passlib.registry import register_crypt_handler
import passlib.utils.handlers as uh

class dummy_bad(uh.StaticHandler):
    name = "dummy_bad"

class alt_dummy_bad(uh.StaticHandler):
    name = "dummy_bad"

register_crypt_handler(alt_dummy_bad)
