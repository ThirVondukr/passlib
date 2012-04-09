"""admin/benchmarks - misc timing tests

this is a *very* rough benchmark script hacked together when the context
parsing was being sped up. it could definitely be improved.
"""
#=============================================================================
# init script env
#=============================================================================
import os, sys
root_dir = os.path.join(os.path.dirname(__file__), os.path.pardir)
sys.path.insert(0, root_dir)

#=============================================================================
# imports
#=============================================================================
# core
import logging; log = logging.getLogger(__name__)
from timeit import Timer
import warnings
# site
# pkg
try:
    from passlib.exc import PasslibConfigWarning
except ImportError:
    PasslibConfigWarning = None
import passlib.utils.handlers as uh
from passlib.utils.compat import u, print_, unicode
# local
__all__ = [
]

#=============================================================================
# utils
#=============================================================================

class BlankHandler(uh.HasRounds, uh.HasSalt, uh.GenericHandler):

    setting_kwds = ("rounds", "salt", "salt_size")
    name = "blank"
    ident = u("$b$")

    checksum_size = 1
    min_salt_size = max_salt_size = 1
    salt_chars = u("a")

    min_rounds = 1000
    max_rounds = 3000
    default_rounds = 2000

    @classmethod
    def from_string(cls, hash):
        r,s,c = uh.parse_mc3(hash, cls.ident, cls.name)
        return cls(rounds=int(r), salt=s, checksum=c)

    def to_string(self):
        return uh.render_mc3(self.ident, self.rounds, self.salt, self.checksum)

    def _calc_checksum(self, password):
        return unicode(password[0:1])

class AnotherHandler(BlankHandler):
    name = "another"
    ident = u("$a$")

#=============================================================================
# crypt context tests
#=============================================================================
def setup_policy():
    import os
    from passlib.context import CryptPolicy
    test_path = os.path.join(root_dir, "passlib", "tests", "sample_config_1s.cfg")

    def test_policy_creation():
        with open(test_path, "rb") as fh:
            policy1 = CryptPolicy.from_string(fh.read())
    yield test_policy_creation

    default = CryptPolicy.from_path(test_path)
    def test_policy_composition():
        policy2 = default.replace(
            schemes = [ "sha512_crypt", "sha256_crypt", "md5_crypt",
                        "des_crypt", "unix_fallback" ],
            deprecated = [ "des_crypt" ],
            )
    yield test_policy_composition

secret = u("secret")
other = u("other")

def setup_context():
    from passlib.context import CryptContext

    def test_context_init():
        return CryptContext(
        schemes=[BlankHandler, AnotherHandler],
        default="another",
        blank__min_rounds=1500,
        blank__max_rounds=2500,
        another__vary_rounds=100,
        )
    yield test_context_init

    ctx = test_context_init()
    def test_context_calls():
        hash = ctx.encrypt(secret, rounds=2001)
        ctx.verify(secret, hash)
        ctx.verify_and_update(secret, hash)
        ctx.verify_and_update(other, hash)
    yield test_context_calls

def setup_handlers():
    from passlib.hash import md5_crypt
    md5_crypt.set_backend("builtin")
    def test_md5_crypt():
        hash = md5_crypt.encrypt(secret)
        md5_crypt.verify(secret, hash)
        md5_crypt.verify(other, hash)
    yield test_md5_crypt

#=============================================================================
# main
#=============================================================================
def pptime(secs):
    precision = 3
    usec = int(secs * 1e6)
    if usec < 1000:
        return "%.*g usec" % (precision, usec)
    msec = usec / 1000
    if msec < 1000:
        return "%.*g msec" % (precision, msec)
    sec = msec / 1000
    return "%.*g sec" % (precision, sec)

def main(*args):
    names = args
    source = globals()
    for key in sorted(source):
        if not key.startswith("setup_"):
            continue
        sname = key[6:]
        setup = source[key]
        for test in setup():
            name = test.__name__
            if name.startswith("test_"):
                name = name[5:]
            if names and name not in names:
                continue
            timer = Timer(test)
            number = 1
            while True:
                t = timer.timeit(number)
                if t > .2:
                    break
                number *= 10
            repeat = 3
            best = min(timer.repeat(repeat, number)) / number
            print_("%30s %s" % (name, pptime(best)))

if __name__ == "__main__":
    import sys
    main(*sys.argv[1:])

#=============================================================================
# eof
#=============================================================================
