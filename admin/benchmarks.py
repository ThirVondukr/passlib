"""admin/benchmarks - misc timing tests

this is a *very* rough benchmark script hacked together when the context
parsing was being sped up. it could definitely be improved.
"""
#=============================================================================
# init app env
#=============================================================================
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.path.pardir))

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
    from passlib.utils import PasslibPolicyWarning
except ImportError:
    PasslibPolicyWarning = None
from passlib.utils import handlers as uh
# local
__all__ = [
]

#=============================================================================
# utils
#=============================================================================

class BlankHandler(uh.HasRounds, uh.HasSalt, uh.GenericHandler):

    setting_kwds = ("rounds", "salt", "salt_size")
    name = "blank"
    ident = u"$b$"

    checksum_size = 1
    min_salt_size = max_salt_size = 1
    salt_chars = u"a"

    min_rounds = 1000
    max_rounds = 3000
    default_rounds = 2000

    @classmethod
    def from_string(cls, hash):
        r,s,c = uh.parse_mc3(hash, cls.ident, cls.name)
        r = int(r)
        return cls(rounds=r, salt=s, checksum=c, strict=bool(c))

    def to_string(self):
        return uh.render_mc3(self.ident, self.rounds, self.salt, self.checksum)

    def calc_checksum(self, password):
        return unicode(password[0:1])

class AnotherHandler(BlankHandler):
    name = "another"
    ident = u"$a$"

#=============================================================================
# crypt context tests
#=============================================================================
def setup_policy():
    import os
    from passlib.context import _load_default_policy, CryptPolicy, \
                                __file__ as mpath
    cpath = os.path.abspath(os.path.join(os.path.dirname(mpath), "default.cfg"))

    def test_policy_creation():
        with file(cpath, "rb") as fh:
            policy1 = CryptPolicy.from_string(fh.read())
    yield test_policy_creation

    default = _load_default_policy()
    def test_policy_composition():
        policy2 = CryptPolicy(
            policy=default,
            schemes = [ "sha512_crypt", "sha256_crypt", "md5_crypt",
                        "des_crypt", "unix_fallback" ],
            deprecated = [ "des_crypt" ],
            )
    yield test_policy_composition

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
    secret = u"secret"
    other = u"other"
#    if PasslibPolicyWarning:
#        warnings.filterwarnings("ignore", category=PasslibPolicyWarning)
    def test_context_calls():
        hash = ctx.encrypt(secret, rounds=2001)
        ctx.verify(secret, hash)
        ctx.verify_and_update(secret, hash)
        ctx.verify_and_update(other, hash)
    yield test_context_calls

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
            print "%30s %s" % (name, pptime(best))

if __name__ == "__main__":
    import sys
    main(*sys.argv[1:])

#=============================================================================
# eof
#=============================================================================
