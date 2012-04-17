"""admin/benchmarks - misc timing tests

this is a *very* rough benchmark script hacked together when the context
parsing was being sped up. it could definitely be improved.
"""
#=============================================================================
# init script env
#=============================================================================
import os, sys
root = os.path.join(os.path.dirname(__file__), os.path.pardir)
sys.path.insert(0, root)

#=============================================================================
# imports
#=============================================================================
# core
import logging; log = logging.getLogger(__name__)
import os
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

#=============================================================================
# benchmarking support
#=============================================================================
class benchmark:
    "class to hold various benchmarking helpers"

    @classmethod
    def constructor(cls, **defaults):
        """mark callable as something which should be benchmarked.
        callable should return a function will be timed.
        """
        def marker(func):
            if func.__doc__:
                name = func.__doc__.splitlines()[0]
            else:
                name = func.__name__
            func._benchmark_task = ("ctor", name, defaults)
            return func
        return marker

    @classmethod
    def run(cls, source, **defaults):
        """run benchmark for all tasks in source, yielding result records"""
        for obj in source.values():
            for record in cls._run_object(obj, defaults):
                yield record

    @classmethod
    def _run_object(cls, obj, defaults):
        args = getattr(obj, "_benchmark_task", None)
        if not args:
            return
        mode, name, options = args
        kwds = defaults.copy()
        kwds.update(options)
        if mode == "ctor":
            itr = obj()
            if not hasattr(itr, "next"):
                itr = [itr]
            for func in itr:
                # TODO: per function name & options
                secs, precision = cls.measure(func, None, **kwds)
                yield name, secs, precision
        else:
            raise ValueError("invalid mode: %r" % (mode,))

    @staticmethod
    def measure(func, setup=None, maxtime=1, bestof=3):
        """timeit() wrapper which tries to get as accurate a measurement as
        possible w/in maxtime seconds.

        :returns:
            ``(avg_seconds_per_call, log10_number_of_repetitions)``
        """
        from timeit import Timer
        from math import log
        timer = Timer(func, setup=setup or '')
        number = 1
        while True:
            delta = min(timer.repeat(bestof, number))
            maxtime -= delta*bestof
            if maxtime < 0:
                return delta/number, int(log(number, 10))
            number *= 10

    @staticmethod
    def pptime(secs, precision=3):
        """helper to pretty-print fractional seconds values"""
        usec = int(secs * 1e6)
        if usec < 1000:
            return "%.*g usec" % (precision, usec)
        msec = usec / 1000
        if msec < 1000:
            return "%.*g msec" % (precision, msec)
        sec = msec / 1000
        return "%.*g sec" % (precision, sec)

#=============================================================================
# utils
#=============================================================================
sample_config_1p = os.path.join(root, "passlib", "tests", "sample_config_1s.cfg")

from passlib.context import CryptContext
if hasattr(CryptContext, "from_path"):
    CryptPolicy = None
else:
    from passlib.context import CryptPolicy

class BlankHandler(uh.HasRounds, uh.HasSalt, uh.GenericHandler):
    name = "blank"
    ident = u("$b$")
    setting_kwds = ("rounds", "salt", "salt_size")

    checksum_size = 1
    min_salt_size = max_salt_size = 1
    salt_chars = u("a")

    min_rounds = 1000
    max_rounds = 3000
    default_rounds = 2000

    @classmethod
    def from_string(cls, hash):
        r,s,c = uh.parse_mc3(hash, cls.ident, handler=cls)
        return cls(rounds=r, salt=s, checksum=c)

    def to_string(self):
        return uh.render_mc3(self.ident, self.rounds, self.salt, self.checksum)

    def _calc_checksum(self, secret):
        return unicode(secret[0:1])

class AnotherHandler(BlankHandler):
    name = "another"
    ident = u("$a$")

SECRET = u("toomanysecrets")
OTHER =  u("setecastronomy")

#=============================================================================
# CryptContext benchmarks
#=============================================================================
@benchmark.constructor()
def test_context_from_path():
    "test speed of CryptContext.from_path()"
    path = sample_config_1p
    if CryptPolicy:
        def helper():
            CryptPolicy.from_path(path)
    else:
        def helper():
            CryptContext.from_path(path)
    return helper

@benchmark.constructor()
def test_context_update():
    "test speed of CryptContext.update()"
    kwds = dict(
        schemes = [ "sha512_crypt", "sha256_crypt", "md5_crypt",
                    "des_crypt", "unix_fallback" ],
        deprecated = [ "des_crypt" ],
        sha512_crypt__min_rounds=4000,
        )
    if CryptPolicy:
        policy=CryptPolicy.from_path(sample_config_1p)
        def helper():
            policy.replace(**kwds)
    else:
        ctx = CryptContext.from_path(sample_config_1p)
        def helper():
            ctx.copy(**kwds)
    return helper

@benchmark.constructor()
def test_context_init():
    "test speed of CryptContext() constructor"
    kwds = dict(
        schemes=[BlankHandler, AnotherHandler],
        default="another",
        blank__min_rounds=1500,
        blank__max_rounds=2500,
        another__vary_rounds=100,
    )
    def helper():
        CryptContext(**kwds)
    return helper

@benchmark.constructor()
def test_context_calls():
    "test speed of CryptContext password methods"
    ctx = CryptContext(
        schemes=[BlankHandler, AnotherHandler],
        default="another",
        blank__min_rounds=1500,
        blank__max_rounds=2500,
        another__vary_rounds=100,
    )
    def helper():
        hash = ctx.encrypt(SECRET, rounds=2001)
        ctx.verify(SECRET, hash)
        ctx.verify_and_update(SECRET, hash)
        ctx.verify_and_update(OTHER, hash)
    return helper

#=============================================================================
# handler benchmarks
#=============================================================================
@benchmark.constructor()
def test_md5_crypt_builtin():
    "test test md5_crypt builtin backend"
    from passlib.hash import md5_crypt
    md5_crypt.set_backend("builtin")
    def helper():
        hash = md5_crypt.encrypt(SECRET)
        md5_crypt.verify(SECRET, hash)
        md5_crypt.verify(OTHER, hash)
    yield helper

@benchmark.constructor()
def test_ldap_salted_md5():
    "test ldap_salted_md5"
    from passlib.hash import ldap_salted_md5 as handler
    def helper():
        hash = handler.encrypt(SECRET, salt='....')
        handler.verify(SECRET, hash)
        handler.verify(OTHER, hash)
    yield helper

#=============================================================================
# main
#=============================================================================
def main(*args):
    source = globals()
    if args:
       orig = source
       source = dict((k,orig[k]) for k in orig if k in args)
    helper = benchmark.run(source, maxtime=2, bestof=3)
    for name, secs, precision in helper:
        print_("%-50s %9s (%d)" % (name, benchmark.pptime(secs), precision))

if __name__ == "__main__":
    import sys
    main(*sys.argv[1:])

#=============================================================================
# eof
#=============================================================================
