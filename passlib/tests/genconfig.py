"""passlib config generation script

this script is a work in progress to develop a script which generates
rounds configuration parameters suitable for a particular host & deployment requirements.
right now it just consists of a function which experimentally determines
the optimal range of rounds values for a given hash, based on the desired time it should take.
"""
#=========================================================
#imports
#=========================================================
#core
from math import log as logb
import logging
import time
import sys
#site
#pkg
from passlib.registry import get_crypt_handler
#local
log = logging.getLogger(__name__)
#=========================================================
#
#=========================================================
class HashTimer(object):
    """helper which determines number of rounds required for hash to take desired amount of time.

    usage::

        >>> timer = HashTimer("sha512_crypt")
        >>> timer.find_rounds(.5)

    .. note::
        This function is not very exact, and generates results
        that are only approximately the same each time (w/in about 5% usually).

        Furthermore, to generate useful values, it should
        be run when the system has an average load
        to get an accurate measurement.
    """
    log = logging.getLogger(__name__ + ".HashTimer")

    def __init__(self, name, samples=1):
        #
        #get handler, extract boundary information
        #
        self.handler = handler = get_crypt_handler(name)
        if 'rounds' not in handler.setting_kwds:
            raise ValueError, "scheme does not support rounds: %r" % (handler.name,)
        self.min_rounds = getattr(handler, "min_rounds", 2)
        self.max_rounds = getattr(handler, "max_rounds", (1<<32)-1)
        rc = self.rounds_cost = getattr(handler, "rounds_cost", "linear")

        #
        #set up functions that vary based on rounds cost function
        #
        if rc == "linear":
            def get_rps(rounds, delta):
                return rounds/delta
            def guess_rounds(rps, target):
                return int(rps*target+.5)
            erradj = 2
        elif rc == "log2":
            def get_rps(rounds, delta):
                return (2**rounds)/delta
            def guess_rounds(rps, target):
                return int(logb(rps*target,2)+.5)
            erradj = 1.1
        else:
            raise NotImplementedError, "unknown rounds cost function: %r" % (rc,)
        self.get_rps = get_rps
        self.guess_rounds = guess_rounds
        self.erradj = erradj

        #
        #init cache
        #
        self.samples = samples
        self.cache = {}
        self.srange = range(samples)

    def time_encrypt(self, rounds):
        "check how long encryption for a given number of rounds will take"
        cache = self.cache
        if rounds in cache:
            return cache[rounds]
        encrypt = self.handler.encrypt
        srange = self.srange
        cur = time.time
        start = cur()
        for x in srange:
            encrypt("too many secrets", rounds=rounds)
        stop = cur()
        delta = (stop-start)/self.samples
        cache[rounds] = delta
        return delta

    def find_rounds(self, target, over=False, under=False):
        """find optimal rounds range for hash

        :arg target: time hashing a password should take
        :param over: if True, returns minimum rounds taking *at least* target seconds.
        :param under: if True, returns maximum rounds taking *at most* target seconds.

        if neither over / under is set, returns rounds taking
        closest to target seconds.

        :returns:
            returns number of rounds closest
            to taking about ``target`` seconds to hash a password.
        """
        if target <= 0:
            raise ValueError, "target must be > 0"

        log = self.log
        name = self.handler.name
        get_rps = self.get_rps
        time_encrypt = self.time_encrypt
        log.info("%s: finding rounds for target time: %f", name, target)

        #
        #check if useful lower & upper bounds already exist in cache
        #
        lower = upper = None
        for rounds, delta in self.cache.iteritems():
            if delta < target:
                if lower is None or rounds > lower:
                    lower = rounds
            else:
                if upper is None or rounds < upper:
                    upper = rounds

        #
        #if bounds not found in cache, run open-ended search for starting bounds
        #
        if lower is None:
            lower = max(1,self.min_rounds)
        if upper is None:
            guess_rounds = self.guess_rounds
            max_rounds = self.max_rounds
            target_above = target*self.erradj #NOTE: we aim a little high as hack to deal w/ measuring error
            rounds = lower
            while True:
                delta = time_encrypt(rounds)
                rps = get_rps(rounds, delta)
                log.debug("%s: ranging target: checked %r -> %fs (%f r/s)", name, rounds, delta, rps)
                if delta < target:
                    lower = rounds
                    if rounds == max_rounds:
                        log.warning("%s: target time out of range: hash would require > max_rounds (%d) in order to take %fs", name, max_rounds, target)
                        return rounds
                    rounds = min(max(guess_rounds(rps, target_above), rounds+1), max_rounds)
                else:
                    upper = rounds
                    break

        #
        #perform binary search till we find match
        #
        while lower+1<upper:
            #NOTE: weighting things in favor of upper, since per-call overhead causes curve to not be quite linear.
            next = (upper*5+lower*3)//8
            delta = time_encrypt(next)
            rps = get_rps(next, delta)
            log.debug("%s: finding target: range %r .. %r: checked %r -> %fs (%f r/s)", name, lower, upper, next, delta, rps)
            if delta < target:
                lower = next
            else:
                upper = next

        #
        #now 'lower' is largest value which takes less than target seconds,
        #and 'upper' is smallest value which takes greater than target seconds.
        #so we pick based on over/under flags, or fallback to whichever one is closest
        #
        if over:
            return upper
        elif under:
            return lower
        else:
            if target-cache[lower] < cache[upper]-target:
                return lower
            else:
                return upper

    def find_rounds_range(self, target_high, target_low=None, over=False, under=False):
        "find min/max rounds which will cause scheme to take specified range of times"
        if target_low is None:
            target_low = target_high * .75
        elif target_low > target_high:
            target_high = target_low
        rounds_high = self.find_rounds(target_high, under=not over, over=over)
        rounds_low = self.find_rounds(target_low, over=not under, under=under)
        if rounds_low > rounds_high:
            #NOTE: this happens sometimes w/ rounds_cost=log2...
            #if nothing hits w/in range, rounds_low will be 1+ rounds_high
            #we just return correctly ordered range
            rounds_low, rounds_high = rounds_high, rounds_low
        return rounds_low, rounds_high

    def estimate_rps(self):
        "return estimated rounds per second based on cached results"
        cache = self.cache
        if not cache:
            raise RuntimeError, "should not be called until cache populated by find_rounds()"
        get_rps = self.get_rps
        rps = sum(r*get_rps(r,d) for r,d in cache.iteritems())/sum(cache)
        if rps > 1000: #for almost all cases, we'd return integer
            rps = int(rps)
        return rps

#=========================================================
#main
#=========================================================
def main(*args):
    from bps.logs import setup_std_logging
    setup_std_logging(level="debug", dev=True)

    timer = HashTimer("sha256_crypt")
    print timer.find_rounds_range(.5)
    print timer.estimate_rps()

    #TODO: give script ability to generate timings for a range of schemes, and minimum / maximum times.

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
#=========================================================
#eof
#=========================================================
