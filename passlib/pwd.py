"""passlib.pwd -- password generation helpers.

current api
===========
generation
    * frontend: generate()
    * backends: PhraseGenerator(), WordGenerator()

strength
    * strength(), classify()
    * XXX: consider redo-ing as returning an informational object,
      ala ``https://github.com/lowe/zxcvbn``'s result object

TODO
====
This module's design is in flux, and may be changed before release.
The following known bits remain:

misc
----
* the terminology about what's being measured by _average_entropy() etc
  may not be correct. this needs fixing before the module is released.
  need to find a good reference on information theory, to make sure terminology
  and formulas are correct :)

    * when researching, also need to find any papers attempting to measure
      guessing entropy (w/ respect to cracker's attack model),
      rather than entropy with respect to a particular password
      generation algorithm.

* add a "crack time" estimation to generate & classify?
  might be useful to give people better idea of what measurements mean.

generation
----------
* unittests for generation code
* add create_generator() frontend?
* straighten out any unicode issues this code may have.
    - primarily, this should always return unicode (currently doesn't)
* don't like existing wordsets.
    - diceware has some weird bordercases that average users may not like
    - electrum's set isn't large enough for these purposes
    - looking into modified version of wordfrequency.info's 5k list
      (could merge w/ diceware, and remove commonly used passwords)

strength
--------
* unittests for strength measurement
* improve api for strength measurement
    * one issue: need way to indicate when measurement is a lower/upper
      bound, rather than and/or the accuracy of a given measurement.
        * need to present this in a way which makes it easy to write
          a password-strength meter,
        * yet can have it's scale tweaked if the heuristics are revised.
        * could look at https://github.com/lowe/zxcvbn for some ideas.
* add more strength measurement algorithms
    * NIST 800-63 should be easy
    * zxcvbn (https://tech.dropbox.com/2012/04/zxcvbn-realistic-password-strength-estimation/)
      might also be good, and has approach similar to composite approach
      i was already thinking about.
    * passfault (https://github.com/c-a-m/passfault) looks *very* thorough,
      but may have licensing issues, plus porting to python
      looks like very big job :(
    * give a look at running things through zlib - might be able to cheaply
      catch extra redundancies.
"""
#=============================================================================
# imports
#=============================================================================
from __future__ import division
# core
from collections import defaultdict
from hashlib import sha256
from itertools import chain
from math import ceil, log as logf
import logging; log = logging.getLogger(__name__)
import os
import zlib
# site
# pkg
from passlib.utils.compat import PY3, irange, itervalues, u
from passlib.utils import rng, getrandstr
# local
__all__ = [
    'generate',
    'strength',
    'classify',
]

#=============================================================================
# constants
#=============================================================================

#: default entropy amount for generated passwords
default_entropy = 48

#: default threshold for rejecting low self-information sequences,
#: measured as % of maximum possible self-information for string & alphabet size.
#: (todo: defend this choice of value -- 'twas picked via experimentation)
default_min_complexity = 0.4

#: default presets
default_charset = "safe52"
default_wordset = "beale"

#: dict of preset characters sets
charsets = dict(
    safe52='2346789ABCDEFGHJKMNPQRTUVWXYZabcdefghjkmnpqrstuvwxyz',
)

#: dict of preset word sets,
#: values set to None are lazy-loaded from disk by _load_wordset()
wordsets = dict(
    diceware=None,
    beale=None,
    electrum=None,
)

#: sha256 digest for wordset files, used as sanity check by _load_wordset()
_wordset_checksums = dict(
    diceware="b39e6c367066a75208424cb591f64f188bb6ad69c61da52195718203c18b93d6",
    beale="4b3ca06b22094df07b078e28f632845191ef927deb5a7c77b0f788b336fb80e6",
    electrum="d4975b36cff7002332f6e8dff5477af52089c48ad6535272bbff6fb850ffe206",
    )

#: misc helper constants
_PCW_MSG = "`preset`, `charset`, and `wordset` are mutually exclusive"
_USPACE = u(" ")
_UEMPTY = u("")

#=============================================================================
# internal helpers
#=============================================================================

# XXX: would this be more appropriate as _self_info()?
def _average_entropy(source, total=False):
    """returns the rate of self-information in a sequence of symbols,
    (or total self-information if total=True).

    this is eqvuialent to the average entropy of a given symbol,
    using the sequence itself as the symbol probability distribution.
    if all elements of the source are unique, this should equal
    ``log(len(source), 2)``.

    :arg source:
        iterable containing 0+ symbols
    :param total:
        instead of returning average entropy rate,
        return total self-information
    :returns:
        float bits
    """
    try:
        size = len(source)
    except TypeError:
        # if len() doesn't work, calculate size by summing counts later
        size = None
    counts = defaultdict(int)
    for char in source:
        counts[char] += 1
    if size is None:
        values = counts.values()
        size = sum(values)
    else:
        values = itervalues(counts)
    if not size:
        return 0
    ### NOTE: below code performs the calculation
    ###       ``- sum(value / size * logf(value / size, 2) for value in values)``,
    ###       and then multplies by ``size`` if total is True,
    ###       it just does it with fewer operations.
    tmp = sum(value * logf(value, 2) for value in values)
    if total:
        return size * logf(size, 2) - tmp
    else:
        return logf(size, 2) - tmp / size

def _max_average_entropy(target, source):
    """calculate maximum _average_entropy() of all possible
    strings of length <target>, if drawn from a set of symbols
    of size <source>.
    """
    # NOTE: this accomplishes it's purpose by assuming maximum self-information
    #       would be a string repeating all symbols ``floor(target/source)``
    #       times, followed by the first ``target % source`` symbols repeated
    #       once more.
    assert target > 0
    assert source > 0
    if target < source:
        # special case of general equation, to prevent intermediate DomainError.
        return logf(target, 2)
    else:
        q, r = divmod(target, source)
        p1 = (q + 1) / target
        p2 = q / target
        return -(r * p1 * logf(p1, 2) + (source - r) * p2 * logf(p2, 2))

def _average_wordset_entropy(wordset):
    """return the average entropy per character in a given wordset,
    using each char's frequency in the wordset as the probability of occurrence.

    :arg wordset:
        iterable containing 1+ words, each of which are themselves
        iterables containing 1+ characters.
    :returns:
        float bits of entropy
    """
    return _average_entropy(chain.from_iterable(wordset))

def _load_wordset(name):
    "helper load compressed wordset from package data"
    # load wordset from data file
    source = os.path.join(os.path.dirname(__file__), "_data",
                          "%s.wordset.z" % name)
    with open(source, "rb") as fh:
        data = fh.read()

    # verify against checksum
    try:
        checksum = _wordset_checksums[name]
    except KeyError: # pragma: no cover -- sanity check
        raise AssertionError("no checksum for wordset: %r" % name)
    if sha256(data).hexdigest() != checksum:
        raise RuntimeError("%r wordset file corrupted" % name)

    # decompress and return wordset
    words = wordsets[name] = zlib.decompress(data).decode("utf-8").splitlines()
    log.debug("loaded %d-element wordset from %r", len(words), source)
    return words

#=============================================================================
# password generators
#=============================================================================
class SequenceGenerator(object):
    """base class used by word & phrase generators.

    These objects take a series of options, corresponding
    to those of the :func:`generate` function.
    They act as callables which can be used to generate a password
    or a list of 1+ passwords. They also expose some read-only
    informational attributes.

    :param entropy:
        Optionally specify the amount of entropy the resulting passwords
        should contain (as measured with respect to the generator itself).
        This will be used to autocalculate the required password size.

        Also exposed as a readonly attribute.

    :param size:
        Optionally specify the size of password to generate,
        measured in whatever symbols the subclass uses (characters or words).
        Note that if both ``size`` and ``entropy`` are specified,
        the larger requested size will be used.

        Also exposed as a readonly attribute.

    :param min_complexity:
        By default, generators derived from this class will avoid
        generating passwords with excessively high per-symbol redundancy
        (e.g. ``aaaaaaaa``). This is done by rejecting any strings
        whose self-information per symbol is below a certain
        percentage of the maximum possible a given string and alphabet
        size. This defaults to 40%, or ``min_complexity=0.4``.

    .. autoattribute:: entropy_rate
    """
    #=============================================================================
    # instance attrs
    #=============================================================================

    #: minimum complexity threshold for rejecting generating strings.
    _min_entropy = None

    #: entropy rate per symbol of generated password (character or word)
    entropy_rate = None

    #: requested size of final passwords
    size = None

    #: random number source to use
    rng = rng

    #=============================================================================
    # init
    #=============================================================================
    def __init__(self, size=None, entropy=None, rng=None, min_complexity=None,
                 **kwds):
        # NOTE: subclass should have already set .entropy_rate
        if size is None:
            size = 1
            if entropy is None:
                entropy = default_entropy
        elif size < 1:
            raise ValueError("`size` must be positive integer")
        if entropy is not None:
            if entropy <= 0:
                raise ValueError("`entropy` must be positive number")
            size = max(size, int(ceil(entropy / self.entropy_rate)))
        self.size = size
        if rng is not None:
            self.rng = rng
        if min_complexity is None:
            min_complexity = default_min_complexity
        if min_complexity < 0 or min_complexity > 1:
            raise ValueError("min_complexity must be between 0 and 1")
        self._max_entropy = _max_average_entropy(size, 2**self.entropy_rate)
        self._min_entropy = min_complexity * self._max_entropy
        super(SequenceGenerator, self).__init__(**kwds)

    #=============================================================================
    # helpers
    #=============================================================================
    @property
    def entropy(self):
        """entropy of generated passwords (
        measured with respect to the generation scheme)"""
        return self.size * self.entropy_rate

    def _gen(self):
        """main generation function"""
        raise NotImplementedError("implement in subclass")

    #=============================================================================
    # iter & callable frontend
    #=============================================================================
    def __call__(self, count=None):
        """create and return passwords"""
        if count is None:
            return self._gen()
        else:
            return [self._gen() for _ in irange(count)]

    def __iter__(self):
        return self

    if PY3:
        def __next__(self):
            return self._gen()
    else:
        def next(self):
            return self._gen()

    #=============================================================================
    # eoc
    #=============================================================================

class WordGenerator(SequenceGenerator):
    """class which generates passwords by randomly choosing
    from a string of unique characters.

    :param charset:
        charset to draw from.
    :param preset:
        name of preset charset to use instead of explict charset.
    :param \*\*kwds:
        all other keywords passed to :class:`SequenceGenerator`.

    .. autoattribute:: charset
    """
    #=============================================================================
    # instance attrs
    #=============================================================================

    #: charset used by this generator
    charset = None

    #=============================================================================
    # init
    #=============================================================================
    def __init__(self, charset=None, preset=None, **kwds):
        if not (charset or preset):
            preset = default_charset
        if preset:
            if charset:
                raise TypeError(_PCW_MSG)
            charset = charsets[preset]
        if len(set(charset)) != len(charset):
            raise ValueError("`charset` cannot contain duplicate elements")
        self.charset = charset
        self.entropy_rate = logf(len(charset), 2)
        super(WordGenerator, self).__init__(**kwds)
        ##log.debug("WordGenerator(): entropy/char=%r", self.entropy_rate)

    #=============================================================================
    # helpers
    #=============================================================================
    def _gen(self):
        while True:
            secret = getrandstr(self.rng, self.charset, self.size)
            # check that it satisfies minimum self-information limit
            # set by min_complexity. i.e., reject strings like "aaaaaaaa"
            if _average_entropy(secret) >= self._min_entropy:
                return secret

    #=============================================================================
    # eoc
    #=============================================================================

class PhraseGenerator(SequenceGenerator):
    """class which generates passphrases by randomly choosing
    from a list of unique words.

    :param wordset:
        wordset to draw from.
    :param preset:
        name of preset wordlist to use instead of ``wordset``.
    :param spaces:
        whether to insert spaces between words in output (defaults to ``True``).
    :param \*\*kwds:
        all other keywords passed to :class:`SequenceGenerator`.

    .. autoattribute:: wordset
    """
    #=============================================================================
    # instance attrs
    #=============================================================================

    #: list of words to draw from
    wordset = None

    #: average entropy per char within wordset
    _entropy_per_char = None

    #: minimum size string this will output, to prevent low-entropy
    #: phrases from leaking through.
    _min_chars = None

    #=============================================================================
    # init
    #=============================================================================
    def __init__(self, wordset=None, preset=None, spaces=True, **kwds):
        if not (wordset or preset):
            preset = default_wordset
        if preset:
            if wordset:
                raise TypeError(_PCW_MSG)
            wordset = wordsets[preset]
            if wordset is None:
                wordset = _load_wordset(preset)
        if len(set(wordset)) != len(wordset):
            raise ValueError("`wordset` cannot contain duplicate elements")
        if not isinstance(wordset, (list, tuple)):
            wordset = tuple(wordset)
        self.wordset = wordset
        self.entropy_rate = logf(len(wordset), 2)
        super(PhraseGenerator, self).__init__(**kwds)
        # NOTE: regarding min_chars:
        #       in order to ensure a brute force attack against underlying
        #       charset isn't more successful than one against the wordset,
        #       we need to reject any passwords which contain so many short
        #       words that ``chars_in_phrase * entropy_per_char <
        #                    words_in_phrase * entropy_per_word``.
        #       this is done by finding the minimum chars required to invalidate
        #       the inequality, and then rejecting any phrases that are shorter.
        self._entropy_per_char = _average_wordset_entropy(wordset)
        self._min_chars = int(self.entropy / self._entropy_per_char)
        if spaces:
            self._min_chars += self.size-1
            self._sep = _USPACE
        else:
            self._sep = _UEMPTY
        ##log.debug("PhraseGenerator(): entropy/word=%r entropy/char=%r min_chars=%r",
        ##          self.entropy_rate, self._entropy_per_char, self._min_chars)

    #=============================================================================
    # helpers
    #=============================================================================
    def _gen(self):
        while True:
            symbols = [self.rng.choice(self.wordset) for _ in irange(self.size)]
            # check that it satisfies minimum self-information limit
            # set by min_complexity. i.e., reject strings like "aaaaaaaa"
            if _average_entropy(symbols) > self._min_entropy:
                secret = self._sep.join(symbols)
                # check that we don't fall below per-character limit
                # on self information. see __init__ for explanation
                if len(secret) >= self._min_chars:
                    return secret

    #=============================================================================
    # eoc
    #=============================================================================

def generate(size=None, entropy=None, count=None,
             preset=None, charset=None, wordset=None,
             **kwds):
    """Generate one or more random password / passphrases.

    This function uses :mod:`random.SystemRandom` to generate
    one or more passwords; it can be configured to generate
    alphanumeric passwords, or full english phrases.
    The complexity of the password can be specified
    by size, or by the desired amount of entropy.

    Usage Example::

        >>> # generate random english phrase with 48 bits of entropy
        >>> from passlib import pwd
        >>> pwd.generate()
        'cairn pen keys flaw'

        >>> # generate a random alphanumeric string with default 52 bits of entropy
        >>> pwd.generate(entropy=52, preset="safe52")
        'DnBHvDjMK6'

    :param size:
        Size of resulting password, measured in characters or words.
        If omitted, the size is autocalculated based on the ``entropy`` parameter.

    :param entropy:
        Strength of resulting password, measured in bits of Shannon entropy
        (defaults to 48).

        Based on the mode in use, the ``size`` parameter will be
        autocalculated so that that an attacker will need an average of
        ``2**(entropy-1)`` attempts to correctly guess the password
        (this measurement assumes the attacker knows the mode
        and configuration options in use, but nothing of the RNG state).

        If both ``entropy`` and ``size`` are specified,
        the larger effective size will be used.

    :param count:
        By default this generates a single password.
        However, if ``count`` is specified, it will return a list
        containing ``count`` passwords instead.

    :param preset:
        Optionally use a pre-defined word-set or character-set
        when generating a password. This option cannot be combined
        with ``charset`` or ``wordset``; if all three are omitted,
        this function defaults to ``preset="beale"``.

        There are currently three presets available:

        ``"safe52"``

            preset which outputs random alphanumeric passwords,
            using a 52-element character set containing the characters A-Z and 0-9,
            except for ``1IiLl0OoS5`` (which were omitted due to their visual similarity).
            This charset has ~5.7 bits of entropy per character.

        ``"diceware"``

            preset which outputs random english phrases,
            drawn randomly from a list of 7776 english words set down
            by the `Diceware <http://world.std.com/~reinhold/diceware.html>`_ project.
            This wordset has ~12.9 bits of entropy per word.

        ``"beale"``

            variant of the Diceware wordlist as edited by
            Alan Beale, also available from the diceware project.
            This wordset has ~12.9 bits of entropy per word.

    :param charset:
        Optionally specifies a string of characters to use when randomly
        generating a password. This option cannot be combined
        with ``preset`` or ``wordset``.

    :param wordset:
        Optionally specifies a list/set of words to use when randomly
        generating a passphrase. This option cannot be combined
        with ``preset`` or ``charset``.

    :param spaces:
        When generating a passphrase, controls whether spaces
        should be inserted between the words. Defaults to ``True``.

    :returns:
        :class:`!str` containing randomly generated password,
        or list of 1+ passwords if ``count`` is specified.
    """
    # create generator from options
    kwds.update(size=size, entropy=entropy)
    if wordset:
        # create generator from wordset
        if preset or charset:
            raise TypeError(_PCW_MSG)
        gen = PhraseGenerator(wordset, **kwds)
    elif charset:
        # create generator from charset
        if preset:
            raise TypeError(_PCW_MSG)
        gen = WordGenerator(charset, **kwds)
    else:
        # create generator from preset
        kwds.update(preset=preset)
        if not preset or preset in wordsets:
            assert preset not in charsets
            gen = PhraseGenerator(**kwds)
        elif preset in charsets:
            gen = WordGenerator(**kwds)
        else:
            raise KeyError("unknown preset: %r" % preset)

    # return passwords
    return gen(count)

#=============================================================================
# password strength measurement
#=============================================================================
def strength(symbols):
    """
    roughly estimate the strength of the password.
    this is a bit better than just using len(password).

    param symbols: a sequence of symbols (e.g. password string/unicode)
    returns: password strength estimate [float]
    """
    return _average_entropy(symbols, total=True)

CLASSIFICATIONS = [
    (10, 0), # everything < 10 returns 0 (weak)
    (20, 1), # 10 <= s < 20 returns 1 (maybe still too weak)
    (None, 2), # everything else returns 2
    # last tuple must be (None, MAXVAL)
]

def classify(symbols, classifications=CLASSIFICATIONS):
    """
    roughly classify the strength of the password.
    this is a bit better than just using len(password).

    :param symbols:
        a sequence of symbols (e.g. password string/unicode)
    :param classifications:
        list of tuples with the format ``(limit, classification)``.

    :returns:
        classification value

    Usage Example::

        >>> from passlib import pwd
        >>> pwd.classify("10011001")
        0
        >>> pwd.classify("secret")
        1
        >>> pwd.classify("Eer6aiya")
        2
    """
    s = strength(symbols)
    for limit, classification in classifications:
        if limit is None or s < limit:
            return classification
    else:
       raise ValueError("classifications needs to end with a (None, MAXVAL) tuple")

#=============================================================================
# eof
#=============================================================================
