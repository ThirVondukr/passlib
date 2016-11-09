"""passlib.pwd -- password generation helpers

TODO
====
* XXX: add a "crack time" estimation to generate & classify?
  might be useful to give people better idea of what measurements mean.

* unittests for generation code

* straighten out any unicode issues this code may have.
    - primarily, this should always return unicode (currently doesn't)

* don't like existing wordsets.
    - diceware has some weird bordercases that average users may not like
    - electrum's set isn't large enough for these purposes
    - looking into modified version of wordfrequency.info's 5k list
      (could merge w/ diceware, and remove commonly used passwords)

* should recommend zxcvbn in the docs for this module.
"""
#=============================================================================
# imports
#=============================================================================
from __future__ import absolute_import, division, print_function, unicode_literals
# core
import codecs
from collections import defaultdict
from math import ceil, log as logf
import logging; log = logging.getLogger(__name__)
import os
# site
# pkg
from passlib import exc
from passlib.utils.compat import PY2, irange, itervalues, int_types
from passlib.utils import rng, getrandstr, to_unicode, memoized_property
# local
__all__ = [
    'genword',
    'genphrase',
]

#=============================================================================
# constants
#=============================================================================

entropy_aliases = dict(
    # barest protection from throttled online attack
    unsafe=12,

    # some protection from unthrottled online attack
    weak=24,

    # some protection from offline attacks
    fair=36,

    # reasonable protection from offline attacks
    strong=48,

    # very good protection from offline attacks
    secure=60,
)

#=============================================================================
# internal helpers
#=============================================================================

def _superclasses(obj, cls):
    """return remaining classes in object's MRO after cls"""
    mro = type(obj).__mro__
    return mro[mro.index(cls)+1:]


def _self_info_rate(source):
    """
    returns 'rate of self-information' --
    i.e. average (per-symbol) entropy of the sequence **source**,
    where probability of a given symbol occurring is calculated based on
    the number of occurrences within the sequence itself.

    if all elements of the source are unique, this should equal ``log(len(source), 2)``.

    :arg source:
        iterable containing 0+ symbols
        (e.g. list of strings or ints, string of characters, etc).

    :returns:
        float bits of entropy
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
    # NOTE: the following performs ``- sum(value / size * logf(value / size, 2) for value in values)``,
    #       it just does so with as much pulled out of the sum() loop as possible...
    return logf(size, 2) - sum(value * logf(value, 2) for value in values) / size


# def _total_self_info(source):
#     """
#     return total self-entropy of a sequence
#     (the average entropy per symbol * size of sequence)
#     """
#     return _self_info_rate(source) * len(source)


#: path to passlib's data dir
_data_dir = os.path.join(os.path.dirname(__file__), "_data")


def _load_wordset(name):
    """
    load wordset from compressed datafile within package data.

    returns tuple so result can be hashed & randomly accessed.
    """
    source = os.path.join(_data_dir, "%s.words.txt" % name)
    with codecs.open(source, "r", "utf-8") as fh:
        gen = (word.strip() for word in fh)
        words = tuple(word for word in gen if word)
    log.debug("loaded %d-element wordset from %r", len(words), source)
    return words


def _dup_repr(source):
    """return repr of duplicates in string/list, for use in error message"""
    seen = set()
    dups = set()
    for elem in source:
        (dups if elem in seen else seen).add(elem)
    dups = sorted(dups)
    trunc = 8
    if len(dups) > trunc:
        trunc = 5
    dup_repr = ", ".join(repr(str(word)) for word in dups[:trunc])
    if len(dups) > trunc:
        dup_repr += ", ... plus %d others" % (len(dups) - trunc)
    return dup_repr

#=============================================================================
# base generator class
#=============================================================================
class SequenceGenerator(object):
    """
    base class used by word & phrase generators.

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

    :param length:
        Optionally specify the length of password to generate,
        measured in whatever symbols the subclass uses (characters or words).
        Note that if both ``length`` and ``entropy`` are specified,
        the larger requested size will be used.

        Also exposed as a readonly attribute.

    .. autoattribute:: length
    .. autoattribute:: symbol_count
    .. autoattribute:: entropy_per_symbol
    .. autoattribute:: entropy

    Subclassing
    -----------
    Subclasses must implement the ``.__next__()`` method,
    and set ``.symbol_count`` before calling base ``__init__`` method.
    """
    #=============================================================================
    # instance attrs
    #=============================================================================

    #: requested size of final password
    length = None

    #: requested entropy of final password
    requested_entropy = "strong"

    #: random number source to use
    rng = rng

    #: number of potential symbols
    symbol_count = None

    #=============================================================================
    # init
    #=============================================================================
    def __init__(self, entropy=None, length=None, rng=None, **kwds):

        # make sure subclass set things up correctly
        assert self.symbol_count is not None, "subclass must set .symbol_count"

        # init length & entropy
        if entropy is not None or length is None:
            if entropy is None:
                entropy = self.requested_entropy
            entropy = entropy_aliases.get(entropy, entropy)
            if entropy <= 0:
                raise ValueError("`entropy` must be positive number")
            min_length = int(ceil(entropy / self.entropy_per_symbol))
            if length is None or length < min_length:
                length = min_length

        self.requested_entropy = entropy

        if length < 1:
            raise ValueError("`length` must be positive integer")
        self.length = length

        # init other common options
        if rng is not None:
            self.rng = rng

        # hand off to parent
        if kwds and _superclasses(self, SequenceGenerator) == (object,):
            raise TypeError("Unexpected keyword(s): %s" % ", ".join(kwds.keys()))
        super(SequenceGenerator, self).__init__(**kwds)

    #=============================================================================
    # informational helpers
    #=============================================================================

    @memoized_property
    def entropy_per_symbol(self):
        """
        average entropy per symbol (assuming all symbols have equal probability)
        """
        return logf(self.symbol_count, 2)

    @memoized_property
    def entropy(self):
        """
        actual entropy of generated passwords.
        (should always be LCM of entropy_per_symbol >= self.entropy)
        """
        return self.length * self.entropy_per_symbol

    #=============================================================================
    # generation
    #=============================================================================
    def __next__(self):
        """main generation function, should create one password/phrase"""
        raise NotImplementedError("implement in subclass")

    def __call__(self, returns=None):
        """
        frontend used by genword() / genphrase() to create passwords
        """
        if returns is None:
            return next(self)
        elif isinstance(returns, int_types):
            return [next(self) for _ in irange(returns)]
        elif returns is iter:
            return self
        else:
            raise exc.ExpectedTypeError(returns, "<None>, int, or <iter>", "returns")

    def __iter__(self):
        return self

    if PY2:
        def next(self):
            return self.__next__()

    #=============================================================================
    # eoc
    #=============================================================================

#=============================================================================
# password generator
#=============================================================================
class WordGenerator(SequenceGenerator):
    """
    class which generates passwords by randomly choosing from a string of unique characters.

    :param chars:
        custom character string to draw from.

    :param charset:
        predefined charset to draw from.

    :param \*\*kwds:
        all other keywords passed to :class:`SequenceGenerator`.

    .. autoattribute:: chars
    .. autoattribute:: charset
    .. autoattribute:: default_charsets
    """
    #=============================================================================
    # class attributes
    #=============================================================================

    #: classwide dict of predefined characters sets
    default_charsets = dict(
        # ascii letters, digits, and some punctuation
        ascii72='0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!@#$%^&*?/',

        # ascii letters and digits
        ascii62='0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ',

        # ascii50, without visually similar '1IiLl', '0Oo', '5S', '8B'
        ascii50='234679abcdefghjkmnpqrstuvwxyzACDEFGHJKMNPQRTUVWXYZ',

        # lower case hexadecimal
        hex='0123456789abcdef',
    )

    #=============================================================================
    # instance attrs
    #=============================================================================

    #: Predefined character set in use (set to None for instances using custom 'chars')
    charset = "ascii62"

    #: string of chars to draw from -- usually filled in from charset
    chars = None

    #=============================================================================
    # init
    #=============================================================================
    def __init__(self, chars=None, charset=None, **kwds):

        # init chars and charset
        if chars:
            if charset:
                raise TypeError("`chars` and `charset` are mutually exclusive")
        else:
            if not charset:
                charset = self.charset
                assert charset
            chars = self.default_charsets[charset]
        self.charset = charset
        chars = to_unicode(chars, param="chars")
        if len(set(chars)) != len(chars):
            raise ValueError("`chars` cannot contain duplicate elements")
        self.chars = chars

        # hand off to parent
        super(WordGenerator, self).__init__(**kwds)
        # log.debug("WordGenerator(): entropy/char=%r", self.entropy_per_symbol)

    #=============================================================================
    # informational helpers
    #=============================================================================

    @memoized_property
    def symbol_count(self):
        return len(self.chars)

    #=============================================================================
    # generation
    #=============================================================================

    def __next__(self):
        while True:
            secret = getrandstr(self.rng, self.chars, self.length)

            # XXX: could do things like optionally ensure character groups
            #      (e.g. letters & punctuation) are included.

            return secret

    #=============================================================================
    # eoc
    #=============================================================================


def genword(entropy=None, length=None, returns=None, **kwds):
    """Generate one or more random passwords.

    This function uses :mod:`random.SystemRandom` to generate
    one or more passwords; it can be configured to generate
    alphanumeric passwords, or full english phrases.
    The complexity of the password can be specified
    by size, or by the desired amount of entropy.

    Usage Example::

        >>> # generate a random alphanumeric string with 48 bits of entropy (the default)
        >>> pwd.genword()
        'DnBHvDjMK6'

        >>> # generate a random hexadecimal string with 52 bits of entropy
        >>> pwd.genword(entropy=52, charset="hex")
        'DnBHvDjMK6'

    :param entropy:
        Strength of resulting password, measured in bits of Shannon entropy
        (defaults to 48).  An appropriate **length** value will be calculated
        based on the requested entropy amount, and the size of the character set.

        If both ``entropy`` and ``length`` are specified,
        the larger effective length will be used.

        This can also be one of a handful of aliases to predefined
        entropy amounts: ``"weak"`` (24), ``"fair"`` (36),
        ``"strong"`` (48), and ``"secure"`` (56).

    :param length:
        Size of resulting password, measured in characters.
        If omitted, the size is auto-calculated based on the ``entropy`` parameter.

    :param returns:
        If ``None`` (the default), this function will generate a single password.
        If an integer, this function will return a list containing that many passwords.
        If the ``iter`` constant, will return an iterator that yields passwords.

    :param charset:
        The character set to draw from, if not specified explicitly by **chars**.
        Defaults to ``"ascii62"``, but can be any of:

        * ``"ascii62"`` -- all digits and ascii upper & lowercase letters.
          Provides ~5.95 entropy per character.

        * ``"ascii50"`` -- subset which excludes visually similar characters
          (``1IiLl0Oo5S8B``). Provides ~5.64 entropy per character.

        * ``"ascii72"`` -- all digits and ascii upper & lowercase letters,
          as well as some punctuation. Provides ~6.17 entropy per character.

        * ``"hex"`` -- Lower case hexadecimal.  Providers 4 bits of entropy per character.

    :param chars:

        Optionally specify custom charset as a string of characters.
        This option cannot be combined with **charset**.

    :returns:
        :class:`!str` containing randomly generated password
        (or list of 1+ passwords if ``choices`` is specified)
    """
    gen = WordGenerator(length=length, entropy=entropy, **kwds)
    return gen(returns)

#=============================================================================
# pass phrase generator
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
    # class attrs
    #=============================================================================

    #: dict of preset word sets,
    #: values set to None are lazy-loaded from disk by _load_wordset()
    default_wordsets = dict(
        diceware=None,
        beale=None,
        electrum=None,
    )

    #=============================================================================
    # instance attrs
    #=============================================================================

    #: predefined wordset to use
    wordset = "beale"

    #: list of words to draw from
    words = None

    #: separator to use when joining words
    sep = " "

    #=============================================================================
    # init
    #=============================================================================
    def __init__(self, wordset=None, words=None, sep=None, **kwds):

        # init words and wordset
        if words is not None:
            if wordset is not None:
                raise TypeError("`words` and `wordset` are mutually exclusive")
        else:
            if wordset is None:
                wordset = self.wordset
                assert wordset
            words = self.default_wordsets[wordset]
            if words is None:
                words = self.default_wordsets[wordset] = _load_wordset(wordset)
        self.wordset = wordset
        if not isinstance(words, (list, tuple)):
            words = tuple(words)
        if len(set(words)) != len(words):
            raise ValueError("`words` cannot contain duplicate elements: " + _dup_repr(words))
        self.words = words

        # init separator
        if sep is None:
            sep = self.sep
        sep = to_unicode(sep, param="sep")
        self.sep = sep

        # hand off to parent
        super(PhraseGenerator, self).__init__(**kwds)
        ##log.debug("PhraseGenerator(): entropy/word=%r entropy/char=%r min_chars=%r",
        ##          self.entropy_per_symbol, self.entropy_per_char, self.min_chars)

    #=============================================================================
    # informational helpers
    #=============================================================================

    @memoized_property
    def symbol_count(self):
        return len(self.words)

    #=============================================================================
    # generation
    #=============================================================================

    def __next__(self):
        while True:
            # create random word
            words = (self.rng.choice(self.words) for _ in irange(self.length))

            # join using separator
            return self.sep.join(words)

    #=============================================================================
    # eoc
    #=============================================================================


def genphrase(entropy=None, length=None, returns=None, **kwds):
    """Generate one or more random password / passphrases.

    This function uses :mod:`random.SystemRandom` to generate
    one or more passwords; it can be configured to generate
    alphanumeric passwords, or full english phrases.
    The complexity of the password can be specified
    by size, or by the desired amount of entropy.

    Usage Example::

        >>> # generate random english phrase with 48 bits of entropy
        >>> from passlib import pwd
        >>> pwd.genphrase()
        'cairn pen keys flaw'

    :param entropy:
        Strength of resulting password, measured in bits of Shannon entropy
        (defaults to 48).

        Based on the mode in use, the ``length`` parameter will be
        autocalculated so that that an attacker will need an average of
        ``2**(entropy-1)`` attempts to correctly guess the password
        (this measurement assumes the attacker knows the mode
        and configuration options in use, but nothing of the RNG state).

        If both ``entropy`` and ``length`` are specified,
        the larger effective size will be used.

    :param length:
        Length of resulting password, measured in words.
        If omitted, the size is autocalculated based on the ``entropy`` parameter.

    :param returns:
        If ``None`` (the default), this function will generate a single password.
        If an integer, this function will return a list containing that many passwords.
        If the ``iter`` constant, will return an iterator that yields passwords.

    :param wordset:
        Optionally use a pre-defined word-set when generating a password.
        There are currently two presets available, the default is ``"beale"``:

        ``"diceware"``

            preset which outputs random english phrases,
            drawn randomly from a list of 7776 english words set down
            by the `Diceware <http://world.std.com/~reinhold/diceware.html>`_ project.
            This wordset has ~12.9 bits of entropy per word.

        ``"beale"``

            variant of the Diceware wordlist as edited by
            Alan Beale, also available from the diceware project.
            This wordset has ~12.9 bits of entropy per word.

    :param words:
        Optionally specifies a list/set of words to use when randomly
        generating a passphrase. This option cannot be combined
        with ``wordset``.

    :param sep:
        Optional separator to use when joining words.
        Defaults to ``" "`` (a space), but can be an empty string, a hyphen, etc.

    :returns:
        :class:`!str` containing randomly generated password,
        or list of 1+ passwords if ``count`` is specified.
    """
    gen = PhraseGenerator(entropy=entropy, length=length, **kwds)
    return gen(returns)

#=============================================================================
# strength measurement
#
# NOTE:
# for a little while, had rough draft of password strength measurement alg here.
# but not sure if there's value in yet another measurement algorithm,
# that's not just duplicating the effort of libraries like zxcbn.
# may revive it later, but for now, leaving some refs to others out there:
#    * NIST 800-63 has simple alg
#    * zxcvbn (https://tech.dropbox.com/2012/04/zxcvbn-realistic-password-strength-estimation/)
#      might also be good, and has approach similar to composite approach i was already thinking about,
#      but much more well thought out.
#    * passfault (https://github.com/c-a-m/passfault) looks thorough,
#      but may have licensing issues, plus porting to python looks like very big job :(
#    * give a look at running things through zlib - might be able to cheaply
#      catch extra redundancies.
# zxcvbn -
#    after some looking, it's not clear which is latest copy.
#    * https://github.com/dropbox/python-zxcvbn -- official, not updated since 2013
#    * https://github.com/rpearl/python-zxcvbn -- fork used by dropbox dev, not updated since 2013
#           released to pypi - https://pypi.python.org/pypi/zxcvbn/1.0
#    * https://github.com/moreati/python-zxcvbn -- has some updates as of july 2015
#           * https://github.com/gordon86/python-zxcvbn (fork of above, released to pypi)
#               - https://pypi.python.org/pypi/zxcvbn-py3/1.1 [2015-10]
#=============================================================================

#=============================================================================
# eof
#=============================================================================
