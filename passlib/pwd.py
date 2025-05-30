import codecs
import contextlib
import os
from collections import defaultdict
from collections.abc import Hashable, MutableMapping
from importlib import resources
from math import ceil, log2

from passlib import exc
from passlib._logging import logger
from passlib.utils import getrandstr, rng, to_unicode
from passlib.utils.decor import memoized_property

# local
__all__ = [
    "genword",
    "default_charsets",
    "genphrase",
    "default_wordsets",
]

# XXX: rename / publically document this map?
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


def _superclasses(obj, cls):
    """return remaining classes in object's MRO after cls"""
    mro = type(obj).__mro__
    return mro[mro.index(cls) + 1 :]


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
        values = counts.values()
    if not size:
        return 0
    # NOTE: the following performs ``- sum(value / size * logf(value / size, 2) for value in values)``,
    #       it just does so with as much pulled out of the sum() loop as possible...
    return log2(size) - sum(value * log2(value) for value in values) / size


# def _total_self_info(source):
#     """
#     return total self-entropy of a sequence
#     (the average entropy per symbol * size of sequence)
#     """
#     return _self_info_rate(source) * len(source)


def _open_asset_path(path, encoding=None):
    """
    :param asset_path:
        string containing absolute path to file,
        or package-relative path using format
        ``"python.module:relative/file/path"``.

    :returns:
        filehandle opened in 'rb' mode
        (unless encoding explicitly specified)
    """
    if encoding:
        return codecs.getreader(encoding)(_open_asset_path(path))
    if os.path.isabs(path):
        return open(path, "rb")  # noqa: SIM115
    package, sep, subpath = path.partition(":")
    if not sep:
        raise ValueError(
            "asset path must be absolute file path "
            f"or use 'pkg.name:sub/path' format: {path!r}"
        )
    return resources.files(package).joinpath(subpath).open("rb")


#: type aliases
_sequence_types = (list, tuple)
_set_types = (set, frozenset)

#: set of elements that ensure_unique() has validated already.
_ensure_unique_cache: set[Hashable] = set()


def _ensure_unique(source, param="source"):
    """
    helper for generators --
    Throws ValueError if source elements aren't unique.
    Error message will display (abbreviated) repr of the duplicates in a string/list
    """
    # check cache to speed things up for frozensets / tuples / strings
    cache = _ensure_unique_cache
    hashable = True
    try:
        if source in cache:
            return True
    except TypeError:
        hashable = False

    # check if it has dup elements
    if isinstance(source, _set_types) or len(set(source)) == len(source):
        if hashable:
            with contextlib.suppress(TypeError):
                # XXX: under pypy, "list() in set()" above doesn't throw TypeError,
                #      but trying to add unhashable it to a set *does*.
                cache.add(source)
        return True

    # build list of duplicate values
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

    # throw error
    raise ValueError(f"`{param}` cannot contain duplicate elements: {dup_repr}")


class SequenceGenerator:
    """
    Base class used by word & phrase generators.

    These objects take a series of options, corresponding
    to those of the :func:`generate` function.
    They act as callables which can be used to generate a password
    or a list of 1+ passwords. They also expose some read-only
    informational attributes.

    Parameters
    ----------
    :param entropy:
        Optionally specify the amount of entropy the resulting passwords
        should contain (as measured with respect to the generator itself).
        This will be used to auto-calculate the required password size.

    :param length:
        Optionally specify the length of password to generate,
        measured as count of whatever symbols the subclass uses (characters or words).
        Note if ``entropy`` requires a larger minimum length,
        that will be used instead.

    :param rng:
        Optionally provide a custom RNG source to use.
        Should be an instance of :class:`random.Random`,
        defaults to :class:`random.SystemRandom`.

    Attributes
    ----------
    .. autoattribute:: length
    .. autoattribute:: symbol_count
    .. autoattribute:: entropy_per_symbol
    .. autoattribute:: entropy

    Subclassing
    -----------
    Subclasses must implement the ``.__next__()`` method,
    and set ``.symbol_count`` before calling base ``__init__`` method.
    """

    #: requested size of final password
    length = None

    #: requested entropy of final password
    requested_entropy = "strong"

    #: random number source to use
    rng = rng

    #: number of potential symbols (must be filled in by subclass)
    symbol_count = None

    def __init__(self, entropy=None, length=None, rng=None, **kwds):
        # make sure subclass set things up correctly
        assert self.symbol_count is not None, "subclass must set .symbol_count"

        # init length & requested entropy
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
            raise TypeError("Unexpected keyword(s): {}".format(", ".join(kwds.keys())))
        super().__init__(**kwds)

    @memoized_property
    def entropy_per_symbol(self):
        """
        Average entropy per symbol (assuming all symbols have equal probability)
        """
        return log2(self.symbol_count)

    @memoized_property
    def entropy(self):
        """
        Effective entropy of generated passwords.

        This value will always be a multiple of :attr:`entropy_per_symbol`.
        If entropy is specified in constructor, :attr:`length` will be chosen so
        so that this value is the smallest multiple >= :attr:`requested_entropy`.
        """
        return self.length * self.entropy_per_symbol

    def __next__(self):
        """main generation function, should create one password/phrase"""
        raise NotImplementedError("implement in subclass")

    def __call__(self, returns=None):
        """
        frontend used by genword() / genphrase() to create passwords
        """
        if returns is None:
            return next(self)
        if isinstance(returns, int):
            return [next(self) for _ in range(returns)]
        if returns is iter:
            return self
        raise exc.ExpectedTypeError(returns, "<None>, int, or <iter>", "returns")

    def __iter__(self):
        return self


#: global dict of predefined characters sets
default_charsets = dict(
    # ascii letters, digits, and some punctuation
    ascii_72="0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!@#$%^&*?/",
    # ascii letters and digits
    ascii_62="0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
    # ascii_50, without visually similar '1IiLl', '0Oo', '5S', '8B'
    ascii_50="234679abcdefghjkmnpqrstuvwxyzACDEFGHJKMNPQRTUVWXYZ",
    # lower case hexadecimal
    hex="0123456789abcdef",
)


class WordGenerator(SequenceGenerator):
    """
    Class which generates passwords by randomly choosing from a string of unique characters.

    Parameters
    ----------
    :param chars:
        custom character string to draw from.

    :param charset:
        predefined charset to draw from.

    :param \\*\\*kwds:
        all other keywords passed to the :class:`SequenceGenerator` parent class.

    Attributes
    ----------
    .. autoattribute:: chars
    .. autoattribute:: charset
    .. autoattribute:: default_charsets
    """

    #: Predefined character set in use (set to None for instances using custom 'chars')
    charset = "ascii_62"

    #: string of chars to draw from -- usually filled in from charset
    chars = None

    def __init__(self, chars=None, charset=None, **kwds):
        # init chars and charset
        if chars:
            if charset:
                raise TypeError("`chars` and `charset` are mutually exclusive")
        else:
            if not charset:
                charset = self.charset
                assert charset
            chars = default_charsets[charset]
        self.charset = charset
        chars = to_unicode(chars, param="chars")
        _ensure_unique(chars, param="chars")
        self.chars = chars

        # hand off to parent
        super().__init__(**kwds)
        # log.debug("WordGenerator(): entropy/char=%r", self.entropy_per_symbol)

    @memoized_property
    def symbol_count(self):
        return len(self.chars)

    def __next__(self):
        # XXX: could do things like optionally ensure certain character groups
        #      (e.g. letters & punctuation) are included
        return getrandstr(self.rng, self.chars, self.length)


def genword(entropy=None, length=None, returns=None, **kwds):
    """Generate one or more random passwords.

    This function uses :mod:`random.SystemRandom` to generate
    one or more passwords using various character sets.
    The complexity of the password can be specified
    by size, or by the desired amount of entropy.

    Usage Example::

        >>> # generate a random alphanumeric string with 48 bits of entropy (the default)
        >>> from passlib import pwd
        >>> pwd.genword()
        'DnBHvDjMK6'

        >>> # generate a random hexadecimal string with 52 bits of entropy
        >>> pwd.genword(entropy=52, charset="hex")
        '310f1a7ac793f'

    :param entropy:
        Strength of resulting password, measured in 'guessing entropy' bits.
        An appropriate **length** value will be calculated
        based on the requested entropy amount, and the size of the character set.

        This can be a positive integer, or one of the following preset
        strings: ``"weak"`` (24), ``"fair"`` (36),
        ``"strong"`` (48), and ``"secure"`` (56).

        If neither this or **length** is specified, **entropy** will default
        to ``"strong"`` (48).

    :param length:
        Size of resulting password, measured in characters.
        If omitted, the size is auto-calculated based on the **entropy** parameter.

        If both **entropy** and **length** are specified,
        the stronger value will be used.

    :param returns:
        Controls what this function returns:

        * If ``None`` (the default), this function will generate a single password.
        * If an integer, this function will return a list containing that many passwords.
        * If the ``iter`` constant, will return an iterator that yields passwords.

    :param chars:

        Optionally specify custom string of characters to use when randomly
        generating a password. This option cannot be combined with **charset**.

    :param charset:

        The predefined character set to draw from (if not specified by **chars**).
        There are currently four presets available:

        * ``"ascii_62"`` (the default) -- all digits and ascii upper & lowercase letters.
          Provides ~5.95 entropy per character.

        * ``"ascii_50"`` -- subset which excludes visually similar characters
          (``1IiLl0Oo5S8B``). Provides ~5.64 entropy per character.

        * ``"ascii_72"`` -- all digits and ascii upper & lowercase letters,
          as well as some punctuation. Provides ~6.17 entropy per character.

        * ``"hex"`` -- Lower case hexadecimal.  Providers 4 bits of entropy per character.

    :returns:
        :class:`!str` string containing randomly generated password;
        or list of 1+ passwords if :samp:`returns={int}` is specified.
    """
    gen = WordGenerator(length=length, entropy=entropy, **kwds)
    return gen(returns)


def _load_wordset(asset_path):
    """
    load wordset from compressed datafile within package data.
    file should be utf-8 encoded

    :param asset_path:
        string containing  absolute path to wordset file,
        or "python.module:relative/file/path".

    :returns:
        tuple of words, as loaded from specified words file.
    """
    # open resource file, convert to tuple of words (strip blank lines & ws)
    with _open_asset_path(asset_path, "utf-8") as fh:
        gen = (word.strip() for word in fh)
        words = tuple(word for word in gen if word)

    # NOTE: works but not used
    # # detect if file uses "<int> <word>" format, and strip numeric prefix
    # def extract(row):
    #     idx, word = row.replace("\t", " ").split(" ", 1)
    #     if not idx.isdigit():
    #         raise ValueError("row is not dice index + word")
    #     return word
    # try:
    #     extract(words[-1])
    # except ValueError:
    #     pass
    # else:
    #     words = tuple(extract(word) for word in words)

    logger.debug("loaded %d-element wordset from %r", len(words), asset_path)
    return words


class WordsetDict(MutableMapping):
    """
    Special mapping used to store dictionary of wordsets.
    Different from a regular dict in that some wordsets
    may be lazy-loaded from an asset path.
    """

    #: dict of key -> asset path
    paths = None

    #: dict of key -> value
    _loaded = None

    def __init__(self, *args, **kwds):
        self.paths = {}
        self._loaded = {}
        super().__init__(*args, **kwds)

    def __getitem__(self, key):
        try:
            return self._loaded[key]
        except KeyError:
            pass
        path = self.paths[key]
        value = self._loaded[key] = _load_wordset(path)
        return value

    def set_path(self, key, path):
        """
        set asset path to lazy-load wordset from.
        """
        self.paths[key] = path

    def __setitem__(self, key, value):
        self._loaded[key] = value

    def __delitem__(self, key):
        if key in self:
            del self._loaded[key]
            self.paths.pop(key, None)
        else:
            del self.paths[key]

    @property
    def _keyset(self):
        keys = set(self._loaded)
        keys.update(self.paths)
        return keys

    def __iter__(self):
        return iter(self._keyset)

    def __len__(self):
        return len(self._keyset)

    # NOTE: speeds things up, and prevents contains from lazy-loading
    def __contains__(self, key):
        return key in self._loaded or key in self.paths


#: dict of predefined word sets.
#: key is name of wordset, value should be sequence of words.
default_wordsets = WordsetDict()

# register the wordsets built into passlib
for name in ["eff_long", "eff_short", "eff_prefixed", "bip39"]:
    default_wordsets.set_path(name, f"passlib:_data/wordsets/{name}.txt")


class PhraseGenerator(SequenceGenerator):
    """class which generates passphrases by randomly choosing
    from a list of unique words.

    :param wordset:
        wordset to draw from.
    :param preset:
        name of preset wordlist to use instead of ``wordset``.
    :param spaces:
        whether to insert spaces between words in output (defaults to ``True``).
    :param \\*\\*kwds:
        all other keywords passed to the :class:`SequenceGenerator` parent class.

    .. autoattribute:: wordset
    """

    #: predefined wordset to use
    wordset = "eff_long"

    #: list of words to draw from
    words = None

    #: separator to use when joining words
    sep = " "

    def __init__(self, wordset=None, words=None, sep=None, **kwds):
        # load wordset
        if words is not None:
            if wordset is not None:
                raise TypeError("`words` and `wordset` are mutually exclusive")
        else:
            if wordset is None:
                wordset = self.wordset
                assert wordset
            words = default_wordsets[wordset]
        self.wordset = wordset

        # init words
        if not isinstance(words, _sequence_types):
            words = tuple(words)
        _ensure_unique(words, param="words")
        self.words = words

        # init separator
        if sep is None:
            sep = self.sep
        sep = to_unicode(sep, param="sep")
        self.sep = sep

        # hand off to parent
        super().__init__(**kwds)
        ##log.debug("PhraseGenerator(): entropy/word=%r entropy/char=%r min_chars=%r",
        ##          self.entropy_per_symbol, self.entropy_per_char, self.min_chars)

    @memoized_property
    def symbol_count(self):
        return len(self.words)

    def __next__(self):
        words = (self.rng.choice(self.words) for _ in range(self.length))
        return self.sep.join(words)


def genphrase(entropy=None, length=None, returns=None, **kwds):
    """Generate one or more random password / passphrases.

    This function uses :mod:`random.SystemRandom` to generate
    one or more passwords; it can be configured to generate
    alphanumeric passwords, or full english phrases.
    The complexity of the password can be specified
    by size, or by the desired amount of entropy.

    Usage Example::

        >>> # generate random phrase with 48 bits of entropy
        >>> from passlib import pwd
        >>> pwd.genphrase()
        'gangly robbing salt shove'

        >>> # generate a random phrase with 52 bits of entropy
        >>> # using a particular wordset
        >>> pwd.genword(entropy=52, wordset="bip39")
        'wheat dilemma reward rescue diary'

    :param entropy:
        Strength of resulting password, measured in 'guessing entropy' bits.
        An appropriate **length** value will be calculated
        based on the requested entropy amount, and the size of the word set.

        This can be a positive integer, or one of the following preset
        strings: ``"weak"`` (24), ``"fair"`` (36),
        ``"strong"`` (48), and ``"secure"`` (56).

        If neither this or **length** is specified, **entropy** will default
        to ``"strong"`` (48).

    :param length:
        Length of resulting password, measured in words.
        If omitted, the size is auto-calculated based on the **entropy** parameter.

        If both **entropy** and **length** are specified,
        the stronger value will be used.

    :param returns:
        Controls what this function returns:

        * If ``None`` (the default), this function will generate a single password.
        * If an integer, this function will return a list containing that many passwords.
        * If the ``iter`` builtin, will return an iterator that yields passwords.

    :param words:

        Optionally specifies a list/set of words to use when randomly generating a passphrase.
        This option cannot be combined with **wordset**.

    :param wordset:

        The predefined word set to draw from (if not specified by **words**).
        There are currently four presets available:

        ``"eff_long"`` (the default)

            Wordset containing 7776 english words of ~7 letters.
            Constructed by the EFF, it offers ~12.9 bits of entropy per word.

            This wordset (and the other ``"eff_"`` wordsets)
            were `created by the EFF <https://www.eff.org/deeplinks/2016/07/new-wordlists-random-passphrases>`_
            to aid in generating passwords.  See their announcement page
            for more details about the design & properties of these wordsets.

        ``"eff_short"``

            Wordset containing 1296 english words of ~4.5 letters.
            Constructed by the EFF, it offers ~10.3 bits of entropy per word.

        ``"eff_prefixed"``

            Wordset containing 1296 english words of ~8 letters,
            selected so that they each have a unique 3-character prefix.
            Constructed by the EFF, it offers ~10.3 bits of entropy per word.

        ``"bip39"``

            Wordset of 2048 english words of ~5 letters,
            selected so that they each have a unique 4-character prefix.
            Published as part of Bitcoin's `BIP 39 <https://github.com/bitcoin/bips/blob/master/bip-0039/english.txt>`_,
            this wordset has exactly 11 bits of entropy per word.

            This list offers words that are typically shorter than ``"eff_long"``
            (at the cost of slightly less entropy); and much shorter than
            ``"eff_prefixed"`` (at the cost of a longer unique prefix).

    :param sep:
        Optional separator to use when joining words.
        Defaults to ``" "`` (a space), but can be an empty string, a hyphen, etc.

    :returns:
        :class:`!str` containing randomly generated passphrase;
        or list of 1+ passphrases if :samp:`returns={int}` is specified.
    """
    gen = PhraseGenerator(entropy=entropy, length=length, **kwds)
    return gen(returns)


# =============================================================================
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
# =============================================================================
