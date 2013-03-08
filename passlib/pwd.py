"""
=================================================
:mod:`passlib.pwd` -- password generation helpers
=================================================

.. todo::

    This module is still a work in progress.

    * Unit tests !!!

    * Add password strength measurement helper(s).
      Currently looking at the NIST 800-63 algorithm, though this incorrectly
      estimates a number of generation schemes.

    * Sanity checks

.. autofunction:: generate(size=None, entropy=None, count=None, preset=None, charset=None, wordset=None, spaces=True)
"""
#=============================================================================
# imports
#=============================================================================
from __future__ import division
# core
from collections import defaultdict
from hashlib import sha256
from math import ceil, log as logf
import logging; log = logging.getLogger(__name__)
import os
import zlib
# site
# pkg
from passlib.utils.compat import PY3, irange, u
from passlib.utils import rng, getrandstr
# local
__all__ = [
    'generate',
]

#=============================================================================
# constants
#=============================================================================

#: default entropy for generated passwords
default_entropy = 48

#: default presets
default_charset = "safe52"
default_wordset = "beale"

#: dict of preset characters sets
charsets = dict(
    safe52='2346789ABCDEFGHJKMNPQRTUVWXYZabcdefghjkmnpqrstuvwxyz',
)

#: dict of preset wordsets, values=None are lazy-loaded from disk
wordsets = dict(
    diceware=None,
    beale=None,
    electrum=None,
)

#: misc helper constants
_PCW_MSG = "`preset`, `charset`, and `wordset` are mutually exclusive"
_USPACE = u(" ")
_UEMPTY = u("")

#=============================================================================
# internal helpers
#=============================================================================
def _entropy_per_char(words):
    """return the average entropy per character in a given wordset,
    using each char's frequency in the wordset as the probability of occurrence.

    :arg words:
        iterable containing 1+ words, each of which are themselves
        iterables containing 1+ characters.
    :returns:
        float bits of entropy
    """
    hist = {}
    for word in words:
        for char in word:
            try:
                hist[char] += 1
            except KeyError:
                hist[char] = 1
    values = hist.values()
    norm = 1.0 / sum(values)
    return -sum(count * norm * logf(count * norm, 2) for count in values)

def _load_wordset(name):
    "helper load compressed wordset from package data"
    # load wordset from data file
    source = os.path.join(os.path.dirname(__file__), "_data",
                          "%s.wordset.z" % name)
    with open(source, "rb") as fh:
        data = fh.read()

    # decompress and return wordset
    words = wordsets[name] = zlib.decompress(data).decode("utf-8").splitlines()
    log.debug("loaded %d-element wordset from %r", len(words), source)
    return words

#=============================================================================
# password generators
#=============================================================================
class SecretGenerator(object):
    """base class used by word & phrase generators.

    These objects take a series of options, corresponding
    to those of the :func:`generate` function.
    They act as callables which can be used to generate a password,
    or a list of passwords, as well as exposing some read-only
    informational attributes:

    .. autoattribute:: size
    .. autoattribute:: entropy
    .. autoattribute:: entropy_per_elem
    """
    #=============================================================================
    # instance attrs
    #=============================================================================

    #: entropy rate per element of generated password
    entropy_per_elem = None

    #: requested size of final passwords
    size = None

    #: random number source to use
    rng = rng

    #=============================================================================
    # init
    #=============================================================================
    def __init__(self, size=None, entropy=None, rng=None, **kwds):
        # NOTE: subclass should have already set .entropy_per_elem
        if size is None:
            size = 1
            if entropy is None:
                entropy = default_entropy
        elif size < 1:
            raise ValueError("`size` must be positive integer")
        if entropy is not None:
            if entropy <= 0:
                raise ValueError("`entropy` must be positive number")
            size = max(size, int(ceil(entropy / self.entropy_per_elem)))
        self.size = size
        if rng is not None:
            self.rng = rng
        super(SecretGenerator, self).__init__(**kwds)

    #=============================================================================
    # helpers
    #=============================================================================
    @property
    def entropy(self):
        """entropy of generated passwords (with respect to the scheme)"""
        return self.size * self.entropy_per_elem

    def _gen(self):
        "main generation function"
        raise NotImplementedError, "implement in subclass"

    #=============================================================================
    # iter & callable frontend
    #=============================================================================
    def __call__(self, count=None):
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

class WordGenerator(SecretGenerator):
    """helper class created by create_generator(),
    used to generate passwords from a charset.

    see :func:`passlib.pwd.create_generator` for details.
    """
    #=============================================================================
    # instance attrs
    #=============================================================================

    #: string of chars to draw from
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
        self.entropy_per_elem = logf(len(charset), 2)
        super(WordGenerator, self).__init__(**kwds)
        ##log.debug("WordGenerator(): entropy/char=%r", self.entropy_per_elem)

    #=============================================================================
    # helpers
    #=============================================================================
    def _gen(self):
        return getrandstr(self.rng, self.charset, self.size)

    #=============================================================================
    # eoc
    #=============================================================================

class PhraseGenerator(SecretGenerator):
    """helper class created by create_generator(),
    used to generate passphrases from a wordset.
    """
    #=============================================================================
    # instance attrs
    #=============================================================================

    #: list of words to draw from
    wordset = None

    #: average entropy per char
    entropy_per_char = None

    #: minimum size string this will output, to prevent low-entropy
    #: phrases from leaking through.
    min_chars = None

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
        self.wordset = wordset
        self.entropy_per_elem = logf(len(wordset), 2)
        super(PhraseGenerator, self).__init__(**kwds)
        # NOTE: regarding min_chars:
        #       in order to ensure a brute force attack against underlying
        #       charset isn't more successful than one against the wordset,
        #       we need to reject any passwords which contain so many short
        #       words that ``chars_in_phrase * entropy_per_char <
        #                    words_in_phrase * entropy_per_word``.
        #       this is done by finding the minimum chars required to invalidate
        #       the inequality, and then rejecting any phrases that are shorter.
        self.entropy_per_char = _entropy_per_char(wordset)
        self.min_chars = int(self.entropy / self.entropy_per_char)
        if spaces:
            self.min_chars += self.size-1
            self._sep = _USPACE
        else:
            self._sep = _UEMPTY
        ##log.debug("PhraseGenerator(): entropy/word=%r entropy/char=%r min_chars=%r",
        ##          self.entropy_per_elem, self.entropy_per_char, self.min_chars)

    #=============================================================================
    # helpers
    #=============================================================================
    def _gen(self):
        while True:
            secret = self._sep.join(self.rng.choice(self.wordset)
                                    for _ in irange(self.size))
            if len(secret) >= self.min_chars: # see __init__ for explanation
                return secret

    #=============================================================================
    # eoc
    #=============================================================================

#=============================================================================
# frontend
#=============================================================================
def generate(size=None, entropy=None, count=None,
             preset=None, charset=None, wordset=None,
             **kwds):
    """generate one or more random password / passphrases.

    This function uses :mod:`random.SystemRandom` to generate
    one or more passwords; it can be configured to generate
    alphanumeric passwords, or full english phrases.
    The complexity of the password can be specified
    by size, or by the desired amount of entropy.

    .. warning::

        This function is primarily intended for generating temporary
        passwords for new user accounts. If used as an aid to generate
        your own passwords, be sure your system's RNG state is safe,
        and that you use a sufficiently high ``entropy`` value for
        the intended purpose.

    Usage Example::

        >>> from passlib.pwd import generate
        >>> # generate random alphanumeric string with default 48 bits of entropy
        >>> generate_password()
        'DnBHvDjMK6'

        >>> # generate random english phrase with 52 bits of entropy
        >>> generate_password(entropy=52, mode="phrase")
        'cairn penn keyes flaw stem'

    :param size:
        Size of resulting password, measured in characters or words.
        If omitted, the size is autocalculated based on the ``entropy`` parameter.

    :param entropy:
        Strength of resulting password, measured in bits of Shannon entropy
        (defaults to 48).

        Based on the ``mode`` in use, the ``size`` parameter will be
        autocalculated so that that an attacker will need an average of
        ``2**(entropy-1)`` attempts to correctly guess the password
        (this measurement assumes the attacker knows the mode
        and configuration options in use, but nothing of the RNG state).

        If both ``entropy`` and ``size`` are specified,
        the larger of the two values will be used.

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

        * ``"safe52"`` -- preset which outputs random alphanumeric passwords,
          using a 52-element character set containing the characters A-Z and 0-9,
          except for ``1IiLl0OoS5`` (which were omitted due to their visual similarity).
          This charset has ~5.7 bits of entropy per character.

        * ``"diceware"`` -- preset which outputs random english phrases,
          drawn randomly from a list of 7776 english words set down
          by the `Diceware <http://world.std.com/~reinhold/diceware.html>` project.
          This wordset has ~12.9 bits of entropy per word.

        * ``"beale"`` -- variant of the Diceware wordlist as edited by
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
# eof
#=============================================================================
