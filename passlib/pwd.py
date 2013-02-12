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

.. autofunction:: generate
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
from passlib.utils.compat import irange, u
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

#: default preset used by generate()
default_preset = "beale"

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
# password generator
#=============================================================================
def generate(size=None, entropy=None, count=None,
             preset=None, charset=None, wordset=None,
             spaces=True, rng=rng):
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
    #
    # load preset
    #
    if not (preset or charset or wordset):
        preset = default_preset
    if preset:
        if charset or wordset:
            raise TypeError(_PCW_MSG)
        if preset in charsets:
            if preset in wordsets: # pragma: no cover -- sanity check
                raise RuntimeError("ambiguous preset name: %r" % preset)
            charset = charsets[preset]
        elif preset in wordsets:
            wordset = wordsets[preset]
            if wordset is None:
                wordset = _load_wordset(preset)
        else:
            raise ValueError("unknown preset: %r" % preset)

    #
    # choose word/phrase mode, validate source, and calc entropy rates
    #
    if wordset:
        if charset:
            raise TypeError(_PCW_MSG)
        phrase_mode = True
        if len(set(wordset)) != len(wordset):
            raise ValueError("`wordset` cannot contain duplicate elements")
        entropy_per_elem = logf(len(wordset), 2)
        entropy_per_char = _entropy_per_char(wordset)
        log.debug("generate(): entropy/word=%r entropy/char=%r",
                  entropy_per_elem, entropy_per_char)
    else:
        assert charset
        phrase_mode = False
        if len(set(charset)) != len(charset):
            raise ValueError("`charset` cannot contain duplicate elements")
        entropy_per_elem = logf(len(charset), 2)
        log.debug("generate(): entropy/char=%r", entropy_per_elem)

    #
    # init size
    #
    if size is None:
        size = 1
        if entropy is None:
            entropy = default_entropy
    elif size < 1:
        raise ValueError("`size` must be positive integer")
    if entropy is not None:
        if entropy <= 0:
            raise ValueError("`entropy` must be positive number")
        size = max(size, int(ceil(entropy / entropy_per_elem)))

    #
    # create mode-specific generator
    #
    if phrase_mode:
        # in order to ensure a brute force attack against underlying
        # charset isn't more successful than one against the wordset,
        # we need to reject any passwords which contain so many short
        # words that ``chars_in_phrase * entropy_per_char <
        #              words_in_phrase * entropy_per_word``.
        # this is done by calculating the minimum chars required to satisfy
        # the inequality, and then rejecting any phrases that are shorter.
        min_chars = int(size * entropy_per_elem / entropy_per_char)
        log.debug("generate(): min_chars=%r", min_chars)
        if spaces:
            min_chars += size-1
            sep = _USPACE
        else:
            sep = _UEMPTY
        def gen():
            while True:
                secret = sep.join(rng.choice(wordset) for _ in irange(size))
                if len(secret) >= min_chars:
                    return secret
                log.debug("skipping %r due to size", secret)
    else:
        def gen():
            return getrandstr(rng, charset, size)

    #
    # return result
    #
    if count is None:
        return gen()
    else:
        return [gen() for _ in irange(count)]

#=============================================================================
# eof
#=============================================================================
