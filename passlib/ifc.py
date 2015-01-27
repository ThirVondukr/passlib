"""passlib.ifc - abstract interfaces used by Passlib"""
#=============================================================================
# imports
#=============================================================================
# core
import logging; log = logging.getLogger(__name__)
import sys
# site
# pkg
# local
__all__ = [
    "PasswordHash",
]

#=============================================================================
# 2/3 compatibility helpers
#=============================================================================
def recreate_with_metaclass(meta):
    """class decorator that re-creates class using metaclass"""
    def builder(cls):
        if meta is type(cls):
            return cls
        return meta(cls.__name__, cls.__bases__, cls.__dict__.copy())
    return builder

#=============================================================================
# PasswordHash interface
#=============================================================================
from abc import ABCMeta, abstractmethod, abstractproperty

# TODO: make this actually use abstractproperty(),
#       now that we dropped py25, 'abc' is always available.

@recreate_with_metaclass(ABCMeta)
class PasswordHash(object):
    """This class describes an abstract interface which all password hashes
    in Passlib adhere to. Under Python 2.6 and up, this is an actual
    Abstract Base Class built using the :mod:`!abc` module.

    See the Passlib docs for full documentation.
    """
    #===================================================================
    # class attributes
    #===================================================================

    #---------------------------------------------------------------
    # general information
    #---------------------------------------------------------------
    ##name
    ##setting_kwds
    ##context_kwds

    #---------------------------------------------------------------
    # salt information -- if 'salt' in setting_kwds
    #---------------------------------------------------------------
    ##min_salt_size
    ##max_salt_size
    ##default_salt_size
    ##salt_chars
    ##default_salt_chars

    #---------------------------------------------------------------
    # rounds information -- if 'rounds' in setting_kwds
    #---------------------------------------------------------------
    ##min_rounds
    ##max_rounds
    ##default_rounds
    ##rounds_cost

    #---------------------------------------------------------------
    # encoding info -- if 'encoding' in context_kwds
    #---------------------------------------------------------------
    ##default_encoding

    #===================================================================
    # primary methods
    #===================================================================
    @classmethod
    @abstractmethod
    def encrypt(cls, secret, **setting_and_context_kwds): # pragma: no cover -- abstract method
        """encrypt secret, returning resulting hash"""
        raise NotImplementedError("must be implemented by subclass")

    @classmethod
    @abstractmethod
    def verify(cls, secret, hash, **context_kwds): # pragma: no cover -- abstract method
        """verify secret against hash, returns True/False"""
        raise NotImplementedError("must be implemented by subclass")

    #===================================================================
    # configuration
    #===================================================================
    @classmethod
    @abstractmethod
    def using(cls, **kwds):
        """
        Return another hasher object (typically a subclass),
        which integrates the configuration options specified by ``kwds``.

        .. todo::

            document which options are accepted.

        :returns:
            typically returns a subclass for most hasher implementations.

        .. todo::

            add this method to main documentation.
        """
        raise NotImplementedError("must be implemented by subclass")

    #===================================================================
    # migration
    #===================================================================
    @classmethod
    @abstractmethod
    def needs_update(cls, hash, secret=None):
        """
        check if hash configuration is outside desired bounds.

        :param hash:
            hash string to examine

        :param secret:
            optional secret known to have verified against the provided hash.
            (this is used by some hashes to detect legacy algorithm mistakes).

        :return:
            whether secret needs re-hashing.

        .. todo::

            add this method to main documentation.
        """
        raise NotImplementedError("must be implemented by subclass")

    #===================================================================
    # additional methods
    #===================================================================
    @classmethod
    @abstractmethod
    def identify(cls, hash): # pragma: no cover -- abstract method
        """check if hash belongs to this scheme, returns True/False"""
        raise NotImplementedError("must be implemented by subclass")

    @classmethod
    @abstractmethod
    def genconfig(cls, **setting_kwds): # pragma: no cover -- abstract method
        """compile settings into a configuration string for genhash()"""
        raise NotImplementedError("must be implemented by subclass")

    @classmethod
    @abstractmethod
    def genhash(cls, secret, config, **context_kwds): # pragma: no cover -- abstract method
        """generated hash for secret, using settings from config/hash string"""
        raise NotImplementedError("must be implemented by subclass")

    #===================================================================
    # undocumented methods / attributes
    #===================================================================
    # the following entry points are used internally by passlib,
    # and aren't documented as part of the exposed interface.
    # they are subject to change between releases,
    # but are documented here so there's a list of them *somewhere*.

    #---------------------------------------------------------------
    # checksum information - defined for many hashes
    #---------------------------------------------------------------
    ## checksum_chars
    ## checksum_size

    #---------------------------------------------------------------
    # experimental methods
    #---------------------------------------------------------------

    ##@classmethod
    ##def normhash(cls, hash):
    ##    """helper to clean up non-canonic instances of hash.
    ##    currently only provided by bcrypt() to fix an historical passlib issue.
    ##    """

    # experimental helper to parse hash into components.
    ##@classmethod
    ##def parsehash(cls, hash, checksum=True, sanitize=False):
    ##    """helper to parse hash into components, returns dict"""

    # experiment helper to estimate bitsize of different hashes,
    # implement for GenericHandler, but may be currently be off for some hashes.
    # want to expand this into a way to programmatically compare
    # "strengths" of different hashes and hash algorithms.
    # still needs to have some factor for estimate relative cost per round,
    # ala in the style of the scrypt whitepaper.
    ##@classmethod
    ##def bitsize(cls, **kwds):
    ##    """returns dict mapping component -> bits contributed.
    ##    components currently include checksum, salt, rounds.
    ##    """

    #===================================================================
    # eoc
    #===================================================================

#=============================================================================
# eof
#=============================================================================
