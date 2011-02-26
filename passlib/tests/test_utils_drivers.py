"""tests for passlib.pwhash -- (c) Assurance Technologies 2003-2009"""
#=========================================================
#imports
#=========================================================
from __future__ import with_statement
#core
import re
import hashlib
from logging import getLogger
#site
#pkg
from passlib.utils import rng, getrandstr
from passlib.utils.drivers import ExtHash, StaticHash
from passlib.tests.utils import HandlerCase
#module
log = getLogger(__name__)

#=========================================================
#sample algorithms - these serve as known quantities
# to test the unittests themselves, as well as other
# parts of passlib. they shouldn't be used as actual password schemes.
#=========================================================
class UnsaltedHash(StaticHash):
    "example algorithm which lacks a salt"
    name = "unsalted_example"

    @classmethod
    def identify(cls, hash):
        return bool(hash and re.match("^[0-9a-f]{40}$", hash))

    @classmethod
    def from_string(cls, hash):
        if hash is None:
            return cls()
        if not cls.identify(hash):
            raise ValueError, "not a unsalted-example hash"
        return cls(checksum=hash, strict=True)

    def to_string(self):
        return self.checksum

    def calc_checksum(self, secret):
        return hashlib.sha1("boblious" + secret).hexdigest()

class SaltedHash(ExtHash):
    "example algorithm with a salt"
    name = "salted_example"
    setting_kwds = ("salt",)

    min_salt_chars = max_salt_chars = 2
    checksum_chars = 40
    salt_charset = checksum_charset = "0123456789abcdef"

    @classmethod
    def identify(cls, hash):
        return bool(hash and re.match("^@salt[0-9a-f]{42}$", hash))

    @classmethod
    def from_string(cls, hash):
        if not cls.identify(hash):
            raise ValueError, "not a salted-example hash"
        return cls(salt=hash[5:7], checksum=hash[7:], strict=True)

    _stub_checksum = '0' * 40
    def to_string(self):
        return "@salt%s%s" % (self.salt, self.checksum or self._stub_checksum)

    def calc_checksum(self, secret):
        return hashlib.sha1(self.salt + secret + self.salt).hexdigest()

#=========================================================
#test sample algorithms - really a self-test of HandlerCase
#=========================================================

#TODO: provide data samples for algorithms
# (positive knowns, negative knowns, invalid identify)

class UnsaltedHashTest(HandlerCase):
    handler = UnsaltedHash

    known_correct_hashes = []

class SaltedHashTest(HandlerCase):
    handler = SaltedHash

    known_correct_hashes = []

#=========================================================
#
#=========================================================

#TODO: test registry system

#=========================================================
#EOF
#=========================================================
