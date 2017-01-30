"""
passlib.tests.test_handlers_cisco - tests for Cisco-specific algorithms
"""
#=============================================================================
# imports
#=============================================================================
from __future__ import absolute_import, division, print_function
# core
import logging
log = logging.getLogger(__name__)
# site
# pkg
from passlib import hash
from passlib.utils.compat import u
from .utils import UserHandlerMixin, HandlerCase
from .test_handlers import UPASS_TABLE
# module
__all__ = [
    "cisco_pix_test",
    "cisco_asa_test",
    "cisco_type7_test",
]
#=============================================================================
# cisco pix
#=============================================================================
class cisco_pix_test(UserHandlerMixin, HandlerCase):
    handler = hash.cisco_pix
    requires_user = False

    known_correct_hashes = [
        #
        # http://www.perlmonks.org/index.pl?node_id=797623
        #
        ("cisco", "2KFQnbNIdI.2KYOU"),

        #
        # http://www.hsc.fr/ressources/breves/pix_crack.html.en
        #
        ("hsc", "YtT8/k6Np8F1yz2c"),

        #
        # www.freerainbowtables.com/phpBB3/viewtopic.php?f=2&t=1441
        #
        ("", "8Ry2YjIyt7RRXU24"),
        (("cisco", "john"), "hN7LzeyYjw12FSIU"),
        (("cisco", "jack"), "7DrfeZ7cyOj/PslD"),

        #
        # http://comments.gmane.org/gmane.comp.security.openwall.john.user/2529
        #
        (("ripper", "alex"), "h3mJrcH0901pqX/m"),
        (("cisco", "cisco"), "3USUcOPFUiMCO4Jk"),
        (("cisco", "cisco1"), "3USUcOPFUiMCO4Jk"),
        (("CscFw-ITC!", "admcom"), "lZt7HSIXw3.QP7.R"),
        ("cangetin", "TynyB./ftknE77QP"),
        (("cangetin", "rramsey"), "jgBZqYtsWfGcUKDi"),

        #
        # http://openwall.info/wiki/john/sample-hashes
        #
        (("phonehome", "rharris"), "zyIIMSYjiPm0L7a6"),

        #
        # from JTR 1.7.9
        #
        ("test1", "TRPEas6f/aa6JSPL"),
        ("test2", "OMT6mXmAvGyzrCtp"),
        ("test3", "gTC7RIy1XJzagmLm"),
        ("test4", "oWC1WRwqlBlbpf/O"),
        ("password", "NuLKvvWGg.x9HEKO"),
        ("0123456789abcdef", ".7nfVBEIEu4KbF/1"),

        #
        # custom
        #
        (("cisco1", "cisco1"), "jmINXNH6p1BxUppp"),

        # ensures utf-8 used for unicode
        (UPASS_TABLE, 'CaiIvkLMu2TOHXGT'),
        ]

#=============================================================================
# cisco_asa
#=============================================================================
def _get_secret(value):
    """extract secret from secret or (secret, user) tuple"""
    if isinstance(value, tuple):
        return value[0]
    else:
        return value

class cisco_asa_test(UserHandlerMixin, HandlerCase):
    handler = hash.cisco_asa
    requires_user = False

    known_correct_hashes = [
        # format: ((secret, user), hash)

        #
        # passlib test vectors
        # TODO: these have not been confirmed by an outside source,
        #       nor tested against an official implementation.
        #       for now, these only confirm we haven't had a regression.
        #

        # 8 char password -- should be same as pix
        (('01234567', ''), '0T52THgnYdV1tlOF'),
        (('01234567', '36'), 'oY0Dh6RVC9KFlopL'),
        (('01234567', 'user'), 'PNZ4ycbbZ0jp1.j1'),
        (('01234567', 'user1234'), 'PNZ4ycbbZ0jp1.j1'),

        # 12 char password -- should be same as pix
        (('0123456789ab', ''), 'S31BxZOGlAigndcJ'),
        (('0123456789ab', '36'), 'JqCXavOaaaTn9B5y'),
        (('0123456789ab', 'user'), 'f.T4BKdzdNkjxQl7'),
        (('0123456789ab', 'user1234'), 'f.T4BKdzdNkjxQl7'),

        # 13 char password -- ASA should switch to larger padding
        (('0123456789abc', ''), 'XGUn8JhVAnJsaJ69'),  # e.g: cisco_pix is 'eacOpB7vE7ZDukSF'
        (('0123456789abc', '36'), 'feNbQYEDXynZXMJH'),
        (('0123456789abc', 'user'), '8Q/FZeam5ai1A47p'),
        (('0123456789abc', 'user1234'), '8Q/FZeam5ai1A47p'),

        # 16 char password -- verify fencepost
        (('0123456789abcdef', ''), 'YO.dC.tE77bB35aH'),
        (('0123456789abcdef', '36'), 'ekOxFx1Mqt8hL3vJ'),
        (('0123456789abcdef', 'user'), 'IneB.wc9sfRzLPoh'),
        (('0123456789abcdef', 'user1234'), 'IneB.wc9sfRzLPoh'),

        # 27 char password -- ASA should still append user
        (('0123456789abcdefqwertyuiopa', ''), '4wp19zS3OCe.2jt5'),
        (('0123456789abcdefqwertyuiopa', '36'), 'GlGggqfEc19br12c'),
        (('0123456789abcdefqwertyuiopa', 'user'), 'zynfWw3UtszxLMgL'),
        (('0123456789abcdefqwertyuiopa', 'user1234'), 'zynfWw3UtszxLMgL'),

        # 28 char password -- ASA shouldn't append user anymore
        (('0123456789abcdefqwertyuiopas', ''), 'W6nbOddI0SutTK7m'),
        (('0123456789abcdefqwertyuiopas', '36'), 'W6nbOddI0SutTK7m'),
        (('0123456789abcdefqwertyuiopas', 'user'), 'W6nbOddI0SutTK7m'),
        (('0123456789abcdefqwertyuiopas', 'user1234'), 'W6nbOddI0SutTK7m'),

        # 32 char password -- verify fencepost
        (('0123456789abcdefqwertyuiopasdfgh', ''), '5hPT/iC6DnoBxo6a'),
        (('0123456789abcdefqwertyuiopasdfgh', '36'), '5hPT/iC6DnoBxo6a'),
        (('0123456789abcdefqwertyuiopasdfgh', 'user'), '5hPT/iC6DnoBxo6a'),
        (('0123456789abcdefqwertyuiopasdfgh', 'user1234'), '5hPT/iC6DnoBxo6a'),

        # 33 char password -- ASA should truncate to 32 (should be same as above)
        (('0123456789abcdefqwertyuiopasdfghj', ''), '5hPT/iC6DnoBxo6a'),
        (('0123456789abcdefqwertyuiopasdfghj', '36'), '5hPT/iC6DnoBxo6a'),
        (('0123456789abcdefqwertyuiopasdfghj', 'user'), '5hPT/iC6DnoBxo6a'),
        (('0123456789abcdefqwertyuiopasdfghj', 'user1234'), '5hPT/iC6DnoBxo6a'),

        # unicode password -- assumes cisco will use utf-8 encoding
        ((u('t\xe1ble'), ''), 'xQXX755BKYRl0ZpQ'),
        ((u('t\xe1ble'), '36'), 'Q/43xXKmIaKLycSj'),
        ((u('t\xe1ble'), 'user'), 'Og8fB4NyF0m5Ed9c'),
        ((u('t\xe1ble'), 'user1234'), 'Og8fB4NyF0m5Ed9c'),
    ]

    # append all the cisco_pix hashes w/ password < 13 chars ... those should be the same.
    known_correct_hashes.extend(row for row in cisco_pix_test.known_correct_hashes
                                if len(_get_secret(row[0])) < 13)

#=============================================================================
# cisco type 7
#=============================================================================
class cisco_type7_test(HandlerCase):
    handler = hash.cisco_type7
    salt_bits = 4
    salt_type = int

    known_correct_hashes = [
        #
        # http://mccltd.net/blog/?p=1034
        #
        ("secure ", "04480E051A33490E"),

        #
        # http://insecure.org/sploits/cisco.passwords.html
        #
        ("Its time to go to lunch!",
         "153B1F1F443E22292D73212D5300194315591954465A0D0B59"),

        #
        # http://blog.ioshints.info/2007/11/type-7-decryption-in-cisco-ios.html
        #
        ("t35t:pa55w0rd", "08351F1B1D431516475E1B54382F"),

        #
        # http://www.m00nie.com/2011/09/cisco-type-7-password-decryption-and-encryption-with-perl/
        #
        ("hiImTesting:)", "020E0D7206320A325847071E5F5E"),

        #
        # http://packetlife.net/forums/thread/54/
        #
        ("cisco123", "060506324F41584B56"),
        ("cisco123", "1511021F07257A767B"),

        #
        # source ?
        #
        ('Supe&8ZUbeRp4SS', "06351A3149085123301517391C501918"),

        #
        # custom
        #

        # ensures utf-8 used for unicode
        (UPASS_TABLE, '0958EDC8A9F495F6F8A5FD'),
    ]

    known_unidentified_hashes = [
        # salt with hex value
        "0A480E051A33490E",

        # salt value > 52. this may in fact be valid, but we reject it for now
        # (see docs for more).
        '99400E4812',
    ]

    def test_90_decode(self):
        """test cisco_type7.decode()"""
        from passlib.utils import to_unicode, to_bytes

        handler = self.handler
        for secret, hash in self.known_correct_hashes:
            usecret = to_unicode(secret)
            bsecret = to_bytes(secret)
            self.assertEqual(handler.decode(hash), usecret)
            self.assertEqual(handler.decode(hash, None), bsecret)

        self.assertRaises(UnicodeDecodeError, handler.decode,
                          '0958EDC8A9F495F6F8A5FD', 'ascii')

    def test_91_salt(self):
        """test salt value border cases"""
        handler = self.handler
        self.assertRaises(TypeError, handler, salt=None)
        handler(salt=None, use_defaults=True)
        self.assertRaises(TypeError, handler, salt='abc')
        self.assertRaises(ValueError, handler, salt=-10)
        self.assertRaises(ValueError, handler, salt=100)

        self.assertRaises(TypeError, handler.using, salt='abc')
        self.assertRaises(ValueError, handler.using, salt=-10)
        self.assertRaises(ValueError, handler.using, salt=100)
        with self.assertWarningList("salt/offset must be.*"):
            subcls = handler.using(salt=100, relaxed=True)
        self.assertEqual(subcls(use_defaults=True).salt, 52)

#=============================================================================
# eof
#=============================================================================
