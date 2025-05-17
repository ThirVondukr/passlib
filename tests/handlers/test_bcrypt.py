from passlib.handlers.bcrypt import bcrypt
from tests.lib.base_test import BaseHandlerTestCase
from tests.test_handlers import UPASS_TABLE

CONFIG_2 = "$2$05$" + "." * 22
CONFIG_A = "$2a$05$" + "." * 22


class TestBcrypt(BaseHandlerTestCase):
    handler = bcrypt
    known_correct_hashes = [
        #
        # from JTR 1.7.9
        #
        ("U*U*U*U*", "$2a$05$c92SVSfjeiCD6F2nAD6y0uBpJDjdRkt0EgeC4/31Rf2LUZbDRDE.O"),
        ("U*U***U", "$2a$05$WY62Xk2TXZ7EvVDQ5fmjNu7b0GEzSzUXUh2cllxJwhtOeMtWV3Ujq"),
        ("U*U***U*", "$2a$05$Fa0iKV3E2SYVUlMknirWU.CFYGvJ67UwVKI1E2FP6XeLiZGcH3MJi"),
        ("*U*U*U*U", "$2a$05$.WRrXibc1zPgIdRXYfv.4uu6TD1KWf0VnHzq/0imhUhuxSxCyeBs2"),
        ("", "$2a$05$Otz9agnajgrAe0.kFVF9V.tzaStZ2s1s4ZWi/LY4sw2k/MTVFj/IO"),
        #
        # test vectors from http://www.openwall.com/crypt v1.2
        # note that this omits any hashes that depend on crypt_blowfish's
        # various CVE-2011-2483 workarounds (hash 2a and \xff\xff in password,
        # and any 2x hashes); and only contain hashes which are correct
        # under both crypt_blowfish 1.2 AND OpenBSD.
        #
        ("U*U", "$2a$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW"),
        ("U*U*", "$2a$05$CCCCCCCCCCCCCCCCCCCCC.VGOzA784oUp/Z0DY336zx7pLYAy0lwK"),
        ("U*U*U", "$2a$05$XXXXXXXXXXXXXXXXXXXXXOAcXxm9kjPGEMsLznoKqmqw7tc8WCx4a"),
        ("", "$2a$05$CCCCCCCCCCCCCCCCCCCCC.7uG0VCzI2bS7j6ymqJi9CdcdxiRTWNy"),
        (
            "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
            "0123456789chars after 72 are ignored",
            "$2a$05$abcdefghijklmnopqrstuu5s2v8.iXieOjg/.AySBTTZIIVFJeBui",
        ),
        (b"\xa3", "$2a$05$/OK.fbVrR/bpIqNJ5ianF.Sa7shbm4.OzKpvFnX1pQLmQW96oUlCq"),
        (
            b"\xff\xa3345",
            "$2a$05$/OK.fbVrR/bpIqNJ5ianF.nRht2l/HRhr6zmCp9vYUvvsqynflf9e",
        ),
        (b"\xa3ab", "$2a$05$/OK.fbVrR/bpIqNJ5ianF.6IflQkJytoRVc1yuaNtHfiuq.FRlSIS"),
        (
            b"\xaa" * 72 + b"chars after 72 are ignored as usual",
            "$2a$05$/OK.fbVrR/bpIqNJ5ianF.swQOIzjOiJ9GHEPuhEkvqrUyvWhEMx6",
        ),
        (
            b"\xaa\x55" * 36,
            "$2a$05$/OK.fbVrR/bpIqNJ5ianF.R9xrDjiycxMbQE2bp.vgqlYpW5wx2yy",
        ),
        (
            b"\x55\xaa\xff" * 24,
            "$2a$05$/OK.fbVrR/bpIqNJ5ianF.9tQZzcJfm3uj2NvJ/n5xkhpqLrMpWCe",
        ),
        # keeping one of their 2y tests, because we are supporting that.
        (b"\xa3", "$2y$05$/OK.fbVrR/bpIqNJ5ianF.Sa7shbm4.OzKpvFnX1pQLmQW96oUlCq"),
        #
        # 8bit bug (fixed in 2y/2b)
        #
        # NOTE: see assert_lacks_8bit_bug() for origins of this test vector.
        (b"\xd1\x91", "$2y$05$6bNw2HLQYeqHYyBfLMsv/OUcZd0LKP39b87nBw3.S2tVZSqiQX6eu"),
        #
        # bsd wraparound bug (fixed in 2b)
        #
        # NOTE: if backend is vulnerable, password will hash the same as '0'*72
        #       ("$2a$04$R1lJ2gkNaoPGdafE.H.16.nVyh2niHsGJhayOHLMiXlI45o8/DU.6"),
        #       rather than same as ("0123456789"*8)[:72]
        # 255 should be sufficient, but checking
        (
            ("0123456789" * 26)[:254],
            "$2a$04$R1lJ2gkNaoPGdafE.H.16.1MKHPvmKwryeulRe225LKProWYwt9Oi",
        ),
        (
            ("0123456789" * 26)[:255],
            "$2a$04$R1lJ2gkNaoPGdafE.H.16.1MKHPvmKwryeulRe225LKProWYwt9Oi",
        ),
        (
            ("0123456789" * 26)[:256],
            "$2a$04$R1lJ2gkNaoPGdafE.H.16.1MKHPvmKwryeulRe225LKProWYwt9Oi",
        ),
        (
            ("0123456789" * 26)[:257],
            "$2a$04$R1lJ2gkNaoPGdafE.H.16.1MKHPvmKwryeulRe225LKProWYwt9Oi",
        ),
        #
        # from py-bcrypt tests
        #
        ("", "$2a$06$DCq7YPn5Rq63x1Lad4cll.TV4S6ytwfsfvkgY8jIucDrjc8deX1s."),
        ("a", "$2a$10$k87L/MF28Q673VKh8/cPi.SUl7MU/rWuSiIDDFayrKk/1tBsSQu4u"),
        ("abc", "$2a$10$WvvTPHKwdBJ3uk0Z37EMR.hLA2W6N9AEBhEgrAOljy2Ae5MtaSIUi"),
        (
            "abcdefghijklmnopqrstuvwxyz",
            "$2a$10$fVH8e28OQRj9tqiDXs1e1uxpsjN0c7II7YPKXua2NAKYvM6iQk7dq",
        ),
        (
            "~!@#$%^&*()      ~!@#$%^&*()PNBFRD",
            "$2a$10$LgfYWkbzEvQ4JakH7rOvHe0y8pHKF9OaFgwUZ2q7W2FFZmZzJYlfS",
        ),
        #
        # custom test vectors
        #
        # ensures utf-8 used for unicode
        (UPASS_TABLE, "$2a$05$Z17AXnnlpzddNUvnC6cZNOSwMA/8oNiKnHTHTwLlBijfucQQlHjaG"),
        # ensure 2b support
        (UPASS_TABLE, "$2b$05$Z17AXnnlpzddNUvnC6cZNOSwMA/8oNiKnHTHTwLlBijfucQQlHjaG"),
        ("", CONFIG_2 + "J2ihDv8vVf7QZ9BsaRrKyqs2tkn55Yq"),
        ("", CONFIG_A + "J2ihDv8vVf7QZ9BsaRrKyqs2tkn55Yq"),
        ("abc", CONFIG_2 + "XuQjdH.wPVNUZ/bOfstdW/FqB8QSjte"),
        ("abc", CONFIG_A + "ev6gDwpVye3oMCUpLY85aTpfBNHD0Ga"),
        ("abc" * 23, CONFIG_2 + "XuQjdH.wPVNUZ/bOfstdW/FqB8QSjte"),
        ("abc" * 23, CONFIG_A + "2kIdfSj/4/R/Q6n847VTvc68BXiRYZC"),
        ("abc" * 24, CONFIG_2 + "XuQjdH.wPVNUZ/bOfstdW/FqB8QSjte"),
        ("abc" * 24, CONFIG_A + "XuQjdH.wPVNUZ/bOfstdW/FqB8QSjte"),
        ("abc" * 24 + "x", CONFIG_2 + "XuQjdH.wPVNUZ/bOfstdW/FqB8QSjte"),
        ("abc" * 24 + "x", CONFIG_A + "XuQjdH.wPVNUZ/bOfstdW/FqB8QSjte"),
    ]
    known_correct_configs = [
        (
            "$2a$04$uM6csdM8R9SXTex/gbTaye",
            UPASS_TABLE,
            "$2a$04$uM6csdM8R9SXTex/gbTayezuvzFEufYGd2uB6of7qScLjQ4GwcD4G",
        ),
    ]
