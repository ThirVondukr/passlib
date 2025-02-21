import warnings

import pytest

from passlib import hash
from tests.test_handlers import UPASS_WAV
from tests.utils import HandlerCase, TestCase


class ldap_pbkdf2_test(TestCase):
    def test_wrappers(self):
        """test ldap pbkdf2 wrappers"""

        assert hash.ldap_pbkdf2_sha1.verify(
            "password",
            "{PBKDF2}1212$OB.dtnSEXZK8U5cgxU/GYQ$y5LKPOplRmok7CZp/aqVDVg8zGI",
        )

        assert hash.ldap_pbkdf2_sha256.verify(
            "password",
            "{PBKDF2-SHA256}1212$4vjV83LKPjQzk31VI4E0Vw$hsYF68OiOUPdDZ1Fg"
            ".fJPeq1h/gXXY7acBp9/6c.tmQ",
        )

        assert hash.ldap_pbkdf2_sha512.verify(
            "password",
            "{PBKDF2-SHA512}1212$RHY0Fr3IDMSVO/RSZyb5ow$eNLfBK.eVozomMr.1gYa1"
            "7k9B7KIK25NOEshvhrSX.esqY3s.FvWZViXz4KoLlQI.BzY/YTNJOiKc5gBYFYGww",
        )


class atlassian_pbkdf2_sha1_test(HandlerCase):
    handler = hash.atlassian_pbkdf2_sha1

    known_correct_hashes = [
        #
        # generated using Jira
        #
        (
            "admin",
            "{PKCS5S2}c4xaeTQM0lUieMS3V5voiexyX9XhqC2dBd5ecVy60IPksHChwoTAVYFrhsgoq8/p",
        ),
        (
            UPASS_WAV,
            "{PKCS5S2}cE9Yq6Am5tQGdHSHhky2XLeOnURwzaLBG2sur7FHKpvy2u0qDn6GcVGRjlmJoIUy",
        ),
    ]

    known_malformed_hashes = [
        # bad char                                    ---\/
        "{PKCS5S2}c4xaeTQM0lUieMS3V5voiexyX9XhqC2dBd5ecVy!0IPksHChwoTAVYFrhsgoq8/p"
        # bad size, missing padding
        "{PKCS5S2}c4xaeTQM0lUieMS3V5voiexyX9XhqC2dBd5ecVy60IPksHChwoTAVYFrhsgoq8/"
        # bad size, with correct padding
        "{PKCS5S2}c4xaeTQM0lUieMS3V5voiexyX9XhqC2dBd5ecVy60IPksHChwoTAVYFrhsgoq8/="
    ]


class pbkdf2_sha1_test(HandlerCase):
    handler = hash.pbkdf2_sha1
    known_correct_hashes = [
        ("password", "$pbkdf2$1212$OB.dtnSEXZK8U5cgxU/GYQ$y5LKPOplRmok7CZp/aqVDVg8zGI"),
        (UPASS_WAV, "$pbkdf2$1212$THDqatpidANpadlLeTeOEg$HV3oi1k5C5LQCgG1BMOL.BX4YZc"),
    ]

    known_malformed_hashes = [
        # zero padded rounds field
        "$pbkdf2$01212$THDqatpidANpadlLeTeOEg$HV3oi1k5C5LQCgG1BMOL.BX4YZc",
        # empty rounds field
        "$pbkdf2$$THDqatpidANpadlLeTeOEg$HV3oi1k5C5LQCgG1BMOL.BX4YZc",
        # too many field
        "$pbkdf2$1212$THDqatpidANpadlLeTeOEg$HV3oi1k5C5LQCgG1BMOL.BX4YZc$",
    ]


class pbkdf2_sha256_test(HandlerCase):
    handler = hash.pbkdf2_sha256
    known_correct_hashes = [
        (
            "password",
            "$pbkdf2-sha256$1212$4vjV83LKPjQzk31VI4E0Vw$hsYF68OiOUPdDZ1Fg.fJPeq1h/gXXY7acBp9/6c.tmQ",
        ),
        (
            UPASS_WAV,
            "$pbkdf2-sha256$1212$3SABFJGDtyhrQMVt1uABPw$WyaUoqCLgvz97s523nF4iuOqZNbp5Nt8do/cuaa7AiI",
        ),
    ]


class pbkdf2_sha512_test(HandlerCase):
    handler = hash.pbkdf2_sha512
    known_correct_hashes = [
        (
            "password",
            "$pbkdf2-sha512$1212$RHY0Fr3IDMSVO/RSZyb5ow$eNLfBK.eVozomMr.1gYa1"
            "7k9B7KIK25NOEshvhrSX.esqY3s.FvWZViXz4KoLlQI.BzY/YTNJOiKc5gBYFYGww",
        ),
        (
            UPASS_WAV,
            "$pbkdf2-sha512$1212$KkbvoKGsAIcF8IslDR6skQ$8be/PRmd88Ps8fmPowCJt"
            "tH9G3vgxpG.Krjt3KT.NP6cKJ0V4Prarqf.HBwz0dCkJ6xgWnSj2ynXSV7MlvMa8Q",
        ),
    ]


class cta_pbkdf2_sha1_test(HandlerCase):
    handler = hash.cta_pbkdf2_sha1
    known_correct_hashes = [
        #
        # test vectors from original implementation
        #
        (
            "hashy the \N{SNOWMAN}",
            "$p5k2$1000$ZxK4ZBJCfQg=$jJZVscWtO--p1-xIZl6jhO2LKR0=",
        ),
        #
        # custom
        #
        ("password", "$p5k2$1$$h1TDLGSw9ST8UMAPeIE13i0t12c="),
        (UPASS_WAV, "$p5k2$4321$OTg3NjU0MzIx$jINJrSvZ3LXeIbUdrJkRpN62_WQ="),
    ]


class dlitz_pbkdf2_sha1_test(HandlerCase):
    handler = hash.dlitz_pbkdf2_sha1
    known_correct_hashes = [
        #
        # test vectors from original implementation
        #
        ("cloadm", "$p5k2$$exec$r1EWMCMk7Rlv3L/RNcFXviDefYa0hlql"),
        ("gnu", "$p5k2$c$u9HvcT4d$Sd1gwSVCLZYAuqZ25piRnbBEoAesaa/g"),
        ("dcl", "$p5k2$d$tUsch7fU$nqDkaxMDOFBeJsTSfABsyn.PYUXilHwL"),
        ("spam", "$p5k2$3e8$H0NX9mT/$wk/sE8vv6OMKuMaqazCJYDSUhWY9YB2J"),
        (UPASS_WAV, "$p5k2$$KosHgqNo$9mjN8gqjt02hDoP0c2J0ABtLIwtot8cQ"),
    ]


class grub_pbkdf2_sha512_test(HandlerCase):
    handler = hash.grub_pbkdf2_sha512
    known_correct_hashes = [
        #
        # test vectors generated from cmd line tool
        #
        # salt=32 bytes
        (
            UPASS_WAV,
            "grub.pbkdf2.sha512.10000.BCAC1CEC5E4341C8C511C529"
            "7FA877BE91C2817B32A35A3ECF5CA6B8B257F751.6968526A"
            "2A5B1AEEE0A29A9E057336B48D388FFB3F600233237223C21"
            "04DE1752CEC35B0DD1ED49563398A282C0F471099C2803FBA"
            "47C7919CABC43192C68F60",
        ),
        # salt=64 bytes
        (
            "toomanysecrets",
            "grub.pbkdf2.sha512.10000.9B436BB6978682363D5C449B"
            "BEAB322676946C632208BC1294D51F47174A9A3B04A7E4785"
            "986CD4EA7470FAB8FE9F6BD522D1FC6C51109A8596FB7AD48"
            "7C4493.0FE5EF169AFFCB67D86E2581B1E251D88C777B98BA"
            "2D3256ECC9F765D84956FC5CA5C4B6FD711AA285F0A04DCF4"
            "634083F9A20F4B6F339A52FBD6BED618E527B",
        ),
    ]


class scram_test(HandlerCase):
    handler = hash.scram

    # TODO: need a bunch more reference vectors from some real
    # SCRAM transactions.
    known_correct_hashes = [
        #
        # taken from example in SCRAM specification (rfc 5802)
        #
        ("pencil", "$scram$4096$QSXCR.Q6sek8bf92$sha-1=HZbuOlKbWl.eR8AfIposuKbhX30"),
        #
        # custom
        #
        # same as 5802 example hash, but with sha-256 & sha-512 added.
        (
            "pencil",
            "$scram$4096$QSXCR.Q6sek8bf92$"
            "sha-1=HZbuOlKbWl.eR8AfIposuKbhX30,"
            "sha-256=qXUXrlcvnaxxWG00DdRgVioR2gnUpuX5r.3EZ1rdhVY,"
            "sha-512=lzgniLFcvglRLS0gt.C4gy.NurS3OIOVRAU1zZOV4P.qFiVFO2/"
            "edGQSu/kD1LwdX0SNV/KsPdHSwEl5qRTuZQ",
        ),
        # test unicode passwords & saslprep (all the passwords below
        # should normalize to the same value: 'IX \xE0')
        (
            "IX \xe0",
            "$scram$6400$0BojBCBE6P2/N4bQ$sha-1=YniLes.b8WFMvBhtSACZyyvxeCc",
        ),
        (
            "\u2168\u3000a\u0300",
            "$scram$6400$0BojBCBE6P2/N4bQ$sha-1=YniLes.b8WFMvBhtSACZyyvxeCc",
        ),
        (
            "\u00adIX \xe0",
            "$scram$6400$0BojBCBE6P2/N4bQ$sha-1=YniLes.b8WFMvBhtSACZyyvxeCc",
        ),
    ]

    known_malformed_hashes = [
        # zero-padding in rounds
        "$scram$04096$QSXCR.Q6sek8bf92$sha-1=HZbuOlKbWl.eR8AfIposuKbhX30",
        # non-digit in rounds
        "$scram$409A$QSXCR.Q6sek8bf92$sha-1=HZbuOlKbWl.eR8AfIposuKbhX30",
        # bad char in salt       ---\/
        "$scram$4096$QSXCR.Q6sek8bf9-$sha-1=HZbuOlKbWl.eR8AfIposuKbhX30",
        # bad char in digest                                       ---\/
        "$scram$4096$QSXCR.Q6sek8bf92$sha-1=HZbuOlKbWl.eR8AfIposuKbhX3-",
        # missing sections
        "$scram$4096$QSXCR.Q6sek8bf92",
        "$scram$4096$QSXCR.Q6sek8bf92$",
        # too many sections
        "$scram$4096$QSXCR.Q6sek8bf92$sha-1=HZbuOlKbWl.eR8AfIposuKbhX30$",
        # missing separator
        "$scram$4096$QSXCR.Q6sek8bf92$sha-1=HZbuOlKbWl.eR8AfIposuKbhX30"
        "sha-256=qXUXrlcvnaxxWG00DdRgVioR2gnUpuX5r.3EZ1rdhVY",
        # too many chars in alg name
        "$scram$4096$QSXCR.Q6sek8bf92$sha-1=HZbuOlKbWl.eR8AfIposuKbhX30,"
        "shaxxx-190=HZbuOlKbWl.eR8AfIposuKbhX30",
        # missing sha-1 alg
        "$scram$4096$QSXCR.Q6sek8bf92$sha-256=HZbuOlKbWl.eR8AfIposuKbhX30",
        # non-iana name
        "$scram$4096$QSXCR.Q6sek8bf92$sha1=HZbuOlKbWl.eR8AfIposuKbhX30",
    ]

    def setUp(self):
        super().setUp()

        # some platforms lack stringprep (e.g. Jython, IronPython)
        self.require_stringprep()

        # silence norm_hash_name() warning
        warnings.filterwarnings("ignore", r"norm_hash_name\(\): unknown hash")

    def test_90_algs(self):
        """test parsing of 'algs' setting"""
        defaults = dict(salt=b"A" * 10, rounds=1000)

        def parse(algs, **kwds):
            for key, value in defaults.items():
                kwds.setdefault(key, value)
            return self.handler(algs=algs, **kwds).algs

        # None -> default list
        assert parse(None, use_defaults=True) == hash.scram.default_algs
        with pytest.raises(TypeError):
            parse(None)

        # strings should be parsed
        assert parse("sha1") == ["sha-1"]
        assert parse("sha1, sha256, md5") == ["md5", "sha-1", "sha-256"]

        # lists should be normalized
        assert parse(["sha-1", "sha256"]) == ["sha-1", "sha-256"]

        # sha-1 required
        with pytest.raises(ValueError):
            parse(["sha-256"])
        with pytest.raises(ValueError):
            parse(algs=[], use_defaults=True)

        # alg names must be < 10 chars
        with pytest.raises(ValueError):
            parse(["sha-1", "shaxxx-190"])

        # alg & checksum mutually exclusive.
        with pytest.raises(RuntimeError):
            parse(["sha-1"], checksum={"sha-1": b"\x00" * 20})

    def test_90_checksums(self):
        """test internal parsing of 'checksum' keyword"""
        # check non-bytes checksum values are rejected
        with pytest.raises(TypeError):
            self.handler(use_defaults=True, checksum={"sha-1": "X" * 20})

        # check sha-1 is required
        with pytest.raises(ValueError):
            self.handler(use_defaults=True, checksum={"sha-256": b"X" * 32})

        # XXX: anything else that's not tested by the other code already?

    def test_91_extract_digest_info(self):
        """test scram.extract_digest_info()"""
        edi = self.handler.extract_digest_info

        # return appropriate value or throw KeyError
        h = "$scram$10$AAAAAA$sha-1=AQ,bbb=Ag,ccc=Aw"
        s = b"\x00" * 4
        assert edi(h, "SHA1") == (s, 10, b"\x01")
        assert edi(h, "bbb") == (s, 10, b"\x02")
        assert edi(h, "ccc") == (s, 10, b"\x03")
        with pytest.raises(KeyError):
            edi(h, "ddd")

        # config strings should cause value error.
        c = "$scram$10$....$sha-1,bbb,ccc"
        with pytest.raises(ValueError):
            edi(c, "sha-1")
        with pytest.raises(ValueError):
            edi(c, "bbb")
        with pytest.raises(ValueError):
            edi(c, "ddd")

    def test_92_extract_digest_algs(self):
        """test scram.extract_digest_algs()"""
        eda = self.handler.extract_digest_algs

        assert eda(
            "$scram$4096$QSXCR.Q6sek8bf92$sha-1=HZbuOlKbWl.eR8AfIposuKbhX30"
        ) == ["sha-1"]

        assert eda(
            "$scram$4096$QSXCR.Q6sek8bf92$sha-1=HZbuOlKbWl.eR8AfIposuKbhX30",
            format="hashlib",
        ) == ["sha1"]

        assert eda(
            "$scram$4096$QSXCR.Q6sek8bf92$"
            "sha-1=HZbuOlKbWl.eR8AfIposuKbhX30,"
            "sha-256=qXUXrlcvnaxxWG00DdRgVioR2gnUpuX5r.3EZ1rdhVY,"
            "sha-512=lzgniLFcvglRLS0gt.C4gy.NurS3OIOVRAU1zZOV4P.qFiVFO2/"
            "edGQSu/kD1LwdX0SNV/KsPdHSwEl5qRTuZQ"
        ) == ["sha-1", "sha-256", "sha-512"]

    def test_93_derive_digest(self):
        """test scram.derive_digest()"""
        # NOTE: this just does a light test, since derive_digest
        # is used by hash / verify, and is tested pretty well via those.
        hash = self.handler.derive_digest

        # check various encodings of password work.
        s1 = b"\x01\x02\x03"
        d1 = b"\xb2\xfb\xab\x82[tNuPnI\x8aZZ\x19\x87\xcen\xe9\xd3"
        assert hash("Ⅸ", s1, 1000, "sha-1") == d1
        assert hash(b"\xe2\x85\xa8", s1, 1000, "SHA-1") == d1
        assert hash("IX", s1, 1000, "sha1") == d1
        assert hash(b"IX", s1, 1000, "SHA1") == d1

        # check algs
        assert (
            hash("IX", s1, 1000, "md5")
            == b"3\x19\x18\xc0\x1c/\xa8\xbf\xe4\xa3\xc2\x8eM\xe8od"
        )
        with pytest.raises(ValueError):
            hash("IX", s1, 1000, "sha-666")

        # check rounds
        with pytest.raises(ValueError):
            hash("IX", s1, 0, "sha-1")

        # unicode salts accepted as of passlib 1.7 (previous caused TypeError)
        assert hash("IX", s1.decode("latin-1"), 1000, "sha1") == d1

    def test_94_saslprep(self):
        """test hash/verify use saslprep"""
        # NOTE: this just does a light test that saslprep() is being
        # called in various places, relying in saslpreps()'s tests
        # to verify full normalization behavior.

        # hash unnormalized
        h = self.do_encrypt("I\u00adX")
        assert self.do_verify("IX", h)
        assert self.do_verify("Ⅸ", h)

        # hash normalized
        h = self.do_encrypt("\xf3")
        assert self.do_verify("ó", h)
        assert self.do_verify("\u200dó", h)

        # throws error if forbidden char provided
        with pytest.raises(ValueError):
            self.do_encrypt("\ufdd0")
        with pytest.raises(ValueError):
            self.do_verify("\ufdd0", h)

    def test_94_using_w_default_algs(self, param="default_algs"):
        """using() -- 'default_algs' parameter"""
        # create subclass
        handler = self.handler
        orig = list(handler.default_algs)  # in case it's modified in place
        subcls = handler.using(**{param: "sha1,md5"})

        # shouldn't have changed handler
        assert handler.default_algs == orig

        # should have own set
        assert subcls.default_algs == ["md5", "sha-1"]

        # test hash output
        h1 = subcls.hash("dummy")
        assert handler.extract_digest_algs(h1) == ["md5", "sha-1"]

    def test_94_using_w_algs(self):
        """using() -- 'algs' parameter"""
        self.test_94_using_w_default_algs(param="algs")

    def test_94_needs_update_algs(self):
        """needs_update() -- algs setting"""
        handler1 = self.handler.using(algs="sha1,md5")

        # shouldn't need update, has same algs
        h1 = handler1.hash("dummy")
        assert not handler1.needs_update(h1)

        # *currently* shouldn't need update, has superset of algs required by handler2
        # (may change this policy)
        handler2 = handler1.using(algs="sha1")
        assert not handler2.needs_update(h1)

        # should need update, doesn't have all algs required by handler3
        handler3 = handler1.using(algs="sha1,sha256")
        assert handler3.needs_update(h1)

    def test_95_context_algs(self):
        """test handling of 'algs' in context object"""
        handler = self.handler
        from passlib.context import CryptContext

        c1 = CryptContext(["scram"], scram__algs="sha1,md5")

        h = c1.hash("dummy")
        assert handler.extract_digest_algs(h) == ["md5", "sha-1"]
        assert not c1.needs_update(h)

        c2 = c1.copy(scram__algs="sha1")
        assert not c2.needs_update(h)

        c2 = c1.copy(scram__algs="sha1,sha256")
        assert c2.needs_update(h)

    def test_96_full_verify(self):
        """test verify(full=True) flag"""

        def vpart(s, h):
            return self.handler.verify(s, h)

        def vfull(s, h):
            return self.handler.verify(s, h, full=True)

        # reference
        h = (
            "$scram$4096$QSXCR.Q6sek8bf92$"
            "sha-1=HZbuOlKbWl.eR8AfIposuKbhX30,"
            "sha-256=qXUXrlcvnaxxWG00DdRgVioR2gnUpuX5r.3EZ1rdhVY,"
            "sha-512=lzgniLFcvglRLS0gt.C4gy.NurS3OIOVRAU1zZOV4P.qFiVFO2/"
            "edGQSu/kD1LwdX0SNV/KsPdHSwEl5qRTuZQ"
        )
        assert vfull("pencil", h)
        assert not vfull("tape", h)

        # catch truncated digests.
        h = (
            "$scram$4096$QSXCR.Q6sek8bf92$"
            "sha-1=HZbuOlKbWl.eR8AfIposuKbhX30,"
            "sha-256=qXUXrlcvnaxxWG00DdRgVioR2gnUpuX5r.3EZ1rdhV,"  # -1 char
            "sha-512=lzgniLFcvglRLS0gt.C4gy.NurS3OIOVRAU1zZOV4P.qFiVFO2/"
            "edGQSu/kD1LwdX0SNV/KsPdHSwEl5qRTuZQ"
        )
        with pytest.raises(ValueError):
            vfull("pencil", h)

        # catch padded digests.
        h = (
            "$scram$4096$QSXCR.Q6sek8bf92$"
            "sha-1=HZbuOlKbWl.eR8AfIposuKbhX30,"
            "sha-256=qXUXrlcvnaxxWG00DdRgVioR2gnUpuX5r.3EZ1rdhVYa,"  # +1 char
            "sha-512=lzgniLFcvglRLS0gt.C4gy.NurS3OIOVRAU1zZOV4P.qFiVFO2/"
            "edGQSu/kD1LwdX0SNV/KsPdHSwEl5qRTuZQ"
        )
        with pytest.raises(ValueError):
            vfull("pencil", h)

        # catch hash containing digests belonging to diff passwords.
        # proper behavior for quick-verify (the default) is undefined,
        # but full-verify should throw error.
        h = (
            "$scram$4096$QSXCR.Q6sek8bf92$"
            "sha-1=HZbuOlKbWl.eR8AfIposuKbhX30,"  # 'pencil'
            "sha-256=R7RJDWIbeKRTFwhE9oxh04kab0CllrQ3kCcpZUcligc,"  # 'tape'
            "sha-512=lzgniLFcvglRLS0gt.C4gy.NurS3OIOVRAU1zZOV4P.qFiVFO2/"  # 'pencil'
            "edGQSu/kD1LwdX0SNV/KsPdHSwEl5qRTuZQ"
        )
        assert vpart("tape", h)
        assert not vpart("pencil", h)
        with pytest.raises(ValueError):
            vfull("pencil", h)
        with pytest.raises(ValueError):
            vfull("tape", h)
