from __future__ import annotations

import pytest

from libpass._utils.binary import B64_CHARS
from libpass.hashers.sha_crypt import SHA256Hasher, SHA512Hasher
from libpass.inspect.sha_crypt import SHA512CryptInfo, inspect_sha_crypt


def test_salt_alphabet():
    assert len(B64_CHARS) == len(set(B64_CHARS))


@pytest.mark.parametrize(
    ("secret", "hash"),
    [
        # from JTR
        ("U*U*U*U*", "$5$LKO/Ute40T3FNF95$U0prpBQd4PloSGU0pnpM4z9wKn4vZ1.jsrzQfPqxph9"),
        ("U*U***U", "$5$LKO/Ute40T3FNF95$fdgfoJEBoMajNxCv3Ru9LyQ0xZgv0OBMQoq80LQ/Qd."),
        ("U*U***U*", "$5$LKO/Ute40T3FNF95$8Ry82xGnnPI/6HtFYnvPBTYgOL23sdMXn8C29aO.x/A"),
        ("*U*U*U*U", "$5$9mx1HkCz7G1xho50$O7V7YgleJKLUhcfk9pgzdh3RapEaWqMtEp9UUBAKIPA"),
        ("", "$5$kc7lRD1fpYg0g.IP$d7CMTcEqJyTXyeq8hTdu/jB/I6DGkoo62NXbHIR7S43"),
        ("Hello world!", "$5$saltstring$5B8vYYiY.CVt1RlTTf8KbXBH3hsxY/GNooZaBBGWEc5"),
        ("password", "$5$V8UMZ8/8.j$GGzeGHZy60318qdLiocMj7DddCnfr7jIcLMDIRy9Tr0"),
        (
            "U*U*U*U*",
            "$5$rounds=50000$LKO/Ute40T3FNF95$S51z7fjx29wblQAQbkqY7G8ExS18kQva39ur8FG5VS0",
        ),
        ("jjti", "$5$UOUBPEMKQRHHRFML$zicoLpMLhBsNGtEplY/ehM0NtiAqxijiBCrolt7WBW0"),
        (
            "hgnirgayjnhvi",
            "$5$XSLWLBSQUCNOWXOB$i7Ho5wUAIjsH2e2zA.WarqYLWir5nmZbUEcjK//Or7.",
        ),
        ("o", "$5$VDCTRFOIDQXRQVHR$uolqT0wEwU.pvI9jq5xU457JQpiwTTKX3PB/9RS4/h4"),
        ("tcepf", "$5$WTYWNCYHNPMXPG$UwZyrq0irhWs4OcLKcqSbFdktZaNAD2by1CiNNw7oID"),
        ("wbfhoc", "$5$DQUHKJNMVOEBGBG$91u2d/jMN5QuW3/kBEPG0xC2G8y1TuDU7SGAUYTX.y0"),
        ("john", "$5$saltstring$0Az3qME7zTXm78kfHrR2OtT8WOu2gd8bcVn/9Y.3l/7"),
        ("a", "$5$saltstring$7cz4bTeQ7MnNssphNhFVrITtuJYY/1tdvLL2uzLvOk8"),
        ("ab", "$5$saltstring$4Wjlxdm/Hbpo8ZQzKFazuvfUZPVVUQn6v1oPTX3nwX/"),
        ("abc", "$5$saltstring$tDHA0KPsYQ8V.LDB1/fgW7cvROod5ZajSrx1tZU2JG9"),
        ("abcd", "$5$saltstring$LfhGTHVGfbAkxy/xKLgvSfXyeE7hZheoMRKhjfvNF6."),
        ("abcde", "$5$saltstring$Qg0Xm9f2VY.ePLAwNXnOPU/s8btLptK/tEU/gFnn8BD"),
        ("abcdef", "$5$saltstring$2Snf.yaHnLnLI3Qhsk2S119X4vKbwQyiTMOHp3Oy7F5"),
        ("abcdefg", "$5$saltstring$4Y5UR.6zwplRx6y93NJVyNkxqdlyT64EV68F2mCrZ16"),
        ("abcdefgh", "$5$saltstring$bEM3iuUR.CTgy8Wygh4zu.CAgmlwx3uxm3dGA34.Ij4"),
        ("abcdefghi", "$5$saltstring$1/OrKXZSFlaEE2DKMhKKE8qCld5X0Ez0vtz5TvO3U3D"),
        ("abcdefghij", "$5$saltstring$1IbZU70/Wo9m1b40ha6Ao8d.v6Ja0.bAFg5/QFVzoX/"),
        ("abcdefghijk", "$5$saltstring$S4gCgloAzqAXE5sRz9DShPvaXrwt4vjDJ4fYgIMbLo1"),
        ("abcdefghijkl", "$5$saltstring$AFNSzsWaoMDvt7lk2bx0rPapzCz2zGahXDdFeoXrNE9"),
        ("abcdefghijklm", "$5$saltstring$QfHc8JBd2DfyloVL0YLDa23Dc67N9mbdYqyRJQlFqZ5"),
        ("abcdefghijklmn", "$5$saltstring$XKHiS.SSJ545PvJJr2t.HyUpmPZDAIT8fVvzr/HGhd0"),
        # custom tests,
        (
            "",
            "$5$rounds=10428$uy/jIAhCetNCTtb0$YWvUOXbkqlqhyoPMpN8BMe.ZGsGx2aBvxTvDFI613c3",
        ),
        (
            " ",
            "$5$rounds=10376$I5lNtXtRmf.OoMd8$Ko3AI1VvTANdyKhBPavaRjJzNpSatKU6QVN9uwS9MH.",
        ),
        (
            "test",
            "$5$rounds=11858$WH1ABM5sKhxbkgCK$aTQsjPkz0rBsH3lQlJxw9HDTDXPKBxC0LlVeV69P.t1",
        ),
        (
            "Compl3X AlphaNu3meric",
            "$5$rounds=10350$o.pwkySLCzwTdmQX$nCMVsnF3TXWcBPOympBUUSQi6LGGloZoOsVJMGJ09UB",
        ),
        (
            "4lpHa N|_|M3r1K W/ Cur5Es: #$%(*)(*%#",
            "$5$rounds=11944$9dhlu07dQMRWvTId$LyUI5VWkGFwASlzntk1RLurxX54LUhgAcJZIt0pYGT7",
        ),
        (
            "with unic\u00d6de",
            "$5$rounds=1000$IbG0EuGQXw5EkMdP$LQ5AfPf13KufFsKtmazqnzSGZ4pxtUNw3woQ.ELRDF4",
        ),
    ],
)
def test_sha256_known_hashes(secret: str, hash: str) -> None:
    hasher = SHA256Hasher()
    assert hasher.verify(hash=hash, secret=secret)


@pytest.mark.parametrize(
    ("hash", "secret"),
    [
        # Test cases from JTR
        # https://github.com/openwall/john/blob/ffd18e6b5d4c8c941f65a2867163db68bb719694/src/sha512crypt_common.h#L87
        (
            "$6$LKO/Ute40T3FNF95$6S/6T2YuOIHY0N3XpLKABJ3soYcXD9mB7uVbtEZDj/LNscVhZoZ9DEH.sBciDrMsHOWOoASbNLTypH/5X26gN0",
            "U*U*U*U*",
        ),
        (
            "$6$LKO/Ute40T3FNF95$wK80cNqkiAUzFuVGxW6eFe8J.fSVI65MD5yEm8EjYMaJuDrhwe5XXpHDJpwF/kY.afsUs1LlgQAaOapVNbggZ1",
            "U*U***U",
        ),
        (
            "$6$LKO/Ute40T3FNF95$YS81pp1uhOHTgKLhSMtQCr2cDiUiN03Ud3gyD4ameviK1Zqz.w3oXsMgO6LrqmIEcG3hiqaUqHi/WEE2zrZqa/",
            "U*U***U*",
        ),
        (
            "$6$OmBOuxFYBZCYAadG$WCckkSZok9xhp4U1shIZEV7CCVwQUwMVea7L3A77th6SaE9jOPupEMJB.z0vIWCDiN9WLh2m9Oszrj5G.gt330",
            "*U*U*U*U",
        ),
        (
            "$6$ojWH1AiTee9x1peC$QVEnTvRVlPRhcLQCk/HnHaZmlGAAjCfrAN0FtOsOnUk5K5Bn/9eLHHiRzrTzaIKjW9NTLNIBUCtNVOowWS2mN.",
            "",
        ),
        (
            "$6$saltstring$svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817G3uBnIFNjnQJuesI68u4OTLiBFdcbYEdFCoEOfaS35inz1",
            "Hello world!",
        ),
        (
            "$6$va2Z2zTYTtF$1CzJmk3A2FO6aH.UrF2BU99oZOYcFlJu5ewPz7ZFvq0w3yCC2G9y4EsymHZxXe5e6Q7bPbyk4BQ5bekdVbmZ20",
            "123456789012345678901234",
        ),
        (
            "$6$1234567890123456$938IMfPJvgxpgwvaqbFcmpz9i/yfYSClzgfwcdDcAdjlj6ZH1fVA9BUe4GDGYN/68UiaR2.pLq4gXFfLZxpMr.",
            "123456789012345678901234",
        ),
        (
            "$6$z5rY05O8xEsEkPIo$e.KPoL.0xBWZHeyY8VQloVEKw2QuDGA9UT7lxO9qduym0ne9sSvl9PZowelKvyji41CYy9Yq0CgJzR6LrmW9m/",
            "1234567890123456789012345678901234567890123456789012345678901234567890123456789",
        ),
        (
            "$6$6IVHO6ILuFRibuMu$SSTNvTegZ5r3jjAish2m1hqfJeX64.btBb8hDQZNvAPx/K.kBfPaFvcXYkC3YxHEBLaOed3UAVDz7NAm.otik0",
            "1234567890123456789012345678901",
        ),
        (
            "$6$ApJWFvgJKcXwSN73$c1wipqpEWqOvcxKg0KcBpMQsNEdbxqIK9M1shyQsGKxIRxCSwcVjAXqGfTTiAJdCVlO2UcBVFNn8m0EjDrujB/",
            "12345678901234567890123456789012",
        ),
        (
            "$6$7B9On3osTM18AJuu$g5gBc05cHNGyskbnLg87OU.BvblHZl0h4JFF7lx6n4qgCRJ6PUVfsruRQadl.eR4jEblHbEPRWK5vfDWWMCaQ.",
            "12345678901234567890123456789012345678901234567",
        ),
        (
            "$6$mpsXsAli1bsaprT2$SBvVIA7N.Tk6Zb.PIHhdlzlUNYXt45XiI9BsOIzjdmo.63YGLoAUQ6TVmeOlMaFKALyQN7.f5xuloVBj2MTkb.",
            "123456789012345678901234567890123456789012345678",
        ),
        (
            "$6$qWotV46KKiE7Ys69$mk9slOOUDXIJ6ElSdzPJDVWFTkxynoUIHtOujyC7mwHe7ZuZp/UzhmHpBgvjahMrrxN55eowki.bTBT6AvRiL.",
            "123456789012345678901234",
        ),
        (
            "$6$DsS6VmHwcMRA5mAo$vWl2YYUsgN3PTtwDLKhfOIEixnA0USAWN2IswislKP7p8pISFLG6PfBJZU8Smekyl0NiReg552lOmEPaOjhKp/",
            "123456789012345",
        ),
        (
            "$6$mwt2GD73BqSk4$ol0oMY1zzm59tnAFnH0OM9R/7SL4gi3VJ42AIVQNcGrYx5S1rlZggq5TBqvOGNiNQ0AmjmUMPc.70kL8Lqost.",
            "password",
        ),
        (
            "$6$rounds=391939$saltstring$P5HDSEq.sTdSBNmknrLQpg6UHp.9.vuEv6QibJNP8ecoNGo9Wa.3XuR7LKu8FprtxGDpGv17Y27RfTHvER4kI0",
            "amy",
        ),
        (
            "$6$rounds=391939$saltstring$JAjUHgEFBJB1lSM25mYGFdH42OOBZ8eytTvKCleaR4jI5cSs0KbATSYyhLj3tkMhmU.fUKfsZkT5y0EYbTLcr1",
            "amy99",
        ),
        (
            "$6$TtrrO3IN$D7Qz38n3JOn4Cc6y0340giveWD8uUvBAdPeCI0iC1cGYCmYHDrVXUEoSf3Qp5TRgo7x0BXN4lKNEj7KOvFTZV1",
            ">7fSy+N\\W=o@Wd&",
        ),
        (
            "$6$yRihAbCh$V5Gr/BhMSMkl6.fBt4TV5lWYY6MhjqApHxDL04HeTgeAX.mZT/0pDDYvArvmCfmMVa/XxzzOBXf1s7TGa2FDL0",
            '0H@<:IS:BfM"V',
        ),
        (
            "$6$rounds=4900$saltstring$p3pnU2njiDujK0Pp5us7qlUvkjVaAM0GilTprwyZ1ZiyGKvsfNyDCnlmc.9ahKmDqyqKXMH3frK1I/oEiEbTK/",
            "Hello world!",
        ),
        (
            "$6$saltstring$fgNTR89zXnDUV97U5dkWayBBRaB0WIBnu6s4T7T8Tz1SbUyewwiHjho25yWVkph2p18CmUkqXh4aIyjPnxdgl0",
            "john",
        ),
        (
            "$6$saltstring$MO53nAXQUKXVLlsbiXyPgMsR6q10N7eF7sPvanwdXnEeCj5kE3eYaRvFv0wVW1UZ4SnNTzc1v4OCOq1ASDQZY0",
            "a",
        ),
        (
            "$6$saltstring$q.eQ9PCFPe/tOHJPT7lQwnVQ9znjTT89hsg1NWHCRCAMsbtpBLbg1FLq7xo1BaCM0y/z46pXv4CGESVWQlOk30",
            "ab",
        ),
        (
            "$6$saltstring$pClZZISU0lxEwKr1z81EuJdiMLwWncjShXap25hiDGVMnCvlF5zS3ysvBdVRZqPDCdSTj06rwjrLX3bOS1Cak/",
            "abc",
        ),
        (
            "$6$saltstring$FJJAXr3hydAPJXM311wrzFhzheQ6LJHrufrYl2kBMnRD2pUi6jdS.fSBJ2J1Qfhcz9tPnlJOzeL7aIYi/dytg.",
            "abcd",
        ),
        (
            "$6$saltstring$XDecvJ/rq8tgbE1Pfuu1cTiZlhnbF5OA/vyP6HRPpDengVqhB38vbZTK/BDfPP6XBgvMzE.q9rj6Ck5blj/FK.",
            "abcde",
        ),
        (
            "$6$saltstring$hYPEYaHik6xSMGV1lDWhF0EerSUyCsC150POu9ksaftUWKWwV8TuqSeSLZUkUhjGy7cn.max5qd5IPSICeklL1",
            "abcdef",
        ),
        (
            "$6$saltstring$YBQ5J5EMRuC6k7B2GTsNaXx8u/957XMB.slQmY/lOjKd1zTIQF.ulLmy8O0VnJJ3cV.1pjP.KCgEjjMpz4pnS1",
            "abcdefg",
        ),
        (
            "$6$saltstring$AQapizZGhnIjtXF8OCvbSxQJBuOKvpzf1solf9b76wXFX0VRkqids5AC4YSibbhMSX0z4463sq1uAd9LvKNuO/",
            "abcdefgh",
        ),
        (
            "$6$saltstring$xc66FVXO.Zvv5pS02B4bCmJh5FCBAZpqTK3NoFxTU9U5b6BokbHwmeqQfMqrrkB3j9CXhCzgvC/pvoGPM1xgM1",
            "abcdefghi",
        ),
        (
            "$6$saltstring$Xet3A8EEzzSuL9hZZ31SfDVPT87qz3a.xxcH7eU50aqARlmXywdlfJ.6Cp/TFG1RcguqwrfUbZBbFn1BQ93Kv.",
            "abcdefghij",
        ),
        (
            "$6$saltstring$MeML1shJ8psyh5R9YJUZNYNqKzYeBvIsITqc/VqJfUDs8xO5YoUhCn4Db7CXuarMDVkBzIUfYq1d8Tj/T1WBU0",
            "abcdefghijk",
        ),
        (
            "$6$saltstring$i/3NHph8ZV2klLuOc5yX5kOnJWj9zuWbKiaa/NNEkYpNyamdQS1c7n2XQS3.B2Cs/eVyKwHf62PnOayqLLTOZ.",
            "abcdefghijkl",
        ),
        (
            "$6$saltstring$l2IxCS4o2S/vud70F1S5Z7H1WE67QFIXCYqskySdLFjjorEJdAnAp1ZqdgfNuZj2orjmeVDTsTXHpZ1IoxSKd.",
            "abcdefghijklm",
        ),
        (
            "$6$saltstring$PFzjspQs/CDXWALauDTav3u5bHB3n21xWrfwjnjpFO5eM5vuP0qKwDCXmlyZ5svEgsIH1oiZiGlRqkcBP5PiB.",
            "abcdefghijklmn",
        ),
        (
            "$6$saltstring$rdREv5Pd9C9YGtg.zXEQMb6m0sPeq4b6zFW9oWY9w4ZltmjH3yzMLgl9iBuez9DFFUvF5nJH3Y2xidiq1dH9M.",
            "abcdefghijklmno",
        ),
    ],
)
def test_sha512_known_hashes(secret: str, hash: str) -> None:
    hasher = SHA512Hasher()
    assert hasher.verify(secret=secret, hash=hash)

    info = inspect_sha_crypt(hash, SHA512CryptInfo)
    assert info
    assert hasher.hash(secret=secret, salt=info.salt, rounds=info.rounds) == hash


@pytest.mark.parametrize(
    ("hasher_cls", "rounds", "hash", "expected"),
    [
        (
            # Default amount of rounds is 5000 if not specified in hash string
            SHA256Hasher,
            5000,
            "$5$V8UMZ8/8.j$GGzeGHZy60318qdLiocMj7DddCnfr7jIcLMDIRy9Tr0",
            False,
        ),
        (
            SHA256Hasher,
            5001,
            "$5$V8UMZ8/8.j$GGzeGHZy60318qdLiocMj7DddCnfr7jIcLMDIRy9Tr0",
            True,
        ),
        (
            SHA256Hasher,
            7777,
            "$5$rounds=7777$V8UMZ8/8.j$GGzeGHZy60318qdLiocMj7DddCnfr7jIcLMDIRy9Tr0",
            False,
        ),
        (
            SHA512Hasher,
            5000,
            "$6$saltstring$xc66FVXO.Zvv5pS02B4bCmJh5FCBAZpqTK3NoFxTU9U5b6BokbHwmeqQfMqrrkB3j9CXhCzgvC/pvoGPM1xgM1",
            False,
        ),
        (
            SHA512Hasher,
            5001,
            "$6$saltstring$xc66FVXO.Zvv5pS02B4bCmJh5FCBAZpqTK3NoFxTU9U5b6BokbHwmeqQfMqrrkB3j9CXhCzgvC/pvoGPM1xgM1",
            True,
        ),
        (
            SHA512Hasher,
            7777,
            "$6$rounds=7777$saltstring$xc66FVXO.Zvv5pS02B4bCmJh5FCBAZpqTK3NoFxTU9U5b6BokbHwmeqQfMqrrkB3j9CXhCzgvC/pvoGPM1xgM1",
            False,
        ),
        (
            SHA256Hasher,
            5000,
            "$6$saltstring$xc66FVXO.Zvv5pS02B4bCmJh5FCBAZpqTK3NoFxTU9U5b6BokbHwmeqQfMqrrkB3j9CXhCzgvC/pvoGPM1xgM1",
            True,
        ),
        (
            SHA512Hasher,
            5000,
            "$5$V8UMZ8/8.j$GGzeGHZy60318qdLiocMj7DddCnfr7jIcLMDIRy9Tr0",
            True,
        ),
    ],
)
def test_needs_update(
    hasher_cls: type[SHA256Hasher | SHA512Hasher],
    rounds: int,
    hash: str,
    expected: bool,
) -> None:
    hasher = hasher_cls(rounds=rounds)
    assert hasher.needs_update(hash=hash) is expected
