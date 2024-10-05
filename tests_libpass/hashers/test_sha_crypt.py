import pytest

from libpass.binary import B64_CHARS
from libpass.hashers.sha_crypt import SHA256Hasher


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
